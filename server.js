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

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "development"
      ? { rejectUnauthorized: false }
      : false,
});

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
      "https://auth.basecrypto.help",
      "http://localhost:4000",
    ],
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
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

transporter.verify()
  .then(() => console.log("✅ Mail server ready"))
  .catch((err) => console.error("❌ Mailer error:", err.message));

/* =========================
   ROUTES
========================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/account", (req, res) => {
  res.sendFile(
    path.resolve(__dirname, "../Thompson/Thompsons-Jewellers-Standalone.html")
  );
});

/* =========================
   REGISTER
========================= */

function normalizePhone(value) {
  let phone = String(value || "").trim();
  phone = phone.replace(/(?:ext\.?|extension|x)\s*\d+$/i, "").trim();
  phone = phone.replace(/[\s().-]/g, "");

  if (phone.startsWith("00")) phone = "+" + phone.slice(2);
  if (/^\d{10}$/.test(phone)) phone = "+1" + phone;
  else if (/^1\d{10}$/.test(phone)) phone = "+" + phone;

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

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = normalizePhone(phone);

    if (!normalizedPhone) {
      return res.status(400).json({
        success: false,
        error: "Enter a valid phone number with country code",
      });
    }

    const existing = await pool.query(
      `SELECT id, email_verified FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail]
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
        [normalizedEmail, normalizedPhone, passwordHash]
      );

      return res.json({ success: true, user: user.rows[0], retry: true });
    }

    const user = await pool.query(
      `INSERT INTO users (email, phone, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email`,
      [normalizedEmail, normalizedPhone, passwordHash]
    );

    res.json({
      success: true,
      user: user.rows[0],
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ success: false, error: "Registration failed" });
  }
});

/* =========================
   SEND EMAIL CODE
========================= */

app.post("/send-email-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: "Email required" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const userResult = await pool.query(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail]
    );

    if (!userResult.rows.length) {
      return res.status(404).json({ success: false, error: "User not found" });
    }


    // cooldown check (last OTP)
    const recent = await pool.query(
      `SELECT created_at
       FROM email_verifications
       WHERE email = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [normalizedEmail]
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

    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await pool.query(
      `DELETE FROM email_verifications WHERE email = $1`,
      [normalizedEmail]
    );

    const verification = await pool.query(
      `INSERT INTO email_verifications (email, code, expires_at)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [normalizedEmail, code, expiresAt]
    );

    try {
      const delivery = await transporter.sendMail({
        from: `"ItHelpDesk" <${process.env.EMAIL_FROM}>`,
        to: normalizedEmail,
        subject: "Your Verification Code",
        text: `Your code is ${code}. Expires in 10 minutes.`,
      });

      if (!delivery.accepted?.length) {
        throw new Error("Mail provider did not accept the recipient");
      }
    } catch (deliveryError) {
      // Never retain a code that the mail provider did not accept.
      await pool.query(
        `DELETE FROM email_verifications WHERE id = $1`,
        [verification.rows[0].id]
      );
      console.error("DELIVERY ERROR:", deliveryError.message);
      return res.status(502).json({
        success: false,
        error: "We could not deliver the code. Please try again.",
      });
    }

    res.json({ success: true, message: "Code sent" });
  } catch (err) {
    console.error("SEND ERROR:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* =========================
   VERIFY EMAIL CODE
========================= */

app.post("/verify-email-code", verifyCodeLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !/^\d{6}$/.test(String(code).trim())) {
      return res.status(400).json({
        success: false,
        error: "Enter a valid 6-digit code",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(`
      SELECT *
      FROM email_verifications
      WHERE email = $1
      ORDER BY created_at DESC
      LIMIT 1
    `, [normalizedEmail]);

    if (!result.rows.length) {
      return res.status(400).json({
        success: false,
        error: "No code found",
      });
    }

    const record = result.rows[0];

    if (Date.now() > Number(record.expires_at)) {
      await pool.query(
        `DELETE FROM email_verifications WHERE email = $1`,
        [normalizedEmail]
      );

      return res.status(400).json({
        success: false,
        error: "Code expired",
      });
    }

    if (record.code !== code.trim()) {
      const failedAttempt = await pool.query(
        `UPDATE email_verifications
         SET attempts = attempts + 1
         WHERE id = $1
         RETURNING attempts`,
        [record.id]
      );

      const attempts = failedAttempt.rows[0]?.attempts ?? 5;
      if (attempts >= 5) {
        await pool.query(
          `DELETE FROM email_verifications WHERE id = $1`,
          [record.id]
        );
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

    await pool.query(
      `UPDATE users SET email_verified = true WHERE email = $1`,
      [normalizedEmail]
    );

    await pool.query(
      `DELETE FROM email_verifications WHERE email = $1`,
      [normalizedEmail]
    );

    // FIXED: get user id properly
    const userResult = await pool.query(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail]
    );

    const userId = userResult.rows[0]?.id;

    const token = jwt.sign(
      { id: userId, email: normalizedEmail },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      message: "Email verified",
      token,
    });

  } catch (err) {
    console.error("VERIFY ERROR:", err);
    res.status(500).json({
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

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail]
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
      { expiresIn: "1h" }
    );

    res.json({
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
    res.status(500).json({ success: false, error: "Login failed" });
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
      [req.user.email]
    );

    res.json({
      success: true,
      user: result.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      error: "Dashboard fetch failed",
    });
  }
});

/* =========================
   CLEANUP JOB
========================= */

setInterval(async () => {
  try {
    await pool.query(
      `DELETE FROM email_verifications WHERE expires_at < $1`,
      [Date.now()]
    );
  } catch (err) {
    console.error("Cleanup error:", err);
  }
}, 5 * 60 * 1000);

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({ success: false, error: "Not found" });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
