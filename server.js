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

const app = express();
const PORT = process.env.PORT || 4000;

const { Pool } = pkg;

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
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
      "https://ithelpdesk.help",
      "https://www.ithelpdesk.help",
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
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        expires_at BIGINT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("✅ Database ready");
  } catch (err) {
    console.error("DB ERROR:", err);
  }
}

initDB();

/* =========================
   MAILER (SENDGRID)
========================= */

const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  secure: false,
  auth: {
    user: "apikey",
    pass: process.env.SENDGRID_API_KEY,
  },
});

transporter.verify()
  .then(() => console.log("✅ Mail server ready"))
  .catch((err) => console.error("❌ Mailer error:", err.message));

/* =========================
   ROUTES
========================= */

import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* =========================
   REGISTER
========================= */

app.post("/register", async (req, res) => {
  try {
    const { email, password, phone } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Missing fields",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await pool.query(
      `SELECT id FROM users WHERE email = $1 LIMIT 1`,
      [normalizedEmail]
    );

    if (existing.rows.length) {
      return res.status(400).json({
        success: false,
        error: "User already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await pool.query(
      `INSERT INTO users (email, phone, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email`,
      [normalizedEmail, phone || null, passwordHash]
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

    await pool.query(
      `INSERT INTO email_verifications (email, code, expires_at)
       VALUES ($1, $2, $3)`,
      [normalizedEmail, code, expiresAt]
    );

    await transporter.sendMail({
      from: `"ItHelpDesk" <${process.env.EMAIL_FROM}>`,
      to: normalizedEmail,
      subject: "Your Verification Code",
      text: `Your code is ${code}. Expires in 10 minutes.`,
    });

    res.json({ success: true, message: "Code sent" });
  } catch (err) {
    console.error("SEND ERROR:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* =========================
   VERIFY EMAIL CODE
========================= */

app.post("/verify-email-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: "Missing fields",
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
      return res.status(400).json({
        success: false,
        error: "Invalid code",
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