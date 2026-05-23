import path from "path";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";

function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

/* =========================
   MIDDLEWARE
========================= */

app.use(cors({
  origin: [
    "https://ithelpdesk.help",
    "https://www.ithelpdesk.help",
    "https://outlook-q5f8.onrender.com",
    "http://localhost:4000"
  ],
  methods: ["GET", "POST"],
  credentials: true
}));


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

/* =========================
   DATABASE
========================= */

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
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
   MAILER
========================= */

const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  secure: false,
  auth: {
    user: "apikey",
    pass: process.env.SENDGRID_API_KEY
  }
});

async function verifyMailer() {
  try {
    await transporter.verify();
    console.log("✅ Mail server ready");
  } catch (err) {
    console.error("❌ Mailer error:", err.message);
  }
}

verifyMailer();

/* =========================
   ROUTES
========================= */

app.get("/", (req, res) => {
  res.sendFile(path.resolve("index.html"));
});

/* =========================
   SEND EMAIL CODE
========================= */

app.post("/send-email-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: "Email is required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({ success: false, error: "Invalid email" });
    }

    const recent = await pool.query(`
      SELECT created_at
      FROM email_verifications
      WHERE email = $1
      ORDER BY created_at DESC
      LIMIT 1
    `, [normalizedEmail]);

    if (recent.rows.length > 0) {
      const last = new Date(recent.rows[0].created_at).getTime();
      if (Date.now() - last < 60 * 1000) {
        return res.status(429).json({
          success: false,
          error: "Wait 1 minute before requesting another code"
        });
      }
    }

    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    await pool.query(`DELETE FROM email_verifications WHERE email = $1`, [normalizedEmail]);

    await pool.query(`
      INSERT INTO email_verifications (email, code, expires_at)
      VALUES ($1, $2, $3)
    `, [normalizedEmail, code, expiresAt]);

    await transporter.sendMail({
      from: `"ItHelpDesk" <${process.env.EMAIL_FROM}>`,
      to: normalizedEmail,
      subject: "Your Verification Code",
      text: `Your code is ${code}. Expires in 10 minutes.`
    });

    res.json({ success: true, message: "Code sent" });

  } catch (err) {
    console.error("SEND ERROR:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* =========================
   VERIFY CODE
========================= */

app.post("/verify-email-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ success: false, error: "Missing fields" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(`
      SELECT * FROM email_verifications
      WHERE email = $1
      ORDER BY created_at DESC
      LIMIT 1
    `, [normalizedEmail]);

    if (!result.rows.length) {
      return res.status(400).json({ success: false, error: "No code found" });
    }

    const record = result.rows[0];

    if (Date.now() > Number(record.expires_at)) {
      await pool.query(`DELETE FROM email_verifications WHERE email = $1`, [normalizedEmail]);
      return res.status(400).json({ success: false, error: "Code expired" });
    }

    if (record.code !== code.trim()) {
      return res.status(400).json({ success: false, error: "Invalid code" });
    }

    await pool.query(`DELETE FROM email_verifications WHERE email = $1`, [normalizedEmail]);

    const token = jwt.sign(
  { email: normalizedEmail },
  process.env.JWT_SECRET,
  { expiresIn: "1h" }
);

res.json({
  success: true,
  message: "Verified",
  token
});

  } catch (err) {
    console.error("VERIFY ERROR:", err);
    res.status(500).json({ success: false, error: "Verification failed" });
  }
});

/* =========================
   CLEANUP JOB
========================= */

setInterval(async () => {
  try {
    await pool.query(`
      DELETE FROM email_verifications
      WHERE expires_at < $1
    `, [Date.now()]);
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
   START
========================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});