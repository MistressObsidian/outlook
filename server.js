import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";
import path from "path";
import rateLimit from "express-rate-limit";

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
    "https://outlook-q5f8.onrender.com"
  ],
  methods: ["GET", "POST"],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

/* =========================
   STATIC FILES
========================= */

app.use(express.static(path.resolve(".")));

/* =========================
   DATABASE (pg + Neon)
========================= */

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // REQUIRED for Neon
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
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
    pass: process.env.SENDGRID_API_KEY,
  },
});

// In-memory store for email verification codes
const emailCodes = new Map();

/* =========================
   ROUTES
========================= */

// Homepage
app.get("/", (req, res) => {
  res.sendFile(path.resolve("index.html"));
});

// Admin page
app.get("/admin", (req, res) => {
  res.sendFile(path.resolve("admin.html"));
});

// Health check
app.get("/api-test", (req, res) => {
  res.json({ success: true, message: "API is running" });
});

// Get submissions
app.get("/admin/submissions", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, email, phone, created_at
      FROM submissions
      ORDER BY created_at DESC
    `);

    res.json({ success: true, submissions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Failed to fetch submissions" });
  }
});

// Send email verification code
app.post("/send-email-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: "Email is required" });
    }

    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    emailCodes.set(email.toLowerCase(), { code, expiresAt });

    await transporter.sendMail({
  from: `"ItHelpDesk Security" <${process.env.EMAIL_FROM}>`,
  to: email,
  subject: "Your security code",
  text: `Your verification code is ${code}. It expires in 10 minutes.`,
  templateId: "d-510f9f4261ff47f2a293b31e0b0ff4b9",
  dynamic_template_data: {
    code: code
  }
});

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Verify email code
app.post("/verify-email-code", (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ success: false, error: "Email and code are required" });
    }

    const record = emailCodes.get(email.toLowerCase());

    if (!record) {
      return res.status(400).json({ success: false, error: "No code found. Request a new one." });
    }

    if (Date.now() > record.expiresAt) {
      emailCodes.delete(email.toLowerCase());
      return res.status(400).json({ success: false, error: "Code expired." });
    }

    if (record.code !== code.trim()) {
      return res.status(400).json({ success: false, error: "Invalid code." });
    }

    emailCodes.delete(email.toLowerCase());
    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin send email
app.post("/admin/send-email", async (req, res) => {
  try {
    const { to, subject, message } = req.body;

    if (!to || !subject || !message) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      html: message.replace(/\n/g, "<br>")
    });

    res.json({ success: true, message: "Email sent" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Submit form
app.post("/submit", async (req, res) => {
  try {
    const { email, phone } = req.body;

    if (!email || !phone) {
      return res.status(400).json({ success: false, error: "Email and phone are required" });
    }

    await pool.query(
      `INSERT INTO submissions (email, phone) VALUES ($1, $2)`,
      [email, phone]
    );

    await transporter.sendMail({
      from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
      replyTo: process.env.EMAIL_REPLY_TO,
      to: process.env.EMAIL_TO,
      subject: "New Submission",
      html: `
        <h2>New Submission</h2>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone}</p>
      `
    });

    res.json({ success: true, message: "Submission received" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

/* =========================
   404 HANDLER
========================= */

app.use((req, res) => {
  res.status(404).json({ success: false, error: "Route not found" });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});