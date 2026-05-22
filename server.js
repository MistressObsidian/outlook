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

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

app.use(express.static(path.resolve(".")));

/* =========================
   DATABASE
========================= */

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function initDB() {
  try {

    // submissions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // otp storage
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
  res.json({
    success: true,
    message: "API is running"
  });
});

/* =========================
   SEND EMAIL CODE
========================= */

app.post("/send-email-code", async (req, res) => {

  try {

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required"
      });
    }

    const normalizedEmail = email.toLowerCase();

    // cooldown protection
    const recentCode = await pool.query(`
      SELECT created_at
      FROM email_verifications
      WHERE email = $1
      ORDER BY created_at DESC
      LIMIT 1
    `, [normalizedEmail]);

    if (recentCode.rows.length > 0) {

      const lastCreated = new Date(recentCode.rows[0].created_at).getTime();
      const now = Date.now();

      if (now - lastCreated < 60 * 1000) {
        return res.status(429).json({
          success: false,
          error: "Please wait before requesting another code."
        });
      }
    }

    const code = crypto.randomInt(100000, 999999).toString();

    const expiresAt = Date.now() + (10 * 60 * 1000);

    // remove old codes
    await pool.query(`
      DELETE FROM email_verifications
      WHERE email = $1
    `, [normalizedEmail]);

    // save new code
    await pool.query(`
      INSERT INTO email_verifications (
        email,
        code,
        expires_at
      )
      VALUES ($1, $2, $3)
    `, [
      normalizedEmail,
      code,
      expiresAt
    ]);

    // send email
    await transporter.sendMail({

      from: `"ItHelpDesk Security" <${process.env.EMAIL_FROM}>`,

      to: normalizedEmail,

      subject: "Security alert: new sign-in detected",

      text: `Your verification code is ${code}. This code expires in 10 minutes.`,

      templateId: "d-3b57d898c5c14adcb4ae56b0bc0efb5b",

      headers: {
        "X-Priority": "3",
        "X-Mailer": "ItHelpDesk"
      },

      dynamic_template_data: {
        code,
        action_url: "https://ithelpdesk.help/",
        device: req.headers["user-agent"] || "Unknown device",
        ip: req.ip || "Unknown IP",
        time: new Date().toLocaleString()
      }

    });

    res.json({
      success: true,
      message: "Verification code sent"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      success: false,
      error: err.message
    });

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
        error: "Email and code are required"
      });
    }

    const normalizedEmail = email.toLowerCase();

    const result = await pool.query(`
      SELECT *
      FROM email_verifications
      WHERE email = $1
      ORDER BY created_at DESC
      LIMIT 1
    `, [normalizedEmail]);

    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: "No verification code found."
      });
    }

    const record = result.rows[0];

    if (Date.now() > Number(record.expires_at)) {

      await pool.query(`
        DELETE FROM email_verifications
        WHERE email = $1
      `, [normalizedEmail]);

      return res.status(400).json({
        success: false,
        error: "Verification code expired."
      });

    }

    if (record.code !== code.trim()) {
      return res.status(400).json({
        success: false,
        error: "Invalid verification code."
      });
    }

    // remove used code
    await pool.query(`
      DELETE FROM email_verifications
      WHERE email = $1
    `, [normalizedEmail]);

    res.json({
      success: true,
      message: "Email verified"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      success: false,
      error: err.message
    });

  }

});

/* =========================
   ADMIN SEND EMAIL
========================= */

app.post("/admin/send-email", async (req, res) => {

  try {

    const { to, subject, message } = req.body;

    if (!to || !subject || !message) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields"
      });
    }

    await transporter.sendMail({

      from: `"ItHelpDesk" <${process.env.EMAIL_FROM}>`,

      to,

      subject,

      text: message,

      html: message.replace(/\n/g, "<br>")

    });

    res.json({
      success: true,
      message: "Email sent"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      success: false,
      error: err.message
    });

  }

});

/* =========================
   SUBMIT FORM
========================= */

app.post("/submit", async (req, res) => {

  try {

    const { email, phone } = req.body;

    if (!email || !phone) {
      return res.status(400).json({
        success: false,
        error: "Email and phone are required"
      });
    }

    await pool.query(`
      INSERT INTO submissions (
        email,
        phone
      )
      VALUES ($1, $2)
    `, [email, phone]);

    await transporter.sendMail({

      from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,

      replyTo: process.env.EMAIL_REPLY_TO,

      to: process.env.EMAIL_TO,

      subject: "New Submission",

      text: `
Email: ${email}
Phone: ${phone}
      `,

      html: `
        <h2>New Submission</h2>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone}</p>
      `

    });

    res.json({
      success: true,
      message: "Submission received"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      success: false,
      error: "Internal server error"
    });

  }

});

/* =========================
   CLEANUP EXPIRED OTPS
========================= */

setInterval(async () => {

  try {

    await pool.query(`
      DELETE FROM email_verifications
      WHERE expires_at < $1
    `, [Date.now()]);

  } catch (err) {

    console.error("OTP cleanup error:", err);

  }

}, 5 * 60 * 1000);

/* =========================
   404 HANDLER
========================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found"
  });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});