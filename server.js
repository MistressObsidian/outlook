import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Pool } from "@neondatabase/serverless";
import nodemailer from "nodemailer";
import path from "path";

dotenv.config();

const app = express();

app.use(cors({
  origin: [
    "https://ithelpdesk.help",
    "https://www.ithelpdesk.help"
  ]
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.resolve(".")));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  secure: false,
  auth: {
    user: "apikey",
    pass: process.env.SENDGRID_API_KEY,
  },
});

// Home route
app.get("/", (req, res) => {
  res.sendFile(path.resolve("index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.resolve("admin.html"));
});

app.get("/admin/submissions", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, phone, created_at FROM submissions ORDER BY created_at DESC"
    );

    res.json({
      success: true,
      submissions: result.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.post("/admin/send-email", async (req, res) => {
  try {
    const { to, subject, message } = req.body;

    if (!to || !subject || !message) {
      return res.status(400).json({
        success: false,
        error: "To, subject, and message are required."
      });
    }

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: to,
      subject: subject,
      html: message.replace(/\n/g, '<br />')
    });

    res.json({
      success: true
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.get("/api-test", (req, res) => {
  res.json({
    working: true
  });
});

// Create table
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        id SERIAL PRIMARY KEY,
        email TEXT,
        phone TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("✅ Database ready");
  } catch (err) {
    console.error(err);
  }
}

initDB();

app.get("/", (req, res) => {
  res.json({
    status: "Backend is running"
  });
});

// Submit route
app.get("/submit", (req, res) => {
  res.json({
    status: "submit route working"
  });
});

app.post("/submit", async (req, res) => {
  try {
    const { email, phone } = req.body;

    console.log("BODY:", req.body);

    if (!email || !phone) {
      return res.status(400).json({
        success: false,
        error: "Missing fields"
      });
    }

    // Save to DB
    await pool.query(
      "INSERT INTO submissions (email, phone) VALUES ($1, $2)",
      [email, phone]
    );

    // Send email notification
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: process.env.EMAIL_TO,
      subject: "New Submission",
      html: `
        <h2>New Submission</h2>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone}</p>
      `
    });

    res.json({
      success: true
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.listen(process.env.PORT || 4000, () => {
  console.log(`🚀 Server running on port ${process.env.PORT || 4000}`);
});