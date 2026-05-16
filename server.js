import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Pool } from "@neondatabase/serverless";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Nodemailer setup with SendGrid
const transporter = nodemailer.createTransport({
  host: "smtp.sendgrid.net",
  port: 587,
  secure: false,
  auth: {
    user: "apikey",
    pass: process.env.SENDGRID_API_KEY,
  },
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

// Save data route
app.post("/submit", async (req, res) => {
  try {
    console.log("BODY:", req.body);

    const { email, phone } = req.body;

    if (!email || !phone) {
      return res.status(400).json({ success: false, error: "Missing fields" });
    }

    // Insert to database
    try {
      await pool.query(
        "INSERT INTO submissions (email, phone) VALUES ($1, $2)",
        [email, phone]
      );
      console.log("✅ Database insert successful");
    } catch (dbErr) {
      console.error("❌ Database error:", dbErr.message);
      throw dbErr;
    }

    // Send confirmation email
    try {
      const emailFrom = process.env.EMAIL_FROM || "Support@ithelpdesk.help";
      console.log("📧 Sending email from:", emailFrom);
      await transporter.sendMail({
        from: emailFrom,
        to: email,
        subject: "Submission Received",
        html: `<p>Thank you for submitting! We received your phone number: <strong>${phone}</strong></p>`,
      });
      console.log("✅ Email sent successfully");
    } catch (emailErr) {
      console.error("❌ Email error:", emailErr.message);
      throw emailErr;
    }

    res.json({ success: true });

  } catch (err) {
    console.error("❌ Error:", err);
    res.status(500).json({ success: false, error: err.message || "Server error" });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});