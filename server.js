import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { Pool } from "@neondatabase/serverless";
import nodemailer from "nodemailer";
import path from "path";

dotenv.config();

const app = express();

const allowedOrigins = [
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(/[,\s]+/) : []),
  ...(process.env.APP_BASE_URL ? [process.env.APP_BASE_URL] : []),
]
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowAnyOrigin = ["1", "true", "yes", "on"].includes(
  (process.env.ALLOW_ANY_ORIGIN ?? "").toLowerCase()
);

const corsOptions = {
  origin: allowAnyOrigin
    ? true
    : function (origin, callback) {
        if (!origin) {
          // Allow non-browser requests like server-to-server or curl.
          return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
        console.warn(`⚠️ CORS denied for origin: ${origin}`);
        callback(new Error("CORS origin denied"));
      },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept",
    "Origin",
    "Referer",
  ],
  exposedHeaders: ["Content-Length"],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204,
  maxAge: 86400,
};

app.use(cors(corsOptions));

// Handle CORS preflight requests without using a path pattern that breaks
// path-to-regexp (avoid app.options("*", ...) which can throw).
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    // Use the cors middleware to set headers and end the preflight.
    return cors(corsOptions)(req, res, () => res.sendStatus(204));
  }
  next();
});

app.use(express.json());

// Serve static files from the project root (so index.html is returned at GET /)
app.use(express.static(path.resolve(".")));

// Root route: return the site's index.html
app.get("/", (req, res) => {
  res.sendFile(path.resolve("index.html"));
});

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
      const emailFromName = process.env.EMAIL_FROM_NAME || "IT HELP DESK";
      const emailReplyTo = process.env.EMAIL_REPLY_TO || emailFrom;
      console.log("📧 Sending email from:", `${emailFromName} <${emailFrom}>`);
      await transporter.sendMail({
        from: `${emailFromName} <${emailFrom}>`,
        to: email,
        replyTo: emailReplyTo,
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

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});