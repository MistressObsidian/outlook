import dotenv from "dotenv";
import pkg from "pg";

dotenv.config();

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

try {
  const result = await pool.query("SELECT version();");
  console.log("✅ Connected!");
  console.log(result.rows[0]);
} catch (err) {
  console.error("❌ Connection failed");
  console.error(err);
} finally {
  await pool.end();
}