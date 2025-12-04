import pkg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? {
        rejectUnauthorized: false,
      }
      : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test connection
pool.on("connect", () => {
  console.log("✅ Connected to Neon PostgreSQL database");
});

pool.on("error", (err) => {
  console.error("❌ Database connection error:", err);
});

export const query = (text, params) => pool.query(text, params);

// Initialize database table
export const initDb = async () => {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        userid SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log("✅ Users table ready");

    // Optional: Log existing users count
    const result = await query("SELECT COUNT(*) FROM users");
    console.log(`📊 Total users in database: ${result.rows[0].count}`);
  } catch (error) {
    console.error("❌ Error initializing database:", error);
  }
};

export default pool;
