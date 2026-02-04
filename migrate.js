import { pool } from "./db.js";

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY,
      email TEXT,
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id SERIAL PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      customer_id INTEGER REFERENCES customers(id),
      credits_remaining INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS credit_ledger (
      id SERIAL PRIMARY KEY,
      api_key_id INTEGER REFERENCES api_keys(id),
      amount INTEGER NOT NULL,
      reason TEXT,
      created_at TIMESTAMP DEFAULT now()
    );
  `);

  console.log("✅ Database migrated");
  process.exit(0);
}

migrate().catch(err => {
  console.error("❌ Migration failed", err);
  process.exit(1);
});

