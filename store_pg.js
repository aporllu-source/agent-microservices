import crypto from "crypto";
import { pool } from "./db.js";

function randomKeyHex(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

export async function createApiKey({ credits = 0 } = {}) {
  const key = "ak_" + randomKeyHex(24);

  const { rows } = await pool.query(
    `INSERT INTO api_keys (key, credits_remaining)
     VALUES ($1, $2)
     RETURNING key, credits_remaining`,
    [key, credits]
  );

  return rows[0];
}

export async function getApiKey(key) {
  const { rows } = await pool.query(
    `SELECT id, key, credits_remaining, active, created_at
     FROM api_keys
     WHERE key = $1 AND active = true`,
    [key]
  );
  return rows[0] || null;
}

export async function decrementCredit(apiKeyId) {
  const res = await pool.query(
    `UPDATE api_keys
     SET credits_remaining = credits_remaining - 1
     WHERE id = $1 AND credits_remaining > 0
     RETURNING credits_remaining`,
    [apiKeyId]
  );
  return res.rowCount === 1;
}

export async function addCredits(apiKeyId, amount, reason = "topup") {
  await pool.query(
    `UPDATE api_keys
     SET credits_remaining = credits_remaining + $1
     WHERE id = $2`,
    [amount, apiKeyId]
  );

  await pool.query(
    `INSERT INTO credit_ledger (api_key_id, amount, reason)
     VALUES ($1, $2, $3)`,
    [apiKeyId, amount, reason]
  );
}

