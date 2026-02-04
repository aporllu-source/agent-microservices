import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import crypto from "crypto";
import { checkWebEntityStatus } from "./checker.js";
import { createApiKey, getApiKey, decrementCredit, addCredits } from "./store_pg.js";

const app = Fastify({ logger: true });

// ====================
// CONFIG
// ====================
const CACHE_TTL_MS = 60 * 60 * 1000;     // 1h
const API_KEY_RPM = 120;                 // req/min por API key
const DEFAULT_INITIAL_CREDITS = 1000;    // créditos al crear una key (ajústalo)
const COST_PER_CALL = 1;                 // 1 crédito por llamada

const cache = new Map();                 // url -> { data, expiresAt }
const apiKeyRate = new Map();            // "key:bucket" -> count

// ====================
// RATE LIMIT IP
// ====================
await app.register(rateLimit, {
  max: 60,
  timeWindow: "1 minute",
  keyGenerator: (req) => req.ip
});

// ====================
// HEALTH
// ====================
app.get("/health", async () => ({ ok: true }));

// ====================
// CATALOG
// ====================
app.get("/catalog.json", async () => ({
  version: "1.0",
  updated_at: new Date().toISOString(),
  services: [
    {
      service: "web_entity_status",
      description: "Checks if a web entity exists, is reachable, and appears legitimate.",
      endpoint: "/v1/web-entity-status",
      method: "POST",
      pricing: {
        model: "credits",
        cost_per_call_credits: COST_PER_CALL
      },
      rate_limits: {
        ip: "60/min",
        api_key: `${API_KEY_RPM}/min`
      },
      inputs: { url: { type: "string", required: true, example: "https://example.com" } },
      outputs: [
        "exists","reachable","http_status","final_url","ssl_valid",
        "suspected_parked_domain","confidence_score","checked_at"
      ],
      auth: { header: "x-api-key" }
    }
  ]
}));

// ====================
// CREATE API KEY (PROTECTED)
// body: { credits?: number }
// ====================
app.post("/v1/api-keys", {
  schema: {
    body: {
      type: "object",
      properties: {
        credits: { type: "integer", minimum: 0, maximum: 100000000 }
      }
    }
  }
}, async (req, reply) => {
  const provisionKey = process.env.PROVISION_KEY || "";
  const header = (req.headers["x-provision-key"] || "").toString();

  if (!provisionKey || header !== provisionKey) {
    reply.code(403);
    return { error: { code: "FORBIDDEN", message: "Missing or invalid x-provision-key" } };
  }

  const initialCredits =
    typeof req.body?.credits === "number" ? req.body.credits : DEFAULT_INITIAL_CREDITS;

  const created = await createApiKey({ credits: initialCredits });
  return { api_key: created.key, credits_remaining: created.credits_remaining };
});

// ====================
// ADMIN: list keys (PROTECTED)
// ====================
app.get("/v1/admin/api-keys", async (req, reply) => {
  const adminKey = process.env.ADMIN_KEY || "";
  const header = (req.headers["x-admin-key"] || "").toString();

  if (!adminKey || header !== adminKey) {
    reply.code(403);
    return { error: { code: "FORBIDDEN", message: "Invalid x-admin-key" } };
  }

  // lista simple: (ojo: en store_pg.js no tenemos función de listar; lo hacemos aquí)
  const { pool } = await import("./db.js");
  const { rows } = await pool.query(
    `SELECT id, key, credits_remaining, active, created_at
     FROM api_keys
     ORDER BY id DESC
     LIMIT 200`
  );

  return { ok: true, items: rows };
});

// ====================
// ADMIN: topup credits (PROTECTED)
// body: { api_key: string, amount: number }
// ====================
app.post("/v1/admin/topup", {
  schema: {
    body: {
      type: "object",
      required: ["api_key", "amount"],
      properties: {
        api_key: { type: "string", minLength: 5, maxLength: 200 },
        amount: { type: "integer", minimum: 1, maximum: 100000000 }
      }
    }
  }
}, async (req, reply) => {
  const adminKey = process.env.ADMIN_KEY || "";
  const header = (req.headers["x-admin-key"] || "").toString();

  if (!adminKey || header !== adminKey) {
    reply.code(403);
    return { error: { code: "FORBIDDEN", message: "Invalid x-admin-key" } };
  }

  const k = await getApiKey(req.body.api_key);
  if (!k) {
    reply.code(404);
    return { error: { code: "NOT_FOUND", message: "API key not found or inactive" } };
  }

  await addCredits(k.id, req.body.amount, "admin_topup");

  const k2 = await getApiKey(req.body.api_key);
  return { ok: true, credits_remaining: k2.credits_remaining };
});

// ====================
// MAIN SERVICE
// POST /v1/web-entity-status
// ====================
app.post("/v1/web-entity-status", {
  schema: {
    body: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string", minLength: 1, maxLength: 2048 }
      }
    }
  }
}, async (req, reply) => {
  const requestId = "req_" + crypto.randomBytes(10).toString("hex");

  try {
    const apiKey = (req.headers["x-api-key"] || "").toString().trim();
    if (!apiKey) {
      reply.code(401);
      return { error: { code: "UNAUTHORIZED", message: "Missing x-api-key" }, request_id: requestId };
    }

    const keyRow = await getApiKey(apiKey);
    if (!keyRow) {
      reply.code(401);
      return { error: { code: "UNAUTHORIZED", message: "Invalid API key" }, request_id: requestId };
    }

    // ---- API KEY RATE LIMIT (RPM)
    const bucket = Math.floor(Date.now() / 60000);
    const rlKey = `${apiKey}:${bucket}`;
    const n = (apiKeyRate.get(rlKey) || 0) + 1;
    apiKeyRate.set(rlKey, n);
    if (n > API_KEY_RPM) {
      reply.code(429);
      return { error: { code: "RATE_LIMITED", message: "API key rate limit exceeded" }, request_id: requestId };
    }

    // ---- CREDIT CHECK
    if (keyRow.credits_remaining < COST_PER_CALL) {
      reply.code(402);
      return {
        error: { code: "OUT_OF_CREDITS", message: "Not enough credits. Top up to continue." },
        credits_remaining: keyRow.credits_remaining,
        request_id: requestId
      };
    }

    // ---- CACHE
    const cacheKey = req.body.url;
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      // cobramos igualmente (lo normal en APIs de verificación)
      const ok = await decrementCredit(keyRow.id);
      if (!ok) {
        reply.code(402);
        return {
          error: { code: "OUT_OF_CREDITS", message: "Not enough credits. Top up to continue." },
          credits_remaining: 0,
          request_id: requestId
        };
      }

      return { ...cached.data, cached: true, request_id: requestId };
    }

    // ---- CHECK
    const result = await checkWebEntityStatus(req.body.url);

    // ---- STORE CACHE
    cache.set(cacheKey, { data: result, expiresAt: Date.now() + CACHE_TTL_MS });

    // ---- DECREMENT CREDIT (after successful check)
    const ok = await decrementCredit(keyRow.id);
    if (!ok) {
      reply.code(402);
      return {
        error: { code: "OUT_OF_CREDITS", message: "Not enough credits. Top up to continue." },
        credits_remaining: 0,
        request_id: requestId
      };
    }

    return { ...result, request_id: requestId };

  } catch (err) {
    req.log.error({ err }, "web_entity_status_failed");
    reply.code(400);
    return { error: { code: "BAD_REQUEST", message: err?.message || "Invalid request" }, request_id: requestId };
  }
});

// ====================
// START
// ====================
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = "0.0.0.0";

app.listen({ port: PORT, host: HOST });

