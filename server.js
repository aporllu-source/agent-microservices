import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import crypto from "crypto";
import { checkWebEntityStatus } from "./checker.js";
import {
  addApiKey,
  hasApiKey,
  getFreeUntil,
  setFreeUntil,
  recordUsage,
  getUsageForKey,
  getUsageSnapshot
} from "./store.js";

const app = Fastify({ logger: true });

// --------------------
// Config global
// --------------------
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hora
const FREE_TTL_MS = 24 * 60 * 60 * 1000; // 24h
const API_KEY_RPM = 120;               // 120 req/min por API key
const API_KEY_DAILY_LIMIT = 1000;      // <-- PRICING REAL: cambia este número

const cache = new Map(); // url -> { data, expiresAt }

// --------------------
// Rate limit por IP (protección básica)
// --------------------
await app.register(rateLimit, {
  max: 60,
  timeWindow: "1 minute",
  keyGenerator: (req) => req.ip
});

// --------------------
// Healthcheck
// --------------------
app.get("/health", async () => ({ ok: true }));

// --------------------
// Catálogo
// --------------------
app.get("/catalog.json", async () => ({
  version: "1.0",
  updated_at: new Date().toISOString(),
  services: [
    {
      service: "web_entity_status",
      description: "Checks if a web entity exists, is reachable, and appears legitimate.",
      endpoint: "/v1/web-entity-status",
      method: "POST",
      pricing: { model: "per_call", first_call: "free", cost_eur: 0.40 },
      limits: {
        free_tier: "1 call / 24h per IP",
        api_key_daily: API_KEY_DAILY_LIMIT
      },
      rate_limits: {
        ip: "60 calls / minute",
        api_key: `${API_KEY_RPM} calls / minute`
      },
      latency_ms: { typical: "200-800", max: 4500 },
      inputs: { url: { type: "string", required: true, example: "https://example.com" } },
      outputs: [
        "exists","reachable","http_status","final_url","ssl_valid",
        "suspected_parked_domain","confidence_score","checked_at"
      ],
      auth: { header: "x-api-key", obtain_key: "POST /v1/api-keys" }
    }
  ]
}));

// --------------------
// Crear API key (persistente)
// --------------------
app.post("/v1/api-keys", async () => {
  const apiKey = "ak_" + crypto.randomBytes(24).toString("hex");
  addApiKey(apiKey);
  return { api_key: apiKey, daily_limit: API_KEY_DAILY_LIMIT };
});

// --------------------
// Admin: ver usage (protegido)
// Header: x-admin-key: <ADMIN_KEY>
// --------------------
app.get("/v1/admin/usage", async (req, reply) => {
  const adminKey = process.env.ADMIN_KEY || "";
  const header = (req.headers["x-admin-key"] || "").toString();

  if (!adminKey || header !== adminKey) {
    reply.code(403);
    return { error: { code: "FORBIDDEN", message: "Missing or invalid x-admin-key" } };
  }

  return { ok: true, usage: getUsageSnapshot() };
});

// --------------------
// Micro-servicio principal
// --------------------
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
    const headerKey = (req.headers["x-api-key"] || "").toString().trim();
    const hasApiKeyHeader = headerKey.length > 0;
    const hasValidApiKey = hasApiKeyHeader && hasApiKey(headerKey);

    // 0️⃣ LÍMITE DIARIO (pricing real)
    if (hasValidApiKey) {
      const u = getUsageForKey(headerKey); // normaliza el día (resetea calls_today si cambia)
      if (u && u.calls_today >= API_KEY_DAILY_LIMIT) {
        reply.code(402);
        return {
          error: {
            code: "DAILY_LIMIT_REACHED",
            message: "Daily limit reached for this API key. Contact support to upgrade."
          },
          limits: {
            daily_limit: API_KEY_DAILY_LIMIT,
            calls_today: u.calls_today
          },
          request_id: requestId
        };
      }
    }

    // Rate limit por API key (120/min) — MVP in-memory
    if (hasValidApiKey) {
      const bucket = Math.floor(Date.now() / 60000);
      const key = `rl:${headerKey}:${bucket}`;

      if (!app.__rl) app.__rl = new Map();
      const m = app.__rl;

      const n = (m.get(key) || 0) + 1;
      m.set(key, n);

      if (n > API_KEY_RPM) {
        reply.code(429);
        return {
          error: { code: "RATE_LIMITED", message: "API key rate limit exceeded" },
          request_id: requestId
        };
      }
    }

    // 1️⃣ FIRST CALL FREE (persistente por IP) — si no hay API key válida
    const ip = req.ip;
    const freeUntil = getFreeUntil(ip);
    const hasFreeAvailable = !freeUntil || freeUntil <= Date.now();

    if (!hasValidApiKey && !hasFreeAvailable) {
      reply.code(402);
      return {
        error: {
          code: "PAYMENT_REQUIRED",
          message: "Free quota used for this IP. Create an API key via POST /v1/api-keys and send it as x-api-key."
        },
        request_id: requestId
      };
    }

    if (!hasValidApiKey && hasFreeAvailable) {
      setFreeUntil(ip, Date.now() + FREE_TTL_MS);
    }

    // 2️⃣ CACHE por URL
    const cacheKey = req.body.url;
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      if (hasValidApiKey) recordUsage(headerKey);
      return { ...cached.data, cached: true, request_id: requestId };
    }

    // 3️⃣ CHECKER
    const result = await checkWebEntityStatus(req.body.url);

    // 4️⃣ GUARDAR EN CACHE
    cache.set(cacheKey, { data: result, expiresAt: Date.now() + CACHE_TTL_MS });

    // 5️⃣ LOG USAGE (solo si API key válida)
    if (hasValidApiKey) recordUsage(headerKey);

    return { ...result, request_id: requestId };

  } catch (err) {
    req.log.error({ err }, "web_entity_status_failed");
    reply.code(400);
    return {
      error: { code: "BAD_REQUEST", message: err?.message || "Invalid request" },
      request_id: requestId
    };
  }
});

// --------------------
// Arranque
// --------------------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = process.env.HOST || "0.0.0.0";

app.listen({ port: PORT, host: HOST });

