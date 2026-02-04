import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import crypto from "crypto";
import { checkWebEntityStatus } from "./checker.js";
import { addApiKey, hasApiKey, getFreeUntil, setFreeUntil } from "./store.js";

const app = Fastify({ logger: true });

// --------------------
// Config global
// --------------------
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hora
const FREE_TTL_MS = 24 * 60 * 60 * 1000; // 24h

const cache = new Map(); // url -> { data, expiresAt }

// --------------------
// Rate limit básico (protección)
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
// Crear API key (persistente)
// --------------------
app.post("/v1/api-keys", async () => {
  const apiKey = "ak_" + crypto.randomBytes(24).toString("hex");
  addApiKey(apiKey);
  return { api_key: apiKey };
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
    const headerKey = req.headers["x-api-key"];
    const hasApiKeyHeader = typeof headerKey === "string" && headerKey.trim().length > 0;
    const keyTrim = hasApiKeyHeader ? headerKey.trim() : "";
    const hasValidApiKey = keyTrim ? hasApiKey(keyTrim) : false;

    // 1️⃣ FIRST CALL FREE (persistente por IP)
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
      return { ...cached.data, cached: true, request_id: requestId };
    }

    // 3️⃣ CHECKER
    const result = await checkWebEntityStatus(req.body.url);

    // 4️⃣ GUARDAR EN CACHE
    cache.set(cacheKey, { data: result, expiresAt: Date.now() + CACHE_TTL_MS });

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
// Catálogo legible por agentes
// --------------------
app.get("/catalog.json", async () => {
  return {
    version: "1.0",
    updated_at: new Date().toISOString(),
    services: [
      {
        service: "web_entity_status",
        description: "Checks if a web entity exists, is reachable, and appears legitimate.",
        endpoint: "/v1/web-entity-status",
        method: "POST",
        pricing: {
          model: "per_call",
          first_call: "free",
          cost_eur: 0.40
        },
        rate_limits: {
          free_tier: "1 call / 24h per IP",
          authenticated: "subject to API key limits"
        },
        latency_ms: {
          typical: "200-800",
          max: 4500
        },
        inputs: {
          url: {
            type: "string",
            required: true,
            example: "https://example.com"
          }
        },
        outputs: [
          "exists",
          "reachable",
          "http_status",
          "final_url",
          "ssl_valid",
          "suspected_parked_domain",
          "confidence_score",
          "checked_at"
        ],
        auth: {
          header: "x-api-key",
          obtain_key: "POST /v1/api-keys"
        }
      }
    ]
  };
});

// --------------------
// Arranque
// --------------------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = process.env.HOST || "0.0.0.0";

app.listen({ port: PORT, host: HOST });

