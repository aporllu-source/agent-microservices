import fs from "fs";

const FILE = "./data.json";

function load() {
  try {
    const raw = fs.readFileSync(FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      apiKeys: Array.isArray(parsed.apiKeys) ? parsed.apiKeys : [],
      freeByIp: typeof parsed.freeByIp === "object" && parsed.freeByIp ? parsed.freeByIp : {},
      usage: typeof parsed.usage === "object" && parsed.usage ? parsed.usage : {}
    };
  } catch {
    return { apiKeys: [], freeByIp: {}, usage: {} };
  }
}

function save(state) {
  fs.writeFileSync(FILE, JSON.stringify(state, null, 2));
}

const state = load();

function todayKeyUTC() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

export function addApiKey(key) {
  if (!state.apiKeys.includes(key)) {
    state.apiKeys.push(key);
    state.usage[key] = state.usage[key] || {
      calls_total: 0,
      day: todayKeyUTC(),
      calls_today: 0,
      last_call_at: null
    };
    save(state);
  }
}

export function hasApiKey(key) {
  return state.apiKeys.includes(key);
}

export function getFreeUntil(ip) {
  return state.freeByIp[ip] ?? null;
}

export function setFreeUntil(ip, expiresAt) {
  state.freeByIp[ip] = expiresAt;
  save(state);
}

export function getUsageForKey(apiKey) {
  if (!apiKey) return null;

  const t = todayKeyUTC();
  const u = state.usage[apiKey] || { calls_total: 0, day: t, calls_today: 0, last_call_at: null };

  if (u.day !== t) {
    u.day = t;
    u.calls_today = 0;
    state.usage[apiKey] = u;
    save(state);
  }

  return u;
}

export function recordUsage(apiKey) {
  if (!apiKey) return;

  const u = getUsageForKey(apiKey) || { calls_total: 0, day: todayKeyUTC(), calls_today: 0, last_call_at: null };

  u.calls_total += 1;
  u.calls_today += 1;
  u.last_call_at = new Date().toISOString();

  state.usage[apiKey] = u;
  save(state);
}

export function getUsageSnapshot() {
  // Ojo: esto no “resetea” el día; para eso usa getUsageForKey
  return state.usage;
}

