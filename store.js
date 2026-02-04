import fs from "fs";

const FILE = "./data.json";

function load() {
  try {
    const raw = fs.readFileSync(FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      apiKeys: Array.isArray(parsed.apiKeys) ? parsed.apiKeys : [],
      freeByIp: typeof parsed.freeByIp === "object" && parsed.freeByIp ? parsed.freeByIp : {}
    };
  } catch {
    return { apiKeys: [], freeByIp: {} };
  }
}

function save(state) {
  fs.writeFileSync(FILE, JSON.stringify(state, null, 2));
}

const state = load();

export function addApiKey(key) {
  if (!state.apiKeys.includes(key)) {
    state.apiKeys.push(key);
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

