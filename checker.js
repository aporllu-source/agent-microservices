import dns from "dns/promises";
import net from "net";
import fetch from "node-fetch";

const TIMEOUT_MS = 4500;
const MAX_REDIRECTS = 5;
const MAX_BYTES = 200_000;
const USER_AGENT = "AgentMicroservice/0.1 (+web_entity_status)";

const PARKING_PATTERNS = [
  "domain for sale",
  "buy this domain",
  "this domain is for sale",
  "sedo",
  "afternic",
  "parked",
  "parking"
];

const CONTACT_HINTS = [
  "contact", "contacto", "kontakt", "contatti", "contato", "nous contacter"
];

const LEGAL_HINTS = [
  "privacy", "terms", "legal", "impressum",
  "aviso legal", "politica de privacidad", "términos", "condiciones"
];

function nowIso() {
  return new Date().toISOString();
}

function clamp01(x) {
  return Math.max(0, Math.min(1, x));
}

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return false;

  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    return false;
  }

  if (ip === "::1") return true;
  const lower = ip.toLowerCase();
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (lower.startsWith("fe8") || lower.startsWith("fe9") ||
      lower.startsWith("fea") || lower.startsWith("feb")) return true;

  return false;
}

function normalizeUrl(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("url is required");

  if (!/^https?:\/\//i.test(s)) {
    s = "https://" + s;
  }

  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(u.protocol)) {
    throw new Error("Only http/https allowed");
  }

  if (u.username || u.password) {
    throw new Error("Credentials in URL not allowed");
  }

  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) {
    throw new Error("Localhost not allowed");
  }

  if (net.isIP(host) && isPrivateIp(host)) {
    throw new Error("Private IP not allowed");
  }

  return u;
}

async function resolveDns(hostname) {
  const ips = [];
  try {
    ips.push(...await dns.resolve4(hostname));
  } catch {}
  try {
    ips.push(...await dns.resolve6(hostname));
  } catch {}
  return ips;
}

function extractSignalsFromHtml(html) {
  const lower = html.toLowerCase();

  const hasTitle = /<title[^>]*>.*?<\/title>/.test(lower);
  const hasContact = CONTACT_HINTS.some(h => lower.includes(h));
  const hasLegal = LEGAL_HINTS.some(h => lower.includes(h));

  const parkingHit = PARKING_PATTERNS.some(p => lower.includes(p));

  return {
    has_title: hasTitle,
    has_contact_like_links: hasContact,
    has_legal_like_links: hasLegal,
    parking_hit: parkingHit
  };
}

function computeConfidence({
  reachable,
  httpStatus,
  sslValid,
  contentTypeHtml,
  contentLengthOk,
  hasTitle,
  hasContactOrLegal,
  suspectedParked
}) {
  let score = 0;
  if (reachable) score += 0.35;
  if (httpStatus >= 200 && httpStatus <= 399) score += 0.15;
  if (sslValid) score += 0.10;
  if (contentTypeHtml) score += 0.10;
  if (contentLengthOk) score += 0.10;
  if (hasTitle) score += 0.10;
  if (hasContactOrLegal) score += 0.10;
  if (suspectedParked) score -= 0.25;
  return clamp01(score);
}

async function fetchWithLimits(url, redirectsLeft) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res;
  const start = Date.now();
  try {
    res = await fetch(url, {
      method: "GET",
      headers: {
        "user-agent": USER_AGENT,
        "accept": "text/html,*/*"
      },
      redirect: "manual",
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }

  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const loc = res.headers.get("location");
    if (loc && redirectsLeft > 0) {
      const nextUrl = new URL(loc, url).toString();
      return fetchWithLimits(nextUrl, redirectsLeft - 1);
    }
  }

  const contentType = (res.headers.get("content-type") || "").toLowerCase();
  let bytes = 0;
  let text = "";

  if (res.body) {
    for await (const chunk of res.body) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buf.length;
      if (bytes > MAX_BYTES) break;
      text += buf.toString("utf8");
    }
  }

  return {
    status: res.status,
    contentType,
    bodyText: text,
    bytesDownloaded: bytes,
    responseTimeMs: Date.now() - start,
    finalUrl: url
  };
}

export async function checkWebEntityStatus(inputUrl) {
  const u = normalizeUrl(inputUrl);
  const ips = await resolveDns(u.hostname);

  if (ips.length === 0) {
    return {
      exists: false,
      reachable: false,
      http_status: null,
      final_url: null,
      response_time_ms: null,
      ssl_valid: null,
      suspected_parked_domain: null,
      signals: {},
      confidence_score: 0,
      checked_at: nowIso()
    };
  }

  if (ips.some(isPrivateIp)) {
    throw new Error("Host resolves to private IP");
  }

  const r = await fetchWithLimits(u.toString(), MAX_REDIRECTS);

  const contentTypeHtml = r.contentType.includes("text/html");
  const contentLengthOk = r.bytesDownloaded >= 5000;
  const sig = extractSignalsFromHtml(r.bodyText);

  const suspectedParked = sig.parking_hit || (!sig.has_title && r.bytesDownloaded < 8000);
  const hasContactOrLegal = sig.has_contact_like_links || sig.has_legal_like_links;

  const confidence = computeConfidence({
    reachable: true,
    httpStatus: r.status,
    sslValid: u.protocol === "https:",
    contentTypeHtml,
    contentLengthOk,
    hasTitle: sig.has_title,
    hasContactOrLegal,
    suspectedParked
  });

  return {
    exists: true,
    reachable: true,
    http_status: r.status,
    final_url: r.finalUrl,
    response_time_ms: r.responseTimeMs,
    ssl_valid: u.protocol === "https:",
    suspected_parked_domain: suspectedParked,
    signals: {
      content_type_html: contentTypeHtml,
      content_length_ok: contentLengthOk,
      has_title: sig.has_title,
      has_contact_like_links: sig.has_contact_like_links,
      has_legal_like_links: sig.has_legal_like_links
    },
    confidence_score: confidence,
    checked_at: nowIso()
  };
}

