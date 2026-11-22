// Decode links rewritten by mail-security gateways, redirectors and click trackers (mirrors unwrap.py).
import { AD_NETWORKS } from "./data.js";
import { splitDomain } from "./psl.js";

const MAX_DEPTH = 5;
const MAX_LEN = 8192;
const HTTP = /^https?:\/\//i;
const PP_V3 = /\/v3\/__(.+?)__;([A-Za-z0-9_\-]*)!/;
const RUN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const AVANAN = /\/v2\/(?:r\d+\/)?___(.+?)___\./i;
export const EMBED_PARAMS = ["url", "u", "redirect", "redirect_url", "redirect_uri", "redirecturl", "redir", "target",
  "dest", "destination", "goto", "link", "out", "to", "continue", "next", "return", "returnurl", "return_url"];

const hostIs = (host, ...domains) => domains.some((d) => host === d || host.endsWith("." + d));

function unquote(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    // Python's unquote never fails: decode what it can, byte run by byte run.
    return s.replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
  }
}

/** parse_qs: first value per lower-cased name, '+' as space, blank values dropped. */
function parseQuery(query) {
  const out = new Map();
  for (const part of query.split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = unquote(part.slice(0, eq).replace(/\+/g, " ")).toLowerCase();
    const v = unquote(part.slice(eq + 1).replace(/\+/g, " "));
    if (v && !out.has(k)) out.set(k, v);
  }
  return out;
}

const first = (qs, ...names) => {
  for (const n of names) if (qs.get(n)) return qs.get(n);
  return null;
};

function clean(url) {
  if (!url) return null;
  url = url.trim();
  return url.length > MAX_LEN || !HTTP.test(url) ? null : url;
}

function b64(text) {
  let t = unquote(text).trim().replace(/-/g, "+").replace(/_/g, "/");
  t += "=".repeat((4 - (t.length % 4)) % 4);
  try {
    const bin = atob(t);
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
}

function proofpointV2(raw) {
  const m = /[?&]u=([^&#]+)/.exec(raw);
  return m ? unquote(m[1].replace(/-/g, "%").replace(/_/g, "/")) : null;
}

function proofpointV3(raw) {
  const m = PP_V3.exec(raw);
  if (!m) return null;
  const url = unquote(m[1]);
  let repl = "";
  if (m[2]) {
    repl = b64(m[2]);
    if (repl === null) return null;
  }
  const chars = Array.from(repl);
  let out = "", pos = 0, used = 0;
  const tok = /\*(\*.)?/g;
  let t;
  while ((t = tok.exec(url))) {
    out += url.slice(pos, t.index);
    let n = 1;
    if (t[0] !== "*") {
      const idx = RUN_CHARS.indexOf(t[0].slice(-1));
      if (idx < 0) return null;
      n = idx + 2;
    }
    if (used + n > chars.length) return null;
    out += chars.slice(used, used + n).join("");
    used += n;
    pos = tok.lastIndex;
  }
  return out + url.slice(pos);
}

function splitUrl(url) {
  // urlsplit-like: scheme, host (lower-case, no port), path, query.
  const m = /^([a-z][a-z0-9+.\-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?/i.exec(url);
  if (!m) return null;
  let net = m[2];
  const at = net.lastIndexOf("@");
  if (at >= 0) net = net.slice(at + 1);
  let host = net;
  if (host.startsWith("[")) host = host.slice(0, host.indexOf("]") + 1);
  else if (host.includes(":")) host = host.slice(0, host.lastIndexOf(":"));
  return { scheme: m[1].toLowerCase(), host: host.toLowerCase().replace(/\.$/, ""), path: m[3] || "", query: m[4] || "" };
}

function decodeOne(url) {
  const parts = splitUrl(url);
  if (!parts || !["http", "https"].includes(parts.scheme) || !parts.host) return null;
  const { host, path } = parts;
  const lpath = path.toLowerCase();
  const qs = parseQuery(parts.query);
  const hop = (service, vendor, kind, inner, trusted = true, domainOnly = null) =>
    ({ service, vendor, kind, host, wrapper_url: url, url: clean(inner), trusted, domain_only: domainOnly, param: null });

  if (hostIs(host, "safelinks.protection.outlook.com", "safelinks.protection.office365.us",
    "safelinks.protection.outlook.de", "safelinks.protection.partner.outlook.cn")) {
    return hop("Microsoft Defender Safe Links", "Microsoft", "gateway", first(qs, "url"));
  }
  if (host === "statics.teams.cdn.office.net" && lpath.includes("/safelinks/")) {
    return hop("Microsoft Teams Safe Links", "Microsoft", "gateway", first(qs, "url"));
  }
  if (host === "urldefense.proofpoint.com") {
    if (path.startsWith("/v1/")) return hop("Proofpoint URL Defense (v1)", "Proofpoint", "gateway", first(qs, "u"));
    if (path.startsWith("/v2/")) return hop("Proofpoint URL Defense (v2)", "Proofpoint", "gateway", proofpointV2(url));
  }
  if ((host === "urldefense.com" || host === "urldefense.us") && url.includes("/v3/__")) {
    return hop("Proofpoint URL Defense (v3)", "Proofpoint", "gateway", proofpointV3(url));
  }
  if (lpath.includes("/fmlurlsvc/") || lpath.replace(/\/+$/, "").endsWith("/fmlurlsvc")) {
    return hop("FortiMail URL click protection", "Fortinet", "gateway", first(qs, "url"), false);
  }
  if (hostIs(host, "mimecast.com", "mimecastprotect.com") && path.startsWith("/s/")) {
    const dom = first(qs, "domain");
    return hop("Mimecast URL Protect", "Mimecast", "gateway", null, true,
      dom && /^[\p{L}\p{N}_.\-]{1,253}$/u.test(dom) ? dom.toLowerCase() : null);
  }
  if (host === "linkprotect.cudasvc.com") return hop("Barracuda Link Protection", "Barracuda", "gateway", first(qs, "a"));
  if (host === "secure-web.cisco.com") {
    const segs = path.split("/");
    return hop("Cisco Secure Email", "Cisco", "gateway", segs.length >= 3 ? unquote(segs.slice(2).join("/")) : null);
  }
  if (host === "clicktime.symantec.com") return hop("Symantec Click-time URL Protection", "Broadcom", "gateway", first(qs, "u"));
  if (hostIs(host, "trendmicro.com", "trendmicro.eu") && lpath.includes("/wis/clicktime/")) {
    return hop("Trend Micro Click-time Protection", "Trend Micro", "gateway", first(qs, "url"));
  }
  if (hostIs(host, "protection.sophos.com")) {
    const enc = first(qs, "u"), dom = first(qs, "d");
    return hop("Sophos Email Time-of-Click", "Sophos", "gateway", enc ? b64(enc) : null, true, dom && !enc ? dom.toLowerCase() : null);
  }
  if (host === "url.avanan.click") {
    const m = AVANAN.exec(url);
    return hop("Check Point Harmony Email (Avanan)", "Check Point", "gateway", m ? m[1] : null);
  }
  if (hostIs(host, "awstrack.me")) {
    const segs = path.split("/");
    return hop("Amazon SES click tracking", "Amazon Web Services", "tracking", segs.length > 2 && segs[1] === "L0" ? unquote(segs[2]) : null);
  }
  if ((host === "google.com" || host === "www.google.com") && path === "/url") return hop("Google redirect", "Google", "redirect", first(qs, "q", "url"));
  if (["l.facebook.com", "lm.facebook.com", "l.messenger.com"].includes(host) && path === "/l.php") return hop("Facebook link shim", "Meta", "redirect", first(qs, "u"));
  if (host === "l.instagram.com") return hop("Instagram link shim", "Meta", "redirect", first(qs, "u"));
  if (host === "slack-redir.net" && path.startsWith("/link")) return hop("Slack redirect", "Slack", "redirect", first(qs, "url"));
  if ((host === "www.youtube.com" || host === "youtube.com") && path === "/redirect") return hop("YouTube redirect", "Google", "redirect", first(qs, "q"));
  if ((host === "www.linkedin.com" || host === "linkedin.com") && (path.startsWith("/redir/") || path.startsWith("/safety/go"))) {
    return hop("LinkedIn redirect", "LinkedIn", "redirect", first(qs, "url"));
  }
  if (host === "steamcommunity.com" && path.startsWith("/linkfilter")) return hop("Steam link filter", "Valve", "redirect", first(qs, "url", "u"));
  for (const [vendor, domains] of Object.entries(AD_NETWORKS)) {
    if (hostIs(host, ...domains)) return hop(`${vendor} ad redirect`, vendor, "advert", null);
  }
  if (hostIs(host, "sendgrid.net") && path.includes("/ls/click")) return hop("SendGrid click tracking", "Twilio SendGrid", "tracking", null);
  if (hostIs(host, "list-manage.com") && path.startsWith("/track/click")) return hop("Mailchimp click tracking", "Intuit Mailchimp", "tracking", null);
  return null;
}

const registrable = (host) => splitDomain(host).registrable || host;

function embedded(url) {
  const parts = splitUrl(url);
  if (!parts || !["http", "https"].includes(parts.scheme) || !parts.host || !parts.query) return null;
  const qs = parseQuery(parts.query);
  for (const name of EMBED_PARAMS) {
    const val = clean(first(qs, name));
    if (!val) continue;
    const inner = splitUrl(val);
    if (inner && inner.host && registrable(inner.host) !== registrable(parts.host)) {
      return { service: "Address inside the link", vendor: "", kind: "embedded", host: parts.host, wrapper_url: url,
        url: val, trusted: false, domain_only: null, param: name };
    }
  }
  return null;
}

/** The page an ExoClick ad was shown on (its 'p=' parameter), when the link names one (mirrors ad_source). */
export function adSource(hop) {
  if (!hop || hop.kind !== "advert" || hop.vendor !== "ExoClick") return null;
  const parts = splitUrl(hop.wrapper_url);
  const page = parts && parts.query ? first(parseQuery(parts.query), "p") : null;
  const inner = page ? splitUrl(page) : null;
  const host = inner && inner.host ? inner.host.toLowerCase().replace(/\.$/, "") : "";
  return /^[a-z0-9][a-z0-9.-]{0,252}$/.test(host) ? host : null;
}

export function unwrap(url) {
  const result = { original: url, destination: url, hops: [], embedded: null };
  if (typeof url !== "string" || url.length > MAX_LEN) return result;
  let current = url.trim();
  const seen = new Set([current]);
  for (let i = 0; i < MAX_DEPTH; i++) {
    const h = decodeOne(current);
    if (!h) break;
    result.hops.push(h);
    if (!h.url || seen.has(h.url)) break;
    seen.add(h.url);
    current = h.url;
  }
  const last = result.hops[result.hops.length - 1];
  if (last && last.url) result.destination = last.url;
  else if (last && last.domain_only) result.destination = `https://${last.domain_only}/`;
  else if (last) result.destination = last.wrapper_url;
  result.opaque = last && !last.url ? last : null;
  if (!result.opaque) result.embedded = embedded(result.destination);
  return result;
}
