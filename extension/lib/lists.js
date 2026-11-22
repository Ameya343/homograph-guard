// Allowlist / blocklist / reported links kept in the browser (used when the desktop app is not installed).
// Matching mirrors threatdb.py: a domain entry covers its sub-domains, a link entry covers longer links under it.
import { normalizeDomain } from "./brands.js";
import { splitDomain } from "./psl.js";

const MAX_ENTRY = 2048;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function isIPv6(h) {
  if (!h.includes(":") || !/^[0-9a-f:.]+$/i.test(h)) return false;
  try {
    return new URL(`http://[${h}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

function hostOf(host) {
  const h = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (IPV4.test(h) || isIPv6(h)) return h;
  return normalizeDomain(h);
}

export function normalizeUrl(url) {
  if (typeof url !== "string" || url.length > 8192) return null;
  let u;
  try {
    u = new URL(url.trim());
  } catch {
    return null;
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname) return null;
  let path = u.pathname || "/";
  if (path.length > 1) path = path.replace(/\/+$/, "") || "/";
  return `${u.protocol}//${u.host}${path}${u.search}`;
}

export function urlCandidates(norm) {
  const q = norm.indexOf("?");
  const base = q >= 0 ? norm.slice(0, q) : norm;
  const sep = base.indexOf("://") + 3;
  const slash = base.indexOf("/", sep);
  const root = slash >= 0 ? base.slice(0, slash) : base;
  const segments = (slash >= 0 ? base.slice(slash + 1) : "").split("/").filter(Boolean);
  const out = q >= 0 ? [norm] : [];
  for (let i = segments.length; i > 0; i--) out.push(`${root}/${segments.slice(0, i).join("/")}`);
  out.push(`${root}/`);
  return [...new Set(out)];
}

export function hostCandidates(host) {
  const h = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (IPV4.test(h) || h.includes(":")) return [h];
  const labels = h.split(".");
  const out = [];
  for (let i = 0; i < labels.length - 1; i++) out.push(labels.slice(i).join("."));
  return out.length ? out : [h];
}

/** ["domain", "evil.example"] or ["url", "https://evil.example/login"]; throws on anything else. */
export function normalizeEntry(text) {
  if (typeof text !== "string") throw new Error("entry must be text");
  text = text.trim();
  if (!text || text.length > MAX_ENTRY) throw new Error("entry is empty or too long");
  if (text.includes("://") || text.includes("/")) {
    const norm = normalizeUrl(text.includes("://") ? text : `https://${text}`);
    if (!norm) throw new Error("not a web link (http/https) or domain");
    const rest = norm.slice(norm.indexOf("://") + 3);
    if (rest.endsWith("/") && rest.indexOf("/") === rest.length - 1) return ["domain", rest.slice(0, -1).replace(/:\d+$/, "")];
    return ["url", norm];
  }
  const host = hostOf(text);
  if (!host) throw new Error("not a valid domain");
  if (!IPV4.test(host) && !isIPv6(host) && !splitDomain(host).registrable) {
    throw new Error(`${host} is a public suffix: it would cover every site under it`);
  }
  return ["domain", host];
}

export function emptyLists() {
  return { allow: [], block: [], reported: [] };
}

export function addEntry(lists, kind, text, note = "") {
  if (kind !== "allow" && kind !== "block") throw new Error("list must be allow or block");
  const [match, value] = normalizeEntry(text);
  const other = kind === "allow" ? "block" : "allow";
  lists[other] = lists[other].filter((e) => !(e.match === match && e.value === value));
  lists[kind] = [{ match, value, note: String(note).slice(0, 300), added: new Date().toISOString() },
    ...lists[kind].filter((e) => !(e.match === match && e.value === value))].slice(0, 5000);
  return { match, value };
}

export function report(lists, url, note = "") {
  const norm = normalizeUrl(url.includes("://") ? url : `https://${url}`);
  if (!norm) throw new Error("only web links (http/https) can be reported");
  lists.reported = [{ url: norm, note: String(note).slice(0, 300), reported: new Date().toISOString() },
    ...lists.reported.filter((r) => r.url !== norm)].slice(0, 5000);
  lists.allow = lists.allow.filter((e) => !(e.match === "url" && e.value === norm));
  return norm;
}

export function removeEntry(lists, kind, text) {
  if (kind === "reported") {
    const norm = normalizeUrl(text.includes("://") ? text : `https://${text}`);
    const before = lists.reported.length;
    lists.reported = lists.reported.filter((r) => r.url !== norm);
    return lists.reported.length < before;
  }
  const [match, value] = normalizeEntry(text);
  const before = lists[kind].length;
  lists[kind] = lists[kind].filter((e) => !(e.match === match && e.value === value));
  return lists[kind].length < before;
}

export function lookup(lists, host, url) {
  const res = { allowed: null, blocked: null, reported: null };
  if (!lists) return res;
  const hosts = host ? hostCandidates(host) : [];
  const norm = url ? normalizeUrl(url) : null;
  const urls = norm ? urlCandidates(norm) : [];
  const spec = (e) => (e.match === "url" ? 10000 : 0) + e.value.length;
  const hit = (e) => (e.match === "domain" && hosts.includes(e.value)) || (e.match === "url" && urls.includes(e.value));
  const block = lists.block.filter(hit).sort((a, b) => spec(b) - spec(a))[0];
  const allow = lists.allow.filter(hit).sort((a, b) => spec(b) - spec(a))[0];
  if (block) res.blocked = { source: "blocklist", ...block };
  if (allow) res.allowed = { source: "allowlist", ...allow };
  const rep = lists.reported.find((r) => urls.includes(r.url));
  if (rep) res.reported = { source: "reported", match: "url", value: rep.url, note: rep.note };
  return res;
}
