// Registrable-domain splitting with the bundled Public Suffix List (ICANN + private), as in domains.py.
import { PLATFORM_SUFFIXES, PSL } from "./data.js";

const RULES = new Set();
const WILDCARDS = new Set();
const EXCEPTIONS = new Set();
for (const rule of PSL.split("\n")) {
  if (rule.startsWith("!")) EXCEPTIONS.add(rule.slice(1));
  else if (rule.startsWith("*.")) WILDCARDS.add(rule.slice(2));
  else RULES.add(rule);
}

/** Public suffix of an ASCII host. ``strictMode`` returns null for unknown TLDs. */
export function publicSuffix(host, strictMode = false) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (!labels.length) return null;
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join(".");
    if (EXCEPTIONS.has(cand)) return labels.slice(i + 1).join(".");
    if (RULES.has(cand)) return cand;
    const parent = labels.slice(i + 1).join(".");
    if (parent && WILDCARDS.has(parent)) return cand;
  }
  return strictMode ? null : labels[labels.length - 1];
}

let unicodeRulesReady = false;
function ensureUnicodeRules() {
  // Some rules are written in Unicode (e.g. рф); add their punycode forms once.
  if (unicodeRulesReady) return;
  unicodeRulesReady = true;
  for (const set of [RULES, WILDCARDS, EXCEPTIONS]) {
    for (const r of [...set]) {
      if (/[^\x00-\x7f]/.test(r)) {
        try {
          const a = new URL(`http://${r}/`).hostname;
          if (a) set.add(a);
        } catch {
          /* ignore */
        }
      }
    }
  }
}

function platform(host) {
  for (const p of PLATFORM_SUFFIXES) if (host === p || host.endsWith("." + p)) return p;
  return null;
}

export function splitDomain(hostAscii) {
  ensureUnicodeRules();
  const host = hostAscii.toLowerCase().replace(/\.$/, "");
  const labels = host.split(".").filter(Boolean);
  const suffix = publicSuffix(host) || "";
  const n = suffix ? suffix.split(".").length : 0;
  const rest = n ? labels.slice(0, labels.length - n) : labels;
  if (!rest.length) return { host, registrable: "", sld: "", suffix, subdomains: [], platform: platform(host) };
  const sld = rest[rest.length - 1];
  return {
    host, registrable: [sld, ...(suffix ? [suffix] : [])].join("."), sld, suffix,
    subdomains: rest.slice(0, -1), platform: platform(host),
  };
}

export function knownSuffix(host) {
  ensureUnicodeRules();
  let h = host.toLowerCase().replace(/\.$/, "");
  if (!h.includes(".")) return false;
  if (/[^\x00-\x7f]/.test(h)) {
    try {
      h = new URL(`http://${h}/`).hostname;
    } catch {
      return false;
    }
  }
  const s = publicSuffix(h, true);
  return Boolean(s) && s !== h;
}
