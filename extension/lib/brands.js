// Protected-brand matching, mirroring brands.py (skeletons of the brands are precomputed in Python).
import { BRAND_TLDS, BRANDS, GENERIC_WORD_BRANDS } from "./data.js";
import { browserAscii, hostToUnicode, labelToUnicode } from "./punycode.js";
import { splitDomain } from "./psl.js";
import { collapse, loose, strict } from "./unicode.js";

const GENERIC = new Set(GENERIC_WORD_BRANDS);
const OWNED_TLDS = new Set(BRAND_TLDS);
const ASCII_DOMAIN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$/;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const WORD_SPLIT = /[^\p{L}\p{N}_]+/u;

export function osaDistance(a, b, limit = 2) {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let prev2 = [];
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i, ...new Array(b.length).fill(0)];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) cur[j] = Math.min(cur[j], prev2[j - 2] + 1);
    }
    if (Math.min(...cur) > limit) return limit + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[prev.length - 1];
}

export function normalizeDomain(text) {
  let d = text.trim().toLowerCase();
  if (!d || d.startsWith("#")) return null;
  if (d.includes("://")) d = d.split("://")[1];
  d = d.split("/")[0].split(":")[0].replace(/\.$/, "");
  if (d.startsWith("*.")) d = d.slice(2);
  if (/[^\x00-\x7f]/.test(d)) {
    d = browserAscii(d);
    if (!d) return null;
  }
  return ASCII_DOMAIN.test(d) ? d : null;
}

export class BrandIndex {
  constructor(rows = BRANDS) {
    this.brands = new Map();
    this.strictIdx = new Map();
    this.looseIdx = new Map();
    this.collapseIdx = new Map();
    const push = (m, k, v) => (m.has(k) ? m.get(k).push(v) : m.set(k, [v]));
    for (const [domain, sld, suffix, sldStrict, sldLoose, sldCollapse, fullCollapse] of rows) {
      const b = { domain, sld, suffix, sldStrict, sldLoose, sldCollapse, fullCollapse };
      this.brands.set(domain, b);
      push(this.strictIdx, sldStrict, b);
      push(this.looseIdx, sldLoose, b);
      push(this.collapseIdx, sldCollapse, b);
    }
  }

  has(domain) {
    return this.brands.has(domain);
  }

  match(parts, hostUnicode) {
    const reg = parts.registrable;
    if (!reg) return [];
    if (this.brands.has(reg)) return [{ brand: reg, kind: "official", weight: 0, severity: "info", detail: `The registrable domain is ${reg} itself.` }];
    if (OWNED_TLDS.has(parts.suffix)) {
      return [{ brand: reg, kind: "owned_tld", weight: 0, severity: "info",
        detail: `Only the company that runs .${parts.suffix} can register names under it, so this is not someone else imitating a brand.` }];
    }
    const sld = labelToUnicode(parts.sld);
    const suffix = hostToUnicode(parts.suffix);
    const sStrict = strict(sld), sLoose = loose(sld), sCol = collapse(sld);
    const best = new Map();
    const offer = (m) => {
      if (!best.has(m.brand) || m.weight > best.get(m.brand).weight) best.set(m.brand, m);
    };
    const swapped = new Set();
    for (const b of this.strictIdx.get(sStrict) || []) {
      if (sld === b.sld) {
        if (swapped.has(b.sld)) continue;
        swapped.add(b.sld);
        offer({ brand: b.domain, kind: "tld_swap", weight: 15, severity: "medium",
          detail: `Same name as ${b.domain} but under .${suffix}. Big brands own many such domains - the DNS comparison helps tell them apart.` });
      } else {
        const sameSuffix = strict(suffix) === strict(b.suffix);
        offer({ brand: b.domain, kind: "homograph", weight: sameSuffix ? 50 : 40, severity: "high",
          detail: `'${sld}' is written with look-alike characters to imitate '${b.sld}'` + (sameSuffix ? "." : ` (on .${suffix} instead of .${b.suffix}).`) });
      }
    }
    for (const b of this.looseIdx.get(sLoose) || []) {
      if (sld !== b.sld) offer({ brand: b.domain, kind: "lookalike", weight: 45, severity: "high",
        detail: `'${sld}' differs from '${b.sld}' only by accents, marks or stroke letters.` });
    }
    for (const b of this.collapseIdx.get(sCol) || []) {
      if (sld !== b.sld) offer({ brand: b.domain, kind: "lookalike", weight: 40, severity: "high",
        detail: `'${sld}' imitates '${b.sld}' with ASCII look-alikes (rn/m, vv/w, 0/o, 1/l/i).` });
    }
    if ([...sCol].length >= 4) {
      for (const b of this.brands.values()) {
        const bc = b.sldCollapse;
        if (bc.length >= 5 && bc !== sCol && Math.abs(bc.length - sCol.length) <= 1 && osaDistance(sCol, bc, 1) === 1) {
          offer({ brand: b.domain, kind: "typosquat", weight: 25, severity: "medium", detail: `'${sld}' is one typo away from '${b.sld}'.` });
        }
      }
    }
    const hostCol = collapse(hostUnicode);
    const ownerPart = collapse([...parts.subdomains, sld].join("."));
    const tokens = ownerPart.split(/[.\-_/]/).filter(Boolean);
    for (const b of this.brands.values()) {
      if (b.domain === reg) continue;
      if (new RegExp(`(^|[./])${escapeRe(b.fullCollapse)}[./]`).test(hostCol)) {
        offer({ brand: b.domain, kind: "subdomain_spoof", weight: 30, severity: "high",
          detail: `'${b.domain}' is used as a decoy prefix; the real site is ${reg}.` });
      } else if (GENERIC.has(b.sld) || b.sld === sld) {
        continue;
      } else if (b.sldCollapse.length >= 3 && tokens.includes(b.sldCollapse)) {
        offer({ brand: b.domain, kind: "embedded", weight: 20, severity: "medium",
          detail: `The brand name '${b.sld}' appears inside an unrelated domain (${reg}).` });
      } else if (b.sldCollapse.length >= 6 && tokens.some((t) => t.includes(b.sldCollapse))) {
        offer({ brand: b.domain, kind: "embedded", weight: 8, severity: "low",
          detail: `'${b.sld}' is contained in the hostname of ${reg}.` });
      }
    }
    return [...best.values()].sort((a, b) => b.weight - a.weight).slice(0, 5);
  }

  namesInText(text, exclude = "") {
    const words = new Set(collapse(text).split(WORD_SPLIT));
    return [...this.brands.values()].filter((b) => [...b.sldCollapse].length >= 4 && words.has(b.sldCollapse)
      && !GENERIC.has(b.sld) && b.domain !== exclude);
  }

  brandInDomainText(text) {
    const d = normalizeDomain(text);
    if (!d) return null;
    const parts = splitDomain(d);
    for (const m of this.match(parts, hostToUnicode(d))) {
      if (m.kind === "official" || ["homograph", "lookalike", "subdomain_spoof", "typosquat"].includes(m.kind)) return m;
    }
    return null;
  }
}
