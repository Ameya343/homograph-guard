// Unicode scripts and confusable "skeletons" (after Unicode TR39), mirroring unicode_tools.py.
import { CONFUSABLES, LATIN_CONFUSABLE_SCRIPTS, LOOSE_EXTRA } from "./data.js";

const SCRIPTS = [
  "Canadian_Aboriginal", "Yi", "Han", "Latin", "Cyrillic", "Greek", "Coptic", "Armenian", "Hebrew", "Arabic",
  "Syriac", "Thaana", "Nko", "Devanagari", "Bengali", "Gurmukhi", "Gujarati", "Oriya", "Tamil", "Telugu",
  "Kannada", "Malayalam", "Sinhala", "Thai", "Lao", "Tibetan", "Myanmar", "Georgian", "Hangul", "Ethiopic",
  "Cherokee", "Ogham", "Runic", "Khmer", "Mongolian", "Hiragana", "Katakana", "Bopomofo", "Tifinagh", "Vai",
  "Lisu", "Glagolitic", "Balinese", "Javanese", "Sundanese", "Buginese", "Tagalog", "Adlam", "Osage",
];
const SCRIPT_RE = SCRIPTS.map((s) => [s, new RegExp(`^\\p{Script=${s}}$`, "u")]);
const LATIN_CONFUSABLE = new Set(LATIN_CONFUSABLE_SCRIPTS);
export const IGNORABLE = new Set(["Common", "Inherited"]);
const CJK_COMBOS = [
  new Set(["Latin", "Han", "Hiragana", "Katakana"]),
  new Set(["Latin", "Han", "Bopomofo"]),
  new Set(["Latin", "Han", "Hangul"]),
];
const cache = new Map();

export function isAscii(s) {
  return /^[\x00-\x7f]*$/.test(s);
}

export function charScript(ch) {
  if (cache.has(ch)) return cache.get(ch);
  let script;
  if (isAscii(ch)) script = /[A-Za-z]/.test(ch) ? "Latin" : "Common";
  else if (/^[\p{P}\p{S}\p{Z}\p{C}]$/u.test(ch)) script = "Common";
  else if (/^\p{M}$/u.test(ch)) script = "Inherited";
  else {
    script = "Unknown";
    for (const [name, re] of SCRIPT_RE) {
      if (re.test(ch)) {
        script = name;
        break;
      }
    }
    if (script === "Unknown" && /^\p{Nd}$/u.test(ch)) script = "Common";
  }
  if (cache.size < 16384) cache.set(ch, script);
  return script;
}

export function scriptsOf(text) {
  const out = new Set();
  for (const ch of text) {
    const s = charScript(ch);
    if (!IGNORABLE.has(s)) out.add(s);
  }
  return out;
}

const isSubset = (a, b) => [...a].every((x) => b.has(x));

export function restrictionLevel(scripts) {
  const s = new Set([...scripts].filter((x) => !IGNORABLE.has(x)));
  if (s.size === 0) return "ascii";
  if (s.size === 1) return "single-script";
  if (CJK_COMBOS.some((combo) => isSubset(s, combo))) return "highly-restrictive";
  if (s.has("Latin") && s.size === 2 && ![...s].some((x) => LATIN_CONFUSABLE.has(x))) return "moderately-restrictive";
  return "minimally-restrictive";
}

export { LATIN_CONFUSABLE };

const mapChars = (s) => Array.from(s, (c) => CONFUSABLES[c] ?? c).join("");

export function strict(s) {
  let t = s.toLowerCase().normalize("NFD");
  t = mapChars(t).toLowerCase();
  t = mapChars(t);
  return t.normalize("NFD");
}

export function loose(s) {
  let t = strict(s).replace(/\p{M}/gu, "");
  t = Array.from(t, (c) => LOOSE_EXTRA[c] ?? c).join("");
  return t.normalize("NFC");
}

export function collapse(s) {
  return loose(s).replaceAll("rn", "m").replaceAll("vv", "w").replace(/[01i|]/g, (c) => (c === "0" ? "o" : "l"));
}

/** [asciiLookalike, kind] for a non-ASCII character, kind = confusable | diacritic. */
export function lookalike(ch) {
  if (isAscii(ch)) return null;
  const s = strict(ch);
  if (s !== ch && isAscii(s) && s.trim()) return [s, "confusable"];
  const l = loose(ch);
  if (l !== ch && isAscii(l) && l.trim()) return [l, "diacritic"];
  return null;
}

export function codepoint(ch) {
  return "U+" + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
}
