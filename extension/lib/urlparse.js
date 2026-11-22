// Browser-faithful URL / email parsing, mirroring urlsafe.py. Pure: input is only treated as data.
import {
  APP_HANDLER_SCHEMES, BIDI_CONTROLS, DANGEROUS_SCHEMES, DEFAULT_PORTS, FAKE_DOTS, FAKE_HYPHENS, FAKE_SLASHES,
  INFO_SCHEMES, INVISIBLE_RANGES,
} from "./data.js";
import { browserAscii, decode, encode, validPunycodeLabel } from "./punycode.js";
import { codepoint, isAscii } from "./unicode.js";

export const MAX_URL_LENGTH = 8192;
const SPECIAL = new Set(Object.keys(DEFAULT_PORTS));
const DANGEROUS = new Set(DANGEROUS_SCHEMES);
const APP_HANDLERS = new Set(APP_HANDLER_SCHEMES);
const INFO = new Set(INFO_SCHEMES);
const BIDI = new Set(BIDI_CONTROLS);
const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.\-]{0,31}):/;
const EMAIL_RE = /^(?:([^<>]{0,200}?)\s*<)?([^\s<>@/]{1,200})@([^\s<>@/?#]{1,300})>?$/;
export const DOMAINISH_RE = /[a-z0-9¡-￿-]+(?:\.[a-z0-9¡-￿-]+)+/gi;
const FORBIDDEN = new Set("\x00\t\n\r #/:<>?@[\\]^|%\x7f");
for (let c = 0; c < 0x20; c++) FORBIDDEN.add(String.fromCharCode(c));

export class InputError extends Error {}

export function finding(code, severity, weight, title, detail = "", evidence = {}) {
  return { code, severity, weight, title, detail, evidence };
}

function isInvisible(cp) {
  for (const [a, b] of INVISIBLE_RANGES) if (cp >= a && cp <= b) return true;
  return false;
}

const describe = (ch) => codepoint(ch);

function scanHidden(raw, p) {
  const chars = Array.from(raw);
  const bidi = chars.map((c, i) => [i, c]).filter(([, c]) => BIDI.has(c.codePointAt(0)));
  if (bidi.length) p.findings.push(finding("URL_BIDI", "high", 40, "Bidirectional control characters",
    "These can visually reverse or reorder parts of the link (the 'RLO' trick), so what you read is not what the browser opens.",
    { characters: bidi.slice(0, 20).map(([i, c]) => [i, describe(c)]) }));
  const hidden = chars.map((c, i) => [i, c]).filter(([, c]) => isInvisible(c.codePointAt(0)) && !BIDI.has(c.codePointAt(0)));
  if (hidden.length) p.findings.push(finding("URL_INVISIBLE", "high", 30, "Invisible characters",
    "Zero-width or invisible characters are hidden from the reader but change the string; they are used to dodge filters and to fake well-known names.",
    { characters: hidden.slice(0, 20).map(([i, c]) => [i, describe(c)]) }));
  const controls = chars.map((c, i) => [i, c]).filter(([, c]) => /\p{Cc}/u.test(c) && !"\t\n\r".includes(c));
  if (controls.length) p.findings.push(finding("URL_CONTROL_CHARS", "medium", 20, "Control characters",
    "Raw control characters have no place in a link and can corrupt logs or terminals.",
    { characters: controls.slice(0, 20).map(([i, c]) => [i, describe(c)]) }));
}

// ---------------------------------------------------------------- IPv4 (WHATWG)
function parseIPv4(host) {
  let parts = host.split(".");
  if (parts.length > 1 && parts[parts.length - 1] === "") parts = parts.slice(0, -1);
  if (!parts.length || parts.length > 4) return null;
  const nums = [];
  for (const part of parts) {
    if (part === "") return null;
    let n;
    if (/^0x/i.test(part)) {
      if (!/^0x[0-9a-f]*$/i.test(part)) return null;
      n = part.length > 2 ? parseInt(part.slice(2), 16) : 0;
    } else if (part.length > 1 && part[0] === "0") {
      if (!/^[0-7]+$/.test(part.slice(1))) return null;
      n = parseInt(part.slice(1), 8);
    } else if (/^\d+$/.test(part)) n = parseInt(part, 10);
    else return null;
    nums.push(n);
  }
  if (nums.slice(0, -1).some((n) => n > 255)) return null;
  if (nums[nums.length - 1] >= 256 ** (5 - nums.length)) return null;
  let value = nums[nums.length - 1];
  nums.slice(0, -1).forEach((n, i) => (value += n * 256 ** (3 - i)));
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

function endsInNumber(host) {
  let parts = host.split(".");
  if (parts.length > 1 && parts[parts.length - 1] === "") parts = parts.slice(0, -1);
  const last = parts[parts.length - 1] || "";
  return /^\d+$/.test(last) || /^0x[0-9a-f]*$/i.test(last);
}

export function isGlobalIp(ip) {
  if (ip.includes(":")) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return false;
    if (/^f[cd]/.test(l) || /^fe[89ab]/.test(l) || /^ff/.test(l) || l.startsWith("2001:db8") || l.startsWith("::ffff:")) return false;
    return true;
  }
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((x) => Number.isNaN(x))) return false;
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function setIp(p, ip, version) {
  p.isIp = true;
  p.ipVersion = version;
  p.hostAscii = p.hostUnicode = p.hostInput = ip;
  p.findings.push(finding("URL_IP_HOST", "medium", 15, "Raw IP address instead of a domain",
    "Real services almost never send links to bare IP addresses.", { ip }));
  if (!isGlobalIp(ip)) p.findings.push(finding("URL_INTERNAL_IP", "medium", 25, "Link points at a private or local address",
    `${ip} is not on the public internet. A link like this can attack your router, localhost services or intranet apps (CSRF / one-click exploit).`, { ip }));
}

// ---------------------------------------------------------------- IDNA
function idnaProcess(host, p) {
  host = host.replace(/\.+$/, "") || host;
  if (isAscii(host)) {
    p.hostAscii = host;
    const bad = [];
    p.hostUnicode = host.split(".").map((label) => {
      if (!label.startsWith("xn--")) return label;
      let u = label;
      try {
        u = decode(label.slice(4));
      } catch {
        /* keep raw */
      }
      if (!validPunycodeLabel(label)) bad.push(label);
      return u;
    }).join(".");
    if (bad.length) {
      p.idnaValid = false;
      p.findings.push(finding("IDN_INVALID", "medium", 20, "Malformed internationalized label",
        "A punycode (xn--) label is not valid IDNA2008. Browsers may refuse it or show it raw; legitimate sites do not publish such names.",
        { labels: bad }));
    }
    return;
  }
  const ascii = browserAscii(host);
  if (ascii && !/[^\x00-\x7f]/.test(ascii)) {
    p.hostAscii = ascii;
    p.hostUnicode = ascii.split(".").map((l) => (l.startsWith("xn--") ? safeDecode(l) : l)).join(".");
    // IDNA2008 (what Python's idna library and many mail clients enforce) only allows letters, digits,
    // marks and '-'. Browsers' UTS #46 mode still resolves symbols such as U+2215, so flag them.
    const symbols = [...new Set(Array.from(p.hostUnicode).filter((c) => !isAscii(c) && /[\p{P}\p{S}\p{Z}\p{C}]/u.test(c)))];
    if (symbols.length) {
      p.idnaValid = false;
      p.findings.push(finding("IDN_INVALID", "medium", 20, "Hostname is not a valid internationalized domain",
        "Modern browsers would refuse this host, but mail clients, chat apps and older software may still display it convincingly.",
        { characters: symbols.map(codepoint) }));
    }
  } else {
    p.idnaValid = false;
    const labels = host.normalize("NFKC").toLowerCase().split(/[.。．｡]/);
    p.hostUnicode = labels.join(".");
    p.hostAscii = labels.map((l) => (isAscii(l) ? l : "xn--" + encode(l))).join(".");
    p.findings.push(finding("IDN_INVALID", "medium", 20, "Hostname is not a valid internationalized domain",
      "Modern browsers would refuse this host, but mail clients, chat apps and older software may still display it convincingly."));
  }
  const changes = [];
  for (const ch of new Set(Array.from(host))) {
    if (isAscii(ch)) continue;
    const probe = browserAscii(`x${ch}x.example`);
    if (!probe) continue;
    const label = probe.split(".")[0];
    const mapped = label.startsWith("xn--") ? safeDecode(label) : label;
    if (mapped !== `x${ch}x`) {
      const inner = mapped.slice(1, -1);
      changes.push(`${codepoint(ch)} -> ${inner ? `'${inner}'` : "(removed)"}`);
    }
  }
  if (changes.length) p.findings.push(finding("IDN_NORMALIZED", "medium", 25, "Host uses characters a browser silently rewrites",
    "Full-width letters, soft hyphens, zero-width spaces and similar characters are mapped or dropped before the lookup. The text you see is not the domain you get.",
    { rewrites: changes.slice(0, 20), effective_host: p.hostUnicode }));
}

function safeDecode(label) {
  try {
    return decode(label.slice(4));
  } catch {
    return label;
  }
}

function fakeSeparators(host, p) {
  const pick = (set) => [...new Set(Array.from(host).filter((c) => set.includes(c)))].map(describe);
  const slashes = pick(FAKE_SLASHES), dots = pick(FAKE_DOTS), hyphens = pick(FAKE_HYPHENS);
  if (slashes.length) p.findings.push(finding("IDN_FAKE_SLASH", "high", 40, "Look-alike slash inside the hostname",
    "A character that looks like '/' makes the host read like a trusted site followed by a path, e.g. 'accounts.google.com∕login.evil.example'.", { characters: slashes }));
  if (dots.length) p.findings.push(finding("IDN_FAKE_DOT", "high", 35, "Look-alike dot inside the hostname",
    "A character that looks like '.' fakes a domain boundary the browser does not see.", { characters: dots }));
  if (hyphens.length) p.findings.push(finding("IDN_FAKE_HYPHEN", "medium", 20, "Look-alike hyphen inside the hostname",
    "Characters such as 'ー' (Katakana) or '一' (CJK) pass for '-' next to Latin text.", { characters: hyphens }));
}

function analyseHost(host, p) {
  if (!host) throw new InputError("no host found");
  if (host.length > 1024) throw new InputError("host is unreasonably long");
  if (host.includes("%")) {
    let decoded = host;
    try {
      decoded = decodeURIComponent(host);
    } catch {
      /* keep */
    }
    if (decoded !== host) {
      p.findings.push(finding("URL_PERCENT_HOST", "medium", 25, "Percent-encoded hostname",
        `The host is written in %-escapes; a browser decodes it to '${decoded.slice(0, 120)}'. Legitimate links never need this.`, { decoded: decoded.slice(0, 200) }));
      host = decoded;
      const before = new Set(p.findings.map((f) => f.code));
      const tmp = { findings: [] };
      scanHidden(decoded, tmp);
      p.findings.push(...tmp.findings.filter((f) => !before.has(f.code)));
    }
  }
  if (host.startsWith("[") && host.endsWith("]")) {
    const h = browserAscii(host);
    if (!h) throw new InputError("invalid IPv6 address");
    setIp(p, h.slice(1, -1), 6);
    return;
  }
  const lower = host.toLowerCase().replace(/[。．｡]/g, ".");
  p.hostInput = lower;
  fakeSeparators(lower, p);
  const forbidden = [...new Set(Array.from(lower).filter((c) => FORBIDDEN.has(c)))];
  if (forbidden.length) {
    p.idnaValid = false;
    p.findings.push(finding("URL_FORBIDDEN_HOST_CHARS", "medium", 20, "Characters a browser forbids in a hostname",
      "Browsers reject this host, but it may still be shown convincingly in messages.", { characters: forbidden.map(codepoint) }));
  }
  if (isAscii(lower) && endsInNumber(lower)) {
    const ip4 = parseIPv4(lower);
    if (!ip4) throw new InputError("host ends in a number but is not a valid IPv4 address");
    if (lower.replace(/\.$/, "") !== ip4) p.findings.push(finding("URL_OBFUSCATED_IP", "high", 35, "Obfuscated IP address",
      `'${lower.slice(0, 60)}' is really the IPv4 address ${ip4}. Hex, octal and integer forms exist only to hide where the link goes.`, { ip: ip4 }));
    setIp(p, ip4, 4);
    return;
  }
  idnaProcess(lower, p);
  if (p.hostAscii && p.hostAscii.length > 253) p.idnaValid = false;
}

function parseEmail(s, p) {
  const m = EMAIL_RE.exec(s);
  if (!m) throw new InputError("could not find an email address");
  p.kind = "email";
  p.scheme = "mailto";
  p.emailLocal = m[2];
  const name = (m[1] || "").trim().replace(/^"+|"+$/g, "").trim();
  p.displayName = name || null;
  analyseHost(m[3], p);
  const local = p.emailLocal;
  const domainish = new RegExp(`^${DOMAINISH_RE.source}$`, "i");
  const lastLabel = local.split(".").pop();
  if (domainish.test(local) && /\p{L}/u.test(lastLabel)) {
    p.findings.push(finding("EMAIL_LOCAL_LOOKS_LIKE_DOMAIN", "medium", 25, "The part before '@' looks like a domain",
      `'${local.slice(0, 80)}@' is only the mailbox name; the address belongs to '${(p.hostUnicode || m[3]).slice(0, 80)}'.`, { local_part: local.slice(0, 200) }));
  }
  if (name) {
    const real = (p.hostUnicode || "").toLowerCase();
    const shown = name.match(DOMAINISH_RE) || [];
    const fakes = shown.filter((d) => d.toLowerCase().replace(/\.$/, "") !== real && !real.endsWith("." + d.toLowerCase()));
    if (fakes.length) p.findings.push(finding("EMAIL_DISPLAY_NAME_DOMAIN", "high", 35, "Display name shows a different domain",
      `The sender name says '${fakes[0].slice(0, 80)}' but the mail really comes from '${real.slice(0, 80)}'. Mail apps often show only the name.`,
      { display_name: name.slice(0, 200), real_domain: real }));
  }
  return p;
}

function fileUrl(after, p) {
  p.scheme = "file";
  const norm = after.replaceAll("\\", "/");
  let host = "";
  if (norm.startsWith("//") && !norm.startsWith("///")) host = norm.slice(2).split("/")[0];
  if (host && host.toLowerCase() !== "localhost") {
    p.findings.push(finding("URL_REMOTE_FILE", "high", 45, "Link to a remote file share",
      `file:// links to '${host.slice(0, 80)}' make Windows connect over SMB and can leak your NTLM credentials without any further click.`, { host: host.slice(0, 200) }));
    analyseHost(host, p);
  } else {
    p.hasHost = false;
    p.findings.push(finding("URL_FILE_SCHEME", "medium", 25, "Link to a local file",
      "file: links open files on your own machine; mail and chat links should never need this."));
  }
  return p;
}

const REFANG = [["[.]", "."], ["(.)", "."], ["{.}", "."], ["[dot]", "."], ["(dot)", "."], ["[://]", "://"], ["[:]", ":"], ["[@]", "@"], ["[at]", "@"]];

export function refang(s) {
  let out = s;
  for (const [fanged, plain] of REFANG) {
    if (out.toLowerCase().includes(fanged)) out = out.replace(new RegExp(fanged.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), plain);
  }
  if (/^h(xx|\*\*)p/i.test(out)) out = "http" + out.slice(4);
  return out;
}

function naiveHost(candidate) {
  // What urllib / most mail filters read as the host (first "//", last "@", no backslash rules).
  const m = /^[a-z][a-z0-9+.\-]*:\/\/([^/?#]*)/i.exec(candidate);
  if (!m) return null;
  let net = m[1];
  const at = net.lastIndexOf("@");
  if (at >= 0) net = net.slice(at + 1);
  if (net.startsWith("[")) {
    const e = net.indexOf("]");
    return e > 0 ? net.slice(1, e).toLowerCase() : null;
  }
  const c = net.indexOf(":");
  if (c >= 0) net = net.slice(0, c);
  return net.toLowerCase() || null;
}

function checkParserConfusion(p, candidate, browserHost) {
  const naive = naiveHost(candidate);
  if (!naive) return;
  const ours = browserHost.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (naive.replace(/\.$/, "").replace(/^\[|\]$/g, "") !== ours) {
    p.findings.push(finding("URL_PARSER_CONFUSION", "high", 35, "Different software sees a different host",
      `A browser opens '${ours.slice(0, 80)}' but common URL parsers (mail filters, scripts) read the host as '${naive.slice(0, 80)}'. This mismatch is a deliberate filter bypass.`,
      { browser_host: ours.slice(0, 200), naive_host: naive.slice(0, 200) }));
  }
}

export function parseUrl(raw) {
  if (typeof raw !== "string") throw new InputError("input must be text");
  if (raw.length > MAX_URL_LENGTH) throw new InputError(`input is longer than ${MAX_URL_LENGTH} characters`);
  if (raw.includes("\x00")) throw new InputError("input contains a NUL byte");
  const p = {
    input: raw, kind: "url", scheme: "", userinfo: null, hostInput: "", hostUnicode: "", hostAscii: null, port: null,
    rest: "", isIp: false, ipVersion: null, idnaValid: true, hasHost: true, emailLocal: null, displayName: null, findings: [],
  };
  scanHidden(raw, p);
  let s = raw.replace(/^[\x00-\x20]+|[\x00-\x20]+$/g, "");
  if (/[\t\n\r]/.test(s)) {
    s = s.replace(/[\t\n\r]/g, "");
    p.findings.push(finding("URL_WHITESPACE_TRICK", "low", 10, "Tabs or newlines inside the URL",
      "Browsers delete them silently; they are used to break naive URL filters."));
  }
  if (!s) throw new InputError("empty input");
  const re = refang(s);
  if (re !== s) {
    p.findings.push(finding("INPUT_DEFANGED", "info", 0, "Input was defanged", "Re-fanged for analysis (hxxp -> http, [.] -> .). Nothing was opened."));
    s = re;
  }
  let m = SCHEME_RE.exec(s);
  let scheme = m ? m[1].toLowerCase() : "";
  let after = m ? s.slice(m[0].length) : s;
  if (m && (scheme.includes(".") || /^\d+([/?#]|$)/.test(after))) {
    m = null;
    scheme = "";
    after = s;
  }
  if (m) {
    if (scheme === "mailto") {
      let target = after.split("?")[0].split(",")[0];
      try {
        target = decodeURIComponent(target);
      } catch {
        /* keep */
      }
      return parseEmail(target, p);
    }
    if (scheme === "file") return fileUrl(after, p);
    if (DANGEROUS.has(scheme)) {
      Object.assign(p, { scheme, hasHost: false, rest: after });
      p.findings.push(finding("URL_DANGEROUS_SCHEME", "critical", 60, `'${scheme}:' link`,
        "This link runs code or embeds content instead of opening a website. Never click it - it is a common one-click attack vector.", { scheme }));
      return p;
    }
    if (APP_HANDLERS.has(scheme)) {
      Object.assign(p, { scheme, hasHost: false, rest: after });
      p.findings.push(finding("URL_APP_HANDLER", "high", 45, `'${scheme}:' launches a local application`,
        "Protocol handlers hand the link to a desktop app instead of the browser. ms-msdt: (Follina), search-ms: and ms-appinstaller: have all been used for one-click malware delivery.",
        { scheme, embedded_urls: (after.match(/https?:\/\/[^\s|"'<>]+/g) || []).slice(0, 3) }));
      return p;
    }
    if (INFO.has(scheme)) {
      Object.assign(p, { scheme, hasHost: false, rest: after });
      return p;
    }
  }
  if (!m && s.includes("@") && EMAIL_RE.test(s) && !s.split("@")[0].includes("/")) return parseEmail(s, p);

  let rest;
  if (m && SPECIAL.has(scheme)) {
    const slashes = after.length - after.replace(/^[/\\]+/, "").length;
    if (after.slice(0, slashes) !== "//") p.findings.push(finding("URL_SLASH_TRICK", "low", 10, "Unusual slashes after the scheme",
      "Browsers accept any mix of '/' and '\\' here; odd forms are used to evade filters.", { written: after.slice(0, slashes) }));
    rest = after.slice(slashes);
  } else if (m && after.startsWith("//")) {
    rest = after.slice(2);
    p.findings.push(finding("URL_UNUSUAL_SCHEME", "low", 10, `Unusual scheme '${scheme}:'`, "Not a normal web link; check which application would handle it.", { scheme }));
  } else if (m) {
    Object.assign(p, { scheme, hasHost: false, rest: after, kind: "other" });
    p.findings.push(finding("URL_UNUSUAL_SCHEME", "medium", 20, `Unknown scheme '${scheme}:'`,
      "Not a web link. Unknown schemes may be handled by local applications.", { scheme }));
    return p;
  } else if (s.startsWith("//")) {
    scheme = "https";
    rest = s.slice(2);
  } else {
    scheme = "http";
    rest = s;
  }
  p.scheme = scheme || "http";
  const special = SPECIAL.has(p.scheme);
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if ("/?#".includes(ch) || (special && ch === "\\")) {
      end = i;
      break;
    }
  }
  const authority = rest.slice(0, end);
  p.rest = rest.slice(end);
  const cutCandidates = [p.rest.indexOf("?"), p.rest.indexOf("#")].filter((i) => i >= 0);
  const cut = cutCandidates.length ? Math.min(...cutCandidates) : p.rest.length;
  if (special && (p.rest.slice(0, cut).includes("\\") || rest[end] === "\\")) {
    p.rest = p.rest.slice(0, cut).replaceAll("\\", "/") + p.rest.slice(cut);
    p.findings.push(finding("URL_BACKSLASH", "low", 10, "Backslash in the URL", "Browsers treat '\\' as '/', other software does not."));
  }
  let hostport = authority;
  const at = authority.lastIndexOf("@");
  if (at >= 0) {
    const userinfo = authority.slice(0, at);
    hostport = authority.slice(at + 1);
    p.userinfo = userinfo;
    let user = userinfo.split(":")[0];
    try {
      user = decodeURIComponent(user);
    } catch {
      /* keep */
    }
    if (user.includes(".") && /\p{L}/u.test(user)) {
      p.findings.push(finding("URL_USERINFO_DECEPTION", "high", 40, "Fake domain placed before '@'",
        `Everything before '@' is a username, not the site. '${user.slice(0, 80)}' is decoration; the browser really goes to the host after the '@'.`, { userinfo: user.slice(0, 200) }));
    } else {
      p.findings.push(finding("URL_USERINFO", "low", 10, "Credentials embedded in the URL", "Links with user:password@ are rare in legitimate mail and blocked by many browsers."));
    }
  }
  let host = hostport, portText = "";
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close === -1) throw new InputError("unterminated IPv6 address");
    host = hostport.slice(0, close + 1);
    const tail = hostport.slice(close + 1);
    if (tail && !tail.startsWith(":")) throw new InputError("garbage after IPv6 address");
    portText = tail.slice(1);
  } else {
    const c = hostport.lastIndexOf(":");
    if (c >= 0) {
      host = hostport.slice(0, c);
      portText = hostport.slice(c + 1);
    }
  }
  if (portText) {
    if (!/^\d+$/.test(portText) || Number(portText) > 65535) throw new InputError(`invalid port '${portText.slice(0, 20)}'`);
    const port = Number(portText);
    if (port !== DEFAULT_PORTS[p.scheme]) {
      p.port = port;
      p.findings.push(finding("URL_ODD_PORT", "low", 5, `Non-standard port ${port}`, "Phishing kits on throwaway servers often listen on unusual ports."));
    }
  }
  analyseHost(host, p);
  checkParserConfusion(p, m ? s : `${p.scheme}://${s}`, host);
  return p;
}
