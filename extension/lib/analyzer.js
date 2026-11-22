// Analysis pipeline, mirroring analyzer.py + homograph.py + scoring.py.
// parse -> unwrap -> characters -> brands -> context -> (optional) DNS -> score.
import { ABUSED_TLDS, LURE_WORDS, NATIVE_TLDS, URL_SHORTENERS, VERSION } from "./data.js";
import { BrandIndex, normalizeDomain } from "./brands.js";
import { lookup as lookupLists } from "./lists.js";
import { hostToUnicode, labelToUnicode } from "./punycode.js";
import { knownSuffix, splitDomain } from "./psl.js";
import {
  charScript, codepoint, IGNORABLE, isAscii, LATIN_CONFUSABLE, lookalike, restrictionLevel, scriptsOf,
} from "./unicode.js";
import { adSource, unwrap } from "./unwrap.js";
import { DOMAINISH_RE, finding, InputError, parseUrl } from "./urlparse.js";

const LURES = new Set(LURE_WORDS);
const SHORTENERS = new Set(URL_SHORTENERS);
const ABUSED = new Set(ABUSED_TLDS);
const STRONG = ["homograph", "lookalike", "subdomain_spoof", "typosquat"];
const GENUINE = ["official", "owned_tld"]; // brand matches that are not impersonation
const MESSAGE_MEDIA = ["email", "chat"]; // context.medium of links found in messages (see core: DNS privacy)
const BRAND_TITLES = {
  official: "Official domain of {brand}", owned_tld: "{brand} is under a company-owned top-level domain",
  homograph: "Homograph of {brand}", lookalike: "Look-alike of {brand}",
  tld_swap: "Same name as {brand} under another TLD", typosquat: "Typosquat of {brand}",
  subdomain_spoof: "{brand} used as a sub-domain decoy", embedded: "Brand name of {brand} inside another domain",
};
export const VERDICT_LABELS = {
  high_risk: "HIGH RISK", suspicious: "SUSPICIOUS", caution: "CAUTION", no_indicators: "NO INDICATORS FOUND", error: "ERROR",
};
const WORDS = /[^\p{L}\p{N}_]+/u;

export function score(findings) {
  let total = Math.max(0, Math.min(100, findings.reduce((s, f) => s + f.weight, 0)));
  if (findings.some((f) => f.severity === "critical")) total = Math.max(total, 70);
  if (total >= 70) return [total, "high_risk"];
  if (total >= 40) return [total, "suspicious"];
  if (total >= 15) return [total, "caution"];
  return [total, "no_indicators"];
}

export function defang(scheme, host, rest = "", port = null) {
  let sch = scheme.toLowerCase();
  if (sch.startsWith("http")) sch = "hxxp" + sch.slice(4);
  return `${sch}[://]${host.replaceAll(".", "[.]")}${port ? ":" + port : ""}${rest}`;
}

// ---------------------------------------------------------------- characters (homograph.py)
function analyzeLabels(hostUnicode, hostAscii, parts) {
  const ulabels = hostUnicode.split(".");
  let alabels = hostAscii.split(".");
  if (alabels.length !== ulabels.length) alabels = ulabels.map(() => "");
  const nSuffix = parts.suffix ? parts.suffix.split(".").length : 0;
  const tld = alabels[alabels.length - 1] ? labelToUnicode(alabels[alabels.length - 1]) : ulabels[ulabels.length - 1];
  const reports = [], findings = [], puny = [];
  ulabels.forEach((ul, idx) => {
    const al = alabels[idx];
    const isSuffix = idx >= ulabels.length - nSuffix;
    const scripts = scriptsOf(ul);
    const level = restrictionLevel(scripts);
    const rep = { index: idx, unicode: ul, ascii: al, scripts: [...scripts].sort(), restriction: level, is_suffix: isSuffix, chars: [] };
    reports.push(rep);
    if (al.startsWith("xn--") || !isAscii(ul)) puny.push(`${ul} = ${al || "?"}`);
    if (isAscii(ul)) return;
    const counts = new Map();
    for (const c of ul) {
      const s = charScript(c);
      if (!IGNORABLE.has(s)) counts.set(s, (counts.get(s) || 0) + 1);
    }
    const majority = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "";
    Array.from(ul).forEach((ch, pos) => {
      const script = charScript(ch);
      const look = lookalike(ch);
      rep.chars.push({ label: idx, position: pos + 1, char: ch, codepoint: codepoint(ch), script,
        looks_like: look ? look[0] : null, lookalike_kind: look ? look[1] : null,
        odd_script: counts.size > 1 && !IGNORABLE.has(script) && script !== majority });
    });
    if (isSuffix) return;
    const odd = rep.chars.filter((c) => c.odd_script).map((c) => `${c.char} ${c.codepoint} (${c.script}${c.looks_like ? `, looks like '${c.looks_like}'` : ""})`);
    if (level === "minimally-restrictive") {
      const classic = scripts.has("Latin") && [...scripts].some((s) => LATIN_CONFUSABLE.has(s));
      findings.push(finding("HG_MIXED_SCRIPT", classic ? "high" : "medium", classic ? 45 : 25,
        `Mixed scripts in '${ul}': ${[...scripts].sort().join(", ")}`,
        classic ? "Legitimate names almost never mix these alphabets inside one label. This is the classic IDN homograph pattern."
          : "Unusual mix of writing systems inside one label.", { label: ul, scripts: [...scripts].sort(), odd_characters: odd.slice(0, 20) }));
    } else if (level === "moderately-restrictive") {
      findings.push(finding("HG_SCRIPT_MIX_UNUSUAL", "low", 5, `Latin mixed with ${[...scripts].filter((s) => s !== "Latin").sort().join(", ")}`,
        "Allowed by browsers, but uncommon.", { label: ul, scripts: [...scripts].sort() }));
    }
    if (level === "single-script" && scripts.size && !scripts.has("Latin")) {
      const script = [...scripts][0];
      const letters = Array.from(ul).filter((c) => !IGNORABLE.has(charScript(c)));
      const mapped = letters.map(lookalike);
      if (letters.length && mapped.every((m) => m && /^[a-z0-9]+$/i.test(m[0]))) {
        const spelled = mapped.map((m) => m[0]).join("");
        const native = (NATIVE_TLDS[script] || []).includes(tld);
        findings.push(finding("HG_WHOLE_SCRIPT", native ? "low" : "high", native ? 5 : 40,
          `'${ul}' is entirely ${script} but reads as Latin '${spelled}'`,
          native ? "Normal under this country-code TLD, but still visually identical to a Latin name."
            : `Every letter is a ${script} look-alike of a Latin letter. Browsers such as Chrome refuse to display such names in Unicode under non-native TLDs.`,
          { label: ul, script, reads_as: spelled, native_tld: native }));
      }
    }
    if (level === "single-script" && scripts.size === 1 && scripts.has("Latin")) {
      const tricks = rep.chars.filter((c) => c.lookalike_kind === "confusable" && /^[a-z0-9]+$/i.test(c.looks_like || ""))
        .map((c) => `${c.char} ${c.codepoint} -> '${c.looks_like}'`);
      if (tricks.length) findings.push(finding("HG_LATIN_LOOKALIKE", "medium", 20, `Rare Latin look-alike letters in '${ul}'`,
        "Characters such as ɡ (script g), ı (dotless i) or ɑ (alpha) imitate plain ASCII letters.", { label: ul, characters: tricks.slice(0, 20) }));
    }
  });
  if (puny.length) findings.unshift(finding("IDN_PUNYCODE", "info", 0, "Internationalized domain name",
    "The real DNS name is the punycode (xn--) form shown here; browsers decide whether to show you the Unicode or the punycode.", { labels: puny.slice(0, 10) }));
  return [reports, findings];
}

// ---------------------------------------------------------------- analyzer
export class Analyzer {
  constructor(brands = new BrandIndex()) {
    this.brands = brands;
  }

  /** Analyse one link. ``dns`` is a DnsInvestigator or null (offline); ``lists`` the browser-kept lists. */
  async analyze(raw, context = null, dns = null, lists = null) {
    const chain = unwrap(raw);
    const inMessage = MESSAGE_MEDIA.includes(context?.medium);
    const [report, findings, matches] = await this.core(chain.destination, dns, inMessage ? "domain" : "host");
    report.input = typeof raw === "string" ? raw.slice(0, 2048) : raw;
    if (chain.hops.length || chain.embedded) {
      report.wrapped = { destination: chain.destination, hops: chain.hops, embedded: chain.embedded };
      findings.push(...(await this.wrapperFindings(chain)));
    }
    if (context) {
      report.context = Object.fromEntries(Object.entries(context).filter(([, v]) => v !== null && v !== undefined && v !== "")
        .map(([k, v]) => [k, String(v).slice(0, 500)]));
      findings.push(...this.linkContextFindings(report.context, report));
    }
    if (lists && report.error === null) findings.push(...this.listFindings(lists, raw, chain, report));
    if (report.error === null) this.finish(report, findings, matches);
    return report;
  }

  listFindings(lists, raw, chain, report) {
    const look = lookupLists(lists, report.url?.host_ascii || null, chain.destination);
    if (chain.hops.length) look.blocked = look.blocked || lookupLists(lists, chain.hops[0].host, raw).blocked;
    report.lists = { allowed: look.allowed, blocked: look.blocked, reported: Boolean(look.reported), feeds: [] };
    const out = [];
    if (look.blocked) out.push(finding("LIST_BLOCKED", "critical", 80, "On your blocklist",
      `${look.blocked.value} was blocked by you.${look.blocked.note ? ` Note: ${look.blocked.note}` : ""}`, { entry: look.blocked.value }));
    if (look.reported) out.push(finding("LIST_REPORTED", "critical", 80, "You reported this link as phishing",
      `Reported as ${look.reported.value}.`, { entry: look.reported.value }));
    if (look.allowed && !look.blocked && !look.reported) out.push(finding("LIST_ALLOWED", "info", -100, "On your allowlist",
      `${look.allowed.value} is trusted by you, so warnings are switched off for it.`, { entry: look.allowed.value }));
    return out;
  }

  finish(report, findings, matches) {
    const [total, verdict] = score(findings);
    report.findings = findings;
    report.score = total;
    report.verdict = verdict;
    report.verdict_label = VERDICT_LABELS[verdict];
    report.summary = summary(verdict, findings, matches);
    const hop = (report.wrapped?.hops || []).find((h) => !h.trusted);
    if (hop && verdict !== "no_indicators") report.summary += ` - via an unverified ${hop.service} link on ${hop.host}`;
    const listed = Object.fromEntries(findings.map((f) => [f.code, f]));
    if (listed.LIST_BLOCKED) report.summary = listed.LIST_BLOCKED.title;
    else if (listed.LIST_REPORTED) report.summary = listed.LIST_REPORTED.title;
    else if (listed.LIST_ALLOWED && verdict === "no_indicators") report.summary = listed.LIST_ALLOWED.title;
  }

  /** dnsName: "host" looks up the full host name, "domain" only its registered domain (links in emails and chats). */
  async core(raw, dns = null, dnsName = "host") {
    const report = {
      schema: "homograph-guard/1", tool_version: VERSION, analyzed_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      input: raw, kind: null, defanged: null, url: null, labels: [], brand_matches: [], findings: [], dns: null,
      score: 0, verdict: "error", verdict_label: VERDICT_LABELS.error, summary: "", error: null,
    };
    let p;
    try {
      p = parseUrl(raw);
    } catch (exc) {
      if (!(exc instanceof InputError)) throw exc;
      report.error = exc.message;
      report.summary = `Could not analyse: ${exc.message}`;
      return [report, [], []];
    }
    const findings = [...p.findings];
    let matches = [];
    report.kind = p.kind;
    const url = {
      scheme: p.scheme, host_unicode: p.hostUnicode || null, host_ascii: p.hostAscii, port: p.port, is_ip: p.isIp,
      idna_valid: p.idnaValid, has_host: p.hasHost, userinfo: p.userinfo, email_local: p.emailLocal,
      display_name: p.displayName, registrable: null, suffix: null, subdomains: [], platform: null,
    };
    report.url = url;
    if (p.hasHost && p.hostAscii) {
      report.defanged = p.kind === "url" ? defang(p.scheme, p.hostAscii, p.rest.slice(0, 200), p.port)
        : `${p.emailLocal}@${p.hostAscii}`.replaceAll(".", "[.]").replaceAll("@", "[@]");
    }
    if (p.hasHost && p.hostAscii && p.isIp) {
      if (dns) report.dns = { asn: await dns.asnLookup([p.hostAscii]) };
    } else if (p.hasHost && p.hostAscii) {
      const parts = splitDomain(p.hostAscii);
      Object.assign(url, { registrable: parts.registrable || null, suffix: parts.suffix || null, subdomains: parts.subdomains, platform: parts.platform });
      const [labels, hg] = analyzeLabels(p.hostUnicode, p.hostAscii, parts);
      report.labels = labels;
      findings.push(...hg);
      matches = this.brands.match(parts, p.hostUnicode);
      report.brand_matches = matches;
      matches.forEach((m, i) => findings.push(brandFinding(m, i === 0)));
      findings.push(...this.decoyFindings(p, parts.registrable));
      findings.push(...this.contextFindings(p, parts, matches, findings));
      if (parts.platform) findings.push(finding("URL_FREE_HOSTING", "low", 10, `Hosted on ${parts.platform}`,
        "Anyone can publish on this platform in minutes; it is heavily used for phishing pages.", { platform: parts.platform }));
      if (parts.subdomains.length >= 4) findings.push(finding("URL_DEEP_SUBDOMAINS", "low", 10, `${parts.subdomains.length} levels of sub-domains`,
        "Long chains push the real domain off the edge of a phone's address bar."));
      if (dns) {
        const top = matches.find((m) => !GENUINE.includes(m.kind))?.brand || null;
        // In a message, look up only the registered domain: a per-recipient token in a
        // sub-domain (a8f3k2.track.example.com) would tell the sender the message was read.
        const name = dnsName === "domain" && p.kind === "url" && parts.registrable ? parts.registrable : p.hostAscii;
        const d = await dns.investigate(name, parts.registrable || null, top, p.kind === "email");
        findings.push(...d.findings);
        report.dns = d.report;
        if (report.dns && name !== p.hostAscii) report.dns.looked_up = name;
      }
    }
    return [report, findings, matches];
  }

  decoyFindings(p, registrable) {
    const out = [];
    if (p.userinfo) {
      let user = p.userinfo.split(":")[0];
      try {
        user = decodeURIComponent(user);
      } catch {
        /* keep */
      }
      const m = this.brands.brandInDomainText(user);
      if (m && m.brand !== registrable) out.push(finding("URL_USERINFO_BRAND", "high", 30, `${m.brand} used as a decoy before '@'`,
        `The link starts with something that reads like ${m.brand}, but that part is only a username; the real destination is ${registrable}.`, { brand: m.brand }));
    }
    if (p.kind === "email" && p.emailLocal) {
      const m = this.brands.brandInDomainText(p.emailLocal);
      if (m && m.brand !== registrable) out.push(finding("EMAIL_LOCAL_BRAND", "high", 25, `Mailbox name imitates ${m.brand}`,
        `'${p.emailLocal.slice(0, 60)}@' looks like ${m.brand}, but the mail domain is ${registrable}.`, { brand: m.brand }));
    }
    if (p.kind === "email" && p.displayName) {
      const hits = this.brands.namesInText(p.displayName, registrable);
      if (hits.length) out.push(finding("EMAIL_DISPLAY_NAME_BRAND", "medium", 20, `Sender name mentions ${hits[0].sld}`,
        `The display name invokes '${hits[0].sld}' but the message comes from ${registrable}, not ${hits[0].domain}.`, { brands: hits.slice(0, 5).map((b) => b.domain) }));
    }
    return out;
  }

  contextFindings(p, parts, matches, soFar) {
    const out = [];
    const owner = [...parts.subdomains, parts.sld].join(".");
    const hostWords = new Set(hostToUnicode(owner).toLowerCase().split(WORDS));
    let restText = p.rest;
    try {
      restText = decodeURIComponent(p.rest);
    } catch {
      /* keep */
    }
    const pathWords = p.kind === "url" ? new Set(restText.toLowerCase().split(WORDS)) : new Set();
    const lures = [...new Set([...hostWords, ...pathWords])].filter((w) => LURES.has(w)).sort();
    const branded = matches.some((m) => !GENUINE.includes(m.kind))
      || soFar.some((f) => ["URL_USERINFO_BRAND", "EMAIL_LOCAL_BRAND", "EMAIL_DISPLAY_NAME_BRAND"].includes(f.code));
    const hostLures = [...hostWords].filter((w) => LURES.has(w)).sort();
    if (lures.length && branded) out.push(finding("URL_LURE_WORDS", "medium", 20, "Brand name combined with credential-lure words",
      `Words like ${lures.slice(0, 4).join(", ")} next to a brand are typical of phishing kits.`, { words: lures.slice(0, 10) }));
    else if (hostLures.length >= 2) out.push(finding("URL_LURE_WORDS", "low", 10, "Credential-lure words in the hostname",
      `The hostname is built from ${hostLures.slice(0, 4).join(", ")}.`, { words: hostLures.slice(0, 10) }));
    if (SHORTENERS.has(parts.registrable)) out.push(finding("URL_SHORTENER", "low", 15, `Short link hides where it leads (${parts.registrable})`,
      "Where it leads is not known: links are never opened to check them. Right-click the link and choose \"Show where this " +
      "short link leads\" to find out without opening the destination. Short links are a common way to get a phishing site " +
      "past filters and readers.", { service: parts.registrable }));
    const tld = parts.suffix ? parts.suffix.split(".").pop() : "";
    if (ABUSED.has(tld)) out.push(finding("URL_ABUSED_TLD", "low", 5, `.${tld} is among the most abused TLDs`,
      "Not proof of anything, but phishing concentrates in cheap or free TLDs." + (tld === "zip" || tld === "mov" ? " .zip/.mov names are also confused with file names." : "")));
    if (p.kind === "url" && !matches.some((m) => STRONG.includes(m.kind))) {
      const inPath = this.brands.namesInText(restText, parts.registrable);
      if (inPath.length && (parts.platform || lures.length)) out.push(finding("URL_PATH_BRAND", "low", 10, `'${inPath[0].sld}' in the path of an unrelated site`,
        `The page path invokes ${inPath[0].domain} on ${parts.registrable}.`, { brands: inPath.slice(0, 5).map((b) => b.domain) }));
    }
    const confusion = soFar.find((f) => f.code === "URL_PARSER_CONFUSION");
    if (confusion) {
      const m = this.brands.brandInDomainText(confusion.evidence.naive_host || "");
      if (m) out.push(finding("URL_PARSER_CONFUSION_BRAND", "high", 25, `Filters would believe this is ${m.brand}`,
        "The parser mismatch makes the link look like a trusted brand to scanners.", { brand: m.brand }));
    }
    return out;
  }

  async wrapperFindings(chain) {
    const out = [];
    for (const h of chain.hops) {
      if (!h.trusted) {
        out.push(finding("WRAP_UNVERIFIED", "medium", 20, `Looks like a ${h.service} link on ${h.host}`,
          `${h.vendor} runs this service on each organisation's own server, so nothing proves ${h.host} is yours. The browser goes to ${h.host} first and only then, if it chooses, to the decoded destination checked below.`,
          { service: h.service, host: h.host }));
        out.push(...(await this.sideFindings(h.wrapper_url, `Wrapper host ${h.host}: `, "wrapper")));
      } else if (h.kind === "gateway") {
        out.push(finding("WRAP_GATEWAY", "info", 0, `Rewritten by ${h.service}`,
          h.url || h.domain_only ? `${h.vendor} wrapped this link for click-time scanning. The real destination was decoded from it, and that is what was checked here.`
            : `${h.vendor} wrapped this link and does not reveal where it leads.`, { service: h.service, host: h.host }));
      } else if (h.kind === "redirect") {
        out.push(finding("WRAP_REDIRECT", "low", 10, `Passes through ${h.service}`,
          `The link starts at ${h.host} but forwards to another site. Phishers use trusted redirect pages so that filters and readers only see the well-known name.`,
          { service: h.service, host: h.host }));
      } else if (h.kind === "tracking") {
        out.push(finding("WRAP_TRACKING", "info", 0, `Click tracking by ${h.service}`,
          h.url ? "Normal for newsletters. The destination was decoded and checked." : "The tracker hides the destination; it cannot be decoded offline.",
          { service: h.service, host: h.host }));
      } else if (h.kind === "advert") {
        const shownOn = adSource(h);
        out.push(finding("AD_REDIRECT", "medium", 25, `Ad network redirect (${h.vendor})`,
          `${h.host} belongs to the ${h.vendor} ad network. Its ad server picks where this link leads only when it is clicked, so the destination cannot be checked in advance. Pop-under and redirect ads like this often lead to scam pages, fake prizes and unwanted downloads.`
            + (shownOn ? ` The link names ${shownOn} as the page that showed the ad.` : ""),
          { network: h.vendor, host: h.host, ...(shownOn ? { shown_on: shownOn } : {}) }));
      }
    }
    const opaque = chain.opaque;
    if (opaque && opaque.kind === "advert") {
      // explained by AD_REDIRECT above
    } else if (opaque && opaque.domain_only) out.push(finding("WRAP_DOMAIN_ONLY", "info", 0, `${opaque.service} reveals only the destination domain`,
      `The full address is hidden; the domain ${opaque.domain_only} was checked.`));
    else if (opaque) out.push(finding("WRAP_OPAQUE", "info", 0, `Destination hidden by ${opaque.service}`,
      "Only the wrapper could be checked. Open such links only if you expected them."));
    if (chain.embedded) {
      const e = chain.embedded;
      out.push(finding("URL_EMBEDDED_URL", "low", 10, `Carries another address in '${e.param}='`,
        `The site at ${e.host} may forward you to ${e.url.slice(0, 120)}. Open redirects like this are used to borrow a trusted name.`,
        { param: e.param, embedded: e.url.slice(0, 500) }));
      out.push(...(await this.sideFindings(e.url, "Embedded address: ", "embedded")));
    }
    return out;
  }

  async sideFindings(url, prefix, part) {
    const [, found] = await this.core(url, null);
    return found.filter((f) => f.weight > 0 && f.code !== "INPUT_DEFANGED")
      .map((f) => ({ ...f, title: prefix + f.title, evidence: { ...f.evidence, part } }));
  }

  linkContextFindings(ctx, report) {
    const out = [];
    const url = report.url || {};
    const real = url.registrable || url.host_ascii || "";
    const shown = ctx.text || "";
    if (shown && real && (ctx.source === "anchor" || ctx.source === "area")) {
      const fake = this.shownDomain(shown, real);
      if (fake && splitDomain(fake).sld === splitDomain(real).sld) {
        out.push(finding("LINK_TEXT_MISMATCH", "low", 10, `Link text shows ${fake} but opens ${real}`,
          `Same name with a different ending. Companies often own both (amazon.com and amazon.in), but check that ${real} really belongs to the same organisation.`,
          { shown: shown.slice(0, 300), shown_domain: fake, real_domain: real }));
      } else if (fake) {
        const official = this.brands.has(fake);
        out.push(finding("LINK_TEXT_MISMATCH", official ? "high" : "medium", official ? 40 : 30, `Link text shows ${fake} but opens ${real}`,
          `The reader sees '${shown.slice(0, 120)}', but clicking goes to ${real}. Showing one address and linking another is the most common phishing trick in email and chat.`,
          { shown: shown.slice(0, 300), shown_domain: fake, real_domain: real }));
      }
    }
    if (ctx.hidden && ctx.medium === "page") {
      out.push(finding("LINK_HIDDEN", "info", 0, `Hidden on the page (${ctx.hidden})`,
        "Websites hide links in menus and pop-ups all the time; it was checked anyway.", { reason: ctx.hidden }));
    } else if (ctx.hidden) {
      out.push(finding("LINK_HIDDEN", "low", 10, `Hidden link (${ctx.hidden})`,
        "The reader cannot see this link. Hidden links are used to slip addresses past filters, to track opens, or to trigger automatic redirects.", { reason: ctx.hidden }));
    }
    return out;
  }

  /** The domain a link's text presents as its address (not a domain merely mentioned in a sentence). */
  shownDomain(shown, real) {
    let text = shown.trim().replace(/^[<>()[\]{}"'“”‘’«»]+|[<>()[\]{}"'“”‘’«»]+$/g, "");
    if (/\s/.test(text)) {
      if (!/^(?:https?:\/\/|www\.)/i.test(text)) return null;
      text = text.split(/\s+/)[0];
    }
    for (const token of (text.match(DOMAINISH_RE) || []).slice(0, 5)) {
      const d = normalizeDomain(token);
      if (!d || !knownSuffix(d)) continue;
      const reg = splitDomain(d).registrable;
      if (reg && reg !== real && !real.endsWith("." + reg)) return reg;
    }
    return null;
  }
}

function brandFinding(m, weighted) {
  return finding(`BRAND_${m.kind.toUpperCase()}`, weighted || m.kind === "official" ? m.severity : "info", weighted ? m.weight : 0,
    BRAND_TITLES[m.kind].replace("{brand}", m.brand), m.detail, { brand: m.brand, kind: m.kind });
}

function summary(verdict, findings, matches) {
  const official = matches.find((m) => m.kind === "official");
  const strong = matches.find((m) => STRONG.includes(m.kind));
  const blocked = findings.find((f) => f.code.startsWith("DNS_BLOCKED"));
  const advert = findings.find((f) => f.code === "AD_REDIRECT");
  if (strong) return `Imitates ${strong.brand} (${strong.kind.replaceAll("_", " ")})`;
  if (advert && !(blocked && blocked.code === "DNS_BLOCKED_SECURITY")) return advert.title; // explains an AdGuard block
  if (blocked) return blocked.title;
  if (official && verdict === "no_indicators") return `Registrable domain is ${official.brand} (protected brand, no homograph tricks)`;
  const scored = findings.filter((f) => f.weight > 0).sort((a, b) => b.weight - a.weight);
  if (verdict === "no_indicators") {
    return "No look-alike characters or deception tricks found" + (scored.length ? ` (${scored.length} minor note${scored.length !== 1 ? "s" : ""})` : "");
  }
  if (official && verdict === "caution") return scored.length ? `${scored[0].title} (domain itself is ${official.brand})` : official.brand;
  return scored.length ? scored[0].title : "Deception indicators found";
}

export { InputError };
