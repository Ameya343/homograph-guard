// Multi-resolver DNS-over-HTTPS comparison, mirroring dns_check.py.
// Only DNS questions about the link's host (and the imitated brand) are sent, to Google, Cloudflare and
// AdGuard. The suspect site itself is never contacted.
import {
  BLOCK_EDE_CODES, BRAND_PROTECTION_NS, ECS_RESOLVER, GENERIC_NS_PROVIDERS, REGIONS, RESOLVERS, SHARED_INFRA_ASNS,
} from "./data.js";

// EDNS Client Subnet "send nothing": the resolver must not pass the user's network on to the domain's
// name servers (which, for a phishing domain, belong to the attacker). Regional lookups send a fixed
// public prefix of the region instead - never the user's own address.
export const PRIVATE_ECS = "0.0.0.0/0";
const MAX_BRAND_IPS = 24;
import { splitDomain } from "./psl.js";
import { isGlobalIp } from "./urlparse.js";

const TYPES = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, OPT: 41 };
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [v, k]));
const RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"];
const NULL_IPS = new Set(["0.0.0.0", "::"]);
const GENERIC_NS = new Set(GENERIC_NS_PROVIDERS);
const EDE_NAMES = { 15: "Blocked", 16: "Censored", 17: "Filtered", 18: "Prohibited" };

const finding = (code, severity, weight, title, detail = "", evidence = {}) => ({ code, severity, weight, title, detail, evidence });

// ---------------------------------------------------------------- wire format
function ecsOption(ecs) {
  const [addr, len] = ecs.split("/");
  const srclen = Number(len);
  const v6 = addr.includes(":");
  const full = v6 ? expandIPv6(addr) : addr.split(".").map(Number);
  const bytes = full.slice(0, Math.ceil(srclen / 8));
  const data = [0, v6 ? 2 : 1, srclen, 0, ...bytes];
  return [0, 8, data.length >> 8, data.length & 255, ...data]; // option code 8 = client subnet (RFC 7871)
}

export function encodeQuery(name, type, ecs = PRIVATE_ECS) {
  const labels = name.replace(/\.$/, "").split(".").filter(Boolean);
  const bytes = [0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]; // id 0 (RFC 8484), RD, 1 question, 1 additional (OPT)
  for (const l of labels) {
    if (l.length > 63 || /[^\x21-\x7e]/.test(l)) throw new RangeError("bad label");
    bytes.push(l.length, ...Array.from(l, (c) => c.charCodeAt(0)));
  }
  bytes.push(0, 0, TYPES[type], 0, 1);
  const opt = ecsOption(ecs);
  bytes.push(0, 0, TYPES.OPT, 0x04, 0xd0, 0, 0, 0, 0, opt.length >> 8, opt.length & 255, ...opt); // EDNS0, 1232 bytes
  return new Uint8Array(bytes);
}

/** 16 bytes of an IPv6 address. */
export function expandIPv6(addr) {
  const [head, tail = ""] = addr.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const words = addr.includes("::") ? [...h, ...new Array(8 - h.length - t.length).fill("0"), ...t] : h;
  return words.flatMap((w) => {
    const n = parseInt(w || "0", 16);
    return [n >> 8, n & 255];
  });
}

export function subnetOf(ip) {
  if (ip.includes(":")) return `${expandIPv6(ip).slice(0, 6).join(".")}/48`;
  const o = ip.split(".");
  return o.length === 4 ? `${o.slice(0, 3).join(".")}.0/24` : null;
}

function readName(buf, offset) {
  const labels = [];
  let jumped = false, end = offset, guard = 0;
  while (guard++ < 128) {
    const len = buf[offset];
    if (len === undefined) throw new RangeError("truncated name");
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) end = offset + 2;
      offset = ((len & 0x3f) << 8) | buf[offset + 1];
      jumped = true;
      continue;
    }
    if (len === 0) {
      if (!jumped) end = offset + 1;
      return [labels.join("."), end];
    }
    labels.push(String.fromCharCode(...buf.subarray(offset + 1, offset + 1 + len)));
    offset += len + 1;
  }
  throw new RangeError("name loop");
}

function ipv6(bytes) {
  const words = [];
  for (let i = 0; i < 16; i += 2) words.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // compress the longest run of zero words
  let best = [-1, 0];
  for (let i = 0; i < 8;) {
    if (words[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && words[j] === "0") j++;
    if (j - i > best[1]) best = [i, j - i];
    i = j;
  }
  if (best[1] < 2) return words.join(":");
  const head = words.slice(0, best[0]).join(":"), tail = words.slice(best[0] + best[1]).join(":");
  return `${head}::${tail}`;
}

export function decodeResponse(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf.length < 12) throw new RangeError("short response");
  const flags = view.getUint16(2);
  const qd = view.getUint16(4), an = view.getUint16(6), ns = view.getUint16(8), ar = view.getUint16(10);
  let off = 12;
  for (let i = 0; i < qd; i++) off = readName(buf, off)[1] + 4;
  const out = { rcode: RCODES[flags & 0xf] || `RCODE${flags & 0xf}`, addresses: [], cnames: [], records: [], ttl: null, ede: [] };
  const total = an + ns + ar;
  for (let i = 0; i < total; i++) {
    const [, after] = readName(buf, off);
    off = after;
    const type = view.getUint16(off), ttl = view.getUint32(off + 4), rdlen = view.getUint16(off + 8);
    const rd = buf.subarray(off + 10, off + 10 + rdlen);
    const rdOff = off + 10;
    off += 10 + rdlen;
    const inAnswer = i < an;
    if (type === TYPES.OPT) {
      for (let p = 0; p + 4 <= rd.length;) {
        const code = (rd[p] << 8) | rd[p + 1], len = (rd[p + 2] << 8) | rd[p + 3];
        if (code === 15 && len >= 2) {
          const info = (rd[p + 4] << 8) | rd[p + 5];
          out.ede.push({ code: info, name: EDE_NAMES[info] || "Other", text: new TextDecoder().decode(rd.subarray(p + 6, p + 4 + len)).slice(0, 200) });
        }
        p += 4 + len;
      }
      continue;
    }
    if (!inAnswer) continue;
    if (out.ttl === null || ttl < out.ttl) out.ttl = ttl;
    if (type === TYPES.A && rdlen === 4) out.addresses.push(Array.from(rd).join("."));
    else if (type === TYPES.AAAA && rdlen === 16) out.addresses.push(ipv6(rd));
    else if (type === TYPES.CNAME) out.cnames.push(readName(buf, rdOff)[0]);
    else if (type === TYPES.NS) out.records.push(readName(buf, rdOff)[0].toLowerCase());
    else if (type === TYPES.MX) out.records.push(readName(buf, rdOff + 2)[0].toLowerCase());
    else if (type === TYPES.TXT) {
      let s = "";
      for (let p = 0; p < rd.length;) {
        const len = rd[p];
        s += new TextDecoder().decode(rd.subarray(p + 1, p + 1 + len));
        p += 1 + len;
      }
      out.records.push(s);
    }
  }
  return out;
}

const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function inNetworks(ip, nets) {
  if (ip.includes(":")) return false;
  const toInt = (a) => a.split(".").reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
  return nets.some((n) => {
    const [base, bits] = n.split("/");
    const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
    return (toInt(ip) & mask) === (toInt(base) & mask);
  });
}

function nsProvider(host) {
  return host.includes("awsdns-") ? "awsdns" : splitDomain(host).registrable || host;
}

export function cymruName(ip) {
  if (ip.includes(":")) return null; // IPv6 origin lookups are skipped in the extension
  return ip.split(".").reverse().join(".") + ".origin.asn.cymru.com";
}

export function parseCymru(txt) {
  const f = txt.split("|").map((x) => x.trim());
  if (f.length < 3) return null;
  const asn = f[0].split(/\s+/).map(Number).find((x) => Number.isInteger(x) && x > 0);
  return asn ? { asn, prefix: f[1] || "", country: f[2] || "", registry: f[3] || "" } : null;
}

// ---------------------------------------------------------------- investigator
export class DnsInvestigator {
  constructor({ fetchImpl = globalThis.fetch.bind(globalThis), timeoutMs = 4000, resolvers = RESOLVERS, asn = true, regions = true } = {}) {
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.resolvers = resolvers;
    this.byKey = Object.fromEntries(resolvers.map((r) => [r.key, r]));
    this.unfiltered = resolvers.filter((r) => !r.filtering);
    this.asnEnabled = asn;
    this.regions = regions;
    this.cache = new Map(); // "key|name|type" -> {expires, promise}
    this.originCache = new Map();
    this.asNameCache = new Map();
  }

  async rawQuery(r, name, type, ecs = PRIVATE_ECS) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this.fetch(`${r.url}?dns=${b64url(encodeQuery(name, type, ecs))}`, {
        headers: { accept: "application/dns-message" }, signal: ctrl.signal, credentials: "omit",
        referrerPolicy: "no-referrer", cache: "no-store",
      });
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}`, addresses: [], cnames: [], records: [], ede: [], rcode: null, ttl: null };
      const ans = decodeResponse(new Uint8Array(await res.arrayBuffer()));
      return { ok: true, error: null, ...ans };
    } catch (e) {
      return { ok: false, error: e.name === "AbortError" ? "timeout" : String(e.message || e).slice(0, 120), addresses: [], cnames: [], records: [], ede: [], rcode: null, ttl: null };
    } finally {
      clearTimeout(timer);
    }
  }

  query(key, name, type, region = null) {
    const k = `${key}|${name}|${type}|${region || ""}`;
    const hit = this.cache.get(k);
    if (hit && hit.expires > Date.now()) return hit.promise;
    const promise = this.rawQuery(this.byKey[key], name, type, region ? REGIONS[region] : PRIVATE_ECS).then((a) => {
      const ttl = a.ok ? Math.min(600, Math.max(30, a.ttl ?? 300)) : 20;
      this.cache.set(k, { expires: Date.now() + ttl * 1000, promise: Promise.resolve(a) });
      return a;
    });
    this.cache.set(k, { expires: Date.now() + 60000, promise });
    if (this.cache.size > 5000) this.cache.delete(this.cache.keys().next().value);
    return promise;
  }

  async run(jobs) {
    const unique = [...new Map(jobs.map((j) => [j.join("|"), j])).values()];
    const answers = await Promise.all(unique.map(([k, n, t, region]) => this.query(k, n, t, region)));
    return new Map(unique.map((j, i) => [j.join("|"), answers[i]]));
  }

  regional(get, name) {
    const out = {};
    for (const region of Object.keys(REGIONS)) {
      const ips = [];
      for (const t of ["A", "AAAA"]) {
        const x = get(ECS_RESOLVER, name, t, region);
        if (x && x.ok) ips.push(...x.addresses.filter((ip) => !NULL_IPS.has(ip)));
      }
      if (ips.length) out[region] = [...new Set(ips)];
    }
    return out;
  }

  async asnLookup(ips) {
    if (!this.asnEnabled) return {};
    ips = [...new Set(ips)].filter((ip) => isGlobalIp(ip) && !ip.includes(":")).slice(0, 12);
    const refs = this.unfiltered.slice(0, 2).map((r) => r.key);
    const todo = ips.filter((ip) => !this.originCache.has(ip));
    for (const key of refs) {
      const pending = todo.filter((ip) => !this.originCache.get(ip));
      if (!pending.length) break;
      const res = await this.run(pending.map((ip) => [key, cymruName(ip), "TXT"]));
      for (const ip of pending) {
        const a = res.get(`${key}|${cymruName(ip)}|TXT`);
        if (a && a.ok) this.originCache.set(ip, a.records.map(parseCymru).find(Boolean) || null);
      }
    }
    const asns = [...new Set(ips.map((ip) => this.originCache.get(ip)?.asn).filter(Boolean))];
    const need = asns.filter((a) => !this.asNameCache.has(a)).slice(0, 10);
    if (need.length) {
      const res = await this.run(need.map((a) => [refs[0], `AS${a}.asn.cymru.com`, "TXT"]));
      for (const a of need) {
        const ans = res.get(`${refs[0]}|AS${a}.asn.cymru.com|TXT`);
        const f = ans && ans.ok && ans.records[0] ? ans.records[0].split("|").map((x) => x.trim()) : [];
        this.asNameCache.set(a, f.length >= 5 ? f[f.length - 1] : "");
      }
    }
    const out = {};
    for (const ip of ips) {
      const info = this.originCache.get(ip);
      if (info) out[ip] = { ...info, as_name: this.asNameCache.get(info.asn) || "" };
    }
    return out;
  }

  blockPage(r, f, peer) {
    const real = f.addresses.filter((ip) => !NULL_IPS.has(ip));
    const peerAddrs = peer && peer.ok ? peer.addresses : [];
    return Boolean(real.length && r.blockNetworks?.length && !real.some((ip) => peerAddrs.includes(ip))
      && real.every((ip) => inNetworks(ip, r.blockNetworks)));
  }

  /** The filtering resolver handed out a real address (not a null route or its block page). */
  resolves(r, f, peer) {
    return Boolean(f && f.ok && f.addresses.some((ip) => !NULL_IPS.has(ip)) && !this.blockPage(r, f, peer));
  }

  blockReason(r, f, peer) {
    if (!f || !f.ok) return null;
    const blockPage = this.blockPage(r, f, peer);
    // A real address means nothing was blocked, even with an extended error code attached
    // (Cloudflare 1.1.1.2 answers web.archive.org normally, with EDE 18).
    if (this.resolves(r, f, peer)) return null;
    for (const e of f.ede) if (String(e.code) in BLOCK_EDE_CODES) return `EDE ${e.code} ${e.name}`;
    const peerReal = peer && peer.ok && peer.rcode === "NOERROR" && peer.addresses.some((ip) => !NULL_IPS.has(ip));
    if (!peerReal) return null;
    if (f.addresses.length && f.addresses.every((ip) => NULL_IPS.has(ip))) return "answered 0.0.0.0 (null route)";
    if (f.rcode === "NXDOMAIN" || f.rcode === "REFUSED") return `answered ${f.rcode}`;
    if (f.rcode === "NOERROR" && !f.addresses.length && !f.cnames.length) return "answered with no address";
    if (blockPage) return "answered with the provider's block-page address";
    return null;
  }

  /** Returns {report, findings} like DnsInvestigator.investigate() in dns_check.py. */
  async investigate(host, registrable, brand = null, wantMx = false) {
    const rep = { transport: "doh", resolvers: [], consensus: "none", addresses: [], asn: {}, ns: [], mx: null, brand: null, warnings: [] };
    const findings = [];
    const refs = this.unfiltered.slice(0, 2).map((r) => r.key);
    const jobs = [];
    for (const r of this.resolvers) jobs.push([r.key, host, "A"], [r.key, host, "AAAA"]);
    if (registrable) for (const k of refs) jobs.push([k, registrable, "NS"]);
    if (wantMx) jobs.push([refs[0], registrable || host, "MX"]);
    if (brand) for (const k of refs) jobs.push([k, brand, "A"], [k, brand, "AAAA"], [k, brand, "NS"]);
    const regions = Boolean(brand) && this.regions && this.byKey[ECS_RESOLVER];
    if (regions) {
      for (const region of Object.keys(REGIONS)) for (const n of [brand, host]) for (const t of ["A", "AAAA"]) jobs.push([ECS_RESOLVER, n, t, region]);
    }
    const res = await this.run(jobs);
    const get = (k, n, t, region) => res.get(region ? `${k}|${n}|${t}|${region}` : `${k}|${n}|${t}`);

    for (const r of this.resolvers) {
      const a = get(r.key, host, "A"), aaaa = get(r.key, host, "AAAA");
      let reason = null;
      if (r.filtering && r.peer && this.byKey[r.peer]) {
        const pa = get(r.peer, host, "A"), paaaa = get(r.peer, host, "AAAA");
        // Judged per name: a real address for A or AAAA means the site is reachable through the filter.
        if (!(this.resolves(r, a, pa) || this.resolves(r, aaaa, paaaa))) {
          reason = this.blockReason(r, a, pa) || this.blockReason(r, aaaa, paaaa);
        }
      }
      rep.resolvers.push({ key: r.key, provider: r.provider, name: r.name, filtering: r.filtering, blocks: r.blocks,
        a: { rcode: a.rcode, addresses: a.addresses, error: a.error, ede: a.ede }, blocked: Boolean(reason), block_reason: reason || "" });
      if (reason) {
        const strong = r.securityOnly;
        findings.push(finding(strong ? "DNS_BLOCKED_SECURITY" : "DNS_BLOCKED_FILTER", strong ? "high" : "medium", strong ? 40 : 20,
          `Blocked by ${r.name}`,
          `${r.provider}'s filtering resolver refuses this domain (${reason}) while its unfiltered twin resolves it - the provider's threat intelligence flags it.`
          + (strong ? "" : " AdGuard also blocks ad/tracker domains, so treat this as a strong hint, not proof."), { resolver: r.key, reason }));
      }
    }
    const answered = this.resolvers.flatMap((r) => [get(r.key, host, "A"), get(r.key, host, "AAAA")]);
    if (!answered.some((x) => x.ok)) {
      const errors = [...new Set(answered.map((x) => x.error || ""))].sort();
      rep.warnings.push("No resolver answered: " + errors.join("; ").slice(0, 300));
      findings.push(finding("DNS_UNAVAILABLE", "info", 0, "DNS comparison unavailable",
        "None of the resolvers could be reached (network policy, firewall or offline). Static analysis results are still valid.", { errors: errors.slice(0, 5) }));
      return { report: rep, findings };
    }
    const aSets = {}, allIps = [], rcodes = [];
    for (const r of this.unfiltered) {
      for (const t of ["A", "AAAA"]) {
        const x = get(r.key, host, t);
        if (!x.ok) continue;
        rcodes.push(x.rcode);
        const real = x.addresses.filter((ip) => !NULL_IPS.has(ip));
        allIps.push(...real);
        if (t === "A" && x.rcode === "NOERROR") aSets[r.key] = new Set(real);
      }
    }
    rep.addresses = [...new Set(allIps)];
    if (rcodes.length && rcodes.every((c) => c === "NXDOMAIN")) {
      rep.consensus = "nxdomain";
      findings.push(finding("DNS_NXDOMAIN", "info", 0, "Domain does not exist in DNS",
        "Not registered, expired, or already taken down. The link cannot load today but may be activated later - do not treat it as safe."));
    }
    const okA = this.unfiltered.filter((r) => get(r.key, host, "A").ok);
    const nullOnly = okA.filter((r) => { const a = get(r.key, host, "A"); return a.addresses.length && a.addresses.every((ip) => NULL_IPS.has(ip)); });
    if (nullOnly.length && nullOnly.length === okA.length) findings.push(finding("DNS_NULL_ROUTED", "low", 5, "Domain's own DNS points to 0.0.0.0",
      "Typical of registrar/registry takedowns or parked malicious domains."));
    const priv = [...new Set(rep.addresses.filter((ip) => !isGlobalIp(ip)))].sort();
    if (priv.length) findings.push(finding("DNS_PRIVATE_IP", "medium", 20, "Resolves to a private / internal address",
      `${priv.slice(0, 4).join(", ")} is not on the public internet. Public names pointing inside your network enable DNS-rebinding and intranet attacks.`, { addresses: priv.slice(0, 10) }));

    const nonEmpty = Object.fromEntries(Object.entries(aSets).filter(([, v]) => v.size));
    const sets = Object.values(nonEmpty);
    const needAsn = Boolean(brand) || (sets.length >= 2 && !sets.every((s) => [...s].every((ip) => sets[0].has(ip)) && s.size === sets[0].size));
    rep.asn = needAsn ? await this.asnLookup(rep.addresses) : {};
    if (sets.length >= 2) {
      const same = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));
      const overlap = (a, b) => [...a].some((x) => b.has(x));
      if (sets.every((s) => same(s, sets[0]))) rep.consensus = "identical";
      else if (sets.every((s, i) => sets.slice(i + 1).every((t) => overlap(s, t)))) rep.consensus = "overlapping";
      else {
        const asnSets = sets.map((s) => new Set([...s].filter((ip) => rep.asn[ip]).map((ip) => rep.asn[ip].asn)));
        if (asnSets.every((s) => s.size) && asnSets.slice(1).every((s) => overlap(asnSets[0], s))) rep.consensus = "different-ips-same-network";
        else if (asnSets.every((s) => s.size)) {
          rep.consensus = "disagree";
          findings.push(finding("DNS_INCONSISTENT", "medium", 15, "Resolvers disagree on where the domain lives",
            "Google, Cloudflare and AdGuard returned addresses on different networks. Possible DNS manipulation or fast-changing infrastructure (GeoDNS can also do this).",
            { answers: Object.fromEntries(Object.entries(nonEmpty).map(([k, v]) => [k, [...v].sort()])) }));
        } else rep.consensus = "different-ips";
      }
    } else if (sets.length === 1) rep.consensus = "single";

    const ttls = this.unfiltered.map((r) => get(r.key, host, "A").ttl).filter((t) => t !== null && t !== undefined);
    const distinct = new Set(Object.values(rep.asn).map((v) => v.asn));
    if (rep.addresses.length >= 6 && distinct.size >= 3 && ttls.length && Math.min(...ttls) <= 300) {
      findings.push(finding("DNS_FAST_FLUX", "medium", 15, "Fast-flux pattern",
        `${rep.addresses.length} addresses across ${distinct.size} networks with TTL ${Math.min(...ttls)}s - typical of botnet-hosted phishing.`));
    }
    const firstOk = (keys, name, type) => keys.map((k) => get(k, name, type)).find((a) => a && a.ok) || null;
    if (registrable) {
      const ns = firstOk(refs, registrable, "NS");
      rep.ns = ns ? ns.records : [];
    }
    if (wantMx) {
      const mx = firstOk(refs.slice(0, 1), registrable || host, "MX");
      rep.mx = mx ? mx.records : [];
      if (mx && !rep.mx.length) findings.push(finding("DNS_NO_MX", "low", 5, "Domain cannot receive email",
        "No MX records: the address is probably used only to send spoofed mail."));
    }
    if (brand && rep.consensus !== "nxdomain") await this.compareBrand(rep, findings, get, refs, brand, host, regions);
    return { report: rep, findings };
  }

  async compareBrand(rep, findings, get, refs, brand, host, regions) {
    const bIps = [];
    for (const k of refs) for (const t of ["A", "AAAA"]) {
      const x = get(k, brand, t);
      if (x && x.ok) bIps.push(...x.addresses.filter((ip) => !NULL_IPS.has(ip)));
    }
    const bRegions = regions ? this.regional(get, brand) : {};
    const sRegions = regions ? this.regional(get, host) : {};
    const brandIps = [...new Set([...bIps, ...Object.values(bRegions).flat()])];
    const sIps = [...new Set([...rep.addresses, ...Object.values(sRegions).flat()])];
    const nsAns = refs.map((k) => get(k, brand, "NS")).find((a) => a && a.ok);
    const bNs = nsAns ? nsAns.records : [];
    const info = { domain: brand, addresses: brandIps.slice(0, MAX_BRAND_IPS), ns: bNs, relation: "unknown", asns: [],
      regions_checked: regions ? Object.keys(REGIONS).length : 0, brand_regions: bRegions, suspect_regions: sRegions };
    rep.brand = info;
    if (!sIps.length) { info.relation = "suspect-does-not-resolve"; return; }
    if (!brandIps.length) { info.relation = "brand-did-not-resolve"; return; }
    Object.assign(rep.asn, await this.asnLookup(brandIps.slice(0, MAX_BRAND_IPS)));
    Object.assign(rep.asn, await this.asnLookup(sIps.filter((ip) => !rep.asn[ip]).slice(0, 12)));
    const bAsn = Object.fromEntries(brandIps.filter((ip) => rep.asn[ip]).map((ip) => [ip, rep.asn[ip]]));
    const sAsns = new Set(sIps.filter((ip) => rep.asn[ip]).map((ip) => rep.asn[ip].asn));
    const bAsns = new Set(Object.values(bAsn).map((v) => v.asn));
    info.asns = [...bAsns].sort((a, b) => a - b);
    const label = (asns) => [...asns].sort((a, b) => a - b).slice(0, 3).map((a) => {
      const nm = Object.values(rep.asn).find((v) => v.asn === a && v.as_name)?.as_name || "";
      return `AS${a}${nm ? " " + nm : ""}`;
    }).join(", ") || "unknown network";
    const where = regions ? ` (checked from ${Object.keys(REGIONS).length} regions)` : "";
    const dedicatedOwner = (ip) => !this.asnEnabled || (rep.asn[ip] && !(String(rep.asn[ip].asn) in SHARED_INFRA_ASNS));
    const bSubnets = new Set(brandIps.map(subnetOf).filter(Boolean));
    const sameSubnet = sIps.filter((ip) => bSubnets.has(subnetOf(ip)) && dedicatedOwner(ip)).sort();
    const bPrefixes = [...new Set(Object.values(bAsn).map((v) => v.prefix).filter(Boolean))];
    const samePrefix = sIps.filter((ip) => dedicatedOwner(ip) && !ip.includes(":") && inNetworks(ip, bPrefixes.filter((p) => !p.includes(":")))).sort();
    const sharedIps = sIps.filter((ip) => brandIps.includes(ip));
    const sharedAsns = new Set([...sAsns].filter((a) => bAsns.has(a)));
    const dedicated = new Set([...sharedAsns].filter((a) => !(String(a) in SHARED_INFRA_ASNS)));
    if (sharedIps.length && (dedicated.size || !this.asnEnabled)) {
      info.relation = "same-ip";
      findings.push(finding("DNS_BRAND_SAME_IP", "info", -20, `Same IP address as the real ${brand}`,
        "The look-alike points at the brand's own servers - typical of a defensive registration that redirects to the real site.", { shared: sharedIps.slice(0, 5) }));
    } else if (sameSubnet.length) {
      info.relation = "same-subnet";
      findings.push(finding("DNS_BRAND_SAME_SUBNET", "info", -15, `Same network block as the real ${brand}`,
        `${sameSubnet[0]} is in the same ${subnetOf(sameSubnet[0])} block as one of ${brand}'s addresses${where}, on a network that is not a public hosting provider.`,
        { addresses: sameSubnet.slice(0, 5) }));
    } else if (samePrefix.length) {
      info.relation = "same-prefix";
      findings.push(finding("DNS_BRAND_SAME_PREFIX", "info", -12, `Inside the real ${brand}'s announced network`,
        `${samePrefix[0]} belongs to an address range that ${brand}'s network announces${where}.`, { addresses: samePrefix.slice(0, 5) }));
    } else if (dedicated.size) {
      info.relation = "same-network";
      findings.push(finding("DNS_BRAND_SAME_NET", "info", -10, `Same network as the real ${brand}`,
        `Both live on ${label(dedicated)}, which is not a public hosting provider.`));
    } else if (sharedAsns.size) {
      info.relation = "shared-provider";
      findings.push(finding("DNS_BRAND_SHARED_PROVIDER", "info", 0, `Same hosting provider as ${brand} (not evidence)`,
        `Both use ${label(sharedAsns)}, where anyone can host a site.`));
    } else if (sAsns.size && bAsns.size) {
      info.relation = "different-network";
      findings.push(finding("DNS_BRAND_DIFF_NET", "medium", 20, `Hosted on a different network than the real ${brand}`,
        `Look-alike: ${label(sAsns)}. Real ${brand}${where}: ${label(bAsns)}. Where the user would actually be taken is not the brand's infrastructure.`));
    }
    const sProv = new Set(rep.ns.map(nsProvider)), bProv = new Set(bNs.map(nsProvider));
    const protection = [...sProv].filter((p) => p in BRAND_PROTECTION_NS).map((p) => BRAND_PROTECTION_NS[p]).sort();
    const sharedNs = rep.ns.filter((n) => bNs.includes(n));
    const provOverlap = [...sProv].filter((p) => bProv.has(p));
    const own = sharedNs.length && !provOverlap.every((p) => GENERIC_NS.has(p) || p === "awsdns");
    if (own) findings.push(finding("DNS_BRAND_SHARED_NS", "info", -25, `Uses ${brand}'s own nameservers`,
      "The look-alike is served by the brand's dedicated DNS - strong sign the brand owns it.", { shared_ns: sharedNs.slice(0, 6) }));
    else if (protection.length) findings.push(finding("DNS_BRAND_PROTECTION_NS", "info", -20, `Parked with ${protection[0]}`,
      "Nameservers of a corporate brand-protection registrar - usually a defensive registration."));
  }
}

export { TYPE_NAMES };
