import assert from "node:assert/strict";
import { test } from "node:test";

import { Analyzer } from "../lib/analyzer.js";
import { decodeResponse, DnsInvestigator, encodeQuery } from "../lib/dns.js";

const T = { A: 1, NS: 2, TXT: 16, AAAA: 28 };

function parseQuestion(bytes) {
  let off = 12;
  const labels = [];
  while (bytes[off]) {
    labels.push(String.fromCharCode(...bytes.subarray(off + 1, off + 1 + bytes[off])));
    off += bytes[off] + 1;
  }
  const type = (bytes[off + 1] << 8) | bytes[off + 2];
  return { name: labels.join(".").toLowerCase(), type, qEnd: off + 5 };
}

function nameBytes(name) {
  const out = [];
  for (const l of name.split(".")) out.push(l.length, ...Array.from(l, (c) => c.charCodeAt(0)));
  return [...out, 0];
}

/** Build a DNS response for ``query`` with records [{type, value}], rcode and optional EDE code. */
function respond(query, { rcode = 0, records = [], ede = null } = {}) {
  const { qEnd } = parseQuestion(query);
  const answers = [];
  for (const r of records) {
    let rd;
    if (r.type === T.A) rd = r.value.split(".").map(Number);
    else if (r.type === T.NS) rd = nameBytes(r.value);
    else if (r.type === T.TXT) rd = [r.value.length, ...Array.from(r.value, (c) => c.charCodeAt(0))];
    answers.push(0xc0, 0x0c, 0, r.type, 0, 1, 0, 0, 1, 44, rd.length >> 8, rd.length & 255, ...rd);
  }
  const additional = [];
  if (ede !== null) {
    const opt = [0, 15, 0, 2, ede >> 8, ede & 255];
    additional.push(0, 0, 41, 4, 208, 0, 0, 0, 0, opt.length >> 8, opt.length & 255, ...opt);
  }
  const header = [0, 0, 0x81, 0x80 | rcode, 0, 1, 0, records.length, 0, 0, 0, ede !== null ? 1 : 0];
  return new Uint8Array([...header, ...query.subarray(12, qEnd), ...answers, ...additional]);
}

// Scenario: paypa1.com imitates paypal.com, Cloudflare security null-routes it, AdGuard blocks with EDE 15.
const HOSTS = {
  "paypa1.com": { A: ["185.10.10.10"], NS: ["ns1.evilhost.example"] },
  "paypal.com": { A: ["64.4.250.36"], NS: ["ns1.p57.dynect.net"] },
  "10.10.10.185.origin.asn.cymru.com": { TXT: ["48282 | 185.10.10.0/24 | RU | ripencc | 2015-01-01"] },
  "36.250.4.64.origin.asn.cymru.com": { TXT: ["17012 | 64.4.240.0/21 | US | arin | 2005-01-01"] },
  "as48282.asn.cymru.com": { TXT: ["48282 | RU | ripencc | 2015-01-01 | HOSTING-RU, RU"] },
  "as17012.asn.cymru.com": { TXT: ["17012 | US | arin | 2005-01-01 | PAYPAL, US"] },
};

function fakeFetch(log) {
  return async (url) => {
    const u = new URL(url);
    const b64 = u.searchParams.get("dns").replace(/-/g, "+").replace(/_/g, "/");
    const query = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
    const q = parseQuestion(query);
    log.push(`${u.hostname} ${q.name} ${q.type}`);
    const type = Object.keys(T).find((k) => T[k] === q.type);
    let body;
    if (u.hostname === "security.cloudflare-dns.com" && q.name === "paypa1.com" && q.type === T.A) {
      body = respond(query, { records: [{ type: T.A, value: "0.0.0.0" }] });
    } else if (u.hostname === "dns.adguard-dns.com" && q.name === "paypa1.com") {
      body = respond(query, { ede: 15 });
    } else {
      const values = (HOSTS[q.name] || {})[type] || [];
      body = respond(query, { rcode: HOSTS[q.name] ? 0 : 3, records: values.map((value) => ({ type: q.type, value })) });
    }
    return { ok: true, status: 200, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
  };
}

test("wire format round trip", () => {
  const q = encodeQuery("example.com", "A");
  const r = respond(q, { records: [{ type: T.A, value: "93.184.215.14" }], ede: 15 });
  const d = decodeResponse(r);
  assert.equal(d.rcode, "NOERROR");
  assert.deepEqual(d.addresses, ["93.184.215.14"]);
  assert.equal(d.ede[0].code, 15);
  assert.throws(() => encodeQuery("bad label.com", "A"));
});

test("blocking, brand network comparison and caching", async () => {
  const log = [];
  const dns = new DnsInvestigator({ fetchImpl: fakeFetch(log) });
  const rep = await new Analyzer().analyze("https://paypa1.com/login", null, dns);
  const codes = rep.findings.map((f) => f.code);
  assert.ok(codes.includes("DNS_BLOCKED_SECURITY"), codes.join());
  assert.ok(codes.includes("DNS_BLOCKED_FILTER"));
  assert.ok(codes.includes("DNS_BRAND_DIFF_NET"));
  assert.equal(rep.dns.consensus, "identical");
  assert.equal(rep.dns.brand.relation, "different-network");
  assert.equal(rep.verdict, "high_risk");
  assert.ok(log.every((l) => /^(dns\.google|cloudflare-dns\.com|security\.cloudflare-dns\.com|dns\.adguard-dns\.com|unfiltered\.adguard-dns\.com) /.test(l)));
  assert.ok(!log.some((l) => l.includes("paypa1.com 1") && l.startsWith("paypa1")), "the suspect host is never contacted");
  const before = log.length;
  await new Analyzer().analyze("https://paypa1.com/other", null, dns);
  assert.equal(log.length, before, "second lookup of the same host is served from cache");
});

test("an extended error code next to a real answer is not a block (web.archive.org case)", async () => {
  const fetchImpl = async (url) => {
    const u = new URL(url);
    const b64 = u.searchParams.get("dns").replace(/-/g, "+").replace(/_/g, "/");
    const query = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
    const q = parseQuestion(query);
    const records = q.type === T.A && q.name === "web.archive.org" ? [{ type: T.A, value: "207.241.237.3" }] : [];
    const body = respond(query, { records, ede: u.hostname === "security.cloudflare-dns.com" ? 18 : null });
    return { ok: true, status: 200, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
  };
  const rep = await new Analyzer().analyze("https://web.archive.org/web/2020/http://example.com/", null, new DnsInvestigator({ fetchImpl }));
  assert.ok(!rep.findings.some((f) => f.code.startsWith("DNS_BLOCKED")), rep.findings.map((f) => f.code).join());
  assert.equal(rep.verdict, "no_indicators");
});

function parseEcs(bytes) {
  const { qEnd } = parseQuestion(bytes);
  let off = qEnd + 1 + 2 + 2 + 4; // OPT: root name, type, class, ttl
  const rdlen = (bytes[off] << 8) | bytes[off + 1];
  off += 2;
  const end = off + rdlen;
  while (off + 4 <= end) {
    const code = (bytes[off] << 8) | bytes[off + 1], len = (bytes[off + 2] << 8) | bytes[off + 3];
    if (code === 8) {
      const family = (bytes[off + 4] << 8) | bytes[off + 5], src = bytes[off + 6];
      const addr = [...bytes.subarray(off + 8, off + 4 + len)];
      while (addr.length < (family === 1 ? 4 : 16)) addr.push(0);
      return family === 1 ? `${addr.join(".")}/${src}` : `ipv6/${src}`;
    }
    off += 4 + len;
  }
  return null;
}

test("brand compared from every region; queries never reveal the user's network", async () => {
  const { REGIONS } = await import("../lib/data.js");
  const seen = new Set();
  const answers = {
    "examplebank.com": { default: "146.75.1.10", [REGIONS.India]: "103.21.244.80" },
    "examp1ebank.com": { default: "103.21.244.99" },
  };
  const cymruTxt = {
    "10.1.75.146.origin.asn.cymru.com": "64500 | 146.75.0.0/16 | US | arin | 2015-01-01",
    "80.244.21.103.origin.asn.cymru.com": "64501 | 103.21.244.0/22 | IN | apnic | 2015-01-01",
    "99.244.21.103.origin.asn.cymru.com": "64501 | 103.21.244.0/22 | IN | apnic | 2015-01-01",
  };
  const fetchImpl = async (url) => {
    const u = new URL(url);
    const b64 = u.searchParams.get("dns").replace(/-/g, "+").replace(/_/g, "/");
    const query = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
    const q = parseQuestion(query);
    const ecs = parseEcs(query);
    seen.add(ecs);
    let records = [];
    if (q.type === T.A && answers[q.name]) records = [{ type: T.A, value: answers[q.name][ecs] || answers[q.name].default }];
    if (q.type === T.TXT && cymruTxt[q.name]) records = [{ type: T.TXT, value: cymruTxt[q.name] }];
    const body = respond(query, { records });
    return { ok: true, status: 200, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
  };
  const dns = new DnsInvestigator({ fetchImpl });
  const { report, findings } = await dns.investigate("examp1ebank.com", "examp1ebank.com", "examplebank.com");
  assert.equal(report.brand.relation, "same-subnet");
  assert.ok(findings.some((f) => f.code === "DNS_BRAND_SAME_SUBNET"));
  assert.deepEqual(report.brand.brand_regions.India, ["103.21.244.80"]);
  const allowed = new Set(["0.0.0.0/0", ...Object.values(REGIONS)]);
  assert.ok([...seen].every((e) => allowed.has(e)), [...seen].join());
  assert.ok(seen.has("0.0.0.0/0"));
  const noRegions = await new DnsInvestigator({ fetchImpl, regions: false }).investigate("examp1ebank.com", "examp1ebank.com", "examplebank.com");
  assert.equal(noRegions.report.brand.relation, "different-network");
});

test("unreachable resolvers degrade to offline results", async () => {
  const dns = new DnsInvestigator({ fetchImpl: async () => { throw new TypeError("Failed to fetch"); } });
  const rep = await new Analyzer().analyze("https://example.org/", null, dns);
  assert.ok(rep.findings.some((f) => f.code === "DNS_UNAVAILABLE"));
  assert.equal(rep.verdict, "no_indicators");
});

test("links in messages are looked up by registered domain only (no read receipts)", async () => {
  const token = "a8f3k2x9q.track.paypa1.com";
  for (const medium of ["email", "chat"]) {
    const log = [];
    const rep = await new Analyzer().analyze(`https://${token}/open?id=1`, { source: "anchor", text: "View", medium },
      new DnsInvestigator({ fetchImpl: fakeFetch(log) }));
    assert.ok(!log.some((l) => l.split(" ")[1] === token), log.join("\n"));
    assert.ok(log.some((l) => l.split(" ")[1] === "paypa1.com"));
    assert.equal(rep.dns.looked_up, "paypa1.com");
  }
  const log = [];
  const rep = await new Analyzer().analyze(`https://${token}/x`, { source: "anchor", text: "View", medium: "page" },
    new DnsInvestigator({ fetchImpl: fakeFetch(log) }));
  assert.ok(log.some((l) => l.split(" ")[1] === token));
  assert.equal(rep.dns.looked_up, undefined);
});
