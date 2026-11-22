import assert from "node:assert/strict";
import { test } from "node:test";

import { Analyzer } from "../lib/analyzer.js";
import * as L from "../lib/lists.js";

test("URL normalisation matches the desktop database", () => {
  assert.equal(L.normalizeUrl("HTTPS://Evil.Example.COM:443/Login/?a=1#frag"), "https://evil.example.com/Login?a=1");
  assert.equal(L.normalizeUrl("javascript:alert(1)"), null);
  assert.deepEqual(L.urlCandidates("https://e.com/a/b?x=1"), ["https://e.com/a/b?x=1", "https://e.com/a/b", "https://e.com/a", "https://e.com/"]);
  assert.deepEqual(L.hostCandidates("a.b.evil.com"), ["a.b.evil.com", "b.evil.com", "evil.com"]);
});

test("entries are validated like the desktop database", () => {
  assert.deepEqual(L.normalizeEntry("Evil-Phish.com"), ["domain", "evil-phish.com"]);
  assert.deepEqual(L.normalizeEntry("evil-phish.com/"), ["domain", "evil-phish.com"]);
  assert.deepEqual(L.normalizeEntry("evil-phish.com/login"), ["url", "https://evil-phish.com/login"]);
  assert.deepEqual(L.normalizeEntry("pаypal.com"), ["domain", "xn--pypal-4ve.com"]);
  for (const bad of ["", "co.uk", "com", "github.io", "not a domain", "javascript:alert(1)", "x".repeat(3000)]) {
    assert.throws(() => L.normalizeEntry(bad), undefined, bad);
  }
});

test("lists decide verdicts, most specific entry first, block beats allow", async () => {
  const lists = L.emptyLists();
  const an = new Analyzer();
  L.addEntry(lists, "block", "https://good-site.com/login", "seen in a phish");
  let rep = await an.analyze("https://good-site.com/login?step=2", null, null, lists);
  assert.equal(rep.verdict, "high_risk");
  assert.equal(rep.summary, "On your blocklist");
  assert.equal((await an.analyze("https://good-site.com/", null, null, lists)).verdict, "no_indicators");
  L.addEntry(lists, "allow", "paypa1.com");
  rep = await an.analyze("https://www.paypa1.com/", null, null, lists);
  assert.equal(rep.verdict, "no_indicators");
  assert.equal(rep.summary, "On your allowlist");
  L.report(lists, "https://paypa1.com/evil");
  assert.equal((await an.analyze("https://paypa1.com/evil", null, null, lists)).summary, "You reported this link as phishing");
  L.addEntry(lists, "block", "paypa1.com");
  assert.equal(lists.allow.length, 0);
  assert.ok(L.removeEntry(lists, "block", "paypa1.com"));
  assert.ok(L.removeEntry(lists, "reported", "https://paypa1.com/evil"));
});
