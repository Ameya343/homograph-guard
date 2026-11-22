import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Analyzer } from "../lib/analyzer.js";

const vectors = JSON.parse(readFileSync(new URL("../../tests/vectors/analysis.json", import.meta.url), "utf8"));
const analyzer = new Analyzer();

for (const v of vectors) {
  test(`same result as Python: ${JSON.stringify(v.input).slice(0, 80)}`, async () => {
    const rep = await analyzer.analyze(v.input, v.context);
    assert.deepEqual(
      { verdict: rep.verdict, score: rep.score, codes: rep.findings.map((f) => f.code).sort(), host_ascii: rep.url?.host_ascii ?? null },
      { verdict: v.verdict, score: v.score, codes: v.codes, host_ascii: v.host_ascii },
    );
  });
}

test("analysis never throws on hostile input", async () => {
  for (const raw of ["", " ", "http://", "http://[", "https://a@b@c", "x".repeat(9000), "http://\u0000", "%%%", "http://1.2.3.999"]) {
    const rep = await analyzer.analyze(raw);
    assert.ok(["error", "no_indicators", "caution", "suspicious", "high_risk"].includes(rep.verdict));
  }
});
