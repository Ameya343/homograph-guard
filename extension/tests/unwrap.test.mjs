import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { unwrap } from "../lib/unwrap.js";

const vectors = JSON.parse(readFileSync(new URL("../../tests/vectors/wrapped_links.json", import.meta.url), "utf8"));

for (const v of vectors) {
  test(`unwrap: ${v.name}`, () => {
    const u = unwrap(v.input);
    assert.deepEqual(u.hops.map((h) => h.service), v.services);
    assert.equal(u.destination, v.destination);
    assert.equal(u.embedded ? u.embedded.url : null, v.embedded ?? null);
    assert.equal(Boolean(u.opaque), v.opaque ?? false);
    if (u.hops.length) assert.equal(u.hops[0].trusted, v.trusted ?? true);
  });
}

test("ad network redirect: recognised, not decoded, source page named", async () => {
  const { adSource } = await import("../lib/unwrap.js");
  const link = "https://s.pemsrv.com/v1/link.php?cat=&idzone=5974550&type=8&p=https%3A%2F%2Ftheblank.net%2F&sub=&block=1&scr_info=aW5saW5lfHBvcE1hZ2ljfDEx";
  const chain = unwrap(link);
  assert.equal(chain.hops[0].kind, "advert");
  assert.equal(chain.destination, link);
  assert.equal(chain.embedded, null);
  assert.equal(adSource(chain.hops[0]), "theblank.net");
  assert.deepEqual(unwrap("https://www.popads.net/").hops, []);
});
