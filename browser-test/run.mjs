// Test the extension in the Chrome or Edge installed on this computer.
//
//   cd browser-test && npm install
//   node run.mjs --browser edge            # or chrome, or a path to the browser executable
//   node run.mjs --browser chrome --sites  # also browse a few real websites and report anything flagged
//
// A separate, throw-away profile is used: your own profile, accounts, history and open windows
// are not touched. Fixture pages are served on the real hostnames (mail.google.com, discord.com,
// web.whatsapp.com, example.com) so the extension's per-site logic runs exactly as it would there.
// While fixtures are served, any other navigation is blocked, so no test click can reach a real
// look-alike domain. DNS-over-HTTPS questions go to the real resolvers.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT = path.resolve(HERE, "..", "extension");
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const browserArg = opt("--browser", "edge");
const shots = path.resolve(opt("--shots", path.join(os.tmpdir(), `hg-browser-test-${Date.now()}`)));
const withSites = args.includes("--sites");

function findBrowser(name) {
  if (existsSync(name)) return name;
  const local = process.env.LOCALAPPDATA || "";
  const candidates = {
    edge: ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"],
    chrome: ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", path.join(local, "Google\\Chrome\\Application\\chrome.exe"),
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"],
  }[name.toLowerCase()] || [];
  const found = candidates.find((p) => p && existsSync(p));
  if (!found) throw new Error(`could not find ${name}; pass --browser <path to the browser executable>`);
  return found;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (cond, what) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${what}`);
  if (!cond) failures++;
};

// ------------------------------------------------------------------ fixture pages
const now = new Date();
const recent = new Date(now - 3600e3).toISOString();
const old = new Date(now - 3 * 86400e3).toISOString();
const pad = (n) => String(n).padStart(2, "0");
const waRecent = `[${pad(now.getHours())}:${pad(now.getMinutes())}, ${now.getMonth() + 1}/${now.getDate()}/${now.getFullYear()}] Bank: `;
const FIX = {
  "https://mail.google.com/mail/u/0/": `<!doctype html><title>Inbox</title>
<nav><a id="outside" href="https://paypa1.com/other">https://www.paypal.com/ (not the open email)</a></nav>
<div role="main"><div class="adn"><h3><span class="gD" email="service@paypa1.com" name="PayPal">PayPal</span></h3>
<div class="a3s">
 <p>Your account is limited. <a id="masked" href="https://paypa1.com/signin">https://www.paypal.com/signin</a></p>
 <p><a id="safe" href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fp%D0%B0ypal.com%2Flogin&amp;data=x">Review activity</a></p>
 <p><a id="forti" href="https://fortimail.corp.example/fmlurlsvc/?fewReq=:B:x&amp;url=https%3a%2f%2fsbi-kyc-update.in%2fverify">Update KYC</a></p>
 <p><a id="aws" href="https://abcd.r.us-east-1.awstrack.me/L0/https:%2F%2Fwww.amaz0n-billing.com%2Faccount/1/x">Your Amazon invoice</a></p>
 <p><a id="ok" href="https://www.paypal.com/help">Help center</a></p>
 <p><a id="jsmail" href="javascript:alert(document.cookie)">View invoice</a></p>
 <div style="display:none"><a id="hidden" href="https://micros0ft-login.top/verify">x</a></div>
 <p id="plain">Or paste hxxps://sbi-kyc-update[.]in/verify into your browser.</p>
</div></div></div>`,
  "https://discord.com/channels/1/2": `<!doctype html><title>Discord</title><main><ol data-list-id="chat-messages">
 <li id="chat-messages-2-1"><time datetime="${old}">3 days ago</time><div><a id="old" href="https://paypa1.com/old">https://www.paypal.com/old</a></div></li>
 <li id="chat-messages-2-2"><time datetime="${recent}">1 hour ago</time><div><a id="steam" href="https://steamcommunity.com/linkfilter/?u=https%3A%2F%2Fsteamcommunlty.com%2Ftrade">https://steamcommunity.com/tradeoffer/new</a></div></li>
 <li id="chat-messages-2-3"><time datetime="${recent}">1 hour ago</time><div><a id="fine" href="https://github.com/">https://github.com/</a></div></li>
</ol></main>`,
  "https://web.whatsapp.com/": `<!doctype html><title>WhatsApp</title><div id="main">
<div role="row"><div data-pre-plain-text="[09:00, 1/2/2020] Old: "><span>see paypa1.com/login</span></div></div>
<div role="row"><div data-pre-plain-text="${waRecent}"><span>Your KYC expires today, update at sbi-kyc-update.in/verify now</span></div></div>
</div>`,
  "https://example.com/page": `<!doctype html><title>A page</title>
<p><a id="g1" href="https://www.paypal.com@evil.example/login">Log in to PayPal</a></p>
<p><span style="font-size:0">https://\u0430\u0440\u0440\u04cf\u0435.com/</span></p>
<form id="f" action="https://xn--pypal-4ve.com/collect"><input name="p"></form>
<p><a id="rel" href="/about">About</a> <a id="js" href="javascript:window.print()">Print</a></p>`,
};
const REAL_SITES = [
  "https://en.wikipedia.org/wiki/IDN_homograph_attack", "https://news.ycombinator.com/", "https://github.com/",
  "https://www.bbc.com/news", "https://www.paypal.com/", "https://mail.google.com/", "https://web.whatsapp.com/",
  "https://discord.com/login",
];

// ------------------------------------------------------------------ run
const exe = findBrowser(browserArg);
const label = path.basename(exe).replace(/\.exe$/i, "").replace(/\s+/g, "-").toLowerCase();
mkdirSync(shots, { recursive: true });
const profile = mkdtempSync(path.join(os.tmpdir(), "hg-profile-"));
const browser = await puppeteer.launch({
  executablePath: exe, headless: false, pipe: true, enableExtensions: true, userDataDir: profile, defaultViewport: null,
  args: ["--no-first-run", "--no-default-browser-check", "--window-size=1320,900", "--window-position=60,40",
    "--disable-features=CalculateNativeWinOcclusion", "--disable-backgrounding-occluded-windows"],
});
try {
  console.log(`browser: ${await browser.version()}  (${exe})`);
  const id = await browser.installExtension(EXT);
  const sw = await (await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().includes(id), { timeout: 20000 })).worker();
  const swErrors = [];
  sw.on("console", (m) => m.type() === "error" && swErrors.push(m.text()));
  check(Boolean(id), `extension loaded (${id})`);

  const page = (await browser.pages())[0] || (await browser.newPage());
  const extErrors = [];
  page.on("console", (m) => {
    const where = m.location()?.url || "";
    if (m.type() === "error" && where.includes(id)) extErrors.push(`${page.url()} :: ${m.text()}`);
  });
  let fixtureMode = true;
  const blockedNavs = [];
  await page.setRequestInterception(true);
  page.on("request", (r) => {
    if (!fixtureMode || r.isInterceptResolutionHandled()) return;
    const html = FIX[r.url().split("#")[0]];
    if (html) return r.respond({ status: 200, contentType: "text/html; charset=utf-8", body: html });
    if (r.isNavigationRequest() && r.frame() === page.mainFrame()) {
      blockedNavs.push(r.url());
      return r.abort();
    }
    return r.continue();
  });

  const status = () => sw.evaluate(async () => {
    const [t] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return chrome.tabs.sendMessage(t.id, { type: "status" });
  });
  const waitStatus = async (pred, timeout = 45000) => {
    const end = Date.now() + timeout;
    let s = {};
    while (Date.now() < end) {
      s = (await status().catch(() => null)) || {};
      if (s.scope && pred(s)) return s;
      await sleep(400);
    }
    return s;
  };
  const verdict = (sel) => page.$eval(sel, (el) => el.getAttribute("data-hg-verdict")).catch(() => "missing");
  const shot = (name) => page.screenshot({ path: path.join(shots, `${label}-${name}.png`) });

  await page.goto("https://mail.google.com/mail/u/0/#inbox/FMfcgz", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#masked[data-hg-verdict]", { timeout: 20000 });
  let s = await waitStatus((x) => x.risky >= 8 && x.pending === 0);
  check(await verdict("#masked") === "high_risk", "Gmail: link text shows paypal.com, the link goes to paypa1.com");
  check(await verdict("#safe") === "high_risk", "Gmail: Microsoft Safe Links decoded to a Cyrillic homograph");
  check(["high_risk", "suspicious"].includes(await verdict("#forti")), "Gmail: FortiMail link decoded, its host marked unverified");
  check(["high_risk", "suspicious"].includes(await verdict("#aws")), "Gmail: Amazon SES (awstrack.me) link decoded to amaz0n-billing.com");
  check(["high_risk", "suspicious"].includes(await verdict("#hidden")), "Gmail: hidden link (display:none) flagged");
  check(await verdict("#jsmail") === "high_risk", "Gmail: javascript: link inside an email flagged");
  check(await verdict("#ok") === null, "Gmail: the real paypal.com link is left alone");
  check(await verdict("#outside") === null, "Gmail: links outside the open email are not scanned");
  check(s.risky === 8 && s.pending === 0, `Gmail: 8 risky links, DNS comparison finished (${s.links} checked)`);
  await sleep(300);
  await shot("gmail");
  const pagesBefore = (await browser.pages()).length;
  const urlBefore = page.url();
  await page.click("#masked");
  await sleep(700);
  check(page.url() === urlBefore && (await browser.pages()).length === pagesBefore && !blockedNavs.length,
    "Gmail: clicking the phishing link shows a warning instead of opening it");
  await shot("gmail-blocked");
  await page.keyboard.press("Escape");

  await page.goto("https://discord.com/channels/1/2", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#steam[data-hg-verdict]", { timeout: 20000 });
  s = await waitStatus((x) => x.pending === 0 && x.links >= 2);
  check(await verdict("#steam") === "high_risk", "Discord: Steam link-filter redirect to steamcommunlty.com flagged");
  check(await verdict("#old") === null && s.links === 2, "Discord: only messages from the last 24 hours are checked");
  await shot("discord");

  await page.goto("https://web.whatsapp.com/", { waitUntil: "domcontentloaded" });
  s = await waitStatus((x) => x.risky >= 1 && x.pending === 0);
  check(s.risky === 1 && s.links === 1, "WhatsApp: today's KYC lure (written as text) flagged, the 2020 message ignored");
  await shot("whatsapp");

  await page.goto("https://example.com/page", { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#g1[data-hg-verdict]", { timeout: 20000 });
  s = await waitStatus((x) => x.risky >= 3 && x.pending === 0);
  check(await verdict("#g1") === "high_risk" && await verdict("#f") === "high_risk", "Page: fake paypal.com before '@', form posting to a homograph");
  check(await verdict("#js") === null && s.risky === 3, "Page: hidden homograph text flagged, the site's own javascript: button not");
  await shot("page");

  await sw.evaluate(() => chrome.storage.local.set({ enabled: false }));
  await page.waitForFunction(() => !document.querySelector("[data-hg-verdict]") && !document.querySelector("hg-guard-ui"), { timeout: 8000 });
  await sw.evaluate(() => chrome.storage.local.set({ enabled: true }));
  await page.waitForSelector("#g1[data-hg-verdict]", { timeout: 20000 });
  check(true, "Switching off removes every mark; switching on rescans");

  const popup = await browser.newPage();
  await popup.setViewport({ width: 300, height: 210 });
  await popup.goto(`chrome-extension://${id}/popup/popup.html`);
  await popup.waitForSelector("#toggle[aria-checked='true']");
  await popup.screenshot({ path: path.join(shots, `${label}-popup.png`) });
  await popup.click("#toggle");
  await popup.waitForSelector("#toggle[aria-checked='false']");
  const off = await sw.evaluate(() => chrome.storage.local.get("enabled").then((v) => v.enabled));
  await popup.click("#toggle");
  await popup.waitForSelector("#toggle[aria-checked='true']");
  const on = await sw.evaluate(() => chrome.storage.local.get("enabled").then((v) => v.enabled));
  check(off === false && on === true, "Popup: the slide switch turns protection off and on");
  await popup.close();

  if (withSites) {
    fixtureMode = false;
    page.removeAllListeners("request");
    await page.setRequestInterception(false);
    const report = [];
    for (const url of REAL_SITES) {
      try {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45000 });
      } catch (e) {
        console.log(`SKIP ${url}: ${String(e.message).slice(0, 100)}`);
        continue;
      }
      const start = Date.now();
      let prev = null, r = {};
      while (Date.now() - start < 60000) {
        r = (await status().catch(() => null)) || {};
        if (r.scope && r.pending === 0 && prev && prev.links === r.links && Date.now() - start > 2500) break;
        prev = r;
        await sleep(700);
      }
      console.log(`SITE ${new URL(page.url()).hostname}: ${r.links} links checked in "${r.scope}", ${r.risky} flagged`);
      for (const it of r.items || []) console.log(`     ${it.verdict.padEnd(10)} ${it.link}  ${it.summary}`);
      report.push({ url, landed: page.url(), ...r });
      await shot(`site-${new URL(page.url()).hostname}`);
    }
    writeFileSync(path.join(shots, `${label}-sites.json`), JSON.stringify(report, null, 2));
  }
  check(extErrors.length === 0, `no errors from the extension's pages${extErrors.length ? ": " + extErrors.slice(0, 3).join(" | ") : ""}`);
  check(swErrors.length === 0, `no errors in the service worker${swErrors.length ? ": " + swErrors.slice(0, 3).join(" | ") : ""}`);
} finally {
  await browser.close();
  rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
}
console.log(`\nscreenshots: ${shots}`);
console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
