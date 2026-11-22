// Service worker / event page: checks the links the content script finds, guards navigations, keeps the lists.
//
// When the Homograph Guard app is installed, every check goes to it over native messaging: the threat
// database, your lists and the full analysis all live on this device and nothing is sent anywhere
// (unless you switch on DNS checks). Without the app, the built-in analysis and lists kept in this
// browser are used instead.
import { Analyzer } from "./lib/analyzer.js";
import { URL_SHORTENERS } from "./lib/data.js";
import { DnsInvestigator } from "./lib/dns.js";
import * as L from "./lib/lists.js";
import { knownSuffix, splitDomain } from "./lib/psl.js";

const ext = globalThis.browser ?? globalThis.chrome;
const HOST = "com.homograph_guard.host";
const analyzer = new Analyzer();
let dns = null; // created only if the user enables DNS checks
const REPORT_TTL_MS = 30 * 60 * 1000;
const MAX_DNS_HOSTS_PER_PAGE = 60;
const reportCache = new Map();
const bypass = new Map(); // url -> expiry: "open anyway" for one navigation
const DNS_MODES = ["off", "suspicious", "all"];

// ------------------------------------------------------------------ settings and lists kept in the browser
async function local(keys) {
  return ext.storage.local.get(keys);
}
async function isEnabled() {
  const { enabled } = await local({ enabled: true });
  return enabled !== false;
}
async function browserLists() {
  const { lists } = await local({ lists: L.emptyLists() });
  return { ...L.emptyLists(), ...lists };
}
async function saveLists(lists) {
  await ext.storage.local.set({ lists });
}
async function browserDnsMode() {
  const { dnsMode } = await local({ dnsMode: "off" });
  return DNS_MODES.includes(dnsMode) ? dnsMode : "off";
}

// ------------------------------------------------------------------ native messaging bridge to the app on this device
const bridge = { port: null, ready: null, hello: null, onHello: null, retryAt: 0, seq: 0, pending: new Map(), checks: new Map() };

function connectNative() {
  if (bridge.port) return bridge.ready;
  if (Date.now() < bridge.retryAt) return Promise.resolve(false);
  let port;
  try {
    port = ext.runtime.connectNative(HOST);
  } catch {
    bridge.retryAt = Date.now() + 60000;
    return Promise.resolve(false);
  }
  bridge.port = port;
  bridge.ready = new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 4000);
    bridge.onHello = (msg) => {
      clearTimeout(timer);
      bridge.hello = msg;
      resolve(true);
    };
    port.onDisconnect.addListener(() => {
      clearTimeout(timer);
      resolve(false);
    });
  });
  port.onMessage.addListener(onNativeMessage);
  port.onDisconnect.addListener(() => {
    void ext.runtime.lastError; // read it so Chrome does not log "Unchecked runtime.lastError"
    bridge.port = null;
    bridge.ready = null;
    bridge.hello = null;
    bridge.retryAt = Date.now() + 30000;
    for (const p of bridge.pending.values()) p.reject(new Error("The Homograph Guard app is not available."));
    bridge.pending.clear();
    for (const c of bridge.checks.values()) c.onLost();
    bridge.checks.clear();
  });
  port.postMessage({ type: "hello", req: "hello" });
  return bridge.ready;
}

function onNativeMessage(msg) {
  if (!msg || typeof msg !== "object") return;
  if (msg.type === "hello" && msg.req === "hello") {
    bridge.onHello?.(msg);
    return;
  }
  if (msg.type === "result") {
    bridge.checks.get(msg.req)?.onResult(msg.id, msg.report);
    return;
  }
  const p = bridge.pending.get(msg.req);
  if (!p) return;
  bridge.pending.delete(msg.req);
  if (msg.type === "error") p.reject(Object.assign(new Error(String(msg.error).slice(0, 300)), { locked: Boolean(msg.locked) }));
  else p.resolve(msg);
}

function nativeRequest(msg, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    if (!bridge.port) return reject(new Error("The Homograph Guard app is not available."));
    const req = `q${++bridge.seq}`;
    const timer = setTimeout(() => {
      bridge.pending.delete(req);
      reject(new Error("The Homograph Guard app did not answer."));
    }, timeoutMs);
    bridge.pending.set(req, { resolve: (v) => (clearTimeout(timer), resolve(v)), reject: (e) => (clearTimeout(timer), reject(e)) });
    bridge.port.postMessage({ ...msg, req });
  });
}

function nativeCheck(links, noDns, onResult, onLost) {
  const req = `c${++bridge.seq}`;
  const remaining = new Map(links.map((l) => [l.id, l]));
  const done = () => bridge.checks.delete(req);
  const timer = setTimeout(() => {
    done();
    if (remaining.size) onLost([...remaining.values()]);
  }, 60000);
  bridge.checks.set(req, {
    onResult(id, report) {
      if (!remaining.delete(id)) return;
      onResult(id, report);
      if (!remaining.size) {
        clearTimeout(timer);
        done();
      }
    },
    onLost() {
      clearTimeout(timer);
      if (remaining.size) onLost([...remaining.values()]);
    },
  });
  bridge.port.postMessage({ type: "check", req, links: links.map(({ id, url, ctx }) => ({ id, url, ctx })), no_dns: noDns });
}

// ------------------------------------------------------------------ built-in analysis (no app installed)
function slim(rep) {
  const findings = [...(rep.findings || [])].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight)).slice(0, 12)
    .map(({ code, severity, weight, title, detail }) => ({ code, severity, weight, title, detail }));
  const d = rep.dns;
  return {
    input: rep.input, verdict: rep.verdict, verdict_label: rep.verdict_label, score: rep.score, summary: rep.summary,
    defanged: rep.defanged, kind: rep.kind, error: rep.error,
    url: rep.url ? { host_unicode: rep.url.host_unicode, host_ascii: rep.url.host_ascii, registrable: rep.url.registrable } : null,
    wrapped: rep.wrapped ? { destination: rep.wrapped.destination,
      hops: rep.wrapped.hops.map(({ service, host, trusted, kind }) => ({ service, host, trusted, kind })),
      embedded: rep.wrapped.embedded ? { url: rep.wrapped.embedded.url, param: rep.wrapped.embedded.param } : null } : null,
    context: rep.context || null, lists: rep.lists || null, findings, checked_on: "browser",
    dns: d && d.resolvers ? { consensus: d.consensus, brand: d.brand ? { domain: d.brand.domain, relation: d.brand.relation } : null,
      resolvers: d.resolvers.map((r) => ({ name: r.name, filtering: r.filtering, blocked: r.blocked, block_reason: r.block_reason,
        rcode: r.a.rcode, addresses: (r.a.addresses || []).slice(0, 3), error: r.a.error })) } : null,
  };
}

function wantsDns(rep, mode, pageRegistrable) {
  const u = rep.url;
  if (mode === "off" || !u || !u.has_host || !u.host_ascii || u.is_ip) return false;
  if (!["url", "email"].includes(rep.kind) || (rep.kind === "url" && !["http", "https"].includes(u.scheme))) return false;
  if (rep.lists && (rep.lists.allowed || rep.lists.blocked || rep.lists.reported)) return false;
  if (pageRegistrable && u.registrable === pageRegistrable && rep.kind === "url") return false;
  return mode === "all" || ["caution", "suspicious", "high_risk"].includes(rep.verdict);
}

function pool(limit) {
  let active = 0;
  const queue = [];
  const next = () => {
    if (active >= limit || !queue.length) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    fn().then(resolve, reject).finally(() => {
      active--;
      next();
    });
  };
  return (fn) => new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    next();
  });
}
const dnsSlot = pool(4);

function cached(key) {
  const hit = reportCache.get(key);
  if (hit && hit.expires > Date.now()) return hit.report;
  reportCache.delete(key);
  return null;
}
function remember(key, report) {
  reportCache.set(key, { expires: Date.now() + REPORT_TTL_MS, report });
  if (reportCache.size > 2000) reportCache.delete(reportCache.keys().next().value);
}

async function browserCheck(links, pageRegistrable, post, isAlive) {
  const lists = await browserLists();
  const mode = await browserDnsMode();
  const dnsHosts = new Set();
  const deferred = [];
  for (const link of links) {
    const key = JSON.stringify([link.url, link.ctx || null]);
    const done = cached(key);
    if (done) {
      post({ type: "result", id: link.id, final: true, report: done });
      continue;
    }
    let offline;
    try {
      offline = await analyzer.analyze(link.url, link.ctx || null, null, lists);
    } catch (e) {
      post({ type: "result", id: link.id, final: true, report: { verdict: "error", summary: String(e).slice(0, 200), findings: [] } });
      continue;
    }
    const host = offline.url?.host_ascii;
    const want = wantsDns(offline, mode, pageRegistrable) && (dnsHosts.has(host) || dnsHosts.size < MAX_DNS_HOSTS_PER_PAGE);
    post({ type: "result", id: link.id, final: !want, report: slim(offline) });
    if (want) {
      dnsHosts.add(host);
      deferred.push({ link, key, score: offline.score });
    } else {
      remember(key, slim(offline));
    }
  }
  deferred.sort((a, b) => b.score - a.score);
  for (const { link, key } of deferred) {
    dnsSlot(async () => {
      if (!isAlive()) return;
      dns = dns || new DnsInvestigator();
      try {
        const full = slim(await analyzer.analyze(link.url, link.ctx || null, dns, lists));
        remember(key, full);
        post({ type: "result", id: link.id, final: true, report: full });
      } catch (e) {
        post({ type: "result", id: link.id, final: true, error: String(e).slice(0, 200) });
      }
    });
  }
}

// ------------------------------------------------------------------ content scripts
const ID_RE = /^[A-Za-z0-9_-]{1,40}$/;
const CTX_KEYS = ["source", "text", "hidden", "where", "medium"];

function sanitizeLinks(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const l of raw.slice(0, 500)) {
    if (!l || typeof l.id !== "string" || !ID_RE.test(l.id) || typeof l.url !== "string" || !l.url || l.url.length > 8192) continue;
    const ctx = {};
    if (l.ctx && typeof l.ctx === "object") {
      for (const k of CTX_KEYS) if (typeof l.ctx[k] === "string") ctx[k] = l.ctx[k].slice(0, 500);
    }
    out.push({ id: l.id, url: l.url, ctx: Object.keys(ctx).length ? ctx : null, bare: l.bare === true });
  }
  return out;
}

function fromContentScript(sender) {
  return sender?.id === ext.runtime.id && sender.tab && typeof sender.tab.id === "number"
    && !String(sender.url || "").startsWith(ext.runtime.getURL(""));
}

function fromExtensionPage(sender, page) {
  return sender?.id === ext.runtime.id && String(sender.url || "").startsWith(ext.runtime.getURL(page));
}

ext.runtime.onConnect.addListener((port) => {
  if (port.name !== "hg-scan" || !fromContentScript(port.sender)) return;
  let alive = true;
  port.onDisconnect.addListener(() => (alive = false));
  const post = (msg) => {
    if (!alive) return;
    try {
      port.postMessage(msg);
    } catch {
      alive = false;
    }
  };
  port.onMessage.addListener(async (msg) => {
    if (msg?.type !== "check") return;
    if (!(await isEnabled())) return;
    const pageRegistrable = typeof msg.page === "string" ? splitDomain(msg.page.slice(0, 253)).registrable : "";
    const links = [];
    for (const link of sanitizeLinks(msg.links)) {
      if (link.bare && !knownSuffix(link.url.split(/[/:?#]/)[0])) post({ type: "result", id: link.id, ignore: true });
      else links.push(link);
    }
    if (!links.length) return;
    if (await connectNative()) {
      nativeCheck(links, false, (id, report) => post({ type: "result", id, final: true, report }),
        (lost) => browserCheck(lost, pageRegistrable, post, () => alive));
    } else {
      browserCheck(links, pageRegistrable, post, () => alive);
    }
  });
});

// ------------------------------------------------------------------ lists, reports and settings (options page, menus, dialog)
async function listsState() {
  if (await connectNative()) {
    const [lists, hello] = await Promise.all([nativeRequest({ type: "lists" }), nativeRequest({ type: "hello" })]);
    return { app: true, version: hello.version, db: hello.db, settings: hello.settings, lists };
  }
  return { app: false, lists: await browserLists(), settings: { dns_mode: await browserDnsMode(), dns_modes: DNS_MODES, locked: [] } };
}

async function changed() {
  reportCache.clear();
  const tabs = await ext.tabs.query({});
  for (const t of tabs) ext.tabs.sendMessage(t.id, { type: "lists-changed" }).catch(() => {});
}

async function addToList(list, entry, note = "") {
  if (await connectNative()) await nativeRequest({ type: "list_add", list, entry, note });
  else {
    const lists = await browserLists();
    L.addEntry(lists, list, entry, note);
    await saveLists(lists);
  }
  await changed();
}

async function removeFromList(list, entry) {
  if (await connectNative()) await nativeRequest({ type: "list_remove", list, entry });
  else {
    const lists = await browserLists();
    L.removeEntry(lists, list, entry);
    await saveLists(lists);
  }
  await changed();
}

async function reportLink(url, note = "") {
  if (await connectNative()) await nativeRequest({ type: "report", url, note });
  else {
    const lists = await browserLists();
    L.report(lists, url, note);
    await saveLists(lists);
  }
  await changed();
}

function siteOf(url) {
  const norm = L.normalizeUrl(url);
  if (!norm) throw new Error("only web links (http/https) can be trusted");
  const host = new URL(norm).hostname;
  return splitDomain(host).registrable || host;
}

async function handleOptions(msg) {
  const text = (v, n) => (typeof v === "string" && v.length <= n ? v : "");
  switch (msg.op) {
    case "state":
      return listsState();
    case "add":
      await addToList(msg.list === "allow" ? "allow" : "block", text(msg.entry, 2048), text(msg.note, 300));
      return listsState();
    case "remove":
      await removeFromList(["allow", "block", "reported"].includes(msg.list) ? msg.list : "block", text(msg.entry, 2048));
      return listsState();
    case "report":
      await reportLink(text(msg.url, 2048), text(msg.note, 300));
      return listsState();
    case "dns": {
      const mode = DNS_MODES.includes(msg.mode) ? msg.mode : null;
      if (!mode) throw new Error("unknown DNS mode");
      if (await connectNative()) await nativeRequest({ type: "settings_set", dns_mode: mode });
      else await ext.storage.local.set({ dnsMode: mode });
      await changed();
      return listsState();
    }
    default:
      throw new Error("unknown request");
  }
}

ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "count" && fromContentScript(sender)) {
    const n = Math.max(0, Math.min(Number(msg.n) || 0, 99));
    ext.action.setBadgeText({ tabId: sender.tab.id, text: n > 0 ? String(n) : "" });
    ext.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: msg.high ? "#B42318" : "#B54708" });
    return false;
  }
  let work = null;
  if (msg?.type === "options" && fromExtensionPage(sender, "options/")) work = handleOptions(msg);
  else if (msg?.type === "user-action" && fromContentScript(sender)) work = handleUserAction(msg);
  else if (msg?.type === "nav-continue" && fromExtensionPage(sender, "warning/")) work = allowOnce(msg.url);
  else if (msg?.type === "nav-trust" && fromExtensionPage(sender, "warning/")) work = addToList("allow", siteOf(String(msg.url))).then(() => ({ ok: true }));
  if (!work) return false;
  work.then((r) => sendResponse(r ?? { ok: true }), (e) => sendResponse({ error: String(e.message || e).slice(0, 300), locked: Boolean(e.locked) }));
  return true;
});

async function handleUserAction(msg) {
  const url = typeof msg.url === "string" && msg.url.length <= 2048 ? msg.url : "";
  if (msg.action === "report") await reportLink(url);
  else if (msg.action === "trust") await addToList("allow", siteOf(url));
  else if (msg.action === "open") {
    const norm = L.normalizeUrl(url);
    if (!norm && !/^mailto:/i.test(url)) throw new Error("only web links can be opened");
    await allowOnce(url);
    await ext.tabs.create({ url });
  } else throw new Error("unknown action");
  return { ok: true };
}

async function allowOnce(url) {
  if (typeof url !== "string" || url.length > 8192) throw new Error("bad link");
  bypass.set(url, Date.now() + 60000);
  return { ok: true };
}

// ------------------------------------------------------------------ right-click menu
async function createMenus() {
  await ext.contextMenus.removeAll();
  ext.contextMenus.create({ id: "hg-report", title: "Report link as phishing", contexts: ["link"] });
  ext.contextMenus.create({ id: "hg-trust", title: "Always trust this link's site", contexts: ["link"] });
  ext.contextMenus.create({ id: "hg-block", title: "Block this link's site", contexts: ["link"] });
  ext.contextMenus.create({ id: "hg-expand", title: "Show where this short link leads", contexts: ["link"],
    targetUrlPatterns: SHORT_PATTERNS });
}

ext.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = String(info.linkUrl || "");
  try {
    if (info.menuItemId === "hg-expand") await revealShortLink(url, tab);
    else if (info.menuItemId === "hg-report") await reportLink(url);
    else if (info.menuItemId === "hg-trust") await addToList("allow", siteOf(url));
    else if (info.menuItemId === "hg-block") await addToList("block", siteOf(url));
  } catch {
    /* not a web link */
  }
});

// ------------------------------------------------------------------ navigation guard
// Links opened from desktop apps (Outlook, Teams, WhatsApp) arrive here without a page to scan.
// Only the database on this device is consulted - never DNS - so browsing stays private.
async function navigationVerdict(url) {
  if (await connectNative()) {
    return new Promise((resolve) => {
      nativeCheck([{ id: "nav", url, ctx: null }], true, (_id, report) => resolve(report), () => resolve(null));
    });
  }
  return slim(await analyzer.analyze(url, null, null, await browserLists()));
}

// A link that redirects (a short link, a tracker) is checked again where it redirects to.
async function guardNavigation(tabId, url) {
  if (tabId < 0 || reveals.has(tabId) || !/^https?:/i.test(url)) return;
  const until = bypass.get(url);
  if (until && until > Date.now()) return;
  if (!(await isEnabled())) return;
  let rep = null;
  try {
    rep = await navigationVerdict(url);
  } catch {
    return;
  }
  if (!rep || rep.verdict !== "high_risk") return;
  const info = { u: url, s: rep.summary, d: rep.defanged || url,
    r: (rep.findings || []).filter((f) => f.weight > 0).slice(0, 4).map((f) => f.title) };
  ext.tabs.update(tabId, { url: ext.runtime.getURL(`warning/warning.html#${encodeURIComponent(JSON.stringify(info))}`) });
}

ext.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0) return;
  if (reveals.has(d.tabId)) revealSaw(d.tabId, d.url); // a script or meta refresh on the service's page
  else guardNavigation(d.tabId, d.url);
});

// ------------------------------------------------------------------ short links: where does it lead? (only when you ask)
// Right-click a short link > "Show where this short link leads". The app asks the shortening service
// (one request per short link, honest User-Agent, no cookies). Services that answer only browsers
// (a "checking your browser" page, as shorturl.at and is.gd show) are asked by this browser instead,
// in a background tab that may load nothing but the service itself and Cloudflare's check: every
// other request in that tab - the destination included - is blocked before it is sent, and the
// blocked address is the answer. The tab is then closed. Nothing is done to get past a check: if
// the service wants a person to confirm, the tab is shown to you.
const SHORT_SERVICES = new Set(URL_SHORTENERS);
const SHORT_PATTERNS = URL_SHORTENERS.map((d) => `*://*.${d}/*`);
const CHECK_HOSTS = ["challenges.cloudflare.com"];
const REVEAL_RULES = [9001, 9002];
const REVEAL_TYPES = ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest",
  "ping", "csp_report", "media", "websocket", "other"];
const REVEAL_SHOW_MS = 8000; // nothing yet: show the tab, the service may want a person to confirm
const REVEAL_GIVE_UP_MS = 120000;
const MAX_SHORT_STEPS = 4;
const reveals = new Map(); // tabId -> reveal in progress
let revealBusy = false;

export function shortLinkOf(raw) {
  let u;
  try {
    u = new URL(String(raw));
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || (u.port && !["80", "443"].includes(u.port))) return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  const service = splitDomain(host).registrable;
  if (!SHORT_SERVICES.has(service)) return null;
  return { url: `https://${host}${u.pathname}${u.search}`, host, service }; // the fragment never reaches the server
}

function hostIn(url, domains) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return domains.some((d) => h === d || h.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

// The answer: a request in the reveal tab to anywhere else (it is blocked, never sent).
function revealSaw(tabId, url) {
  const r = reveals.get(tabId);
  if (!r || typeof url !== "string" || hostIn(url, r.allowed) || url === "about:blank") return false;
  r.done({ destination: url });
  return true;
}

async function cleanUpReveal() {
  await ext.declarativeNetRequest?.updateSessionRules({ removeRuleIds: REVEAL_RULES }).catch(() => {});
  const { reveal } = await ext.storage.session?.get("reveal").catch(() => ({})) ?? {};
  if (reveal && typeof reveal.tabId === "number") await ext.tabs.remove(reveal.tabId).catch(() => {});
  await ext.storage.session?.remove("reveal").catch(() => {});
}
cleanUpReveal(); // after a browser or extension restart in the middle of one

async function findInBrowser(short, opener, onNeedsYou) {
  if (!ext.declarativeNetRequest?.updateSessionRules) throw new Error("This browser cannot block the destination safely, so the link was not opened.");
  const allowed = [short.service, ...CHECK_HOSTS];
  // The new tab's own about:blank load must finish first: committing late, it would cancel the short link's load.
  const loaded = new Set();
  const onCommitted = (d) => d.frameId === 0 && loaded.add(d.tabId);
  ext.webNavigation.onCommitted.addListener(onCommitted);
  let tab;
  try {
    tab = await ext.tabs.create({ url: "about:blank", active: false, ...(opener && opener.id >= 0 ? { windowId: opener.windowId, index: opener.index + 1 } : {}) });
    for (let i = 0; i < 60 && !loaded.has(tab.id); i++) await new Promise((r) => setTimeout(r, 50));
  } finally {
    ext.webNavigation.onCommitted.removeListener(onCommitted);
  }
  const r = { allowed, done: null };
  const answer = new Promise((resolve) => (r.done = resolve));
  reveals.set(tab.id, r);
  const timers = [];
  try {
    await ext.storage.session?.set({ reveal: { tabId: tab.id } }).catch(() => {});
    await ext.declarativeNetRequest.updateSessionRules({
      removeRuleIds: REVEAL_RULES,
      addRules: [
        { id: REVEAL_RULES[0], priority: 100, action: { type: "block" },
          condition: { tabIds: [tab.id], excludedRequestDomains: allowed, resourceTypes: REVEAL_TYPES } },
        // pop-ups and workers the service starts are not in the tab: block what it initiates, too
        { id: REVEAL_RULES[1], priority: 100, action: { type: "block" },
          condition: { initiatorDomains: [short.service], excludedRequestDomains: allowed, resourceTypes: REVEAL_TYPES } },
      ],
    });
    await ext.tabs.update(tab.id, { url: short.url });
    timers.push(setTimeout(() => {
      ext.tabs.update(tab.id, { active: true }).catch(() => {});
      onNeedsYou();
    }, REVEAL_SHOW_MS));
    timers.push(setTimeout(() => r.done({ reason: `${short.service} did not say where the link leads within two minutes` }), REVEAL_GIVE_UP_MS));
    timers.push(setInterval(() => ext.runtime.getPlatformInfo().catch(() => {}), 20000)); // keeps the worker awake
    return await answer;
  } finally {
    for (const t of timers) {
      clearTimeout(t);
      clearInterval(t);
    }
    reveals.delete(tab.id);
    await ext.declarativeNetRequest.updateSessionRules({ removeRuleIds: REVEAL_RULES }).catch(() => {});
    await ext.tabs.remove(tab.id).catch(() => {});
    await ext.storage.session?.remove("reveal").catch(() => {});
  }
}

async function checkDestination(first, steps, destination) {
  if (await connectNative()) {
    try {
      return (await nativeRequest({ type: "expand", url: first.url, steps: steps.map((s) => s.url), destination }, 20000)).report;
    } catch {
      /* checked in this browser below */
    }
  }
  const lists = await browserLists();
  let rep = await analyzer.analyze(destination, null, null, lists);
  if (wantsDns(rep, await browserDnsMode(), "")) {
    dns = dns || new DnsInvestigator();
    rep = await analyzer.analyze(destination, null, dns, lists);
  }
  return { ...slim(rep), short_link: { service: first.service, destination, reason: null, browser_needed: false, by: "browser" } };
}

export async function revealShortLink(raw, tab) {
  const first = shortLinkOf(raw);
  const tell = (msg) => {
    if (tab && tab.id >= 0) ext.tabs.sendMessage(tab.id, { type: "short-link", url: first?.url || String(raw).slice(0, 2048), ...msg }, { frameId: 0 }).catch(() => {});
    return msg;
  };
  if (!first) return tell({ state: "error", error: "This is not a link from a known link-shortening service." });
  if (revealBusy) return tell({ state: "error", error: "Still finding out where another short link leads. Try again in a moment." });
  revealBusy = true;
  tell({ state: "working", service: first.service });
  try {
    if (await connectNative()) {
      try {
        const rep = (await nativeRequest({ type: "expand", url: first.url }, 45000)).report;
        const s = rep?.short_link;
        if (s?.destination) return tell({ state: "done", service: first.service, destination: s.destination, by: "app", report: rep });
        if (s?.final) return tell({ state: "error", service: first.service, error: s.reason });
      } catch (e) {
        if (e.locked) return tell({ state: "error", service: first.service, error: e.message }); // switched off
        /* the app could not ask (a firewall, a proxy): this browser can */
      }
    }
    const steps = [first];
    let current = first;
    for (;;) {
      const found = await findInBrowser(current, tab, () => tell({ state: "needs-you", service: current.service }));
      if (!found.destination) return tell({ state: "error", service: current.service, error: found.reason });
      const next = shortLinkOf(found.destination);
      if (next && steps.length < MAX_SHORT_STEPS && !steps.some((s) => s.url === next.url)) {
        steps.push(next);
        current = next;
        continue;
      }
      const report = await checkDestination(first, steps, found.destination);
      return tell({ state: "done", service: first.service, destination: found.destination, by: "browser", report });
    }
  } catch (e) {
    return tell({ state: "error", service: first.service, error: String(e?.message || e).slice(0, 300) });
  } finally {
    revealBusy = false;
  }
}
globalThis.homographGuard = { revealShortLink, shortLinkOf, findInBrowser }; // for the tests

ext.webRequest.onBeforeRedirect.addListener((d) => {
  if (!revealSaw(d.tabId, d.redirectUrl)) guardNavigation(d.tabId, d.redirectUrl);
}, { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] });
ext.webRequest.onErrorOccurred.addListener((d) => {
  if (revealSaw(d.tabId, d.url)) return;
  const r = reveals.get(d.tabId);
  if (r && !/ABORTED/i.test(d.error || "")) { // the shortening service itself could not be reached
    r.done({ reason: `${new URL(d.url).hostname} could not be reached (${String(d.error || "network error").slice(0, 60)})` });
  }
}, { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] });
ext.webNavigation.onCreatedNavigationTarget.addListener((d) => {
  if (reveals.has(d.sourceTabId)) ext.tabs.remove(d.tabId).catch(() => {}); // no pop-ups from the service
});
ext.tabs.onRemoved.addListener((tabId) => {
  reveals.get(tabId)?.done({ reason: "the tab was closed before the service said where the link leads" });
});

// ------------------------------------------------------------------ on/off state, icon, badge
function iconPaths(on) {
  const v = on ? "on" : "off";
  return { 16: `icons/${v}-16.png`, 32: `icons/${v}-32.png`, 48: `icons/${v}-48.png`, 128: `icons/${v}-128.png` };
}
async function refreshIcon() {
  const on = await isEnabled();
  await ext.action.setIcon({ path: iconPaths(on) });
  await ext.action.setTitle({ title: on ? "Homograph Guard - on" : "Homograph Guard - off" });
  if (!on) await ext.action.setBadgeText({ text: "" });
}

ext.runtime.onInstalled.addListener(async () => {
  const { enabled } = await local("enabled");
  if (enabled === undefined) await ext.storage.local.set({ enabled: true });
  await ext.action.setBadgeBackgroundColor({ color: "#B42318" });
  await createMenus();
  await refreshIcon();
});
ext.runtime.onStartup.addListener(() => {
  createMenus().catch(() => {});
  refreshIcon();
});
ext.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && "enabled" in changes) refreshIcon();
});
