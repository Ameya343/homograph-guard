// Homograph Guard content script.
// Finds the links in what the user is focused on - the open email, the last day of the open chat,
// or the current page - including hidden ones and addresses written as plain text, sends them to the
// service worker for analysis, and marks the risky ones. Links are never fetched or opened from here.
(() => {
  if (window.__homographGuard) return;
  window.__homographGuard = true;
  const ext = globalThis.browser ?? globalThis.chrome; // Firefox: promise-based browser.*; Chrome/Edge: chrome.*

  const DAY_MS = 24 * 60 * 60 * 1000;
  const MAX_LINKS = 400; // checked per scan
  const MAX_COLLECT = 10000; // looked at per scan, to pick the 400 nearest the screen
  const MAX_TEXT_NODES = 4000;
  const RISKY = new Set(["high_risk", "suspicious"]);
  const FILEISH_TLDS = new Set("py md rs sh pl pm ps sc so zip mov gz ms cc".split(" "));
  const TEXT_URL = /(?<![@\p{L}\p{N}_.\-])(?:(?:h(?:tt|xx|\*\*)ps?|ftp)(?::\/\/|\[:\/\/\])[^\s<>"'`]+|www\d{0,3}(?:\.|\[\.\])[^\s<>"'`]+|(?:[\p{L}\p{N}_\-]{1,63}(?:\.|\[\.\]|\(\.\))){1,8}(?:xn--[a-z0-9\-]{2,59}|\p{L}{2,24})(?::\d{2,5})?(?:\/[^\s<>"'`]*)?)/giu;
  const TRAILING = ".,;:!?'\")]}>*";

  const state = {
    enabled: false,
    port: null,
    entries: new Map(), // key -> entry
    byId: new Map(),
    elToEntry: new WeakMap(),
    decorated: new Set(),
    live: new Set(), // keys seen in the latest scan
    seq: 0,
    observer: null,
    timer: null,
    poll: null,
    href: location.href,
    focusLabel: "",
    ui: null,
    minimized: false,
    dismissedAt: -1,
    bypass: null,
    short: null, // the last "Show where this short link leads" answer
    shortTimer: null,
  };

  // ------------------------------------------------------------------ what is in focus
  const q = (sel, root = document) => root.querySelector(sel);
  const qa = (sel, root = document) => [...root.querySelectorAll(sel)];
  const shown = (el) => el && el.getClientRects().length > 0;

  function recentRows(container, rowSelector, timeOf) {
    if (!container) return [];
    const rows = qa(rowSelector, container);
    if (!rows.length) return [];
    const stamps = rows.map(timeOf);
    if (!stamps.some((t) => t)) return rows.slice(-50); // no timestamps: the latest 50 messages
    const now = Date.now();
    let last = null;
    return rows.filter((row, i) => {
      if (stamps[i]) last = stamps[i];
      return last !== null && now - last <= DAY_MS && last - now <= DAY_MS;
    });
  }

  const isoTime = (sel) => (row) => {
    const t = q(sel, row)?.getAttribute("datetime");
    const ms = t ? Date.parse(t) : NaN;
    return Number.isNaN(ms) ? null : ms;
  };

  function whatsappTime(row) {
    // data-pre-plain-text="[10:15, 11/13/2026] Name: " (date order and clock style follow the locale)
    const raw = q("[data-pre-plain-text]", row)?.getAttribute("data-pre-plain-text") || "";
    const m = /\[(\d{1,2})[:.](\d{2})(?:\s*([ap])\.?\s*m\.?)?,\s*(\d{1,4})[./-](\d{1,2})[./-](\d{1,4})\]/i.exec(raw);
    if (!m) return null;
    let [, hh, mm, ampm, a, b, c] = m;
    let h = Number(hh);
    if (ampm) h = (h % 12) + (ampm.toLowerCase() === "p" ? 12 : 0);
    const candidates = [];
    const year = (y) => (y.length <= 2 ? 2000 + Number(y) : Number(y));
    if (a.length === 4) candidates.push([Number(a), Number(b), Number(c)]);
    else candidates.push([year(c), Number(a), Number(b)], [year(c), Number(b), Number(a)]); // m/d and d/m
    const now = Date.now();
    const times = candidates.filter(([, mo, d]) => mo >= 1 && mo <= 12 && d >= 1 && d <= 31)
      .map(([y, mo, d]) => new Date(y, mo - 1, d, h, Number(mm)).getTime())
      .filter((t) => t <= now + DAY_MS);
    return times.length ? Math.max(...times) : null;
  }

  function telegramRows() {
    const webk = qa(".bubbles .bubble[data-timestamp]");
    if (webk.length) {
      return recentRows(q(".bubbles"), ".bubble[data-timestamp]", (r) => Number(r.dataset.timestamp) * 1000 || null);
    }
    // Telegram Web A groups messages by day under a "Today" / "Yesterday" / date header.
    const groups = qa(".messages-container .message-date-group");
    const recent = groups.filter((g) => /^(today|yesterday)$/i.test((q(".sticky-date, .message-date-group-title", g)?.textContent || "").trim()));
    return (recent.length ? recent : groups.slice(-1)).flatMap((g) => qa(".Message", g));
  }

  const ADAPTERS = [
    {
      name: "Gmail", scope: "this email", medium: "email", test: (h) => h === "mail.google.com",
      focus() {
        const main = q('[role="main"]');
        if (!main) return { roots: [] };
        const roots = qa("div.a3s", main).filter(shown); // bodies of the messages that are open
        const extras = roots.length ? qa("span.gD[email]", main).map((s) => {
          const email = s.getAttribute("email"), name = s.getAttribute("name") || s.textContent.trim();
          return { url: name && name !== email ? `${name} <${email}>` : email, ctx: { source: "header", where: "sender" }, el: s };
        }) : [];
        return { roots, extras };
      },
    },
    {
      name: "Outlook", scope: "this email", medium: "email",
      test: (h) => /^outlook\.(live|office|office365)\.com$/.test(h) || h === "outlook.cloud.microsoft",
      focus: () => ({ roots: qa('[aria-label="Message body"], div[role="document"].allowTextSelection').filter(shown) }),
    },
    {
      name: "Yahoo Mail", scope: "this email", medium: "email", test: (h) => h === "mail.yahoo.com",
      focus: () => ({ roots: qa('[data-test-id="message-view-body-content"]').filter(shown) }),
    },
    {
      name: "Discord", scope: "this chat (last 24 h)", test: (h) => h === "discord.com" || h.endsWith(".discord.com"),
      focus: () => ({ roots: recentRows(q('[data-list-id="chat-messages"]'), 'li[id^="chat-messages-"]', isoTime("time[datetime]")) }),
    },
    {
      name: "WhatsApp", scope: "this chat (last 24 h)", test: (h) => h === "web.whatsapp.com",
      focus: () => ({ roots: recentRows(q("#main"), 'div[role="row"]', whatsappTime) }),
    },
    {
      name: "Telegram", scope: "this chat (last 24 h)", test: (h) => h === "web.telegram.org",
      focus: () => ({ roots: telegramRows() }),
    },
    {
      name: "Slack", scope: "this channel (last 24 h)", test: (h) => h === "app.slack.com",
      focus: () => ({ roots: recentRows(q('[data-qa="message_pane"], .p-message_pane, [role="main"]'),
        '[data-qa="virtual-list-item"], [data-qa="message_container"]',
        (r) => Number(q("[data-ts]", r)?.getAttribute("data-ts")) * 1000 || null) }),
    },
    {
      name: "Teams", scope: "this chat (last 24 h)", test: (h) => /^teams\.(microsoft|live)\.com$/.test(h) || h === "teams.cloud.microsoft",
      focus: () => ({ roots: recentRows(q('[data-tid="message-pane-list-viewport"], #chat-pane-list, [role="main"]'),
        '[data-tid="chat-pane-item"], [data-tid="chat-pane-message"]', isoTime("time[datetime]")) }),
    },
    {
      name: "Messenger", scope: "this chat", test: (h) => h === "www.messenger.com" || (h === "www.facebook.com" && location.pathname.startsWith("/messages")),
      focus: () => ({ roots: [q('[role="main"]')].filter(Boolean) }),
    },
  ];

  function currentFocus() {
    const host = location.hostname;
    const adapter = ADAPTERS.find((a) => a.test(host));
    if (!adapter) return { roots: document.body ? [document.body] : [], extras: [], scope: "this page", page: true, medium: "page" };
    let f;
    try {
      f = adapter.focus();
    } catch {
      f = { roots: [] };
    }
    return { roots: f.roots || [], extras: f.extras || [], scope: adapter.scope, page: false, app: adapter.name, medium: adapter.medium || "chat" };
  }

  // ------------------------------------------------------------------ link collection
  function absolute(raw) {
    raw = (raw || "").trim();
    if (!raw || raw.startsWith("#")) return null;
    if (/^[a-z][a-z0-9+.\-]*:/i.test(raw)) return raw; // keep the raw text: tricks live in it
    if (raw.startsWith("//")) return location.protocol + raw;
    return null; // relative links stay on the same site
  }

  function linkText(a) {
    let t = (a.innerText || a.textContent || "").replace(/\s+/g, " ").trim();
    if (!t) t = q("img[alt]", a)?.getAttribute("alt") || a.getAttribute("aria-label") || a.getAttribute("title") || "";
    return t.slice(0, 300);
  }

  function styleReason(el) {
    for (let n = el, depth = 0; n && n.nodeType === 1 && depth < 40; n = n.parentElement, depth++) {
      if (n.hasAttribute("hidden")) return "hidden attribute";
      const s = getComputedStyle(n);
      if (s.display === "none") return "display:none";
      if (s.visibility === "hidden" || s.visibility === "collapse") return "visibility:hidden";
      if (Number(s.opacity) < 0.05) return "opacity:0";
      if (s.contentVisibility === "hidden") return "content-visibility:hidden";
    }
    return null;
  }

  function hiddenReason(el) {
    if (!el || el.nodeType !== 1) return null;
    const opts = { opacityProperty: true, visibilityProperty: true, checkOpacity: true, checkVisibilityCSS: true };
    if (typeof el.checkVisibility === "function" && !el.checkVisibility(opts)) {
      return styleReason(el) || "not displayed";
    }
    if (!el.getClientRects().length) return styleReason(el) || "not displayed";
    const s = getComputedStyle(el);
    const hasImage = Boolean(q("img, svg", el));
    if (!hasImage && parseFloat(s.fontSize) < 1) return "font-size:0";
    if (!hasImage && /rgba\(\s*\d+,\s*\d+,\s*\d+,\s*0\s*\)|transparent/.test(s.color)) return "transparent text";
    const r = el.getBoundingClientRect();
    if (r.right + scrollX < -200 || r.bottom + scrollY < -200) return "moved off-screen";
    if (r.width * r.height < 2 && (el.textContent || "").trim()) return "zero size";
    if (/inset\(\s*50%/.test(s.clipPath) || /rect\(\s*0/.test(s.clip)) return "clipped away";
    return null;
  }

  function refang(s) {
    let out = s.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".").replace(/\[:\/\/\]/g, "://").replace(/\[:\]/g, ":");
    if (/^h(xx|\*\*)p/i.test(out)) out = "http" + out.slice(4);
    return out;
  }

  function textUrls(root, add, where) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const p = node.parentElement;
        if (!p || p.isContentEditable || p.closest("a, script, style, noscript, textarea, input, hg-guard-ui")) return NodeFilter.FILTER_REJECT;
        return /[.\[]/.test(node.data) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
      },
    });
    let count = 0;
    for (let node = walker.nextNode(); node && count < MAX_TEXT_NODES; node = walker.nextNode(), count++) {
      TEXT_URL.lastIndex = 0;
      let m;
      while ((m = TEXT_URL.exec(node.data))) {
        let text = m[0];
        while (text && TRAILING.includes(text[text.length - 1])) {
          if (text.endsWith(")") && (text.match(/\(/g) || []).length >= (text.match(/\)/g) || []).length) break;
          text = text.slice(0, -1);
        }
        if (!text) continue;
        const url = refang(text);
        const bare = !url.includes("://") && !/^www/i.test(url);
        if (bare) {
          const host = url.split(/[/:]/)[0];
          if (FILEISH_TLDS.has(host.split(".").pop().toLowerCase())) continue;
        }
        const range = document.createRange();
        range.setStart(node, m.index);
        range.setEnd(node, m.index + text.length);
        add(url, { source: "text", hidden: hiddenReason(node.parentElement), where }, null, range, bare);
      }
    }
  }

  // A website's own javascript:/data: links (buttons, "Print") are part of the page, which runs its own code
  // anyway. They are only dangerous in content other people send: emails and chat messages.
  const PAGE_SCRIPT_LINK = /^[\s\x00-\x20]*(?:javascript|vbscript|data|blob|about):/i;

  function collect(focus) {
    const found = [];
    const seen = new Set();
    const where = focus.page ? "this page" : focus.app;
    const add = (url, ctx, el, range = null, bare = false) => {
      if (found.length >= MAX_COLLECT) return;
      if (focus.page && PAGE_SCRIPT_LINK.test(url.replace(/[\t\n\r]/g, ""))) return;
      const clean = Object.fromEntries(Object.entries({ ...ctx, medium: focus.medium }).filter(([, v]) => v));
      found.push({ url, ctx: clean, el, range, bare });
    };
    for (const root of focus.roots) {
      if (!root || !root.querySelectorAll) continue;
      const anchors = [...(root.matches?.("a[href], area[href]") ? [root] : []), ...qa("a[href], area[href]", root)];
      for (const a of anchors) {
        if (seen.has(a)) continue;
        seen.add(a);
        if (a.isContentEditable) continue; // a draft or an editor: the user's own text is never marked or intercepted
        const url = absolute(a.getAttribute("href"));
        if (!url) continue;
        add(url, { source: a.localName === "area" ? "area" : "anchor", text: linkText(a), hidden: hiddenReason(a), where }, a);
      }
      for (const a of qa("a", root)) { // SVG links
        if (seen.has(a) || a.isContentEditable) continue;
        const x = a.getAttributeNS("http://www.w3.org/1999/xlink", "href") || a.getAttribute("xlink:href");
        const url = absolute(x);
        if (url) {
          seen.add(a);
          add(url, { source: "anchor", text: linkText(a), hidden: hiddenReason(a), where }, a);
        }
      }
      for (const el of qa("[data-href], [data-url], [data-link]", root)) {
        if (el.isContentEditable) continue;
        const url = absolute(el.getAttribute("data-href") || el.getAttribute("data-url") || el.getAttribute("data-link"));
        if (url) add(url, { source: "attribute", hidden: hiddenReason(el), where }, el);
      }
      if (focus.page) {
        for (const f of qa("form[action]", root)) {
          const url = absolute(f.getAttribute("action"));
          if (url) add(url, { source: "form", hidden: hiddenReason(f), where }, f);
        }
        for (const f of qa("iframe[src], frame[src], embed[src], object[data]", root)) {
          const url = absolute(f.getAttribute("src") || f.getAttribute("data"));
          if (url) add(url, { source: f.localName === "object" ? "object" : f.localName, hidden: hiddenReason(f), where }, f);
        }
      }
      textUrls(root, add, where);
    }
    if (focus.page) {
      for (const m of qa('meta[http-equiv="refresh" i]')) {
        const u = /url\s*=\s*['"]?([^'";]+)/i.exec(m.getAttribute("content") || "");
        const url = u && absolute(u[1]);
        if (url) add(url, { source: "meta-refresh", hidden: "automatic redirect", where }, null);
      }
    }
    for (const x of focus.extras || []) add(x.url, x.ctx, x.el);
    state.truncated = found.length > MAX_LINKS;
    return state.truncated ? nearest(found, MAX_LINKS) : found;
  }

  // A long page: check the links nearest to what is on screen (scrolling brings the next ones in),
  // so the work per scan stays bounded however long the page is.
  function nearest(found, n) {
    const top = 0, bottom = innerHeight;
    const distance = (f) => {
      const box = f.el?.getBoundingClientRect?.() || f.range?.getBoundingClientRect?.();
      if (!box) return 0; // a redirect in the page head, the sender of an email: always checked
      if (!box.width && !box.height) return 1e9 - 1; // hidden: after everything that is shown
      return box.bottom < top ? top - box.bottom : box.top > bottom ? box.top - bottom : 0;
    };
    return found.map((f, i) => [distance(f), i, f]).sort((a, b) => a[0] - b[0] || a[1] - b[1]).slice(0, n).map((x) => x[2]);
  }

  // ------------------------------------------------------------------ scanning
  function connect() {
    if (state.port) return state.port;
    try {
      state.port = chrome.runtime.connect({ name: "hg-scan" });
    } catch {
      return null; // extension was reloaded; this old content script is orphaned
    }
    state.port.onMessage.addListener(onResult);
    state.port.onDisconnect.addListener(() => {
      state.port = null;
      for (const e of state.entries.values()) if (!e.final) e.sent = false; // resend after reconnect
    });
    return state.port;
  }

  function resetForNavigation() {
    state.href = location.href;
    state.live.clear();
    state.dismissedAt = -1;
  }

  function scan() {
    state.timer = null;
    state.pendingSince = 0;
    if (!state.enabled || document.visibilityState !== "visible") return;
    if (location.href !== state.href) resetForNavigation();
    const focus = currentFocus();
    state.focusLabel = focus.scope;
    const found = collect(focus);
    const live = new Set();
    for (const e of state.entries.values()) {
      e.els = new Set();
      e.ranges = [];
    }
    const batch = [];
    for (const f of found) {
      const key = `${f.url}\u0000${JSON.stringify(f.ctx)}`;
      let e = state.entries.get(key);
      if (!e) {
        e = { id: `l${++state.seq}`, key, url: f.url, ctx: f.ctx, bare: f.bare, els: new Set(), ranges: [], report: null, final: false, sent: false, ignore: false };
        state.entries.set(key, e);
        state.byId.set(e.id, e);
      }
      if (f.el) {
        e.els.add(f.el);
        state.elToEntry.set(f.el, e);
      }
      if (f.range) e.ranges.push(f.range);
      live.add(key);
      if (!e.sent) {
        e.sent = true;
        batch.push({ id: e.id, url: e.url, ctx: e.ctx, bare: e.bare });
      }
    }
    state.live = live;
    if (state.entries.size > 3000) { // forget links from conversations the user has left
      for (const [key, e] of state.entries) {
        if (!live.has(key)) {
          state.entries.delete(key);
          state.byId.delete(e.id);
        }
      }
    }
    if (batch.length) {
      const port = connect();
      if (port) {
        try {
          port.postMessage({ type: "check", page: location.hostname, links: batch });
        } catch {
          state.port = null;
        }
      }
    }
    render();
  }

  // Wait for the page to settle (600 ms without changes), but on pages that never settle (a ticking
  // clock, a busy chat) scan at least every 3 seconds instead of postponing forever.
  function scheduleScan(delay = 600) {
    const now = Date.now();
    if (!state.pendingSince) state.pendingSince = now;
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(scan, Math.max(0, Math.min(delay, state.pendingSince + 3000 - now)));
  }

  function onResult(msg) {
    if (msg?.type !== "result") return;
    const e = state.byId.get(msg.id);
    if (!e) return;
    if (msg.ignore) e.ignore = true;
    if (msg.report) e.report = msg.report;
    if (msg.final || msg.error) e.final = true;
    scheduleRender();
  }

  let renderTimer = null;
  function scheduleRender() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => {
      renderTimer = null;
      render();
    }, 120);
  }

  const isRisky = (e) => e && !e.ignore && e.report && RISKY.has(e.report.verdict);

  function liveEntries() {
    return [...state.live].map((k) => state.entries.get(k)).filter(Boolean);
  }

  // ------------------------------------------------------------------ decorations
  function render() {
    if (!state.enabled) return;
    const risky = liveEntries().filter(isRisky);
    const want = new Map();
    for (const e of risky) for (const el of e.els) want.set(el, e.report.verdict);
    for (const el of state.decorated) {
      if (!want.has(el)) {
        el.removeAttribute("data-hg-verdict");
        state.decorated.delete(el);
      }
    }
    for (const [el, verdict] of want) {
      if (el.getAttribute("data-hg-verdict") !== verdict) el.setAttribute("data-hg-verdict", verdict);
      state.decorated.add(el);
    }
    if (globalThis.CSS?.highlights && typeof Highlight === "function") {
      for (const v of RISKY) {
        const ranges = risky.filter((e) => e.report.verdict === v).flatMap((e) => e.ranges);
        if (ranges.length) CSS.highlights.set(`hg-${v}`, new Highlight(...ranges));
        else CSS.highlights.delete(`hg-${v}`);
      }
    }
    renderPanel(risky);
    send({ type: "count", n: risky.length, high: risky.some((e) => e.report.verdict === "high_risk") });
  }

  function clearDecorations() {
    for (const el of state.decorated) el.removeAttribute("data-hg-verdict");
    state.decorated.clear();
    if (globalThis.CSS?.highlights) for (const v of RISKY) CSS.highlights.delete(`hg-${v}`);
  }

  // ------------------------------------------------------------------ UI (closed shadow root, page CSS cannot reach it)
  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .wrap { --bg:#ffffff; --fg:#17212b; --muted:#56626f; --rule:#dbe1e8; --chip:#f2f4f7; --high:#b42318; --high-bg:#fef3f2;
      --sus:#b54708; --sus-bg:#fffaeb; --ok:#067647; --ok-bg:#ecfdf3; --btn:#17212b; --btn-fg:#fff; --shadow:0 12px 32px rgba(16,24,40,.18), 0 2px 6px rgba(16,24,40,.08);
      font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--fg); }
    @media (prefers-color-scheme: dark) { .wrap { --bg:#1b2129; --fg:#e8edf2; --muted:#a2adb9; --rule:#33404d; --chip:#26303b;
      --high:#ff8a7a; --high-bg:#3a1d1a; --sus:#ffb35c; --sus-bg:#3a2a12; --ok:#75e0a7; --ok-bg:#0f2e1f; --btn:#e8edf2; --btn-fg:#17212b; --shadow:0 12px 32px rgba(0,0,0,.5); } }
    .panel { position: fixed; right: 16px; bottom: 16px; width: min(380px, calc(100vw - 32px)); max-height: min(60vh, 520px);
      display: flex; flex-direction: column; background: var(--bg); border: 1px solid var(--rule); border-radius: 12px;
      box-shadow: var(--shadow); overflow: hidden; animation: rise .22s ease-out; }
    @keyframes rise { from { transform: translateY(8px); opacity: 0; } to { transform: none; opacity: 1; } }
    header { display: flex; align-items: center; gap: 8px; padding: 10px 10px 10px 14px; border-bottom: 1px solid var(--rule); }
    header .title { font-weight: 650; flex: 1; min-width: 0; }
    header .title small { display: block; font-weight: 400; color: var(--muted); font-size: 12px; }
    .icon-btn { all: unset; cursor: pointer; width: 28px; height: 28px; display: grid; place-items: center; border-radius: 6px; color: var(--muted); font-size: 16px; }
    .icon-btn:hover, .icon-btn:focus-visible { background: var(--chip); color: var(--fg); outline: none; }
    ul { list-style: none; margin: 0; padding: 4px 0; overflow: auto; }
    li { padding: 10px 14px; border-bottom: 1px solid var(--rule); }
    li:last-child { border-bottom: 0; }
    .row { display: flex; gap: 8px; align-items: baseline; }
    .pill { flex: none; font-size: 11px; font-weight: 700; letter-spacing: .02em; padding: 1px 7px; border-radius: 999px; }
    .pill.high_risk { color: var(--high); background: var(--high-bg); }
    .pill.suspicious { color: var(--sus); background: var(--sus-bg); }
    .pill.caution { color: var(--sus); background: var(--chip); }
    .pill.no_indicators { color: var(--ok); background: var(--ok-bg); }
    .pill.error { color: var(--muted); background: var(--chip); }
    .card { position: fixed; top: 16px; right: 16px; width: min(400px, calc(100vw - 32px)); background: var(--bg);
      border: 1px solid var(--rule); border-radius: 12px; box-shadow: var(--shadow); overflow: hidden; animation: rise .22s ease-out; }
    .card-body { padding: 12px 14px 14px; }
    .card .dest { margin: 0 0 10px; padding: 8px 10px; border-radius: 8px; background: var(--chip); }
    .card ol { margin: 8px 0 0; padding-left: 18px; }
    .card ol li { border: 0; padding: 2px 0; }
    .card .actions { margin-top: 12px; }
    .url { font: 12px/1.4 ui-monospace, "Cascadia Mono", Consolas, monospace; overflow-wrap: anywhere; }
    .why { color: var(--muted); margin-top: 3px; }
    .tags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
    .tag { font-size: 11px; padding: 1px 6px; border-radius: 4px; background: var(--chip); color: var(--muted); }
    .show { all: unset; cursor: pointer; font-size: 12px; font-weight: 600; margin-top: 6px; color: var(--fg); text-decoration: underline; text-underline-offset: 2px; }
    footer { padding: 8px 14px; font-size: 11.5px; color: var(--muted); border-top: 1px solid var(--rule); }
    .pillbtn { all: unset; position: fixed; right: 16px; bottom: 16px; cursor: pointer; padding: 8px 14px; border-radius: 999px;
      background: var(--high); color: #fff; font-weight: 650; box-shadow: var(--shadow); font-size: 13px; }
    .pillbtn.suspicious { background: var(--sus); }
    .tip { position: fixed; z-index: 2; max-width: 340px; padding: 8px 10px; border-radius: 8px; background: var(--bg); color: var(--fg);
      border: 1px solid var(--rule); box-shadow: var(--shadow); pointer-events: none; }
    dialog.hg-dialog { border: 0; padding: 0; margin: auto; background: transparent; color: inherit; max-width: calc(100vw - 32px);
      max-height: calc(100vh - 32px); overflow: visible; font: inherit; animation: fade .15s ease-out; }
    dialog.hg-dialog::backdrop { background: rgba(16,24,40,.45); }
    @keyframes fade { from { opacity: 0; } }
    .dialog { width: min(500px, calc(100vw - 32px)); background: var(--bg); color: var(--fg); border-radius: 14px; box-shadow: var(--shadow); padding: 20px; }
    .actions .minor { display: flex; gap: 14px; flex-wrap: wrap; flex: 1; align-items: center; }
    .actions .major { display: flex; gap: 8px; }
    .link-btn { all: unset; cursor: pointer; font-size: 12.5px; color: var(--muted); text-decoration: underline; text-underline-offset: 2px; }
    .link-btn:focus-visible { outline: 2px solid var(--fg); outline-offset: 2px; }
    .link-btn[disabled] { cursor: default; text-decoration: none; }
    .dialog h2 { margin: 0 0 4px; font-size: 18px; color: var(--high); }
    .dialog h2.suspicious { color: var(--sus); }
    .dialog .dest { margin: 12px 0; padding: 10px; border-radius: 8px; background: var(--chip); }
    .dialog ol { margin: 8px 0 0; padding-left: 18px; }
    .dialog ol li { border: 0; padding: 2px 0; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 18px; flex-wrap: wrap; }
    .btn { all: unset; cursor: pointer; padding: 8px 14px; border-radius: 8px; font-weight: 600; }
    .btn.primary { background: var(--btn); color: var(--btn-fg); }
    .btn.ghost { color: var(--muted); }
    .btn:focus-visible { outline: 2px solid var(--fg); outline-offset: 2px; }
    @media (prefers-reduced-motion: reduce) { .panel, .card, dialog.hg-dialog { animation: none; } }
  `;

  function ensureUi() {
    if (state.ui && state.ui.host.isConnected) return state.ui;
    state.ui = null; // the page removed our element: build it again
    const host = document.createElement("hg-guard-ui");
    host.style.cssText = "all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    const wrap = document.createElement("div");
    wrap.className = "wrap";
    root.append(style, wrap);
    (document.body || document.documentElement).appendChild(host);
    state.ui = { host, root, wrap, panel: null, tip: null, modal: null };
    return state.ui;
  }

  const h = (tag, attrs = {}, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid); // text is never parsed as HTML
    return el;
  };

  const label = (v) => (v === "high_risk" ? "High risk" : "Suspicious");
  const VERDICT_NAMES = { high_risk: "High risk", suspicious: "Suspicious", caution: "Caution", no_indicators: "No warnings", error: "Not checked" };
  // Attacker-controlled strings are shown without bidi/invisible controls.
  const safe = (s, n = 200) => String(s ?? "").replace(/[\u0000-\u001f\u007f-\u009f­؜​-‏‪-‮⁠-⁩﻿]/g, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}>`).slice(0, n);

  function tagsFor(e) {
    const r = e.report, tags = [];
    const codes = new Set(r.findings.map((f) => f.code));
    if (codes.has("LIST_BLOCKED")) tags.push("on your blocklist");
    if (codes.has("LIST_REPORTED")) tags.push("you reported it");
    for (const f of r.findings) if (f.code === "FEED_LISTED") tags.push(f.title.replace(/^Listed by /, "listed by ").replace(/ \(.*\)$/, ""));
    if (e.ctx.hidden) tags.push(`hidden: ${e.ctx.hidden}`);
    const mismatch = r.findings.find((f) => f.code === "LINK_TEXT_MISMATCH");
    if (mismatch) tags.push(`text shows ${mismatch.title.replace(/^Link text shows (\S+).*/, "$1")}`);
    for (const hop of r.wrapped?.hops || []) tags.push(hop.trusted ? hop.service : `${hop.service} (unverified)`);
    for (const res of r.dns?.resolvers || []) if (res.blocked) tags.push(`blocked by ${res.name.split(" (")[0]}`);
    if (e.ctx.source === "text") tags.push("written as text");
    if (e.ctx.source === "header") tags.push("sender");
    if (!e.final) tags.push("checking…");
    return tags;
  }

  function reveal(e) {
    const el = [...e.els].find((x) => x.isConnected && x.getClientRects().length) || e.ranges.find((r) => r.startContainer.isConnected)?.startContainer.parentElement;
    if (!el) return false;
    el.scrollIntoView({ block: "center", behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    el.setAttribute("data-hg-flash", "");
    setTimeout(() => el.removeAttribute("data-hg-flash"), 2600);
    return true;
  }

  function renderPanel(risky) {
    const ui = state.ui;
    if (!risky.length) {
      if (ui?.panel) {
        ui.panel.remove();
        ui.panel = null;
      }
      return;
    }
    if (state.dismissedAt >= risky.length) return;
    const u = ensureUi();
    if (u.panel) u.panel.remove();
    const anyHigh = risky.some((e) => e.report.verdict === "high_risk");
    const n = risky.length;
    if (state.minimized) {
      u.panel = h("button", { class: `pillbtn ${anyHigh ? "" : "suspicious"}`, title: "Show the risky links",
        onclick: () => { state.minimized = false; render(); } }, `⚠ ${n} risky link${n === 1 ? "" : "s"}`);
      u.wrap.append(u.panel);
      return;
    }
    const order = { high_risk: 0, suspicious: 1 };
    const items = [...risky].sort((a, b) => order[a.report.verdict] - order[b.report.verdict] || b.report.score - a.report.score).map((e) => {
      const r = e.report;
      const canShow = [...e.els].some((x) => x.isConnected && x.getClientRects().length) || e.ranges.length;
      return h("li", {},
        h("div", { class: "row" }, h("span", { class: `pill ${r.verdict}` }, label(r.verdict)),
          h("span", { class: "url" }, safe(r.defanged || r.input, 160))),
        h("div", { class: "why" }, safe(r.summary, 220)),
        h("div", { class: "tags" }, tagsFor(e).map((t) => h("span", { class: "tag" }, safe(t, 80)))),
        canShow ? h("button", { class: "show", onclick: () => reveal(e) }, state.focusLabel === "this page" ? "Show on the page" : "Show in the message") : null);
    });
    const pending = risky.some((e) => !e.final);
    const onDevice = risky.some((e) => e.report.checked_on === "device");
    const usedDns = risky.some((e) => e.report.dns);
    const footer = pending ? "Checking…"
      : `Checked ${onDevice ? "on this device (threat database and your lists)" : "in this browser"}${usedDns ? " and with Google, Cloudflare and AdGuard DNS" : ""}. Nothing was opened.`;
    u.panel = h("section", { class: "panel", role: "region", "aria-label": "Homograph Guard warnings" },
      h("header", {},
        h("div", { class: "title" }, `${n} risky link${n === 1 ? "" : "s"}`, h("small", {}, `${state.focusLabel === "this page" ? "on" : "in"} ${state.focusLabel}`)),
        h("button", { class: "icon-btn", title: "Minimise", "aria-label": "Minimise", onclick: () => { state.minimized = true; render(); } }, "–"),
        h("button", { class: "icon-btn", title: "Dismiss", "aria-label": "Dismiss", onclick: () => { state.dismissedAt = n; u.panel?.remove(); u.panel = null; } }, "×")),
      h("ul", {}, items),
      h("footer", {}, footer));
    u.wrap.append(u.panel);
  }

  function showTip(e, el) {
    const u = ensureUi();
    hideTip();
    const r = e.report;
    const rect = el.getBoundingClientRect();
    const dest = r.wrapped?.destination && r.wrapped.hops?.length ? `Real destination: ${safe(r.defanged || r.wrapped.destination, 140)}` : safe(r.defanged || "", 140);
    u.tip = h("div", { class: "tip", role: "tooltip" },
      h("div", { class: "row" }, h("span", { class: `pill ${r.verdict}` }, label(r.verdict)), h("strong", {}, safe(r.summary, 140))),
      h("div", { class: "why url" }, dest));
    u.wrap.append(u.tip);
    const tw = Math.min(340, innerWidth - 16);
    u.tip.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - tw - 8))}px`;
    const below = rect.bottom + 8, height = u.tip.offsetHeight;
    u.tip.style.top = `${below + height < innerHeight ? below : Math.max(8, rect.top - height - 8)}px`;
  }

  function hideTip() {
    if (state.ui?.tip) {
      state.ui.tip.remove();
      state.ui.tip = null;
    }
  }

  function send(msg) {
    try {
      return Promise.resolve(ext.runtime.sendMessage(msg)).catch(() => null);
    } catch {
      return Promise.resolve(null); // the extension was reloaded
    }
  }

  const VISIBILITY_V2 = typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;

  function showModal(e, anchor) {
    const u = ensureUi();
    if (u.modal) {
      u.modal.close?.();
      u.modal.remove();
    }
    const r = e.report;
    const href = anchor.href || e.url;
    const scheme = (href.split(":")[0] || "").toLowerCase();
    const openable = ["http", "https", "mailto"].includes(scheme);
    const site = r.url?.registrable || r.url?.host_ascii || "";
    // Anti-clickjacking: buttons that weaken protection react only to real clicks, after the dialog has been
    // on screen for a moment, and - where the browser can tell - while nothing on the page covers it.
    const shownAt = performance.now();
    let unobstructed = !VISIBILITY_V2;
    let io = null;
    const guarded = (fn) => (ev) => {
      if (!ev.isTrusted || performance.now() - shownAt < 700 || !unobstructed) return;
      fn(ev);
    };
    const dialog = h("dialog", { class: "hg-dialog", "aria-labelledby": "hg-t" });
    const close = () => {
      io?.disconnect();
      if (dialog.open) dialog.close();
      dialog.remove();
      if (u.modal === dialog) u.modal = null;
      anchor.focus?.();
    };
    const reasons = r.findings.filter((f) => f.weight > 0).slice(0, 4).map((f) => h("li", {}, safe(f.title, 160)));
    const back = h("button", { class: "btn primary", onclick: close }, "Go back");
    const anyway = openable ? h("button", { class: "btn ghost", onclick: guarded(() => {
      close();
      send({ type: "user-action", action: "open", url: href });
    }) }, "Open anyway") : null;
    const reportBtn = /^https?$/.test(scheme) ? h("button", { class: "link-btn", onclick: guarded(async () => {
      reportBtn.disabled = true;
      reportBtn.textContent = "Reporting…";
      const res = await send({ type: "user-action", action: "report", url: href });
      reportBtn.textContent = res?.ok ? "Reported - it stays blocked on this device" : "Could not report";
    }) }, "Report as phishing") : null;
    let armed = false;
    const trustBtn = /^https?$/.test(scheme) && site ? h("button", { class: "link-btn", onclick: guarded(async () => {
      if (!armed) {
        armed = true;
        trustBtn.textContent = `Click again to always trust ${safe(site, 80)}`;
        return;
      }
      trustBtn.disabled = true;
      const res = await send({ type: "user-action", action: "trust", url: href });
      if (res?.ok) close();
      else trustBtn.textContent = safe(res?.error || "Could not add it to your allowlist", 120);
    }) }, "I trust this site") : null;
    dialog.append(h("div", { class: "dialog", role: "alertdialog" },
      h("h2", { id: "hg-t", class: r.verdict }, r.verdict === "high_risk" ? "This link looks like phishing" : "This link looks suspicious"),
      h("div", {}, safe(r.summary, 240)),
      h("div", { class: "dest url" }, `Goes to: ${safe(r.defanged || r.input, 300)}`),
      reasons.length ? h("ol", {}, reasons) : null,
      h("div", { class: "actions" }, h("div", { class: "minor" }, reportBtn, trustBtn), h("div", { class: "major" }, anyway, back))));
    dialog.addEventListener("cancel", (ev) => {
      ev.preventDefault();
      close();
    });
    dialog.addEventListener("click", (ev) => {
      if (ev.target === dialog) close(); // click on the backdrop
    });
    u.modal = dialog;
    u.wrap.append(dialog);
    dialog.showModal(); // the top layer: page content cannot be placed above it
    if (VISIBILITY_V2) {
      io = new IntersectionObserver((entries) => {
        for (const en of entries) unobstructed = en.isVisible;
      }, { trackVisibility: true, delay: 100 });
      io.observe(dialog.firstElementChild);
    }
    back.focus();
  }

  // ------------------------------------------------------------------ "Show where this short link leads"
  function showShortCard(msg) {
    const u = ensureUi();
    const r = msg.report || null;
    state.short = { state: msg.state, url: msg.url || null, destination: msg.destination || null, by: msg.by || null,
      verdict: r?.verdict || null, summary: r?.summary || null, error: msg.error || null };
    clearTimeout(state.shortTimer);
    if (msg.state === "working" || msg.state === "needs-you") {
      state.shortTimer = setTimeout(() => showShortCard({ ...msg, state: "error", report: null,
        error: "No answer came back, so where this short link leads is still not known." }), 150000);
    }
    u.card?.remove();
    const close = () => {
      clearTimeout(state.shortTimer);
      u.card?.remove();
      u.card = null;
    };
    const service = safe(msg.service || "the shortening service", 60);
    let body;
    if (msg.state === "working") {
      body = [h("div", { class: "why" }, `Asking ${service} where it leads. The destination is not opened.`)];
    } else if (msg.state === "needs-you") {
      body = [h("div", {}, `${service} wants to check that a person is asking. Finish that in the tab that just opened: `
        + "the destination stays blocked there. Close that tab to stop.")];
    } else if (msg.state === "error" || !r) {
      body = [h("div", {}, safe(msg.error || "Could not find out where this short link leads.", 300))];
    } else {
      const reasons = (r.findings || []).filter((f) => f.weight > 0 && f.code !== "URL_SHORTENER_EXPANDED").slice(0, 3);
      body = [
        h("div", { class: "dest url" }, `Leads to: ${safe(r.defanged || msg.destination, 300)}`),
        h("div", { class: "row" }, h("span", { class: `pill ${VERDICT_NAMES[r.verdict] ? r.verdict : "error"}` }, VERDICT_NAMES[r.verdict] || "Checked"),
          h("strong", {}, safe(r.summary, 200))),
        reasons.length ? h("ol", {}, reasons.map((f) => h("li", {}, safe(f.title, 160)))) : null,
        h("div", { class: "why" }, `Found by ${msg.by === "browser" ? "your browser" : "the Homograph Guard app"} asking ${service}. `
          + "The destination was not opened."),
      ];
    }
    const canOpen = msg.state === "done" && r && !RISKY.has(r.verdict) && /^https?:/i.test(msg.destination || "");
    const open = canOpen ? h("button", { class: "btn ghost", onclick: (ev) => {
      if (!ev.isTrusted) return;
      close();
      send({ type: "user-action", action: "open", url: msg.destination });
    } }, "Open it") : null;
    u.card = h("section", { class: "card", role: "status", "aria-live": "polite", "aria-label": "Where this short link leads" },
      h("header", {},
        h("div", { class: "title" }, msg.state === "done" && r ? "Where this short link leads" : "Short link", h("small", { class: "url" }, safe(msg.url, 160))),
        h("button", { class: "icon-btn", title: "Close", "aria-label": "Close", onclick: close }, "×")),
      h("div", { class: "card-body" }, body, h("div", { class: "actions" }, open, h("button", { class: "btn primary", onclick: close }, "Close"))));
    u.wrap.append(u.card);
  }

  // ------------------------------------------------------------------ events
  function entryFor(target) {
    const el = target?.closest?.("a, area, [data-href], [data-url], [data-link]");
    return el ? [el, state.elToEntry.get(el)] : [null, null];
  }

  function onClick(ev) {
    if (!state.enabled) return;
    const [el, e] = entryFor(ev.target);
    if (!el || !isRisky(e) || !state.live.has(e.key)) return;
    if (ev.type === "auxclick" && ev.button !== 1) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    hideTip();
    showModal(e, el);
  }

  function onOver(ev) {
    if (!state.enabled) return;
    const [el, e] = entryFor(ev.target);
    if (el && isRisky(e)) showTip(e, el);
  }

  function onOut(ev) {
    const [el] = entryFor(ev.target);
    if (el && !el.contains(ev.relatedTarget)) hideTip();
  }

  function start() {
    if (state.enabled) return;
    state.enabled = true;
    document.addEventListener("click", onClick, true);
    document.addEventListener("auxclick", onClick, true);
    document.addEventListener("mouseover", onOver, true);
    document.addEventListener("mouseout", onOut, true);
    document.addEventListener("visibilitychange", onVisible);
    document.addEventListener("scroll", onScroll, { capture: true, passive: true });
    state.observer = new MutationObserver((muts) => {
      if (muts.every((m) => m.target === state.ui?.host || state.ui?.host?.contains(m.target))) return;
      scheduleScan();
    });
    state.observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["href", "hidden"] });
    state.poll = setInterval(() => {
      if (location.href !== state.href) scheduleScan(200);
    }, 1500);
    scheduleScan(50);
  }

  function stop() {
    state.enabled = false;
    document.removeEventListener("click", onClick, true);
    document.removeEventListener("auxclick", onClick, true);
    document.removeEventListener("mouseover", onOver, true);
    document.removeEventListener("mouseout", onOut, true);
    document.removeEventListener("visibilitychange", onVisible);
    document.removeEventListener("scroll", onScroll, { capture: true });
    state.observer?.disconnect();
    clearInterval(state.poll);
    clearTimeout(state.timer);
    clearDecorations();
    state.ui?.host.remove();
    state.ui = null;
    state.port?.disconnect();
    state.port = null;
    state.entries.clear();
    state.byId.clear();
    state.live.clear();
  }

  function onScroll() {
    if (state.truncated) scheduleScan(400); // more links than one scan checks: follow the reader
  }

  function onVisible() {
    if (document.visibilityState === "visible") scheduleScan(100);
  }

  chrome.storage.local.get({ enabled: true }, ({ enabled }) => (enabled !== false ? start() : stop()));
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && "enabled" in changes) (changes.enabled.newValue !== false ? start() : stop());
  });
  chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    if (sender?.id !== chrome.runtime.id) return;
    if (msg?.type === "lists-changed") {
      for (const e of state.entries.values()) Object.assign(e, { sent: false, report: null, final: false, ignore: false });
      scheduleScan(100);
      return;
    }
    if (msg?.type === "short-link") {
      showShortCard(msg);
      return;
    }
    if (msg?.type !== "status") return;
    const live = liveEntries().filter((e) => !e.ignore);
    const risky = live.filter(isRisky);
    reply({ enabled: state.enabled, scope: state.focusLabel, links: live.length, risky: risky.length,
      pending: live.filter((e) => !e.final).length,
      checked_on: [...new Set(live.filter((e) => e.report).map((e) => e.report.checked_on || "browser"))],
      items: risky.slice(0, 25).map((e) => ({ verdict: e.report.verdict, link: e.report.defanged || e.report.input,
        summary: e.report.summary, source: e.ctx.source, hidden: e.ctx.hidden || null, text: e.ctx.text || null,
        on: e.report.checked_on || "browser" })), short: state.short || null });
  });
})();
