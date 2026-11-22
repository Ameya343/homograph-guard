const ext = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
let state = null;
let current = "allow";

const HELP = {
  allow: "Domains and links you trust. Warnings are switched off for them, whatever the database or the checks say.",
  block: "Domains and links you never want to open. They are always shown as dangerous.",
  reported: "Links you reported as phishing. They are blocked on this device; reports are not sent anywhere.",
};

async function call(msg) {
  const res = await ext.runtime.sendMessage({ type: "options", ...msg });
  if (res?.error) throw new Error(res.error);
  return res;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) e.append(kid); // text is never parsed as HTML
  return e;
}

function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

function renderStatus() {
  const box = $("status-text");
  box.textContent = "";
  if (state.app) {
    const db = state.db || {};
    box.append(el("span", { class: "status-ok" }, "Connected to the Homograph Guard app on this device."), " ",
      `Threat database: ${(db.domains || 0).toLocaleString()} domains and ${(db.urls || 0).toLocaleString()} links, updated ${ago(db.updated)}.`);
    if (!db.updated) box.append(" Run an update from the app to download it.");
  } else {
    box.append(el("span", { class: "status-warn" }, "The Homograph Guard app is not installed on this device."), " ",
      "The extension still checks every link itself and keeps your lists in this browser. Install the app to add the daily threat database.");
  }
}

function renderDns() {
  const s = state.settings || {};
  for (const input of document.querySelectorAll("input[name=dns]")) {
    input.checked = input.value === s.dns_mode;
    input.disabled = (s.locked || []).includes("dns_mode");
  }
  $("dns-locked").hidden = !(s.locked || []).includes("dns_mode");
}

function entriesFor(list) {
  const l = state.lists || {};
  if (list === "reported") return (l.reported || []).map((r) => ({ value: r.url, note: r.note, when: r.reported }));
  return (l[list] || []).map((e) => ({ value: e.value, note: e.note, when: e.added }));
}

function renderList() {
  for (const tab of document.querySelectorAll("[role=tab]")) tab.setAttribute("aria-selected", String(tab.dataset.list === current));
  $("list-help").textContent = HELP[current];
  $("entry").placeholder = current === "reported" ? "https://phishing-site.example/login" : "example.com or https://example.com/page";
  $("add-btn").textContent = current === "reported" ? "Report" : "Add";
  const items = entriesFor(current);
  const ul = $("entries");
  ul.textContent = "";
  for (const it of items) {
    ul.append(el("li", {},
      el("span", { class: "value" }, it.value, it.note ? el("div", { class: "meta" }, it.note) : null),
      el("span", { class: "meta" }, it.when ? new Date(it.when).toLocaleDateString() : ""),
      el("button", { type: "button", onclick: () => act({ op: "remove", list: current, entry: it.value }) }, "Remove")));
  }
  $("empty").hidden = items.length > 0;
  const org = state.lists?.organisation;
  const orgItems = org ? [...(org.allow || []).map((v) => `allow  ${v}`), ...(org.block || []).map((v) => `block  ${v}`)] : [];
  $("org").hidden = orgItems.length === 0;
  $("org-entries").textContent = "";
  for (const v of orgItems) $("org-entries").append(el("li", {}, el("span", { class: "value" }, v)));
}

function render() {
  renderStatus();
  renderDns();
  renderList();
}

async function act(msg) {
  $("error").hidden = true;
  try {
    state = await call(msg);
    render();
    return true;
  } catch (e) {
    $("error").textContent = e.message;
    $("error").hidden = false;
    return false;
  }
}

$("add").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const entry = $("entry").value.trim();
  const note = $("note").value.trim();
  const ok = current === "reported" ? await act({ op: "report", url: entry, note }) : await act({ op: "add", list: current, entry, note });
  if (ok) {
    $("entry").value = "";
    $("note").value = "";
  }
});

for (const tab of document.querySelectorAll("[role=tab]")) {
  tab.addEventListener("click", () => {
    current = tab.dataset.list;
    renderList();
  });
}

for (const input of document.querySelectorAll("input[name=dns]")) {
  input.addEventListener("change", () => act({ op: "dns", mode: input.value }));
}

call({ op: "state" }).then((s) => {
  state = s;
  render();
}).catch((e) => {
  $("status-text").textContent = e.message;
});
