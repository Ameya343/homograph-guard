const ext = globalThis.browser ?? globalThis.chrome;
const toggle = document.getElementById("toggle");
const stateText = document.getElementById("state");
const statusText = document.getElementById("status");
let enabled = true;

function paint() {
  toggle.setAttribute("aria-checked", String(enabled));
  stateText.textContent = enabled ? "On - checking links as you read" : "Off";
  document.body.classList.toggle("off", !enabled);
}

function say(text, kind = "") {
  statusText.textContent = text;
  statusText.className = `status ${kind}`;
}

async function refreshStatus() {
  if (!enabled) {
    say("Paused. Links are not checked until you turn protection back on.");
    return;
  }
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  let s;
  try {
    s = await ext.tabs.sendMessage(tab.id, { type: "status" });
  } catch {
    say("Works on web pages, webmail and web chats. Reload this tab if it was open before the extension.");
    return;
  }
  if (!s) return;
  const scope = s.scope || "this page";
  const where = `${scope === "this page" ? "on" : "in"} ${scope}`;
  if (s.risky > 0) say(`⚠ ${s.risky} risky link${s.risky === 1 ? "" : "s"} ${where}. Risky links are outlined in red and blocked when clicked.`, "risk");
  else if (s.pending > 0) say(`Checking ${s.pending} link${s.pending === 1 ? "" : "s"} ${where}…`);
  else if (s.links > 0) say(`${s.links} link${s.links === 1 ? "" : "s"} checked ${where}. None look risky.`, "ok");
  else say(`Watching ${scope}. Open an email or chat and its links are checked automatically.`);
}

toggle.addEventListener("click", async () => {
  enabled = !enabled;
  paint();
  await ext.storage.local.set({ enabled });
  setTimeout(refreshStatus, 300);
});

document.getElementById("settings").addEventListener("click", (ev) => {
  ev.preventDefault();
  ext.runtime.openOptionsPage();
  window.close();
});

ext.storage.local.get({ enabled: true }).then((v) => {
  enabled = v.enabled !== false;
  paint();
  requestAnimationFrame(() => requestAnimationFrame(() => document.body.classList.remove("init")));
  refreshStatus();
  setInterval(refreshStatus, 1000);
});
