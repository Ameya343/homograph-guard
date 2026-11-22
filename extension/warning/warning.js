const ext = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const shownAt = performance.now();

let info = {};
try {
  const raw = JSON.parse(decodeURIComponent(location.hash.slice(1)));
  if (raw && typeof raw === "object") info = raw;
} catch {
  /* malformed: show a generic warning */
}
const url = typeof info.u === "string" && /^https?:\/\//i.test(info.u) ? info.u.slice(0, 8192) : "";
// Everything shown here is inserted as text, never as HTML.
$("summary").textContent = typeof info.s === "string" ? info.s.slice(0, 300) : "Known phishing or malware site.";
$("dest").textContent = typeof info.d === "string" ? info.d.slice(0, 500) : url;
for (const r of Array.isArray(info.r) ? info.r.slice(0, 6) : []) {
  if (typeof r === "string") $("reasons").append(Object.assign(document.createElement("li"), { textContent: r.slice(0, 200) }));
}

// Weakening protection needs a real click, after the page has been on screen for a moment.
const deliberate = (ev) => ev.isTrusted && performance.now() - shownAt > 700;

$("back").addEventListener("click", () => {
  if (history.length > 2) history.go(-2); // skip the blocked navigation itself
  else window.close();
  setTimeout(() => location.replace("about:blank"), 300);
});

$("continue").disabled = !url;
$("continue").addEventListener("click", async (ev) => {
  if (!deliberate(ev) || !url) return;
  const res = await ext.runtime.sendMessage({ type: "nav-continue", url });
  if (res?.ok) location.replace(url);
});

let armed = false;
$("trust").hidden = !url;
$("trust").addEventListener("click", async (ev) => {
  if (!deliberate(ev) || !url) return;
  if (!armed) {
    armed = true;
    $("trust").textContent = `Click again to always trust ${new URL(url).hostname}`;
    return;
  }
  $("trust").disabled = true;
  const res = await ext.runtime.sendMessage({ type: "nav-trust", url });
  if (res?.ok) {
    await ext.runtime.sendMessage({ type: "nav-continue", url });
    location.replace(url);
  } else {
    $("trust").textContent = res?.error || "Could not add it to your allowlist";
  }
});
$("back").focus();
