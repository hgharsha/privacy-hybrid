const $ = (id) => document.getElementById(id);
const H = {"Content-Type": "application/json", "X-Requested-With": "privhybrid"};
// Mac unreachable (off, asleep, other network): show a banner; hide it as soon as any request works again.
const nativeFetch = window.fetch.bind(window);
window.fetch = async (...a) => {
  try { const r = await nativeFetch(...a); $("offline").hidden = true; return r; }
  catch (e) { $("offline").hidden = false; throw e; }
};
setInterval(() => { if (!$("offline").hidden) fetch("/api/state").catch(() => {}); }, 8000);
const post = (url, body, signal) => fetch(url, {method: "POST", headers: H, body: JSON.stringify(body || {}), signal});
let pendingLocal = "";  // the question that was stopped, so "Run locally" re-asks that one even if newer ones were sent
let chain = Promise.resolve(), waiting = 0, ctl = new AbortController();  // ctl: the Stop button aborts everything asked so far
let chatId = "", registering = false;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;  // textContent only: replies are never parsed as HTML
  return e;
}

async function boot() {
  const r = await fetch("/api/state");
  if (r.status === 401) { $("login").hidden = false; $("app").hidden = true; return; }
  $("login").hidden = true; $("app").hidden = false;
  const s = await r.json();
  $("health").textContent = `Local model: ${s.health.ollama ? "up" : "down"} · Web search: ${s.health.search ? "up" : "off"}`;
  $("who").textContent = s.email;
  cloudName = s.cloud_label || cloudName; $("cloudLabel").textContent = cloudName; FLOWS.claude[2][0] = cloudName.startsWith("Claude") ? "Claude" : "Cloud model";
  $("setBtn").hidden = $("auditBtn").hidden = !s.admin;
  applyPrefs(s.prefs || {});
  setExtreme(!!(s.prefs || {}).extreme);
  $("reviewCloud").checked = (s.prefs || {}).review_cloud !== false;
  loadLock();
  setupSamples(s.demo);
  renderDocs(s.docs, s.folders || []);
  renderFacts(s.facts || []);
  loadChats();
  loadSched();
}

// --- scheduled jobs: run on the Mac while signed out, results arrive as chats ---
let sched = null;
const fmtTime = (t) => t ? new Date(t * 1000).toLocaleString([], {weekday: "short", hour: "2-digit", minute: "2-digit"}) : "-";
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const when = (x) => `${x.freq === "weekly" ? "Every " + DAYS[x.weekday] : "Every day"} at ${String(x.hour).padStart(2, "0")}:${String(x.minute).padStart(2, "0")}`;

async function loadSched() {
  const r = await fetch("/api/sched");
  if (!r.ok) return;
  renderSched(await r.json());
}

const lastRuns = {};  // job id -> last_run seen, to notice a run that finished while this page was open
let schedNotice = "";
setInterval(() => { if (sched && sched.optin && !document.hidden) loadSched(); }, 10000);

function renderSched(st) {
  const finished = st.jobs.filter((j) => j.last_run && lastRuns[j.id] !== undefined && lastRuns[j.id] !== j.last_run);
  for (const j of st.jobs) lastRuns[j.id] = j.last_run || 0;
  if (finished.length) { schedNotice = `Finished: ${finished[0].question.slice(0, 40)} (${finished[0].status}). See Chats.`; loadChats(); }
  sched = st;
  $("schedSec").hidden = !st.server;
  if (!st.server) return;
  const ul = $("jobs"); ul.replaceChildren();
  $("schedAdd").hidden = !st.optin;
  $("schedOpt").textContent = st.optin ? "Turn off scheduled jobs" : "Turn on scheduled jobs";
  $("schedNote").textContent = !st.optin ? "Off. Jobs can run while you are signed out once you turn this on."
    : !st.keychain ? "The Keychain is not answering. Unlock the Mac and reload."
    : schedNotice || (st.snapshot_at && st.jobs.some((j) => j.mode === "local") ? `Folder copy updated ${fmtTime(st.snapshot_at)}.` : "");
  for (const j of st.jobs) {
    const li = el("li", j.paused ? "paused" : "");
    li.append(el("span", "", j.question.length > 60 ? j.question.slice(0, 57) + "..." : j.question));
    li.append(el("small", "muted", `${j.mode === "web" ? "web" : "folder: " + j.folder} · ${when(j.schedule)} · ${j.paused ? "paused" : "next " + fmtTime(j.next_run)}${j.last_run ? " · last " + fmtTime(j.last_run) + ": " + j.status : ""}`));
    const row = el("span", "row");
    for (const [label, action] of [["Run now", "run"], [j.paused ? "Resume" : "Pause", j.paused ? "resume" : "pause"], ["Delete", "delete"]]) {
      const b = el("button", "ghost", label); b.type = "button";
      b.onclick = async () => {
        schedNotice = action === "run" ? "Queued. It runs within 30 seconds; the answer appears under Chats." : "";
        const x = await post("/api/sched/job", {action, id: j.id}); if (x.ok) renderSched(await x.json());
      };
      row.append(b);
    }
    li.append(row); ul.append(li);
  }
}

$("schedAdd").onclick = () => {
  $("jerr").textContent = ""; $("schedForm").reset();
  const f = $("jfolder"); f.replaceChildren(); for (const n of sched.folders) f.append(new Option(n, n));
  $("jmode").onchange(); $("jfreq").onchange();
  $("schedDlg").showModal();
};
$("jmode").onchange = () => { $("jfolder").hidden = $("jmode").value !== "local" || !sched.folders.length; };
$("jfreq").onchange = () => { $("jday").hidden = $("jfreq").value !== "weekly"; };
$("schedCancel").onclick = () => $("schedDlg").close();
$("schedForm").onsubmit = async (ev) => {
  ev.preventDefault();
  const [hour, minute] = $("jtime").value.split(":").map(Number);
  const r = await post("/api/sched/job", {action: "add", question: $("jq").value, mode: $("jmode").value, folder: $("jfolder").value,
    schedule: {freq: $("jfreq").value, hour, minute, weekday: Number($("jday").value)}});
  const j = await r.json();
  if (!r.ok) { $("jerr").textContent = j.error || "Could not save"; return; }
  $("schedDlg").close(); renderSched(j);
};

$("schedOpt").onclick = () => {
  const on = sched.optin;
  $("optTitle").textContent = on ? "Turn off scheduled jobs" : "Turn on scheduled jobs";
  $("optText").textContent = on ? "This deletes your scheduled jobs, the folder copies and any results you have not opened yet."
    : "A key is stored in this Mac's Keychain so jobs can run while you are signed out. Your scheduled questions and a copy of the folders local jobs use are then protected by that key, not your password, so anyone who can use your Mac login can read them. Turn on FileVault and use a strong Mac password. Jobs never use Claude.";
  $("optGo").textContent = on ? "Turn off" : "Turn on"; $("optErr").textContent = ""; $("optPw").value = "";
  $("schedOptDlg").showModal();
};
$("optCancel").onclick = () => $("schedOptDlg").close();
$("schedOptForm").onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await post("/api/sched/optin", {enable: !sched.optin, password: $("optPw").value});
  const j = await r.json();
  if (!r.ok) { $("optErr").textContent = j.error || "Could not change"; return; }
  $("schedOptDlg").close(); renderSched(j);
};

let factsWatch = 0;
async function watchFacts() {
  const mine = ++factsWatch, before = $("facts").querySelectorAll("button").length;
  for (let i = 0; i < 18 && mine === factsWatch; i++) {
    await new Promise((ok) => setTimeout(ok, 10000));
    try {
      const r = await fetch("/api/state"); if (!r.ok) return;
      const facts = (await r.json()).facts || [];
      if (facts.length !== before) { renderFacts(facts); return; }
    } catch (e) { return; }
  }
}

// Long lists show the newest few, with one button for the rest (the open chat always stays visible).
const SHOW = 5, openLists = new Set();
function limitItems(parent, items, key, limit = SHOW) {
  if (items.length <= limit) return;
  const rest = items.slice(limit);
  const btn = el("button", "ghost mini more"); btn.type = "button";
  const paint = () => {
    const all = openLists.has(key);
    for (const li of rest) li.hidden = !all && !li.classList.contains("current");
    btn.textContent = all ? "Show fewer" : `Show all ${items.length}`;
    btn.setAttribute("aria-expanded", String(all));
  };
  btn.onclick = () => { openLists.has(key) ? openLists.delete(key) : openLists.add(key); paint(); };
  paint();
  const li = el("li", "morerow"); li.append(btn); parent.append(li);
}

function renderFacts(facts) {
  const ul = $("facts"); ul.replaceChildren();
  if (!facts.length) ul.append(el("li", "muted", "Nothing yet. Tell me about your plans and preferences."));
  for (const f of facts) {
    const li = el("li", "", f.text);
    const rm = el("button", "ghost", "Forget"); rm.type = "button";
    rm.onclick = async () => { await post("/api/facts/delete", {id: f.id}); boot(); };
    li.append(rm); ul.append(li);
  }
  limitItems(ul, [...ul.querySelectorAll("li")].filter((li) => li.querySelector("button")), "facts");
}

async function loadChats() {
  const ul = $("chats"); ul.replaceChildren();
  const {chats} = await (await fetch("/api/chats")).json();
  for (const c of chats) {
    const li = el("li", c.id === chatId ? "current" : "");
    const open = el("button", "ghost", c.title || "Chat"); open.type = "button";
    if (c.id === chatId) open.setAttribute("aria-current", "true");
    open.onclick = () => { openChat(c.id); if (mobile.matches) { $("sideBtn").setAttribute("aria-expanded", "false"); syncSide(); } };
    const del = el("button", "ghost", "Delete"); del.type = "button";
    del.title = "Deletes this chat and what the assistant learned from it";
    del.onclick = async () => { await post("/api/chats/delete", {id: c.id}); if (c.id === chatId) newChat(); else loadChats(); };
    li.append(open, del); ul.append(li);
  }
  limitItems(ul, [...ul.children], "chats");
}

async function openChat(id) {
  const c = await (await fetch("/api/chats/get?id=" + encodeURIComponent(id))).json();
  chatId = id; shown = (c.msgs || []).length; $("chat").replaceChildren();
  for (const m of c.msgs || []) {
    addMsg("user", m.q);
    const box = addMsg("bot", ""); const md = el("div", "md"); md.append(renderMd(m.a)); box.append(md);
    const badge = el("span", "badge " + (m.route === "claude" ? "cloud" : "local"), routeName(m.route)); box.before(badge);
    for (const n of m.notices || []) box.append(el("div", "notice", n));
    if (m.steps?.length) {
      const d = el("details"); d.append(el("summary", "", "What happened"), flowView(m.route, m.steps, "done"));
      m.steps.forEach((x) => d.append(el("div", "", x))); box.append(d);
    }
  }
  loadChats();
}

function newChat() { chatId = ""; shown = 0; $("chat").replaceChildren(); loadChats(); }

// Another device may have added to the chats: look again when this page comes back into view, and every 20 s while it is open.
let shown = 0;
async function refresh() {
  if (document.hidden || waiting > 0) return;
  try {
    await loadChats();
    if (chatId) {
      const c = await (await fetch("/api/chats/get?id=" + encodeURIComponent(chatId))).json();
      if ((c.msgs || []).length > shown) await openChat(chatId);
    }
  } catch (e) { /* signed out or offline: the next tick tries again */ }
}
// A home-screen app can sit frozen on an old copy of this script: when it returns, reload if the script on the server changed.
let srcLen = 0;
async function newerScript() {
  try {
    const t = await (await fetch("/static/app.js", {cache: "no-store"})).text();
    if (!srcLen) { srcLen = t.length; return false; }
    return t.length !== srcLen;
  } catch (e) { return false; }
}
newerScript();
async function comeBack() {
  if (document.hidden || waiting > 0) return;
  if (await newerScript()) { location.reload(); return; }
  refresh();
}
document.addEventListener("visibilitychange", comeBack);
window.addEventListener("pageshow", comeBack);
window.addEventListener("focus", comeBack);
window.addEventListener("online", comeBack);
setInterval(refresh, 20000);
const FLOWS = {
  local: [["You", "mac"], ["Local model", "mac"], ["Answer", "mac"]],
  public_fact: [["You", "mac"], ["Write query", "mac"], ["Web search", "net"], ["Local model", "mac"], ["Answer", "mac"]],
  claude: [["You", "mac"], ["Mask & check", "mac"], ["Claude", "net"], ["Restore", "mac"], ["Answer", "mac"]],
};
const DONE_AT = {  // step text prefix -> how many nodes are finished
  local: [["route:", 1], ["answered by", 3]],
  public_fact: [["route:", 1], ["local model wrote", 2], ["search returned", 3], ["local model combined", 5]],
  claude: [["route:", 1], ["local privacy check passed", 2], ["Claude answered", 3], ["The cloud model answered", 3], ["restored values", 5]],
};
// A tracker for one request: green nodes stay on this computer, amber ones leave it. `end` is "done", "stopped" or "error".
function flowView(route, steps, end) {
  const nodes = FLOWS[route] || FLOWS.local;
  let done = 0;
  for (const st of steps) for (const [pre, n] of DONE_AT[route] || []) if (st.startsWith(pre)) done = Math.max(done, n);
  if (end === "done") done = nodes.length;
  const ol = el("ol", "flow"); ol.setAttribute("aria-label", "Where your request went");
  nodes.forEach(([label, where], i) => {
    const state = i < done ? "done" : i === done && !end ? "active" : i === done ? end : "";
    const li = el("li", `node ${where} ${state}`);
    li.append(el("span", "dot", i < done ? "✓" : end && i === done ? "!" : String(i + 1)), el("span", "lbl", label),
      el("small", "", where === "net" ? "leaves this computer" : "on this computer"));
    ol.append(li);
  });
  return ol;
}

let cloudName = "Claude (masked)";
const routeName = (r) => ({local: "Local only", public_fact: "Local + web facts", claude: cloudName}[r] || r);

const NEW_FOLDER = "\u0000new";
function folderOptions(sel, folders, first, extra) {
  const keep = sel.value; sel.replaceChildren();
  sel.append(new Option(first, ""));
  for (const f of folders) sel.append(new Option(f, f));
  if (extra) sel.append(new Option("New folder…", NEW_FOLDER));
  sel.value = folders.includes(keep) || keep === "" ? keep : "";
}
function askPassword(name) {  // a real password field, so it is never shown on screen
  return new Promise((resolve) => {
    const dlg = $("pdfDlg"), inp = $("pdfInput");
    $("pdfName").textContent = name; inp.value = "";
    let done = false;
    const finish = (v) => { if (done) return; done = true; inp.value = ""; dlg.close(); resolve(v); };
    $("pdfForm").onsubmit = (ev) => { ev.preventDefault(); finish(inp.value); };
    $("pdfCancel").onclick = () => finish("");
    dlg.oncancel = () => finish("");
    dlg.showModal(); inp.focus();
  });
}
function askFolder() {
  const n = (prompt("Folder name") || "").trim().slice(0, 40);
  return n;
}
let tipCounts = [0, 0];
function updateTip(n, f) {
  tipCounts = [n, f];
  const scoped = $("scope").value !== "";
  $("scopeTip").textContent = scoped ? "Searching only this folder: faster and more focused."
    : n >= 15 ? `You have ${n} files. For faster, more focused answers, group them into folders and pick one above.`
    : "Tip: with many files, keep related ones in a folder and pick it here to search just that folder.";
  $("scopeTip").classList.toggle("warn", !scoped && n >= 15);
}
function pickFolder(d, folders) {
  const sel = $("moveSel"), nw = $("moveNew");
  sel.replaceChildren(new Option("Unsorted", ""));
  for (const f of folders) sel.append(new Option(f, f));
  sel.append(new Option("New folder…", NEW_FOLDER));
  sel.value = d.folder || ""; nw.value = ""; nw.hidden = true;
  $("moveName").textContent = d.name;
  $("moveDlg").showModal();
  $("moveForm").onsubmit = async () => {
    const f = sel.value === NEW_FOLDER ? nw.value.trim().slice(0, 40) : sel.value;
    if (sel.value === NEW_FOLDER && !f) return;
    if (f) { const cr = await post("/api/folder/create", {name: f}); if (!cr.ok) { alert((await cr.json()).error || "Could not create the folder"); return; } }
    await post("/api/move", {name: d.name, folder: f}); boot();
  };
}
$("moveSel").onchange = (ev) => {
  $("moveNew").hidden = ev.target.value !== NEW_FOLDER;
  if (!$("moveNew").hidden) $("moveNew").focus();
};
$("moveCancel").onclick = () => $("moveDlg").close();
function renderDocs(docs, saved) {
  const used = [...new Set(docs.map((d) => d.folder).filter(Boolean))].sort();
  const folders = [...new Set([...used, ...saved])].sort();  // saved folders include empty ones
  folderOptions($("upFolder"), folders, "Unsorted", true);
  folderOptions($("scope"), used, "All my files", false);
  updateTip(docs.length, used.length);
  const ul = $("docs"); ul.replaceChildren();
  for (const name of ["", ...folders]) {
    const items = docs.filter((d) => (d.folder || "") === name);
    if (!items.length && !name) continue;
    const det = el("details", "folder"); det.open = true;
    const sm = el("summary", "", `${name || "Unsorted"} (${items.length})`);
    if (name) {
      const rf = el("button", "ghost mini", "Rename"); rf.type = "button";
      rf.onclick = async (ev) => {
        ev.preventDefault();
        const n = prompt("New folder name (blank = move files to Unsorted)", name);
        if (n === null) return;
        await post("/api/folder/rename", {old: name, new: n.trim()}); boot();
      };
      const df = el("button", "ghost mini", "Delete"); df.type = "button";
      df.onclick = async (ev) => {
        ev.preventDefault();
        if (!confirm(items.length ? `Delete the folder "${name}"? Its ${items.length} file(s) stay, in Unsorted.` : `Delete the empty folder "${name}"?`)) return;
        await post("/api/folder/delete", {name}); boot();
      };
      sm.append(rf, df);
    }
    det.append(sm);
    for (const d of items) {
      const li = el("li"); const nm = el("span", "docname", d.name); nm.title = d.name; li.append(nm);
      const mv = el("button", "ghost", "Move");
      mv.type = "button";
      mv.onclick = () => pickFolder(d, folders);
      const rn = el("button", "ghost", "Rename"); rn.type = "button";
      rn.onclick = async () => {
        const n = prompt("New file name", d.name);
        if (n === null || !n.trim() || n.trim() === d.name) return;
        const r = await post("/api/rename", {name: d.name, new: n.trim()});
        if (!r.ok) addMsg("notice", (await r.json()).error); boot();
      };
      const rm = el("button", "ghost", "Remove");
      rm.type = "button";
      rm.onclick = async () => { await post("/api/remove", {name: d.name}); boot(); };
      li.append(mv, rn, rm);
      if (d.notes.some((n) => n.startsWith("Filename"))) li.title = d.notes[0];
      det.append(li);
    }
    limitItems(det, [...det.querySelectorAll("li")], "docs:" + name);
    ul.append(det);
  }
}
$("upFolder").onchange = async (ev) => {
  if (ev.target.value !== NEW_FOLDER) return;
  const n = askFolder();
  if (!n) { ev.target.value = ""; return; }
  const cr = await post("/api/folder/create", {name: n});
  if (!cr.ok) { alert((await cr.json()).error || "Could not create the folder"); ev.target.value = ""; return; }
  await boot(); $("upFolder").value = n;
};

$("switchMode").onclick = () => {
  registering = !registering;
  $("loginBtn").textContent = registering ? "Create account" : "Sign in";
  $("switchMode").textContent = registering ? "Have an account? Sign in" : "New here? Register";
  $("regNote").hidden = !registering;
  $("pw").autocomplete = registering ? "new-password" : "current-password";
  $("loginErr").textContent = "";
};
$("loginForm").onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await post(registering ? "/api/register" : "/api/login", {email: $("email").value, password: $("pw").value});
  if (r.ok) { $("pw").value = ""; $("loginErr").textContent = ""; chatId = ""; $("chat").replaceChildren(); boot(); }
  else $("loginErr").textContent = (await r.json()).error || "Could not sign in";
};
const CFG = ["answer", "check", "summary", "query", "embed"];
function fillSelect(sel, installed, value) {
  const names = installed.includes(value) ? installed : [value, ...installed];
  sel.replaceChildren(...names.map(n => { const o = document.createElement("option"); o.value = n; o.textContent = installed.includes(n) ? n : n + " (not installed)"; return o; }));
  sel.value = value;
}
function chkSmall() {  // size from the model name (":7b", "-8b"); unknown size gives no warning
  const m = /[:\-_](\d+(?:\.\d+)?)b\b/i.exec($("cfg_check").value || "");
  $("chkWarn").hidden = !(m && parseFloat(m[1]) < 14);
}
$("cfg_check").onchange = chkSmall;
async function loadCfg() {
  const r = await fetch("/api/config"); if (!r.ok) { $("cfgStatus").textContent = "Could not load settings."; return; }
  const {config: c, installed} = await r.json();
  $("cfgRuntime").value = c.local_runtime; $("cfgRuntime").disabled = c.local_runtime_env;
  $("cfgUrl").value = c.ollama_url; $("cfgUrl").disabled = c.ollama_url_env;
  $("cfgEmbedUrl").value = c.embed_url || ""; $("cfgEmbedUrl").disabled = c.embed_url_env;
  $("cfgBackups").value = (c.ollama_backups || []).join("\n"); $("cfgBackups").disabled = c.ollama_backups_env;
  for (const k of CFG) { fillSelect($("cfg_" + k), installed, c[k]); $("cfg_" + k).disabled = c[k + "_env"]; }
  chkSmall();
  $("remoteWarn").textContent = c.remote_ollama_warning || ""; $("remoteWarn").hidden = !c.remote_ollama_warning;
  $("cloudProv").disabled = c.cloud_provider_env; $("cloudKey").disabled = c.cloud_key_env; $("cloudKeyClear").disabled = c.cloud_key_env;
  $("cloudProv").value = c.cloud_provider; $("cloudUrl").value = c.cloud_url; $("cloudModel").value = c.cloud_model;
  $("cloudOther").hidden = c.cloud_provider !== "openai_compat"; $("cloudKey").value = "";
  $("cloudKeyState").textContent = c.cloud_key_env ? "(set by PRIVHYBRID_CLOUD_API_KEY)" : c.cloud_key_set ? "(a key is saved)" : "(no key saved)";
  const st = $("cfgStatus");
  st.className = "status " + (installed.length ? "ok" : "bad");
  const rt = c.local_runtime === "local_openai" ? "The local model server" : "Ollama";
  st.textContent = installed.length ? `${rt} is running · ${installed.length} models installed` : `Can't reach ${rt}. Start it and reopen Settings.`;
}
$("cfgForm").onsubmit = async (ev) => {
  ev.preventDefault();
  const body = {local_runtime: $("cfgRuntime").value, ollama_url: $("cfgUrl").value, ollama_backups: $("cfgBackups").value, embed_url: $("cfgEmbedUrl").value, cloud_provider: $("cloudProv").value, cloud_url: $("cloudUrl").value, cloud_model: $("cloudModel").value};
  if ($("cloudKey").value) body.cloud_api_key = $("cloudKey").value;
  for (const k of CFG) body[k] = $("cfg_" + k).value;
  const r = await post("/api/config", body);
  const err = r.ok ? "" : (await r.json()).error;
  if (r.ok) { await loadCfg(); boot(); }
  $("cfgMsg").textContent = r.ok ? "Saved. Used from your next question." : err;
};
$("cloudProv").onchange = () => { $("cloudOther").hidden = $("cloudProv").value !== "openai_compat"; };
$("cloudKeyClear").onclick = async () => {
  const r = await post("/api/config", {cloud_api_key_clear: true});
  $("cfgMsg").textContent = r.ok ? "Saved key removed." : (await r.json()).error; if (r.ok) loadCfg();
};
async function loadTls() {
  const el = $("tlsInfo"); el.hidden = true;
  const r = await fetch("/api/tls"); if (!r.ok) return;
  const t = await r.json(); if (!t.enabled || !t.expires) return;
  el.textContent = t.days_left < 0 ? `The HTTPS certificate expired on ${t.expires}. Renew it: python3 scripts/install.py --tls --renew-tls --bind <your IP>`
    : `HTTPS certificate expires ${t.expires} (${t.days_left} days).` + (t.days_left < 30 ? " Renew it soon: python3 scripts/install.py --tls --renew-tls --bind <your IP>" : "");
  el.hidden = false;
}
$("setBtn").onclick = () => { $("cfgMsg").textContent = ""; loadCfg(); loadTls(); $("setDlg").showModal(); };
$("setClose").onclick = () => $("setDlg").close();
$("acctBtn").onclick = () => { $("pwMsg").textContent = ""; $("acctDlg").showModal(); };
$("acctClose").onclick = () => $("acctDlg").close();
$("pwForm").onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await post("/api/password", {old: $("oldPw").value, new: $("newPw").value});
  $("pwMsg").textContent = r.ok ? "Password changed. Other devices were signed out." : (await r.json()).error;
  if (r.ok) { $("oldPw").value = ""; $("newPw").value = ""; }
};
$("delForm").onsubmit = async (ev) => {
  ev.preventDefault();
  if (!confirm("Delete this account and everything in it?")) return;
  const r = await post("/api/account/delete", {password: $("delPw").value});
  if (r.ok) { $("delPw").value = ""; $("acctDlg").close(); chatId = ""; $("chat").replaceChildren(); boot(); }
  else alert((await r.json()).error);
};
$("logoutBtn").onclick = async () => { await post("/api/logout"); chatId = ""; $("chat").replaceChildren(); boot(); };

$("file").onchange = async (ev) => {
  const files = [...ev.target.files]; if (!files.length) return;
  const folder = $("upFolder").value === NEW_FOLDER ? "" : $("upFolder").value;
  for (const [i, f] of files.entries()) {
    const note = addMsg("notice", `Uploading ${i + 1} of ${files.length}: ${f.name}`);
    const buf = new Uint8Array(await f.arrayBuffer());
    let bin = ""; for (const b of buf) bin += String.fromCharCode(b);
    let r = await post("/api/upload", {name: f.name, data: btoa(bin), folder});
    for (let tries = 0; !r.ok && tries < 3; tries++) {  // a locked PDF: ask for its password (sent once over this connection, never saved)
      const err = (await r.clone().json()).error || "";
      if (!/^(Password needed|Wrong PDF password)/.test(err)) break;
      const pw = await askPassword(f.name);
      if (!pw) break;
      r = await post("/api/upload", {name: f.name, data: btoa(bin), folder, password: pw});
    }
    note.textContent = r.ok ? `Added ${f.name}` : `${f.name}: ${(await r.json()).error}`;
  }
  ev.target.value = ""; boot();
};

// Small markdown renderer for replies. It builds DOM nodes from text only, never HTML, and links must be http(s).
function inline(text) {
  const out = document.createDocumentFragment();
  const re = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\*[^*\s][^*\n]*\*|\[[^\]\n]+\]\(https?:\/\/[^\s)]+\))/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.append(text.slice(last, m.index));
    const t = m[0];
    if (t[0] === "`") out.append(el("code", "", t.slice(1, -1)));
    else if (t.startsWith("**")) out.append(el("strong", "", t.slice(2, -2)));
    else if (t[0] === "*") out.append(el("em", "", t.slice(1, -1)));
    else {
      const k = /^\[([^\]]+)\]\((.+)\)$/.exec(t), a = el("a", "", k[1]);
      a.href = k[2]; a.target = "_blank"; a.rel = "noopener noreferrer"; out.append(a);
    }
    last = m.index + t.length;
  }
  if (last < text.length) out.append(text.slice(last));
  return out;
}
function renderMd(text) {
  const root = document.createDocumentFragment(), lines = String(text).split("\n");
  let para = [], list = null, code = null;
  const flush = () => { if (para.length) { const p = el("p"); p.append(inline(para.join("\n"))); root.append(p); para = []; } list = null; };
  for (const line of lines) {
    if (code) { if (line.startsWith("```")) { root.append(code.pre); code = null; } else code.node.textContent += (code.node.textContent ? "\n" : "") + line; continue; }
    if (line.startsWith("```")) { flush(); const pre = el("pre"), node = el("code"); pre.append(node); code = {pre, node}; continue; }
    const li = /^\s*(?:[-*•]|(\d+)[.)])\s+(.*)$/.exec(line), h = /^#{1,4}\s+(.*)$/.exec(line);
    if (li) {
      const tag = li[1] ? "ol" : "ul";
      if (!list || list.tagName.toLowerCase() !== tag) { flush(); list = el(tag); root.append(list); }
      const item = el("li"); item.append(inline(li[2])); list.append(item);
    } else if (h) { flush(); const e = el("h3"); e.append(inline(h[1])); root.append(e); }
    else if (!line.trim()) flush();
    else { list = null; para.push(line); }
  }
  if (code) root.append(code.pre);
  flush();
  return root;
}

const nearBottom = () => document.documentElement.scrollHeight - window.scrollY - window.innerHeight < 160;
const toBottom = () => window.scrollTo({top: document.documentElement.scrollHeight});

function addMsg(kind, text) {
  const m = el("div", kind === "user" ? "msg user" : kind === "notice" ? "notice" : "msg", text);
  $("chat").append(m); toBottom(); return m;
}

function ask(question, mode) {
  const remember = $("remember").checked, sig = ctl.signal;
  addMsg("user", question);
  const box = addMsg("bot", "");
  const badge = el("span", "badge " + (waiting ? "queued" : "working"), waiting ? "queued…" : "working…"); box.before(badge);
  waiting++; $("stop").hidden = false;
  const job = chain.then(() => {
    if (sig.aborted) throw new DOMException("stopped", "AbortError");
    badge.className = "badge working"; badge.textContent = "working…"; return runAsk(question, mode, box, badge, remember, sig);
  })
    .catch((e) => {
      if (e.name === "AbortError") { badge.className = "badge stopped"; badge.textContent = "Stopped by you"; return; }
      badge.className = "badge error"; badge.textContent = "Error";
    })
    .finally(() => { if (--waiting === 0) $("stop").hidden = true; });
  chain = job;
}

$("stop").onclick = () => { post("/api/cancel").catch(() => {}); ctl.abort(); ctl = new AbortController(); };

async function runAsk(question, mode, box, badge, remember, sig) {
  const body = el("div", "md"); box.append(body); let raw = "";
  const steps = el("details"); steps.open = true; steps.append(el("summary", "", "What happened"));
  const log = []; let route = "", flow = null;
  const draw = (end) => { const f = flowView(route, log, end); flow ? flow.replaceWith(f) : steps.prepend(f); flow = f; };
  box.append(steps);
  const r = await post("/api/chat", {question, mode, chat_id: chatId, remember, folder: $("scope").value}, sig);
  if (!r.ok) { badge.className = "badge error"; badge.textContent = "Error"; body.textContent = (await r.json()).error || "Request failed"; return; }
  const reader = r.body.getReader(), dec = new TextDecoder(); let buf = "";
  while (true) {
    const {value, done} = await reader.read(); if (done) break;
    buf += dec.decode(value, {stream: true});
    let i; while ((i = buf.indexOf("\n\n")) >= 0) { handle(buf.slice(0, i)); buf = buf.slice(i + 2); }
  }
  function handle(block) {
    const stick = nearBottom(); handle1(block); if (stick) toBottom();
  }
  function handle1(block) {
    const ev = /^event: (.*)$/m.exec(block)?.[1], data = JSON.parse(/^data: (.*)$/m.exec(block)?.[1] || "null");
    if (ev === "step") {
      steps.append(el("div", "", data)); log.push(data);
      if (data.startsWith("route: ")) route = data.slice(7);
      draw("");
    }
    else if (ev === "notice") box.append(el("div", "notice", data));
    else if (ev === "chunk") { raw += data; body.replaceChildren(renderMd(raw)); }
    else if (ev === "done") {
      badge.textContent = routeName(data.route);
      watchFacts();  // facts are extracted in the background; refresh the list once they are in
      if (data.chat_id) { const fresh = data.chat_id !== chatId; chatId = data.chat_id; shown = Math.max(shown, 0) + 1; if (fresh) loadChats(); }
      badge.className = "badge " + (data.route === "claude" ? "cloud" : "local");
      route = data.route; draw("done");
      if (data.sources.length) { const s = el("details"); s.append(el("summary", "", "Sources")); data.sources.forEach((u) => s.append(el("div", "", u))); box.append(s); }
    } else if (ev === "preview") {
      $("pvDest").textContent = `Destination: ${data.host}` + (Object.keys(data.kinds || {}).length ? ` · masked: ${Object.entries(data.kinds).map(([k, n]) => `${k} ×${n}`).join(", ")}` : "");
      $("pvText").value = data.text;
      const warn = (data.warnings || []).length > 0;
      $("pvWarn").hidden = !warn; $("pvWarnList").textContent = (data.warnings || []).join("; ");
      $("pvConfirm").checked = false; $("pvSend").disabled = warn;
      $("pvConfirm").onchange = () => { $("pvSend").disabled = warn && !$("pvConfirm").checked; };
      const dlg = $("preview"); dlg.returnValue = "no";
      dlg.onclose = () => post("/api/approve", {id: data.id, ok: dlg.returnValue === "yes", confirmed: warn && $("pvConfirm").checked}).catch(() => {});  // Esc or closing counts as no
      dlg.showModal();
    } else if (ev === "needs_approval") {
      badge.className = "badge stopped"; badge.textContent = "Stopped"; body.textContent = "Nothing was sent."; pendingLocal = question;
      if (route) { draw("stopped"); steps.querySelector(".node.stopped .dot").title = data.reason; } else steps.remove();
      $("apReason").textContent = data.reason;
      $("apKinds").textContent = Object.entries(data.kinds || {}).map(([k, n]) => `${k} ×${n}`).join(", ");
      $("approval").showModal();
    } else if (ev === "error") { badge.className = "badge error"; badge.textContent = "Error"; if (route) draw("error"); body.textContent = `${data.error}${data.detail ? ": " + data.detail : ""}`; }
  }
}

$("ask").onsubmit = (ev) => {
  ev.preventDefault();
  const q = $("q").value.trim(); if (!q) return;
  $("q").value = "";
  ask(q, document.querySelector("input[name=mode]:checked").value);
};
// Up/Down in the message box walks back through the questions in the open chat (read from the page, never stored anywhere else).
let recall = -1, draft = "";
function sentQuestions() { return [...$("chat").querySelectorAll(".msg.user")].map((m) => m.textContent).reverse(); }
$("q").onkeydown = (ev) => {
  const q = $("q");
  if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); recall = -1; $("ask").requestSubmit(); return; }
  if ((ev.key !== "ArrowUp" && ev.key !== "ArrowDown") || ev.isComposing || ev.shiftKey || ev.altKey || ev.ctrlKey || ev.metaKey) return;
  const list = sentQuestions();
  if (ev.key === "ArrowUp") {
    if (q.value.slice(0, q.selectionStart).includes("\n") || !list.length || recall + 1 >= list.length) return;  // only from the first line
    if (recall < 0) draft = q.value;
    ev.preventDefault(); q.value = list[++recall]; q.setSelectionRange(0, 0);
  } else if (recall >= 0) {
    if (q.value.slice(q.selectionEnd).includes("\n")) return;  // only from the last line
    ev.preventDefault(); recall--; q.value = recall < 0 ? draft : list[recall]; q.setSelectionRange(q.value.length, q.value.length);
  }
};
$("q").addEventListener("input", () => { recall = -1; });
$("approval").onclose = () => { if ($("approval").returnValue === "local" && pendingLocal) ask(pendingLocal, "local"); };
$("resetBtn").onclick = async () => { await post("/api/reset"); newChat(); };
const ROUTE_NAMES = {local: "Local model", get claude() { return cloudName; }, search: "Web search", public_fact: "Web facts"};
const dur = (ms) => ms == null ? "–" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
function maskedText(kinds) {
  const t = Object.entries(kinds || {}).map(([k, n]) => `${n} ${k}`).join(", ");
  return t || "–";
}
$("auditBtn").onclick = async () => {
  const r = await (await fetch("/api/activity")).json();
  const h = $("actHealth"); h.replaceChildren();
  for (const [name, up] of [["Local model", r.health.ollama], ["Web search", r.health.search]]) {
    const p = el("span", "pill " + (up ? "up" : "down"), `${name}: ${up ? "up" : "off"}`);
    h.append(p);
  }
  const cards = $("actRoutes"); cards.replaceChildren();
  for (const [route, st] of Object.entries(r.summary.routes)) {
    const c = el("div", "card2");
    c.append(el("strong", "", ROUTE_NAMES[route] || route),
             el("span", "big", String(st.ok + st.blocked + st.error)),
             el("span", "muted", `${st.ok} ok · ${st.blocked} stopped · ${st.error} failed`),
             el("span", "muted", `avg ${dur(st.avg_ms)}`));
    cards.append(c);
  }
  if (!cards.children.length) cards.append(el("p", "muted", "No requests yet."));
  const m = Object.entries(r.summary.masked);
  $("actMasked").textContent = m.length ? "Masked before sending to Claude: " + m.map(([k, n]) => `${n} ${k}`).join(", ") : "";
  const body = $("actTable").tBodies[0]; body.replaceChildren();
  for (const x of r.recent) {
    const tr = el("tr");
    tr.append(el("td", "", new Date(x.ts * 1000).toLocaleTimeString()), el("td", "", ROUTE_NAMES[x.route] || x.route),
              el("td", "res " + (x.outcome || ""), x.outcome === "blocked" ? "stopped" : x.outcome === "ok" ? "ok" : "failed"),
              el("td", "", dur(x.ms)), el("td", "", maskedText(x.kinds)));
    body.append(tr);
  }
  const raw = await (await fetch("/api/audit")).json();
  $("auditBody").textContent = raw.rows.map((x) => JSON.stringify(x)).join("\n") || "No entries yet.";
  $("auditDlg").showModal();
  $("auditDlg").scrollTop = 0;
};
boot();

const THEMES = ["auto", "light", "dark"];
const STYLES = ["mac", "indigo", "ocean", "forest", "graphite", "vision"];
function applyTheme(t) {
  if (t === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  for (const id of ["themeBtn", "themeBtn2"]) $(id).textContent = "Theme: " + t[0].toUpperCase() + t.slice(1);
}
function applyStyle(k) { document.documentElement.dataset.style = k; $("styleSel").value = k; }
function curTheme() { try { return localStorage.getItem("ph_theme") || "auto"; } catch (e) { return "auto"; } }
function curStyle() { try { const k = localStorage.getItem("ph_style"); return STYLES.includes(k) ? k : "mac"; } catch (e) { return "mac"; } }
// The account's saved choice wins after login; the browser copy only styles the login page.
function applyPrefs(p) {
  const t = THEMES.includes(p.theme) ? p.theme : curTheme(), k = STYLES.includes(p.style) ? p.style : curStyle();
  try { t === "auto" ? localStorage.removeItem("ph_theme") : localStorage.setItem("ph_theme", t); localStorage.setItem("ph_style", k); } catch (e) {}
  applyTheme(t); applyStyle(k);
}
const savePrefs = () => post("/api/prefs", {style: curStyle(), theme: curTheme()}).catch(() => {});

// Extreme privacy: the server answers every question on this Mac whatever the mode says; here the choices just show it.
function setExtreme(on) {
  $("extreme").checked = on;
  document.querySelector(`input[name=mode][value=${on ? "local" : "auto"}]`).checked = true;  // off puts it back to Auto
  for (const r of document.querySelectorAll("input[name=mode]")) r.disabled = on;
  document.body.classList.toggle("extreme", on);
  $("ask").dataset.extreme = on ? "1" : "";
  if (typeof syncVoice === "function" && typeof SR !== "undefined") syncVoice();
}
$("extreme").onchange = async () => {
  const on = $("extreme").checked;
  const r = await post("/api/prefs", {extreme: on});
  if (!r.ok) { $("extreme").checked = !on; return; }
  setExtreme(on); loadSched().catch(() => {});
};
for (const id of ["themeBtn", "themeBtn2"]) $(id).onclick = () => {
  const t = THEMES[(THEMES.indexOf(curTheme()) + 1) % 3];
  try { t === "auto" ? localStorage.removeItem("ph_theme") : localStorage.setItem("ph_theme", t); } catch (e) {}
  applyTheme(t);
  if (!$("app").hidden) savePrefs();
};
$("styleSel").onchange = () => {
  const k = $("styleSel").value;
  try { localStorage.setItem("ph_style", k); } catch (e) {}
  applyStyle(k); savePrefs();
};
applyTheme(curTheme()); applyStyle(curStyle());

// Demo only: a pick list of ready-made questions, one per scenario. Picking fills the box and the mode; Send submits.
const SAMPLES = [
  ["Local: library", [
    ["local", "What filing status and allowances are on my W-4?"],
    ["local", "How much is my minimum payment and when is it due?"],
    ["local", "What deposits and withdrawals are on Maria's statement?"],
    ["local", "What did I spend on my credit card this month?"]]],
  ["Local: general notes", [
    ["local", "What should I try to eat in Lisbon?"],
    ["local", "Plan a two-day Lisbon itinerary from my notes."]]],
  ["Web facts (nothing private sent)", [
    ["web", "What are the current mortgage rates?"],
    ["auto", "What is the latest news on interest rates today?"]]],
  ["Claude, masked", [
    ["claude", "Summarise my bank statement for Claude"],
    ["claude", "Draft a polite email to Jane Doe (jane.doe@example.com) about the $4,250.00 invoice due 10/15/2026."]]],
  ["Stopped before sending (private data)", [
    ["claude", "Summarise my W-4 and bank statement for Claude"]]],
  ["Guards", [
    ["auto", "What is my filing status? What is my balance? What is due? What is my address?"],
    ["local", "x".repeat(8100)]]],
];
function setupSamples(on) {
  $("samples").hidden = !on;
  const sel = $("sampleSel");
  if (!on || sel.options.length) return;
  sel.append(el("option", "", "Pick a question to try…"));
  sel.firstChild.value = "";
  for (const [group, items] of SAMPLES) {
    const g = document.createElement("optgroup"); g.label = group;
    items.forEach(([mode, q], i) => {
      const o = el("option", "", q.length > 70 ? q.slice(0, 67) + "… (very long)" : q);
      o.value = group + "|" + i; g.append(o);
    });
    sel.append(g);
  }
  sel.onchange = () => {
    if (!sel.value) return;
    const [group, i] = sel.value.split("|");
    const [mode, q] = SAMPLES.find((x) => x[0] === group)[1][+i];
    document.querySelector(`input[name=mode][value=${mode}]`).checked = true;
    $("q").value = q; $("q").focus();
  };
}
const mobile = matchMedia("(max-width:760px)");
const syncSide = () => { $("side").classList.toggle("collapsed", mobile.matches && $("sideBtn").getAttribute("aria-expanded") !== "true"); };
$("sideBtn").onclick = () => { $("sideBtn").setAttribute("aria-expanded", $("sideBtn").getAttribute("aria-expanded") === "true" ? "false" : "true"); syncSide(); };
mobile.onchange = syncSide; syncSide();

const panelOff = () => { try { return localStorage.getItem("panelOff") === "1"; } catch { return false; } };
const syncPanel = () => {
  const off = panelOff();
  document.querySelector("main").classList.toggle("side-off", off);
  $("panelBtn").textContent = off ? "Show panel" : "Hide panel"; $("panelBtn").setAttribute("aria-expanded", off ? "false" : "true");
};
$("panelBtn").onclick = () => { try { localStorage.setItem("panelOff", panelOff() ? "0" : "1"); } catch {} syncPanel(); };
syncPanel();

$("scope").addEventListener("change", () => updateTip(...tipCounts));

// Sidebar sections: open on a wide screen, all minimised on a phone (tap to expand).
const secs = () => document.querySelectorAll("details.sec");
const syncSecs = () => secs().forEach((d) => { d.open = !mobile.matches; });
mobile.addEventListener("change", syncSecs); syncSecs();


// --- Voice input: record and transcribe on the Mac (private), or use the browser's own dictation (the audio goes to Apple or Google).
const voice = {rec: null, chunks: [], stream: null, sr: null};
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
const voiceMode = () => {
  try { if ($("extreme").checked) return "mac"; return localStorage.getItem("ph_voice") === "device" && SR ? "device" : "mac"; } catch (e) { return "mac"; }
};
function syncVoice() {
  const dev = $("voiceSel").querySelector("option[value=device]");
  dev.disabled = !SR || $("extreme").checked;
  $("voiceSel").value = voiceMode();
  $("mic").hidden = !navigator.mediaDevices?.getUserMedia && !SR;
}
$("voiceSel").onchange = () => { try { localStorage.setItem("ph_voice", $("voiceSel").value); } catch (e) {} syncVoice(); };
$("extreme").addEventListener("change", syncVoice);
syncVoice();

function micState(on, label) {
  $("mic").setAttribute("aria-pressed", String(on)); $("mic").classList.toggle("rec", on);
  $("mic").textContent = on ? "⏹" : "🎤"; $("mic").title = label || (on ? "Stop" : "Speak your question");
}
function addText(t) {
  if (!t) return;
  const q = $("q"); q.value = (q.value.trim() ? q.value.trim() + " " : "") + t; q.focus();
}
async function micToggle() {
  if (voice.rec) { voice.rec.stop(); return; }
  if (voice.sr) { voice.sr.stop(); return; }
  if (voiceMode() === "device") {
    const sr = voice.sr = new SR(); sr.interimResults = false; sr.lang = navigator.language || "en-US";
    sr.onresult = (e) => addText([...e.results].map((r) => r[0].transcript).join(" ").trim());
    sr.onerror = (e) => addMsg("notice", e.error === "not-allowed" ? "Microphone access was blocked. Allow it in your browser settings." : "Dictation stopped (" + e.error + ").");
    sr.onend = () => { voice.sr = null; micState(false); };
    sr.start(); micState(true); return;
  }
  try {
    voice.stream = await navigator.mediaDevices.getUserMedia({audio: true});
  } catch (e) {
    addMsg("notice", "Microphone access was blocked. Allow it for this site in your browser settings and try again."); return;
  }
  const rec = voice.rec = new MediaRecorder(voice.stream); voice.chunks = [];
  rec.ondataavailable = (e) => { if (e.data.size) voice.chunks.push(e.data); };
  rec.onstop = async () => {
    voice.stream.getTracks().forEach((t) => t.stop()); voice.rec = null;
    micState(false, "Transcribing…"); $("mic").disabled = true;
    try {
      const blob = new Blob(voice.chunks, {type: rec.mimeType});
      const bytes = new Uint8Array(await blob.arrayBuffer()); let bin = "";
      for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      const r = await post("/api/transcribe", {data: btoa(bin)});
      const j = await r.json();
      if (r.ok) addText(j.text || ""); else addMsg("notice", j.error || "Could not transcribe that.");
    } catch (e) { addMsg("notice", "Could not transcribe that."); }
    $("mic").disabled = false; micState(false);
  };
  rec.start(); micState(true, "Stop and transcribe");
}
$("mic").onclick = micToggle;

// every dialog gets a close (X) that stays visible while scrolling, so a phone never traps you; tapping outside also closes read-only ones
for (const dlg of document.querySelectorAll("dialog")) {
  const x = document.createElement("button");
  x.type = "button"; x.className = "dlgX ghost"; x.textContent = "✕"; x.setAttribute("aria-label", "Close");
  x.onclick = () => { if (dlg.dispatchEvent(new Event("cancel", { cancelable: true }))) dlg.close(); };
  dlg.prepend(x);
  if (["auditDlg", "acctDlg", "approval"].includes(dlg.id)) {
    dlg.addEventListener("click", (ev) => {
      if (ev.target !== dlg) return;
      const r = dlg.getBoundingClientRect();
      if (ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom) x.click();
    });
  }
}

$("reviewCloud").onchange = async () => {
  const on = $("reviewCloud").checked;
  const r = await post("/api/prefs", {review_cloud: on});
  if (!r.ok) $("reviewCloud").checked = !on;
};

// Optional OS-level lockdown (administrator, this computer only). macOS shows its own password dialog; the app never sees the password.
async function loadLock() {
  try {
    const r = await fetch("/api/admin/lockdown", {method: "POST", headers: {"Content-Type": "application/json", "X-Requested-With": "privhybrid"}, body: JSON.stringify({action: "status"})});
    if (!r.ok) return;  // not the administrator: the block stays hidden
    const d = await r.json();
    $("lockRow").hidden = false;
    $("lockMsg").textContent = d.message || "";
    $("lockOn").disabled = !d.local || d.platform !== "darwin";
  } catch (e) { /* not signed in yet */ }
}
$("lockOn").onclick = async () => {
  if (!confirm("This asks macOS for your administrator password and blocks the internet for the app's user (loopback only). It can be removed with scripts/lockdown.sh off. Continue?")) return;
  const r = await post("/api/admin/lockdown", {action: "on", confirm: true});
  const d = await r.json().catch(() => ({}));
  $("lockMsg").textContent = d.message || d.error || "";
};
