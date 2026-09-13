const historyEl = document.getElementById("history");
const emptyStateEl = document.getElementById("empty-state");
const statusEl = document.getElementById("socket-status");
const statusDotEl = statusEl.querySelector(".status-dot");
const statusTextEl = document.getElementById("socket-status-text");
const inspectorEl = document.getElementById("inspector");
const inspectorToggleBtn = document.getElementById("inspector-toggle");
const inspectorCloseBtn = document.getElementById("inspector-close");
const toolCallsEl = document.getElementById("tool-calls");
const toolCountEl = document.getElementById("tool-count");
const inputEl = document.getElementById("chat-input");
const sendBtn = document.getElementById("send-btn");
const quickButtons = document.querySelectorAll(".quick-btn");
const sidebarEl = document.getElementById("sidebar");
const sidebarToggleBtn = document.getElementById("sidebar-toggle");
const sidebarBackdrop = document.getElementById("sidebar-backdrop");
const sessionBadgeEl = document.getElementById("session-badge");
const newChatBtn = document.getElementById("new-chat-btn");
const runtimeModelEl = document.getElementById("runtime-model");
const usageInEl = document.getElementById("usage-in");
const usageOutEl = document.getElementById("usage-out");
const viewTitleEl = document.getElementById("view-title");
const viewSubtitleEl = document.getElementById("view-subtitle");

let socket = null;
let reconnectTimer = null;
let sessionId = null;
let modelName = null;
let authEnabled = false;
let currentUser = null; // { id, email, name, picture } when signed in
let authReady = false;  // true once we've resolved auth state and (if needed) signed in
let sessionUsage = { input_tokens: 0, output_tokens: 0 };
let inspectorCalls = [];
const INSPECTOR_KEY = "vulngent.inspector.collapsed";
let inspectorCollapsed = localStorage.getItem(INSPECTOR_KEY) === "1";

// --- All module state lives here: anything a top-level call path can touch
// must be initialized before evaluation continues (TDZ guard).
let typingBubble = null;
let pendingSpawn = null; // { prompt?: string, prefill?: string, label?: string }
let openPopover = null;

// Agent companion physics
let cursorTarget = { x: 0, y: 0 };
let cursorPos = { x: 0, y: 0 };
let cursorActive = false;
let cursorRafId = null;
let hoverItem = null; // .dash-item element being hovered
let dwellTimer = null;
let hideTimer = null;
let menuItem = null; // item the pinned menu refers to
let agentAnchor = null; // "navbar" | "bubble" | null (free mouse-follow)
let agentBubbleEl = null;
let agentLerpFactor = 0.18;

// Section selection
let sectionPopover = null;
let sectionDocListenerBound = false;

// Streaming responses
let streamBubble = null;
let streamTextEl = null;
let streamText = "";

// ==== Views ====
const VIEWS = {
  chat: { title: "Remediation Chat", subtitle: "Ask about assets, vulnerabilities, or plan actions." },
  dashboard: { title: "Dashboard", subtitle: "Ledger posture at a glance." },
  reports: { title: "Reports", subtitle: "Generate shareable status reports." },
  settings: { title: "Settings", subtitle: "Environment, integrations, and report branding." },
  profile: { title: "Profile", subtitle: "Your account and session." },
};
let currentView = "chat";

const NAV_ACTIVE = ["bg-indigo-50", "text-indigo-700"];
const NAV_IDLE = ["text-slate-600", "hover:bg-slate-100"];

function setView(view) {
  if (!VIEWS[view]) return;
  currentView = view;
  for (const name of Object.keys(VIEWS)) {
    const section = document.getElementById(`view-${name}`);
    section.classList.toggle("hidden", name !== view);
    section.classList.toggle("flex", name === view && name === "chat");
  }
  document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
    const active = btn.dataset.view === view;
    btn.classList.remove(...NAV_ACTIVE, ...NAV_IDLE);
    btn.classList.add(...(active ? NAV_ACTIVE : NAV_IDLE));
  });
  viewTitleEl.textContent = VIEWS[view].title;
  viewSubtitleEl.textContent = VIEWS[view].subtitle;
  document.querySelectorAll(".chat-only").forEach((el) => {
    el.classList.toggle("hidden", view !== "chat");
  });
  applyInspectorVisibility();
  setSidebarOpen(false);
  resetCursor();
  if (view === "dashboard") loadDashboard();
  if (view === "settings") loadSettings();
  if (view === "profile") renderProfileView();
  repositionAgent();
}

document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
  btn.addEventListener("click", () => setView(btn.dataset.view));
});
// Initial view is applied at the end of the module: setView touches state
// (cursor timers, dashboard els) declared further down, and calling it here
// hits the temporal dead zone and kills the whole script.
queueMicrotask(() => setView("chat"));

// ==== Inspector panel ====
function applyInspectorVisibility() {
  const hidden = inspectorCollapsed || currentView !== "chat";
  inspectorEl.classList.toggle("hidden", hidden);
  inspectorEl.classList.toggle("lg:flex", !hidden);
  requestAnimationFrame(drawWires);
}

function setInspectorCollapsed(collapsed) {
  inspectorCollapsed = collapsed;
  localStorage.setItem(INSPECTOR_KEY, collapsed ? "1" : "0");
  applyInspectorVisibility();
}

applyInspectorVisibility();
inspectorToggleBtn.addEventListener("click", () => setInspectorCollapsed(!inspectorCollapsed));
inspectorCloseBtn.addEventListener("click", () => setInspectorCollapsed(true));

// ==== Mobile sidebar ====
function setSidebarOpen(open) {
  if (open) {
    sidebarEl.classList.remove("hidden", "-translate-x-full");
    sidebarEl.classList.add("flex");
    sidebarBackdrop.classList.remove("hidden");
  } else {
    sidebarEl.classList.add("hidden", "-translate-x-full");
    sidebarEl.classList.remove("flex");
    sidebarBackdrop.classList.add("hidden");
  }
}
sidebarToggleBtn.addEventListener("click", () => setSidebarOpen(true));
sidebarBackdrop.addEventListener("click", () => setSidebarOpen(false));

// ==== WebSocket ====
function connect() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${protocol}://${window.location.host}/ws`);
  socket.addEventListener("open", () => updateStatus("ready"));
  socket.addEventListener("message", (event) => handleSocketMessage(event));
  socket.addEventListener("close", () => {
    updateStatus("offline");
    reconnectTimer = setTimeout(connect, 2000);
  });
  socket.addEventListener("error", () => updateStatus("offline"));
}

// ==== Auth ====
const loginOverlayEl = document.getElementById("login-overlay");
const googleBtnEl = document.getElementById("google-signin-btn");
const microsoftBtnEl = document.getElementById("microsoft-signin-btn");
const loginErrorEl = document.getElementById("login-error");
const profileCardEl = document.getElementById("profile-card");
const profileAvatarEl = document.getElementById("profile-avatar");
const profileNameEl = document.getElementById("profile-name");
const profileEmailEl = document.getElementById("profile-email");
const logoutBtn = document.getElementById("logout-btn");

let authConfig = { google: { enabled: false }, microsoft: { enabled: false } };
let msalInstance = null;

function initialsFrom(user) {
  const src = (user && (user.name || user.email)) || "";
  const parts = src.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

async function initAuth() {
  try {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    authEnabled = !!data.enabled;
    currentUser = data.user || null;
  } catch (err) {
    authEnabled = false;
    currentUser = null;
  }

  if (!authEnabled || currentUser) {
    // Auth off, or already signed in: open the app.
    hideLogin();
    renderProfile();
    startApp();
    return;
  }

  // Auth on but not signed in: fetch provider config, show the login screen,
  // and DON'T open the socket or start the agent companion yet.
  try {
    authConfig = await (await fetch("/api/auth/config")).json();
  } catch (err) {
    /* keep defaults */
  }
  showLogin();
  renderProfile();
}

function startApp() {
  if (authReady) return;
  authReady = true;
  setAgentAnchor("navbar"); // spawn the agent companion only once we're in.
  connect();
  loadSessions();
}

function showLogin() {
  loginOverlayEl.classList.remove("hidden");
  loginOverlayEl.classList.add("flex");
  renderGoogleButton();
  renderMicrosoftButton();
}

function hideLogin() {
  loginOverlayEl.classList.add("hidden");
  loginOverlayEl.classList.remove("flex");
}

function renderGoogleButton() {
  if (!authConfig.google || !authConfig.google.enabled) return;
  // GIS may still be loading; retry until google.accounts is ready.
  if (!(window.google && google.accounts && google.accounts.id)) {
    setTimeout(renderGoogleButton, 150);
    return;
  }
  google.accounts.id.initialize({
    client_id: authConfig.google.client_id,
    callback: onGoogleCredential,
  });
  googleBtnEl.innerHTML = "";
  google.accounts.id.renderButton(googleBtnEl, {
    theme: "outline",
    size: "large",
    shape: "pill",
    text: "signin_with",
    logo_alignment: "left",
    width: 260,
  });
}

function renderMicrosoftButton() {
  if (!authConfig.microsoft || !authConfig.microsoft.enabled) return;
  microsoftBtnEl.classList.remove("hidden");
}

async function onGoogleCredential(response) {
  await submitLogin("/api/auth/google", { credential: response.credential });
}

async function ensureMsal() {
  if (msalInstance) return msalInstance;
  // MSAL browser lib may still be loading.
  let tries = 0;
  while (!(window.msal && msal.PublicClientApplication) && tries < 40) {
    await new Promise((r) => setTimeout(r, 150));
    tries += 1;
  }
  if (!(window.msal && msal.PublicClientApplication)) {
    throw new Error("Microsoft sign-in library failed to load.");
  }
  const tenant = authConfig.microsoft.tenant || "common";
  msalInstance = new msal.PublicClientApplication({
    auth: {
      clientId: authConfig.microsoft.client_id,
      authority: `https://login.microsoftonline.com/${tenant}`,
      redirectUri: window.location.origin,
    },
    cache: { cacheLocation: "sessionStorage" },
  });
  await msalInstance.initialize();
  return msalInstance;
}

async function onMicrosoftClick() {
  loginErrorEl.classList.add("hidden");
  try {
    const pca = await ensureMsal();
    const result = await pca.loginPopup({ scopes: ["openid", "profile", "email"] });
    const idToken = result && result.idToken;
    if (!idToken) throw new Error("No id token returned by Microsoft.");
    await submitLogin("/api/auth/microsoft", { id_token: idToken });
  } catch (err) {
    loginErrorEl.textContent = (err && err.message) || "Microsoft sign-in failed.";
    loginErrorEl.classList.remove("hidden");
  }
}

async function submitLogin(url, body) {
  loginErrorEl.classList.add("hidden");
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Sign-in failed.");
    }
    const data = await res.json();
    currentUser = data.user;
    hideLogin();
    renderProfile();
    startApp();
  } catch (err) {
    loginErrorEl.textContent = err.message || "Sign-in failed.";
    loginErrorEl.classList.remove("hidden");
  }
}

function renderProfile() {
  if (!authEnabled || !currentUser) {
    profileCardEl.classList.add("hidden");
    profileCardEl.classList.remove("flex");
    return;
  }
  profileCardEl.classList.remove("hidden");
  profileCardEl.classList.add("flex");
  profileNameEl.textContent = currentUser.name || currentUser.email || "Signed in";
  profileEmailEl.textContent = currentUser.email || "";
  paintAvatar(profileAvatarEl, currentUser, "text-[11px]");
  if (currentView === "profile") renderProfileView();
}

// Paint an avatar element: use the picture if present+loadable, else initials.
// `el` is a <span> container we fill with either an <img> or initials text.
function paintAvatar(el, user, textClass = "text-xs") {
  if (!el) return;
  const initials = initialsFrom(user);
  el.textContent = initials;
  el.classList.add("avatar-initials");
  if (user && user.picture) {
    const img = new Image();
    img.referrerPolicy = "no-referrer";
    img.onload = () => {
      el.textContent = "";
      el.classList.remove("avatar-initials");
      img.className = "h-full w-full rounded-[inherit] object-cover";
      el.appendChild(img);
    };
    img.onerror = () => {
      /* keep initials */
    };
    img.src = user.picture;
  }
}

function renderProfileView() {
  const el = document.getElementById("view-profile-body");
  if (!el) return;
  if (!authEnabled) {
    el.innerHTML = `<div class="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500">
      Authentication is disabled on this server. Set a Google or Microsoft client id to enable user accounts.
    </div>`;
    return;
  }
  if (!currentUser) {
    el.innerHTML = `<div class="rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-500">You are not signed in.</div>`;
    return;
  }
  const providerLabel = currentUser.provider === "microsoft" ? "Microsoft" : "Google";
  el.innerHTML = `
    <div class="rounded-2xl border border-slate-200 bg-white p-6">
      <div class="flex items-center gap-4">
        <span id="profile-view-avatar" class="flex h-16 w-16 shrink-0 items-center justify-center overflow-hidden rounded-2xl bg-slate-900 text-xl font-semibold text-white"></span>
        <div class="min-w-0">
          <p class="truncate text-lg font-semibold text-slate-800">${escapeHTML(currentUser.name || "—")}</p>
          <p class="truncate text-sm text-slate-400">${escapeHTML(currentUser.email || "")}</p>
          <span class="mt-1 inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-500">Signed in with ${providerLabel}</span>
        </div>
      </div>
      <dl class="mt-6 grid grid-cols-1 gap-4 border-t border-slate-100 pt-5 sm:grid-cols-2">
        <div>
          <dt class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Name</dt>
          <dd class="mt-0.5 text-sm text-slate-700">${escapeHTML(currentUser.name || "—")}</dd>
        </div>
        <div>
          <dt class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Email</dt>
          <dd class="mt-0.5 text-sm text-slate-700">${escapeHTML(currentUser.email || "—")}</dd>
        </div>
        <div>
          <dt class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Provider</dt>
          <dd class="mt-0.5 text-sm text-slate-700">${providerLabel}</dd>
        </div>
        <div>
          <dt class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">User ID</dt>
          <dd class="mt-0.5 font-mono text-sm text-slate-700">#${currentUser.id}</dd>
        </div>
      </dl>
      <div class="mt-6 border-t border-slate-100 pt-5">
        <button id="profile-logout" class="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:bg-red-50 hover:text-red-500">Sign out</button>
      </div>
    </div>`;
  paintAvatar(document.getElementById("profile-view-avatar"), currentUser, "text-xl");
  const btn = document.getElementById("profile-logout");
  if (btn) btn.addEventListener("click", () => logoutBtn && logoutBtn.click());
}

if (logoutBtn) {
  logoutBtn.addEventListener("click", async (event) => {
    event.stopPropagation();
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (err) {
      /* ignore */
    }
    if (window.google && google.accounts && google.accounts.id) {
      google.accounts.id.disableAutoSelect();
    }
    window.location.reload();
  });
}
if (microsoftBtnEl) microsoftBtnEl.addEventListener("click", onMicrosoftClick);
if (profileCardEl) {
  profileCardEl.addEventListener("click", () => setView("profile"));
}

initAuth();

function handleSocketMessage(event) {
  const payload = JSON.parse(event.data);
  switch (payload.type) {
    case "session":
      handleNewSession(payload);
      break;
    case "history":
      renderHistory(payload.entries ?? []);
      break;
    case "agent_response":
      removeTypingIndicator();
      if (streamBubble) {
        finalizeStream(payload.entry);
      } else {
        renderAgentMessage(payload.entry);
      }
      if (payload.session_usage) updateSessionUsage(payload.session_usage);
      break;
    case "stream_start":
      startStreamBubble();
      break;
    case "stream_delta":
      appendStreamDelta(payload.delta || "");
      break;
    case "tool_call_progress":
      appendToolCall(payload.call);
      break;
    case "report_suggestion":
      renderReportSuggestion(payload.report);
      break;
    case "confirmation_needed":
      renderConfirmationCard(payload.plan);
      break;
    case "confirmation_cleared":
      resolveConfirmationCards();
      break;
    case "status":
      updateStatus(payload.status);
      break;
    case "error":
      renderSystemMessage(payload.message);
      break;
    default:
      break;
  }
}

// ==== Session ====
function handleNewSession(payload) {
  sessionId = payload.session_id;
  modelName = payload.model;
  sessionBadgeEl.textContent = `session ${sessionId}`;
  runtimeModelEl.textContent = modelName || "—";
  runtimeModelEl.title = modelName || "";
  // Fresh session: clear chat, inspector, and usage counters.
  historyEl.innerHTML = "";
  typingBubble = null;
  inspectorCalls = [];
  renderInspector();
  updateSessionUsage({ input_tokens: 0, output_tokens: 0 });
  restoreEmptyState();
  loadSessions();
  // A dashboard action asked us to seed this fresh session.
  if (pendingSpawn) {
    const spawn = pendingSpawn;
    pendingSpawn = null;
    if (spawn.prefill) {
      setView("chat");
      inputEl.value = spawn.prefill;
      autogrowInput();
      inputEl.focus();
    } else if (spawn.prompt) {
      appendUserMessage(spawn.prompt);
      socket.send(JSON.stringify({ type: "user_message", text: spawn.prompt }));
    }
  }
}

function renderHistory(entries) {
  for (const entry of entries) {
    if (entry.role === "user") {
      appendUserMessage(entry.message || "");
    } else {
      renderAgentMessage(entry);
    }
  }
}

sessionBadgeEl.addEventListener("click", async () => {
  if (!sessionId) return;
  try {
    await navigator.clipboard.writeText(sessionId);
    sessionBadgeEl.textContent = "copied!";
    setTimeout(() => (sessionBadgeEl.textContent = `session ${sessionId}`), 1200);
  } catch (err) {
    /* clipboard unavailable */
  }
});

newChatBtn.addEventListener("click", () => {
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({ type: "new_chat" }));
});

function updateSessionUsage(usage) {
  sessionUsage = usage;
  usageInEl.textContent = formatTokens(usage.input_tokens || 0);
  usageOutEl.textContent = formatTokens(usage.output_tokens || 0);
  usageInEl.parentElement.title = `${(usage.input_tokens || 0).toLocaleString()} input tokens this session`;
  usageOutEl.parentElement.title = `${(usage.output_tokens || 0).toLocaleString()} output tokens this session`;
}

function formatTokens(n) {
  if (n >= 1000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`;
  return String(n);
}

// ==== Status pill ====
const STATUS_META = {
  ready: { label: "Ready", pill: "border-emerald-200 bg-emerald-50 text-emerald-700", dot: "bg-emerald-500" },
  thinking: { label: "Thinking…", pill: "border-amber-200 bg-amber-50 text-amber-700", dot: "bg-amber-500" },
  awaiting_confirmation: { label: "Needs confirmation", pill: "border-indigo-200 bg-indigo-50 text-indigo-700", dot: "bg-indigo-500" },
  offline: { label: "Disconnected", pill: "border-red-200 bg-red-50 text-red-600", dot: "bg-red-500" },
  connecting: { label: "Connecting…", pill: "border-slate-200 bg-white text-slate-500", dot: "bg-slate-300" },
};

function updateStatus(mode) {
  const meta = STATUS_META[mode] || STATUS_META.connecting;
  statusTextEl.textContent = meta.label;
  statusEl.className = `status-pill inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${meta.pill}${mode === "thinking" ? " status-thinking" : ""}`;
  statusDotEl.className = `status-dot h-1.5 w-1.5 rounded-full ${meta.dot}`;
  const busy = mode === "thinking" || mode === "offline";
  sendBtn.disabled = busy;
  if (mode === "thinking") {
    showTypingIndicator();
    if (currentView === "chat") {
      setAgentBubble(typingBubble);
      setAgentAnchor("bubble", typingBubble);
    }
  } else {
    removeTypingIndicator();
    if (mode === "ready" || mode === "offline") {
      clearAgentBubble();
      setAgentAnchor("navbar");
    }
  }
}

// ==== Composer ====
function autogrowInput() {
  inputEl.style.height = "auto";
  inputEl.style.height = Math.min(inputEl.scrollHeight, 160) + "px";
}
inputEl.addEventListener("input", autogrowInput);
inputEl.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    triggerSend();
  }
});
sendBtn.addEventListener("click", () => triggerSend());

quickButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const prompt = button.dataset.prompt;
    if (!prompt) return;
    setView("chat");
    inputEl.value = prompt;
    autogrowInput();
    triggerSend();
  });
});

function triggerSend() {
  const text = inputEl.value.trim();
  if (!text) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    renderSystemMessage("Not connected to the server. Retrying…");
    return;
  }
  inputEl.value = "";
  autogrowInput();
  appendUserMessage(text);
  socket.send(JSON.stringify({ type: "user_message", text }));
}

// ==== Chat rendering ====
const EMPTY_STATE_HTML = emptyStateEl ? emptyStateEl.outerHTML : "";

function hideEmptyState() {
  const el = document.getElementById("empty-state");
  if (el) el.remove();
}

function restoreEmptyState() {
  if (document.getElementById("empty-state")) return;
  historyEl.insertAdjacentHTML("afterend", EMPTY_STATE_HTML);
}

function scrollToBottom() {
  historyEl.scrollTop = historyEl.scrollHeight;
}

function showTypingIndicator() {
  if (typingBubble) return;
  hideEmptyState();
  typingBubble = document.createElement("article");
  typingBubble.className = "chat-message flex items-start gap-2.5";
  typingBubble.innerHTML = `
    ${avatarSvg()}
    <div class="agent-bubble flex items-center gap-1 rounded-2xl rounded-tl-sm border border-slate-200 bg-white px-3.5 py-2.5 shadow-sm">
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
      <span class="typing-dot"></span>
    </div>`;
  historyEl.appendChild(typingBubble);
  scrollToBottom();
}
function removeTypingIndicator() {
  if (typingBubble) {
    typingBubble.remove();
    typingBubble = null;
  }
}

// The indigo ring marking the bubble the agent is streaming into.
function setAgentBubble(articleEl) {
  clearAgentBubble();
  if (!articleEl) return;
  const bubble = articleEl.querySelector(".agent-bubble") || articleEl;
  bubble.classList.add("agent-active-bubble");
}
function clearAgentBubble() {
  document.querySelectorAll(".agent-active-bubble").forEach((el) => el.classList.remove("agent-active-bubble"));
}

// ==== Streaming responses ====
function startStreamBubble() {
  if (streamBubble) return;
  hideEmptyState();
  removeTypingIndicator();
  streamText = "";
  streamBubble = document.createElement("article");
  streamBubble.className = "chat-message flex items-start gap-2.5";
  streamBubble.innerHTML = `
    ${avatarSvg()}
    <div class="agent-bubble max-w-[80%] rounded-2xl rounded-tl-sm border border-slate-200 bg-white px-3.5 py-2.5 text-sm shadow-sm">
      <div class="markdown stream-text"></div>
    </div>`;
  streamTextEl = streamBubble.querySelector(".stream-text");
  historyEl.appendChild(streamBubble);
  scrollToBottom();
  setAgentBubble(streamBubble);
  if (currentView === "chat") setAgentAnchor("bubble", streamBubble);
}

function appendStreamDelta(delta) {
  if (!streamBubble) startStreamBubble();
  streamText += delta;
  streamTextEl.textContent = streamText;
  scrollToBottom();
  // Keep the agent chip riding the tail of the streamed text.
  if (currentView === "chat" && agentAnchor === "bubble" && agentBubbleEl === streamBubble) {
    const point = anchorPoint();
    if (point) cursorTarget = point;
  }
}

function finalizeStream(entry) {
  const bubble = streamBubble;
  streamBubble = null;
  streamTextEl = null;
  streamText = "";
  if (bubble) bubble.remove(); // replaced by the authoritative rendered entry
  renderAgentMessage(entry);
}

// Where should the agent chip be right now?
function repositionAgent() {
  if (currentView === "chat") {
    if (typingBubble) {
      setAgentAnchor("bubble", typingBubble);
    } else {
      const last = historyEl.lastElementChild;
      if (last && last.classList.contains("chat-message")) {
        springAgentTo("bubble", last);
      } else {
        springAgentTo("navbar");
      }
    }
  } else if (currentView === "dashboard") {
    startRoam(dashboardViewEl, 120);
  } else if (currentView === "chat") {
    startRoam(historyEl, 60);
  } else {
    springAgentTo("navbar");
  }
}

function startRoam(container, yOffset) {
  setAgentAnchor(null); // hand control to the mouse-follow handlers
  agentLerpFactor = 0.18;
  agentCursorEl.classList.remove("agent-spring");
  agentCursorEl.classList.add("agent-follow");
  if (!cursorActive) {
    const rect = container.getBoundingClientRect();
    startCursor(rect.left + rect.width / 2, rect.top + yOffset);
  }
}

function avatarSvg(classes = "bg-indigo-50 text-indigo-600") {
  return `<span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${classes}">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
  </span>`;
}

function feedbackTimestamp(timestamp) {
  if (!timestamp) return "";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function shortModelName(model) {
  if (!model) return "";
  return model.split("/").pop();
}

// Build a user avatar element (initials by default, replaced by photo if it loads).
// Returns null when auth is off / no user, so unauthenticated chat looks unchanged.
function buildUserAvatar() {
  if (!currentUser) return null;
  const span = document.createElement("span");
  span.className =
    "flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-lg bg-slate-900 text-[11px] font-semibold text-white";
  paintAvatar(span, currentUser, "text-[11px]");
  return span;
}

function appendUserMessage(text) {
  hideEmptyState();
  const wrapper = document.createElement("article");
  wrapper.className = "chat-message flex items-start justify-end gap-2.5";
  const bubble = document.createElement("div");
  bubble.className =
    "bubble-user max-w-[80%] whitespace-pre-wrap rounded-2xl rounded-tr-sm bg-slate-900 px-3.5 py-2.5 text-sm leading-relaxed text-slate-50 shadow-sm";
  bubble.textContent = text;
  wrapper.appendChild(bubble);
  const avatar = buildUserAvatar();
  if (avatar) wrapper.appendChild(avatar);
  historyEl.appendChild(wrapper);
  scrollToBottom();
}

function renderAgentMessage(entry) {
  hideEmptyState();
  const wrapper = document.createElement("article");
  wrapper.className = "chat-message flex items-start gap-2.5";

  const bubble = document.createElement("div");
  bubble.className = "max-w-[80%] rounded-2xl rounded-tl-sm border border-slate-200 bg-white px-3.5 py-2.5 text-sm shadow-sm";
  bubble.innerHTML = `<div class="markdown">${renderMessageWithSections(entry)}</div>`;

  if (entry.thoughts && entry.thoughts.length) {
    const thoughtsEl = document.createElement("details");
    thoughtsEl.className = "thoughts mt-2 border-t border-slate-100 pt-1.5 text-xs text-slate-400";
    thoughtsEl.innerHTML = `
      <summary class="flex items-center gap-1 text-[11px] font-medium text-slate-400 hover:text-slate-600">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6" /></svg>
        Reasoning (${entry.thoughts.length})
      </summary>
      <div class="mt-1 italic leading-snug">${entry.thoughts.map(escapeHTML).join("<br/>")}</div>`;
    bubble.appendChild(thoughtsEl);
  }

  // Per-tool chips = invocation reasons; they anchor the wire endpoints on the bubble side.
  const toolCalls = entry.tool_calls || [];
  if (toolCalls.length) {
    const chipsBar = document.createElement("div");
    chipsBar.className = "tool-chips mt-2 flex flex-wrap gap-1.5";
    toolCalls.forEach((call, idx) => {
      chipsBar.appendChild(buildToolChip(call, idx, entry));
    });
    bubble.appendChild(chipsBar);
  }

  const metaParts = [];
  const time = feedbackTimestamp(entry.timestamp);
  if (time) metaParts.push(time);
  if (entry.usage && (entry.usage.input_tokens || entry.usage.output_tokens)) {
    metaParts.push(`${formatTokens(entry.usage.input_tokens)} in · ${formatTokens(entry.usage.output_tokens)} out`);
  }
  if (entry.usage && entry.usage.model) {
    metaParts.push(shortModelName(entry.usage.model));
  }
  if (metaParts.length) {
    const meta = document.createElement("span");
    meta.className = "mt-1.5 block border-t border-slate-100 pt-1.5 text-[10px] text-slate-400";
    meta.textContent = metaParts.join(" · ");
    bubble.appendChild(meta);
  }

  bubble.classList.add("agent-bubble");
  wrapper.innerHTML = avatarSvg();
  wrapper.appendChild(bubble);
  historyEl.appendChild(wrapper);
  makeChatMsgHoverable(wrapper, entry.message || "");
  scrollToBottom();

  if (currentView === "chat") {
    setAgentBubble(wrapper);
    springAgentTo("bubble", wrapper);
  }

  updateInspector(entry.tool_calls ?? []);
  requestAnimationFrame(drawWires);
}

function buildToolChip(call, idx, entry) {
  const chip = document.createElement("button");
  const color = wireColor(call.call_id);
  chip.type = "button";
  chip.className = `tool-chip${call.is_error ? " tool-chip-err" : ""}`;
  chip.dataset.callId = call.call_id;
  chip.dataset.wireIndex = String(idx);
  chip.style.color = color;
  chip.style.borderColor = color;
  chip.style.background = `color-mix(in srgb, ${color} 10%, white)`;
  const argPreview = shortArgPreview(call);
  chip.title = `${call.name}\n${argPreview ? argPreview + `\n` : ""}#${idx + 1} · ${call.result || ""}`.slice(0, 300);
  const dot = document.createElement("span");
  dot.className = "wire-dot";
  const label = document.createElement("span");
  label.textContent = call.name.replace(/_/g, " ");
  chip.appendChild(dot);
  chip.appendChild(label);
  const lit = (on) => setWireLit(call.call_id, on);
  chip.addEventListener("mouseenter", () => lit(true));
  chip.addEventListener("mouseleave", () => lit(false));
  chip.addEventListener("click", () => {
    const card = document.getElementById(`tool-card-${cssEscape(call.call_id)}`);
    if (!card) return;
    lit(true);
    card.classList.add("wire-lit-card");
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    setTimeout(() => {
      lit(false);
      card.classList.remove("wire-lit-card");
    }, 1600);
  });
  return chip;
}

function shortArgPreview(call) {
  if (!call.arguments || typeof call.arguments === "string") return "";
  const entries = Object.entries(call.arguments).slice(0, 2);
  return entries.map(([k, v]) => `${k}=${String(v).slice(0, 40)}`).join(" ");
}

function renderSystemMessage(message) {
  hideEmptyState();
  const wrapper = document.createElement("article");
  wrapper.className = "chat-message flex items-start gap-2.5";
  wrapper.innerHTML = `
    ${avatarSvg("bg-red-50 text-red-500")}
    <div class="rounded-xl border border-red-200 bg-red-50 px-3.5 py-2 text-sm text-red-700">${escapeHTML(message)}</div>`;
  historyEl.appendChild(wrapper);
  scrollToBottom();
}

// ==== Response sections: highlight + continue ====

// Assistant bubbles are agent-hover targets (same UX as dashboard items).
function makeChatMsgHoverable(wrapper, rawText) {
  wrapper.classList.add("chat-msg-item");
  const sections = wrapper.querySelectorAll(".msg-section");
  const payload = { kind: "chat_msg", text: rawText };
  if (sections.length) {
    sections.forEach((sec) => {
      sec.dataset.item = JSON.stringify({ kind: "chat_msg", text: sec.dataset.sectionText || rawText });
    });
  } else {
    wrapper.dataset.item = JSON.stringify(payload);
  }
}

function renderMessageWithSections(entry) {
  const sections = Array.isArray(entry.sections) ? entry.sections.filter((s) => s && s.content) : [];
  if (!sections.length) {
    return renderMarkdown(entry.message);
  }
  let html = "";
  sections.forEach((s, i) => {
    html += `<div class="msg-section" data-section-key="${escapeHTML(s.key)}" data-section-text="${escapeHTML(s.content)}">`;
    if (sections.length > 1) {
      html += `<span class="section-tag">${escapeHTML(s.key.replace(/_/g, " "))}</span>`;
    }
    html += `<div class="markdown">${renderMarkdown(s.content)}</div></div>`;
  });
  return html;
}

function initSectionInteractions() {
  if (sectionDocListenerBound) return;
  sectionDocListenerBound = true;
  document.addEventListener("click", (event) => {
    const sectionEl = event.target.closest(".msg-section");
    if (!sectionEl) {
      dismissSectionPopover();
      return;
    }
    event.stopPropagation();
    if (sectionEl.classList.contains("section-selected")) {
      dismissSectionPopover();
      return;
    }
    selectSection(sectionEl);
  });
}

function selectSection(sectionEl) {
  dismissSectionPopover();
  sectionEl.classList.add("section-selected");
  const key = sectionEl.dataset.sectionKey || "section";
  const text = sectionEl.dataset.sectionText || "";
  const pop = document.createElement("div");
  pop.className = "section-popover absolute z-50 w-64 rounded-xl border border-slate-200 bg-white p-3 shadow-xl";
  pop.innerHTML = `
    <p class="text-[10px] font-semibold uppercase tracking-wider text-indigo-500">${escapeHTML(key.replace(/_/g, " "))}</p>
    <p class="mt-1 line-clamp-2 text-xs text-slate-500">${escapeHTML(text.slice(0, 120))}${text.length > 120 ? "…" : ""}</p>
    <div class="mt-2.5 flex gap-1.5">
      <button class="section-continue flex-1 rounded-lg bg-indigo-600 px-2.5 py-1.5 text-[11px] font-semibold text-white transition hover:bg-indigo-500">Go deeper</button>
      <button class="section-copy rounded-lg border border-slate-200 px-2.5 py-1.5 text-[11px] font-medium text-slate-500 transition hover:bg-slate-50" title="Copy section">Copy</button>
    </div>`;
  document.body.appendChild(pop);
  const rect = sectionEl.getBoundingClientRect();
  pop.style.left = `${Math.min(rect.left, window.innerWidth - 270)}px`;
  pop.style.top = `${rect.bottom + 6 + window.scrollY}px`;
  pop.querySelector(".section-continue").addEventListener("click", () => {
    dismissSectionPopover();
    continueOnSection(key, text);
  });
  pop.querySelector(".section-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      /* clipboard unavailable */
    }
    dismissSectionPopover();
  });
  sectionPopover = pop;
}

function dismissSectionPopover() {
  if (sectionPopover) {
    sectionPopover.remove();
    sectionPopover = null;
  }
  document.querySelectorAll(".msg-section.section-selected").forEach((el) => el.classList.remove("section-selected"));
}

function continueOnSection(key, text) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    renderSystemMessage("Not connected to the server.");
    return;
  }
  const quoted = text.length > 400 ? `${text.slice(0, 400)}…` : text;
  const prompt = `Go deeper on the "${key.replace(/_/g, " ")}" section of your last reply. Expand with more detail, data, and concrete next steps. The section was:\n\n> ${quoted.replace(/\n/g, "\n> ")}`;
  appendUserMessage(`Go deeper: ${key.replace(/_/g, " ")}`);
  socket.send(JSON.stringify({ type: "user_message", text: prompt }));
}

initSectionInteractions();

// ==== Report suggestions (inline in chat) ====
function renderReportSuggestion(report) {
  hideEmptyState();
  const format = String((report && report.format) || "pdf").toLowerCase();
  const reason = (report && report.reason) || "A shareable report is ready to generate.";
  const card = document.createElement("article");
  card.className = "chat-message report-suggestion flex items-start gap-2.5";
  card.innerHTML = `
    ${avatarSvg("bg-violet-50 text-violet-600")}
    <div class="max-w-[85%] rounded-2xl rounded-tl-sm border border-violet-200 bg-violet-50 px-4 py-3">
      <div class="flex items-center gap-2">
        <svg class="text-violet-500" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
        <p class="text-sm font-semibold text-violet-800">Suggested report · ${escapeHTML(format.toUpperCase())}</p>
      </div>
      <p class="mt-1.5 text-sm text-violet-900">${escapeHTML(reason)}</p>
      <div class="mt-3 flex gap-2">
        <button class="report-accept rounded-lg bg-violet-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-violet-500">Generate</button>
        <button class="report-dismiss rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-600 transition hover:bg-slate-50">Dismiss</button>
      </div>
    </div>`;
  const acceptBtn = card.querySelector(".report-accept");
  const dismissBtn = card.querySelector(".report-dismiss");
  acceptBtn.addEventListener("click", async () => {
    acceptBtn.disabled = true;
    dismissBtn.disabled = true;
    acceptBtn.textContent = "Generating…";
    await generateReport(format);
    acceptBtn.textContent = "Generated ✓";
  });
  dismissBtn.addEventListener("click", () => card.remove());
  historyEl.appendChild(card);
  scrollToBottom();
}

// ==== Confirmation cards (inline in the chat) ====
function renderConfirmationCard(plan) {
  hideEmptyState();
  const card = document.createElement("article");
  card.className = "chat-message confirmation-card flex items-start gap-2.5";
  const summary = escapeHTML((plan && (plan.summary || plan.tool_name)) || "Proposed action");
  const args = plan && plan.arguments ? JSON.stringify(plan.arguments, null, 2) : "";
  card.innerHTML = `
    ${avatarSvg("bg-amber-50 text-amber-600")}
    <div class="max-w-[85%] rounded-2xl rounded-tl-sm border border-amber-200 bg-amber-50 px-4 py-3">
      <div class="flex items-center gap-2">
        <svg class="text-amber-500" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
        <p class="text-sm font-semibold text-amber-800">Approval required</p>
      </div>
      <p class="mt-1.5 text-sm text-amber-900">${summary}</p>
      ${args ? `<pre class="mt-2 max-h-48 overflow-auto rounded-lg bg-white/70 p-2 text-[11px] leading-snug text-slate-600">${escapeHTML(args)}</pre>` : ""}
      <div class="mt-3 flex gap-2">
        <button class="confirm-yes rounded-lg bg-emerald-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-500">Approve</button>
        <button class="confirm-no rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-600 transition hover:bg-slate-50">Decline</button>
      </div>
    </div>`;
  card.querySelector(".confirm-yes").addEventListener("click", () => sendConfirmation(card, true));
  card.querySelector(".confirm-no").addEventListener("click", () => sendConfirmation(card, false));
  historyEl.appendChild(card);
  scrollToBottom();
  updateStatus("awaiting_confirmation");
}

function sendConfirmation(card, decision) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    renderSystemMessage("Not connected to the server.");
    return;
  }
  const buttons = card.querySelectorAll("button");
  buttons.forEach((button) => {
    button.disabled = true;
    button.classList.add("opacity-50", "cursor-not-allowed");
  });
  appendUserMessage(decision ? "Approved" : "Declined");
  socket.send(JSON.stringify({ type: "confirmation_response", decision }));
}

function resolveConfirmationCards() {
  document.querySelectorAll(".confirmation-card button").forEach((button) => {
    button.disabled = true;
  });
}

// ==== Tool wiring (chat <-> inspector cables) ====
const wireLayerEl = document.getElementById("wire-layer");
const WIRE_COLORS = ["#6366F1", "#8B5CF6", "#7C3AED", "#A78BFA", "#4F46E5", "#9333EA", "#6D28D9", "#3B82F6"];


// Right-angle trace with rounded corners: chip -> channel -> card.
function orthoPath(sx, sy, tx, ty, mx) {
  const r = 7;
  const dy = ty - sy;
  if (Math.abs(dy) < 2 * r || mx >= tx - 2 * r) {
    return `M ${sx} ${sy} L ${tx} ${sy}`; // near-straight: single horizontal run
  }
  const s = Math.sign(dy);
  return [
    `M ${sx} ${sy}`,
    `L ${mx - r} ${sy}`,
    `Q ${mx} ${sy} ${mx} ${sy + s * r}`,
    `L ${mx} ${ty - s * r}`,
    `Q ${mx} ${ty} ${mx + r} ${ty}`,
    `L ${tx} ${ty}`,
  ].join(" ");
}

function wireColor(callId) {
  let hash = 0;
  const str = String(callId || "");
  for (let i = 0; i < str.length; i++) hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
  return WIRE_COLORS[hash % WIRE_COLORS.length];
}

function drawWires() {
  // Use the viewport as the coordinate frame — the inspector is a sibling of the
  // chat <main>, so a parent-only frame is never guaranteed to contain both ends.
  const frame = document.body;
  const frameRect = { left: 0, top: 0, width: window.innerWidth, height: window.innerHeight };
  const inspectorOpen = !inspectorCollapsed && currentView === "chat" && !inspectorEl.closest(".hidden") && getComputedStyle(inspectorEl).display !== "none";
  if (!inspectorOpen) {
    wireLayerEl.classList.add("hidden");
    wireLayerEl.innerHTML = "";
    return;
  }
  wireLayerEl.classList.remove("hidden");
  // Size the SVG box explicitly in px so viewBox tracks 1:1 with rendered pixels
  // even with preserveAspectRatio="none" and no parent transform.
  wireLayerEl.style.width = `${frameRect.width}px`;
  wireLayerEl.style.height = `${frameRect.height}px`;
  wireLayerEl.setAttribute("viewBox", `0 0 ${frameRect.width} ${frameRect.height}`);
  let markup = "";
  document.querySelectorAll(".tool-chip[data-call-id]").forEach((chip) => {
    const card = document.getElementById(`tool-card-${cssEscape(chip.dataset.callId)}`);
    if (!card || !historyEl.contains(chip)) return;
    // Anchor to the bubble's right edge (at the chip's y) so the trace only ever
    // crosses the reserved wire gutter, never text. Chips highlight the wire; the
    // bubble edge is the physical exit point.
    const bubbleEl = chip.closest(".agent-bubble") || chip.closest(".chat-msg-item");
    if (!bubbleEl) return;
    const sr = chip.getBoundingClientRect();
    const br = bubbleEl.getBoundingClientRect();
    const tr = card.getBoundingClientRect();
    const sx = br.right - frameRect.left;
    const sy = sr.top + sr.height / 2 - frameRect.top;
    const tx = tr.left - frameRect.left;
    const ty = tr.top + tr.height / 2 - frameRect.top;
    if (tx <= sx) return; // card left of chip (inspector closed/overlaid) -> skip
    // Orthogonal (PCB-style) routing in the reserved gutter: staggered vertical
    // channel per chip, then a sideways eject into the inspector card.
    const idx = Number(chip.dataset.wireIndex || 0);
    const mx = Math.max(sx + 14, tx - 30 - (idx % 5) * 9);
    const color = wireColor(chip.dataset.callId);
    markup += `<path class="wire-cable" data-call-id="${cssEscape(chip.dataset.callId)}" d="${orthoPath(sx, sy, tx, ty, mx)}" stroke="${color}" />`;
    // Ports on both ends: a terminal box where the cable leaves the bubble and
    // where it lands on the inspector card.
    markup += `<rect class="wire-cable" data-call-id="${cssEscape(chip.dataset.callId)}" x="${sx - 2}" y="${sy - 5}" width="4" height="10" rx="1.2" fill="none" stroke="${color}" />`;
    markup += `<circle class="wire-cable" data-call-id="${cssEscape(chip.dataset.callId)}" cx="${sx + 1}" cy="${sy}" r="2.1" fill="${color}" />`;
    markup += `<rect class="wire-cable" data-call-id="${cssEscape(chip.dataset.callId)}" x="${tx - 4}" y="${ty - 5}" width="4" height="10" rx="1.2" fill="none" stroke="${color}" />`;
    markup += `<circle class="wire-cable" data-call-id="${cssEscape(chip.dataset.callId)}" cx="${tx - 2}" cy="${ty}" r="2.1" fill="${color}" />`;
  });
  wireLayerEl.innerHTML = markup;
}

function setWireLit(callId, on) {
  wireLayerEl.querySelectorAll(`.wire-cable[data-call-id="${cssEscape(callId)}"]`).forEach((p) => p.classList.toggle("wire-lit", on));
}

function jumpToChip(callId) {
  const chip = document.querySelector(`.tool-chip[data-call-id="${cssEscape(callId)}"]`);
  if (!chip) return;
  setWireLit(callId, true);
  chip.classList.add("wire-lit", "wire-lit-chip");
  chip.scrollIntoView({ behavior: "smooth", block: "center" });
  setTimeout(() => {
    setWireLit(callId, false);
    chip.classList.remove("wire-lit", "wire-lit-chip");
  }, 1600);
}

function cssEscape(value) {
  return window.CSS && CSS.escape ? CSS.escape(String(value)) : String(value).replace(/[^a-zA-Z0-9_-]/g, "_");
}

let wireRafPending = false;
function scheduleWires() {
  if (wireRafPending) return;
  wireRafPending = true;
  requestAnimationFrame(() => {
    wireRafPending = false;
    drawWires();
  });
}

window.addEventListener("resize", scheduleWires);
historyEl.addEventListener("scroll", scheduleWires, { passive: true });
toolCallsEl.addEventListener("scroll", scheduleWires, { passive: true });

// ==== Tool inspector ====
function updateInspector(calls) {
  // Accumulate across responses instead of replacing: each assistant bubble's tool
  // chips stay wired to their inspector cards for the whole session. A later message
  // (e.g. a confirmed write) must not evict cards from earlier messages.
  const seen = new Set(inspectorCalls.map((c) => c.call_id));
  for (const call of calls ?? []) {
    if (!seen.has(call.call_id)) {
      inspectorCalls.push(call);
      seen.add(call.call_id);
    }
  }
  renderInspector();
}

function appendToolCall(call) {
  if (!inspectorCalls.some((existing) => existing.call_id === call.call_id)) {
    inspectorCalls.push(call);
  } else {
    const index = inspectorCalls.findIndex((existing) => existing.call_id === call.call_id);
    inspectorCalls[index] = call;
  }
  renderInspector();
}

function renderInspector() {
  toolCallsEl.innerHTML = "";
  if (!inspectorCalls.length) {
    toolCountEl.classList.add("hidden");
    toolCallsEl.innerHTML = `
      <div class="flex h-full flex-col items-center justify-center gap-2 text-center">
        <svg class="text-slate-300" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" /></svg>
        <p class="text-xs text-slate-400">Tool calls and results will appear here.</p>
      </div>`;
    return;
  }
  toolCountEl.textContent = String(inspectorCalls.length);
  toolCountEl.classList.remove("hidden");
  inspectorCalls.forEach((call, index) => {
    const card = document.createElement("article");
    const isError = Boolean(call.is_error);
    const latest = index === inspectorCalls.length - 1;
    card.className = `tool-card rounded-xl border bg-white shadow-sm ${isError ? "border-red-200" : "border-slate-200"}`;
    card.id = `tool-card-${call.call_id}`;
    card.dataset.callId = call.call_id;
    const color = wireColor(call.call_id);
    card.innerHTML = `
      <button class="flex w-full items-center gap-2 px-3 pt-2.5 text-left">
        <span class="h-1.5 w-1.5 shrink-0 rounded-full" style="background:${color}"></span>
        <p class="truncate font-mono text-xs font-semibold text-slate-700" title="${escapeHTML(call.name)}">${escapeHTML(call.name)}</p>
        <span class="ml-auto shrink-0 text-[10px] text-slate-300">#${index + 1}</span>
      </button>
      <div class="px-3 pb-2.5 pt-1">
        ${toolSection("Arguments", formatPayload(call.arguments), latest)}
        ${toolSection(isError ? "Error" : "Result", formatPayload(call.result_parsed ?? call.result), latest && !isError)}
      </div>`;
    card.querySelector("button").addEventListener("click", () => jumpToChip(call.call_id));
    toolCallsEl.appendChild(card);
  });
  toolCallsEl.scrollTop = toolCallsEl.scrollHeight;
  requestAnimationFrame(drawWires);
}

function toolSection(label, content, open) {
  return `
    <details class="tool-section rounded-lg bg-slate-50" ${open ? "open" : ""}>
      <summary class="flex items-center gap-1.5 px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-600">
        <svg class="chevron" width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6" /></svg>
        ${label}
      </summary>
      <pre class="nice-scroll max-h-56 overflow-auto px-2 pb-2 text-[11px] leading-relaxed text-slate-600">${content}</pre>
    </details>`;
}

// ==== Dashboard ====
const SEVERITY_COLORS = {
  critical: "#DC2626",
  high: "#EA580C",
  medium: "#D97706",
  low: "#65A30D",
  info: "#64748B",
};

const dashboardUpdatedEl = document.getElementById("dashboard-updated");
document.getElementById("dashboard-refresh").addEventListener("click", () => loadPosture());

// ==== Dashboard tabs ====
// Each tab loads lazily on first open, so switching views doesn't fan out three
// aggregate queries the user may never look at.
const DASH_TABS = {
  posture: { load: () => loadPosture(), subtitle: "Ledger posture at a glance." },
  operations: { load: () => loadOps(), subtitle: "Throughput, MTTR, and SLA performance." },
  usage: { load: () => loadUsage(), subtitle: "What the agents cost and what they returned." },
};
const DASH_TAB_ACTIVE = ["bg-white", "text-indigo-700", "shadow-sm", "ring-1", "ring-slate-200"];
const DASH_TAB_IDLE = ["text-slate-500", "hover:text-slate-700"];
let currentDashTab = "posture";
const loadedDashTabs = new Set();

function setDashTab(tab, { force = false } = {}) {
  if (!DASH_TABS[tab]) return;
  currentDashTab = tab;
  for (const name of Object.keys(DASH_TABS)) {
    document.getElementById(`dash-panel-${name}`).classList.toggle("hidden", name !== tab);
  }
  document.querySelectorAll(".dash-tab").forEach((btn) => {
    const active = btn.dataset.dash === tab;
    btn.classList.remove(...DASH_TAB_ACTIVE, ...DASH_TAB_IDLE);
    btn.classList.add(...(active ? DASH_TAB_ACTIVE : DASH_TAB_IDLE));
  });
  viewSubtitleEl.textContent = DASH_TABS[tab].subtitle;
  if (force || !loadedDashTabs.has(tab)) {
    loadedDashTabs.add(tab);
    DASH_TABS[tab].load();
  }
  resetCursor();
  repositionAgent();
}

document.querySelectorAll(".dash-tab").forEach((btn) => {
  btn.addEventListener("click", () => setDashTab(btn.dataset.dash));
});

function loadDashboard() {
  // Re-entering the Dashboard view refreshes whichever tab is showing.
  setDashTab(currentDashTab, { force: true });
}

async function loadPosture() {
  dashboardUpdatedEl.textContent = "Loading…";
  try {
    const res = await fetch("/api/dashboard");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderDashboard(await res.json());
  } catch (err) {
    dashboardUpdatedEl.textContent = "Failed to load dashboard.";
  }
}

function renderDashboard(data) {
  const c = data.counts || {};
  dashboardUpdatedEl.textContent = `Updated ${feedbackTimestamp(data.generated_at) || "just now"}`;

  const kpis = [
    { label: "Open", value: c.open, color: "#0F172A" },
    { label: "In progress", value: c.in_progress, color: "#4F46E5" },
    { label: "Overdue", value: c.overdue, color: "#B91C1C", alert: c.overdue > 0 },
    { label: "Remediated", value: c.remediated, color: "#059669" },
    { label: "Assets", value: c.assets, color: "#0F172A" },
    { label: "Commitments due", value: c.commitments_due, color: "#D97706" },
  ];
  document.getElementById("dashboard-kpis").innerHTML = kpis
    .map(
      (k) => `
      <div class="dash-item rounded-2xl border ${k.alert ? "border-red-200 bg-red-50" : "border-slate-200 bg-white"} p-3.5" data-item='${escapeHTML(JSON.stringify({ kind: "kpi", title: k.label, value: k.value ?? 0 }))}'>
        <p class="text-2xl font-semibold" style="color:${k.color}">${k.value ?? 0}</p>
        <p class="mt-0.5 text-[11px] font-medium text-slate-400">${k.label}</p>
      </div>`
    )
    .join("");

  const sevContainer = document.getElementById("dashboard-severity");
  const entries = Object.entries(data.by_severity || {});
  const total = entries.reduce((sum, [, n]) => sum + n, 0) || 1;
  sevContainer.innerHTML = entries.length
    ? entries
        .map(([sev, n]) => {
          const pct = Math.max((n / total) * 100, n ? 2 : 0);
          return `
          <div class="dash-item flex items-center gap-3 rounded-lg px-2 py-1.5" data-item='${escapeHTML(JSON.stringify({ kind: "severity", severity: sev, title: `${sev} severity`, value: n }))}'>
            <span class="w-16 shrink-0 text-xs capitalize text-slate-500">${sev}</span>
            <div class="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
              <div class="h-full rounded-full transition-all duration-500" style="width:${pct}%;background:${SEVERITY_COLORS[sev] || "#64748B"}"></div>
            </div>
            <span class="w-8 shrink-0 text-right text-xs font-medium text-slate-600">${n}</span>
          </div>`;
        })
        .join("")
    : '<p class="text-xs text-slate-400">No actionable vulnerabilities.</p>';

  document.getElementById("dashboard-top").innerHTML = (data.top_vulns || []).length
    ? data.top_vulns
        .map(
          (v) => `
        <div class="dash-item flex items-center gap-2.5 rounded-lg px-2 py-2.5" data-item='${escapeHTML(JSON.stringify({ kind: "vuln", external_id: v.external_id, title: v.title, asset: v.asset }))}'>
          <span class="shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase text-white" style="background:${SEVERITY_COLORS[v.severity] || "#64748B"}">${v.severity}</span>
          <div class="min-w-0 flex-1">
            <p class="truncate text-xs font-medium text-slate-700" title="${escapeHTML(v.title)}">${escapeHTML(v.title)}</p>
            <p class="truncate font-mono text-[10px] text-slate-400">${escapeHTML(v.external_id)}${v.asset ? ` · ${escapeHTML(v.asset)}` : ""}</p>
          </div>
          ${v.days_overdue != null ? `<span class="shrink-0 rounded-full bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-600">${v.days_overdue}d late</span>` : ""}
          ${chatsBadge(v.chats)}
          <span class="shrink-0 text-xs font-semibold text-slate-500">${v.priority_score != null ? v.priority_score.toFixed(1) : "—"}</span>
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No actionable vulnerabilities.</p>';

  document.getElementById("dashboard-commitments").innerHTML = (data.commitments_due || []).length
    ? data.commitments_due
        .map(
          (c) => `
        <div class="dash-item flex items-center gap-2.5 rounded-lg px-2 py-2.5" data-item='${escapeHTML(JSON.stringify({ kind: "commitment", external_id: c.external_id, title: c.description, asset: null }))}'>
          <div class="min-w-0 flex-1">
            <p class="truncate text-xs font-medium text-slate-700">${escapeHTML(c.description)}</p>
            <p class="mt-0.5 font-mono text-[10px] text-slate-400">${escapeHTML(c.external_id)} · due ${escapeHTML(c.due_date)} · ${escapeHTML(c.status)}</p>
          </div>
          ${chatsBadge(c.chats)}
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No commitments due in the next 7 days.</p>';
}

// ==== Remediation operations ====
const opsUpdatedEl = document.getElementById("ops-updated");
const opsWindowEl = document.getElementById("ops-window");
opsWindowEl.addEventListener("change", () => loadOps());

async function loadOps() {
  opsUpdatedEl.textContent = "Loading…";
  try {
    const res = await fetch(`/api/ops?window_days=${Number(opsWindowEl.value || 90)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderOps(await res.json());
  } catch (err) {
    opsUpdatedEl.textContent = "Failed to load remediation operations.";
  }
}

function pct(value) {
  return value == null ? "—" : `${Math.round(value * 100)}%`;
}

function renderOps(data) {
  const c = data.counts || {};
  const sla = data.sla || {};
  opsUpdatedEl.textContent = `${data.window_label || ""} · updated ${feedbackTimestamp(data.generated_at) || "just now"}`;

  const net = c.net_backlog_change ?? 0;
  document.getElementById("ops-kpis").innerHTML = [
    ["Remediated", c.remediated ?? 0, "#059669"],
    ["Discovered", c.discovered ?? 0, "#0F172A"],
    // Sign matters more than magnitude here: >0 means the backlog grew in-window.
    ["Net backlog", `${net > 0 ? "+" : ""}${net}`, net > 0 ? "#B91C1C" : "#059669"],
    ["MTTR", data.mttr_days != null ? `${data.mttr_days}d` : "—", "#4F46E5"],
    ["SLA met", pct(sla.compliance), sla.compliance != null && sla.compliance < 0.8 ? "#B91C1C" : "#059669"],
    ["Oldest open", c.oldest_open_days != null ? `${c.oldest_open_days}d` : "—", "#D97706"],
  ]
    .map(([label, value, color]) =>
      usageCard(label, value, color, { kind: "kpi", title: label.toLowerCase(), value: String(value) })
    )
    .join("");

  const tp = data.throughput || [];
  const maxBar = Math.max(...tp.flatMap((p) => [p.discovered, p.remediated]), 0) || 1;
  document.getElementById("ops-throughput").innerHTML = tp.length
    ? `<div class="flex h-32 items-end gap-1.5">${tp
        .map(
          (p) => `
          <div class="flex h-full flex-1 items-end gap-0.5" title="week of ${escapeHTML(p.week_start)} · ${p.discovered} in / ${p.remediated} closed">
            <div class="flex-1 rounded-t bg-slate-300" style="height:${Math.max((p.discovered / maxBar) * 100, p.discovered ? 3 : 0)}%"></div>
            <div class="flex-1 rounded-t bg-emerald-500" style="height:${Math.max((p.remediated / maxBar) * 100, p.remediated ? 3 : 0)}%"></div>
          </div>`
        )
        .join("")}</div>
       <div class="mt-2 flex items-center gap-3 text-[10px] text-slate-400">
         <span class="flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-slate-300"></span>discovered</span>
         <span class="flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-emerald-500"></span>remediated</span>
         <span class="ml-auto">${escapeHTML(tp[0].week_start)} → ${escapeHTML(tp[tp.length - 1].week_start)}</span>
       </div>`
    : '<p class="text-xs text-slate-400">No intake or closures in this window.</p>';

  const aging = data.aging || {};
  const agingTotal = Object.values(aging).reduce((s, n) => s + n, 0) || 1;
  const AGING_COLORS = { "0-30d": "#65A30D", "31-60d": "#D97706", "61-90d": "#EA580C", "90d+": "#DC2626" };
  document.getElementById("ops-aging").innerHTML = Object.entries(aging).length
    ? Object.entries(aging)
        .map(
          ([bucket, n]) => `
        <div class="dash-item flex items-center gap-3 rounded-lg px-2 py-1.5" data-item='${escapeHTML(JSON.stringify({ kind: "kpi", title: `backlog aged ${bucket}`, value: n }))}'>
          <span class="w-14 shrink-0 text-xs text-slate-500">${escapeHTML(bucket)}</span>
          <div class="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
            <div class="h-full rounded-full" style="width:${Math.max((n / agingTotal) * 100, n ? 2 : 0)}%;background:${AGING_COLORS[bucket] || "#64748B"}"></div>
          </div>
          <span class="w-8 shrink-0 text-right text-xs font-medium text-slate-600">${n}</span>
        </div>`
        )
        .join("")
    : '<p class="text-xs text-slate-400">Nothing open.</p>';

  const mttr = data.mttr_by_severity || {};
  const maxMttr = Math.max(...Object.values(mttr), 0) || 1;
  document.getElementById("ops-mttr").innerHTML = Object.entries(mttr).length
    ? Object.entries(mttr)
        .map(
          ([sev, days]) => `
        <div class="dash-item flex items-center gap-3 rounded-lg px-2 py-1.5" data-item='${escapeHTML(JSON.stringify({ kind: "severity", severity: sev, title: `${sev} MTTR`, value: days }))}'>
          <span class="w-16 shrink-0 text-xs capitalize text-slate-500">${escapeHTML(sev)}</span>
          <div class="h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
            <div class="h-full rounded-full" style="width:${Math.max((days / maxMttr) * 100, 2)}%;background:${SEVERITY_COLORS[sev] || "#64748B"}"></div>
          </div>
          <span class="w-12 shrink-0 text-right text-xs font-medium text-slate-600">${days}d</span>
        </div>`
        )
        .join("")
    : '<p class="text-xs text-slate-400">Nothing has been remediated in this window yet.</p>';

  document.getElementById("ops-owners").innerHTML = (data.owners || []).length
    ? data.owners
        .map(
          (o) => `
        <div class="dash-item flex items-center gap-2.5 rounded-lg px-2 py-2.5" data-item='${escapeHTML(JSON.stringify({ kind: "kpi", title: `owner ${o.owner}`, value: `${o.open_count} open` }))}'>
          <div class="min-w-0 flex-1">
            <p class="truncate text-xs font-medium text-slate-700">${escapeHTML(o.owner)}</p>
            <p class="truncate text-[10px] text-slate-400">${o.open_count} open · ${o.commitments_open} open commitments · ${o.commitments_met}/${o.commitments_met + o.commitments_missed} kept</p>
          </div>
          ${o.reliability != null ? `<span class="shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${o.reliability >= 0.75 ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"}">${pct(o.reliability)} kept</span>` : ""}
          ${o.overdue_count ? `<span class="shrink-0 rounded-full bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-600">${o.overdue_count} late</span>` : ""}
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No owners with open work.</p>';

  document.getElementById("ops-slowest").innerHTML = (data.slowest_closures || []).length
    ? data.slowest_closures
        .map(
          (s) => `
        <div class="dash-item flex items-center gap-2.5 rounded-lg px-2 py-2.5" data-item='${escapeHTML(JSON.stringify({ kind: "vuln", external_id: s.external_id, title: `${s.external_id} closure`, asset: null }))}'>
          <span class="shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase text-white" style="background:${SEVERITY_COLORS[s.severity] || "#64748B"}">${escapeHTML(s.severity)}</span>
          <span class="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-600">${escapeHTML(s.external_id)}</span>
          ${s.within_sla === false ? '<span class="shrink-0 rounded-full bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-600">missed SLA</span>' : ""}
          <span class="shrink-0 text-xs font-semibold text-slate-600">${s.days_to_remediate}d</span>
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No closures in this window.</p>';
}

// ==== Agent usage, cost & value ====
const usageUpdatedEl = document.getElementById("usage-updated");
const usageWindowEl = document.getElementById("usage-window");
usageWindowEl.addEventListener("change", () => loadUsage());
document.getElementById("usage-report-btn").addEventListener("click", () => generateUsageReport("pdf", usageWindow()));

function usageWindow() {
  return Number(usageWindowEl.value || 30);
}

function formatUSD(value) {
  const n = Number(value || 0);
  // Agent spend is routinely sub-cent; $0.00 would read as "free" rather than "tiny".
  if (n > 0 && n < 0.01) return `$${n.toFixed(4)}`;
  return `$${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

async function loadUsage() {
  usageUpdatedEl.textContent = "Loading…";
  try {
    const res = await fetch(`/api/usage?window_days=${usageWindow()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderUsage(await res.json());
  } catch (err) {
    usageUpdatedEl.textContent = "Failed to load agent usage.";
  }
  loadPhoenixUsage();
}

// Phoenix is optional: the panel stays hidden unless an endpoint is configured, and a
// configured-but-unreachable Phoenix surfaces the error rather than showing blank cards.
async function loadPhoenixUsage() {
  const panel = document.getElementById("phoenix-panel");
  try {
    const res = await fetch(`/api/usage/phoenix?window_days=${usageWindow()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.enabled) {
      panel.classList.add("hidden");
      return;
    }
    panel.classList.remove("hidden");
    renderPhoenix(data);
  } catch (err) {
    panel.classList.add("hidden");
  }
}

function renderPhoenix(data) {
  const statusEl = document.getElementById("phoenix-status");
  const subEl = document.getElementById("phoenix-sub");
  const bodyEl = document.getElementById("phoenix-body");

  if (!data.ok) {
    statusEl.className = "shrink-0 rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-semibold text-red-700";
    statusEl.textContent = "unreachable";
    subEl.textContent = "Configured, but the last query failed.";
    bodyEl.innerHTML = `<p class="rounded-lg bg-white p-2.5 text-[11px] text-red-600">${escapeHTML(data.error || "Unknown error.")}</p>`;
    return;
  }

  statusEl.className = "shrink-0 rounded-full bg-violet-100 px-2 py-0.5 text-[10px] font-semibold text-violet-700";
  statusEl.textContent = "connected";
  subEl.textContent = `Project "${data.project}" \u00b7 observed from traces, priced by Phoenix`;

  const tokens = data.tokens || {};
  const cost = data.cost || {};
  const cards = [
    ["Traces", data.trace_count ?? "\u2014", "#7C3AED"],
    ["Observed tokens", tokens.total != null ? formatTokens(tokens.total) : "\u2014", "#7C3AED"],
    ["Observed cost", cost.total != null ? formatUSD(cost.total) : "\u2014", "#7C3AED"],
  ];
  const models = (data.by_model || []).slice(0, 6);

  const cardsHTML = cards
    .map(
      ([label, value, color]) => `
      <div class="rounded-xl border border-violet-200 bg-white p-3">
        <p class="text-lg font-semibold" style="color:${color}">${escapeHTML(String(value))}</p>
        <p class="mt-0.5 text-[10px] font-medium text-slate-400">${escapeHTML(label)}</p>
      </div>`
    )
    .join("");

  const modelsHTML = models.length
    ? `<div class="mt-3 divide-y divide-violet-100 rounded-xl border border-violet-200 bg-white">${models
        .map(
          (m) => `
        <div class="flex items-center gap-2.5 px-3 py-2">
          <span class="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-600">${escapeHTML(shortModelName(m.model))}</span>
          <span class="shrink-0 text-[10px] text-slate-400">${m.calls} calls</span>
          <span class="shrink-0 text-xs font-semibold text-slate-600">${formatTokens(m.total_tokens)}</span>
        </div>`
        )
        .join("")}</div>
       <p class="mt-1.5 text-[10px] text-slate-400">Per-model rows are sampled from the ${data.span_sample} most recent spans; the totals above cover the whole window.</p>`
    : "";

  const warnHTML = (data.degraded || []).length
    ? `<p class="mt-2 rounded-lg bg-amber-50 p-2 text-[10px] text-amber-700">${escapeHTML(data.degraded.join(" \u00b7 "))}</p>`
    : "";

  bodyEl.innerHTML = `<div class="grid grid-cols-3 gap-3">${cardsHTML}</div>${modelsHTML}${warnHTML}`;
}

function usageCard(label, value, color, item) {
  return `
    <div class="dash-item rounded-2xl border border-slate-200 bg-white p-3.5" data-item='${escapeHTML(JSON.stringify(item))}'>
      <p class="text-xl font-semibold" style="color:${color}">${escapeHTML(String(value))}</p>
      <p class="mt-0.5 text-[11px] font-medium text-slate-400">${escapeHTML(label)}</p>
    </div>`;
}

function renderUsage(data) {
  const t = data.totals || {};
  const v = data.value || {};
  usageUpdatedEl.textContent = `${data.window_label || ""} · updated ${feedbackTimestamp(data.generated_at) || "just now"}`;

  document.getElementById("usage-kpis").innerHTML = [
    ["Agent turns", t.turns ?? 0, "#0F172A"],
    ["Sessions", t.sessions ?? 0, "#0F172A"],
    ["Tokens", formatTokens(t.total_tokens ?? 0), "#4F46E5"],
    ["Tool calls", `${t.tool_calls ?? 0}${t.tool_errors ? ` / ${t.tool_errors} err` : ""}`, t.tool_errors ? "#B91C1C" : "#0F172A"],
    ["Spend", formatUSD(t.cost_usd), "#EA580C"],
  ]
    .map(([label, value, color]) =>
      usageCard(label, value, color, { kind: "kpi", title: `agent ${label.toLowerCase()}`, value: String(value) })
    )
    .join("");

  document.getElementById("usage-value").innerHTML = [
    ["Agent cost", formatUSD(v.agent_cost_usd), "#0F172A"],
    ["Analyst time saved", `${(v.analyst_hours_saved ?? 0).toFixed(1)}h`, "#4F46E5"],
    ["Labor value", formatUSD(v.labor_value_usd), "#059669"],
    ["Net value", formatUSD(v.net_value_usd), (v.net_value_usd ?? 0) >= 0 ? "#059669" : "#B91C1C"],
    ["ROI", v.roi_multiple != null ? `${v.roi_multiple}x` : "—", "#0F172A"],
  ]
    .map(([label, value, color]) =>
      usageCard(label, value, color, { kind: "kpi", title: `agent ${label.toLowerCase()}`, value: String(value) })
    )
    .join("");

  const p = data.pricing || {};
  document.getElementById("usage-assumptions").textContent =
    `Assumptions: $${p.input_per_mtok}/M input tokens, $${p.output_per_mtok}/M output tokens, ` +
    `$${p.analyst_hourly_rate}/hr analyst, ${p.minutes_per_action} min saved per automated action ` +
    `(${v.actions_automated ?? 0} in window), ${p.minutes_per_answer} min per answered question ` +
    `(${v.questions_answered ?? 0}). Tune these in Settings → Agent economics.`;

  const daily = data.daily || [];
  const maxCost = Math.max(...daily.map((d) => d.cost_usd), 0) || 1;
  document.getElementById("usage-trend").innerHTML = daily.length
    ? `<div class="flex h-28 items-end gap-1">${daily
        .map(
          (d) => `
          <div class="group flex h-full flex-1 flex-col justify-end" title="${escapeHTML(d.day)} · ${d.turns} turns · ${formatUSD(d.cost_usd)}">
            <div class="w-full rounded-t bg-indigo-500/80 transition group-hover:bg-indigo-600" style="height:${Math.max((d.cost_usd / maxCost) * 100, 2)}%"></div>
          </div>`
        )
        .join("")}</div>
       <div class="mt-1.5 flex justify-between text-[10px] text-slate-400"><span>${escapeHTML(daily[0].day)}</span><span>${escapeHTML(daily[daily.length - 1].day)}</span></div>`
    : '<p class="text-xs text-slate-400">No agent activity recorded in this window.</p>';

  const models = data.by_model || [];
  document.getElementById("usage-models").innerHTML = models.length
    ? models
        .map(
          (m) => `
        <div class="dash-item flex items-center gap-2.5 rounded-lg px-2 py-2.5" data-item='${escapeHTML(JSON.stringify({ kind: "kpi", title: `model ${m.model}`, value: `${m.turns} turns` }))}'>
          <div class="min-w-0 flex-1">
            <p class="truncate text-xs font-medium text-slate-700">${escapeHTML(shortModelName(m.model))}</p>
            <p class="truncate font-mono text-[10px] text-slate-400">${m.turns} turns · ${formatTokens(m.input_tokens)} in / ${formatTokens(m.output_tokens)} out</p>
          </div>
          <span class="shrink-0 text-xs font-semibold text-slate-600">${escapeHTML(formatUSD(m.cost_usd))}</span>
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No agent turns recorded.</p>';

  const tools = (data.by_tool || []).slice(0, 10);
  const maxCalls = Math.max(...tools.map((x) => x.calls), 0) || 1;
  document.getElementById("usage-tools").innerHTML = tools.length
    ? tools
        .map(
          (x) => `
        <div class="dash-item flex items-center gap-2.5 rounded-lg px-2 py-2" data-item='${escapeHTML(JSON.stringify({ kind: "kpi", title: `tool ${x.name}`, value: `${x.calls} calls` }))}'>
          <span class="shrink-0 rounded-md px-1.5 py-0.5 text-[9px] font-bold uppercase ${x.is_write ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-slate-500"}">${x.is_write ? "write" : "read"}</span>
          <span class="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-600">${escapeHTML(x.name)}</span>
          <div class="hidden h-1.5 w-20 shrink-0 overflow-hidden rounded-full bg-slate-100 sm:block">
            <div class="h-full rounded-full bg-indigo-400" style="width:${(x.calls / maxCalls) * 100}%"></div>
          </div>
          ${x.errors ? `<span class="shrink-0 rounded-full bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-600">${x.errors} err</span>` : ""}
          <span class="w-6 shrink-0 text-right text-xs font-semibold text-slate-600">${x.calls}</span>
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No tool calls recorded.</p>';

  const outcomes = data.ledger_outcomes || {};
  document.getElementById("usage-outcomes").innerHTML = Object.entries(outcomes)
    .map(([key, count]) => {
      const label = key.replace(/_/g, " ");
      return `
        <div class="dash-item rounded-xl border border-slate-200 bg-slate-50 p-3" data-item='${escapeHTML(JSON.stringify({ kind: "kpi", title: label, value: count }))}'>
          <p class="text-lg font-semibold text-slate-800">${count}</p>
          <p class="mt-0.5 text-[10px] font-medium capitalize text-slate-400">${escapeHTML(label)}</p>
        </div>`;
    })
    .join("");
}

// ==== Reports ====
const reportPreviewWrap = document.getElementById("report-preview-wrap");
const reportPreviewEl = document.getElementById("report-preview");
document.getElementById("report-preview-close").addEventListener("click", () => reportPreviewWrap.classList.add("hidden"));

document.querySelectorAll(".report-gen").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Generating…";
    await generateReport(btn.dataset.format);
    btn.disabled = false;
    btn.textContent = original;
  });
});

const usageReportWindowEl = document.getElementById("usage-report-window");
document.querySelectorAll(".usage-gen").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Generating…";
    await generateUsageReport(btn.dataset.format, Number(usageReportWindowEl.value || 30));
    btn.disabled = false;
    btn.textContent = original;
  });
});

async function generateReport(format) {
  return fetchReport(`/api/reports/generate?format=${encodeURIComponent(format)}`, format, "vulngent-report");
}

async function generateUsageReport(format, windowDays) {
  return fetchReport(
    `/api/reports/usage?format=${encodeURIComponent(format)}&window_days=${windowDays ?? 30}`,
    format,
    "vulngent-agent-usage"
  );
}

async function fetchReport(url, format, fallbackName) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (format === "md" || format === "markdown" || format === "txt") {
      reportPreviewEl.textContent = await res.text();
      reportPreviewWrap.classList.remove("hidden");
      if (currentView !== "reports") setView("reports");
      reportPreviewWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
      return;
    }
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^";]+)"?/);
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = (match && match[1]) || `${fallbackName}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objectUrl);
  } catch (err) {
    renderSystemMessage(`Failed to generate the ${format.toUpperCase()} report.`);
  }
}

// ==== Helpers ====
function formatPayload(value) {
  if (value === null || value === undefined) {
    return '<span class="italic text-slate-400">(empty)</span>';
  }
  if (Array.isArray(value) && value.length === 0) {
    return '<span class="italic text-slate-400">[] — no matching records</span>';
  }
  if (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0) {
    return '<span class="italic text-slate-400">{} — empty object</span>';
  }
  if (typeof value === "string") {
    if (value.trim().length === 0) return '<span class="italic text-slate-400">(empty)</span>';
    return escapeHTML(value);
  }
  return escapeHTML(JSON.stringify(value, null, 2));
}

function renderMarkdown(markdown) {
  if (!markdown) return "";
  if (window.marked && typeof window.marked.parse === "function") {
    try {
      return window.marked.parse(escapeHTML(markdown), { async: false });
    } catch (err) {
      return `<p>${escapeHTML(markdown)}</p>`;
    }
  }
  return fallbackMarkdown(escapeHTML(markdown));
}

function fallbackMarkdown(html) {
  html = html.replace(/```([\s\S]+?)```/g, (_, code) => `<pre>${code}</pre>`);
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.+)$/gm, "<h1>$1</h1>");
  html = html.replace(/\[(.+?)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
  html = html.replace(/\n/g, "<br />");
  return html;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ==== Session list (sidebar) ====
const chatListEl = document.getElementById("chat-list");

let showArchivedChats = false;

document.getElementById("chats-archived-toggle").addEventListener("click", () => {
  showArchivedChats = !showArchivedChats;
  document.getElementById("chats-archived-toggle").textContent = showArchivedChats ? "Show active" : "Show archived";
  loadSessions();
});

async function loadSessions() {
  try {
    const res = await fetch(`/api/sessions${showArchivedChats ? "?archived=true" : ""}`);
    if (!res.ok) return;
    renderSessionList((await res.json()).sessions || []);
  } catch (err) {
    /* ignore */
  }
}

function renderSessionList(sessions) {
  if (!sessions.length) {
    chatListEl.innerHTML = `<p class="px-3 py-2 text-xs text-slate-400">${showArchivedChats ? "No archived chats." : "No previous chats yet."}</p>`;
    return;
  }
  chatListEl.innerHTML = "";
  sessions.forEach((s) => {
    const active = s.id === sessionId;
    const row = document.createElement("div");
    row.className = "group flex items-start gap-0.5";
    row.innerHTML = `
      <button class="chat-open flex min-w-0 flex-1 items-start gap-2 rounded-lg px-2 py-2 text-left text-xs transition ${
        active ? "bg-indigo-50 text-indigo-700" : "text-slate-600 hover:bg-slate-100"
      }" title="Resume chat ${escapeHTML(s.id)}">
        <svg class="mt-0.5 shrink-0 ${active ? "text-indigo-400" : "text-slate-300"}" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>
        <span class="min-w-0 flex-1">
          <span class="block truncate font-medium">${escapeHTML(s.title)}</span>
          <span class="mt-0.5 block font-mono text-[10px] ${active ? "text-indigo-400" : "text-slate-400"}">${s.id} · ${timeAgo(s.updated_at)} · ${s.message_count} msg</span>
        </span>
      </button>
      <span class="mt-1 flex shrink-0 flex-col gap-0.5 opacity-0 transition group-hover:opacity-100">
        <button class="chat-action rounded-md p-1 text-slate-400 hover:bg-slate-200 hover:text-slate-600" data-act="${showArchivedChats ? "unarchive" : "archive"}" title="${showArchivedChats ? "Restore" : "Archive"}">
          ${showArchivedChats
            ? '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 8 12 3 21 8" /><line x1="21" y1="8" x2="21" y2="17" /><polyline points="21 17 12 21 3 17" /><line x1="3" y1="17" x2="3" y2="8" /></svg>'
            : '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8" /><rect x="1" y="3" width="22" height="5" /><line x1="10" y1="12" x2="14" y2="12" /></svg>'}
        </button>
        <button class="chat-action rounded-md p-1 text-slate-400 hover:bg-red-50 hover:text-red-500" data-act="delete" title="Delete">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" /><path d="M10 11v6M14 11v6" /><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" /></svg>
        </button>
      </span>`;
    row.querySelector(".chat-open").addEventListener("click", () => resumeChat(s.id));
    row.querySelectorAll(".chat-action").forEach((actionBtn) => {
      actionBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        if (actionBtn.dataset.act === "delete") {
          deleteChatSession(s.id, s.title);
        } else {
          archiveChatSession(s.id, actionBtn.dataset.act === "archive");
        }
      });
    });
    chatListEl.appendChild(row);
  });
}

async function archiveChatSession(id, archived) {
  try {
    const res = await fetch(`/api/sessions/${id}/archive?archived=${archived}`, { method: "POST" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast({ title: archived ? "Chat archived" : "Chat restored" });
  } catch (err) {
    showToast({ title: "Archive failed" });
  }
  loadSessions();
}

async function deleteChatSession(id, title) {
  if (!confirm(`Delete chat "${title || id}" permanently? This removes all its messages.`)) return;
  try {
    const res = await fetch(`/api/sessions/${id}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast({ title: "Chat deleted" });
    // Deleting the live session would let the next message silently recreate it
    // (persist_user_message creates the row when missing), so start fresh first.
    if (id === sessionId && socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "new_chat" }));
    }
  } catch (err) {
    showToast({ title: "Delete failed" });
  }
  loadSessions();
}

function timeAgo(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function resumeChat(id) {
  if (!socket || socket.readyState !== WebSocket.OPEN || id === sessionId) {
    if (id === sessionId) setView("chat");
    return;
  }
  socket.send(JSON.stringify({ type: "resume_session", session_id: id }));
  setView("chat");
}

// ==== Toasts ====
const toastsEl = document.getElementById("toasts");

function showToast({ title, body, actionLabel, onAction }) {
  const toast = document.createElement("div");
  toast.className = "toast rounded-xl border border-slate-200 bg-white p-3.5 shadow-lg";
  toast.innerHTML = `
    <div class="flex items-start gap-2.5">
      <span class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-indigo-50 text-indigo-500">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>
      </span>
      <div class="min-w-0 flex-1">
        <p class="text-xs font-semibold text-slate-700">${escapeHTML(title)}</p>
        ${body ? `<p class="mt-0.5 truncate text-[11px] text-slate-400">${escapeHTML(body)}</p>` : ""}
        ${actionLabel ? `<button class="toast-action mt-2 rounded-lg bg-indigo-600 px-2.5 py-1 text-[11px] font-semibold text-white transition hover:bg-indigo-500">${escapeHTML(actionLabel)}</button>` : ""}
      </div>
      <button class="toast-close shrink-0 rounded-md p-1 text-slate-300 hover:bg-slate-100 hover:text-slate-500">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
      </button>
    </div>`;
  const dismiss = () => toast.remove();
  toast.querySelector(".toast-close").addEventListener("click", dismiss);
  if (actionLabel && onAction) {
    toast.querySelector(".toast-action").addEventListener("click", () => {
      onAction();
      dismiss();
    });
  }
  toastsEl.appendChild(toast);
  setTimeout(dismiss, 9000);
}

// ==== Spawn chats from the dashboard ====
function spawnChat({ prompt, prefill, label }) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    showToast({ title: "Not connected", body: "Cannot start a chat right now." });
    return;
  }
  pendingSpawn = { prompt, prefill };
  socket.send(JSON.stringify({ type: "new_chat" }));
  if (prompt) {
    showToast({
      title: label || "New chat started",
      body: prompt,
      actionLabel: "Jump to chat",
      onAction: () => {
        setView("chat");
        scrollToBottom();
      },
    });
  }
}

// ==== Agent cursor + hover menu on dashboard items ====
const agentCursorEl = document.getElementById("agent-cursor");
const cursorMenuEl = document.getElementById("cursor-menu");
const dashboardViewEl = document.getElementById("view-dashboard");
const agentParkEl = document.getElementById("agent-park");

window.addEventListener("resize", () => {
  if (agentAnchor) cursorTarget = anchorPoint() || cursorTarget;
});
historyEl.addEventListener("scroll", () => {
  if (agentAnchor === "bubble") {
    const point = anchorPoint();
    if (point) cursorTarget = point;
  }
});

// The agent chip lives in the navbar until work pulls it elsewhere. It is only
// spawned once the app actually starts (startApp) so it never shows behind the
// login overlay; when auth is off, startApp runs immediately on load.
if (authReady) setAgentAnchor("navbar");

function cursorLoop() {
  if (agentAnchor) {
    const point = anchorPoint();
    if (point) cursorTarget = point;
  }
  cursorPos.x += (cursorTarget.x - cursorPos.x) * agentLerpFactor;
  cursorPos.y += (cursorTarget.y - cursorPos.y) * agentLerpFactor;
  agentCursorEl.style.transform = `translate3d(${cursorPos.x + 14}px, ${cursorPos.y + 14}px, 0)`;
  if (cursorActive) {
    cursorRafId = requestAnimationFrame(cursorLoop);
  }
}

function startCursor(x, y) {
  cursorPos = { x, y };
  cursorTarget = { x, y };
  if (!cursorActive) {
    cursorActive = true;
    agentCursorEl.classList.remove("hidden");
    cursorRafId = requestAnimationFrame(cursorLoop);
  }
}

function stopCursor() {
  cursorActive = false;
  if (cursorRafId) cancelAnimationFrame(cursorRafId);
  cursorRafId = null;
}

// --- Anchored movement: the agent springs/zips between parking spots ---
function anchorPoint() {
  if (agentAnchor === "navbar") {
    const rect = agentParkEl.getBoundingClientRect();
    return { x: rect.left + rect.width / 2 - 26, y: rect.top + rect.height / 2 - 12 };
  }
  if (agentAnchor === "bubble" && agentBubbleEl && agentBubbleEl.isConnected) {
    const rect = agentBubbleEl.getBoundingClientRect();
    return { x: rect.left + 10, y: rect.top - 26 };
  }
  return null;
}

function setAgentAnchor(anchor, bubbleEl = null) {
  if (agentAnchor === anchor && agentBubbleEl === bubbleEl) return;
  agentAnchor = anchor;
  agentBubbleEl = bubbleEl;
  agentLerpFactor = 0.22; // tighter tracking for anchored targets
  if (!cursorActive) {
    const point = anchorPoint();
    if (point) {
      cursorPos = { ...point };
      cursorTarget = { ...point };
      cursorActive = true;
      agentCursorEl.classList.remove("hidden");
      cursorRafId = requestAnimationFrame(cursorLoop);
    }
  }
}

function springAgentTo(anchor, bubbleEl = null) {
  // Long rubber-band zip to a far-away anchor (navbar <-> chat stream).
  agentAnchor = anchor;
  agentBubbleEl = bubbleEl;
  agentLerpFactor = 0.075; // slow chase + snappy transition = elastic overshoot
  agentCursorEl.classList.remove("agent-follow");
  agentCursorEl.classList.add("agent-spring", "agent-moving");
  if (!cursorActive) {
    const point = anchorPoint();
    if (point) {
      cursorTarget = { ...point };
      cursorActive = true;
      agentCursorEl.classList.remove("hidden");
      cursorRafId = requestAnimationFrame(cursorLoop);
    }
  }
  setTimeout(() => agentCursorEl.classList.remove("agent-moving"), 900);
}

function parseItem(el) {
  try {
    return JSON.parse(el.dataset.item || "{}");
  } catch (err) {
    return {};
  }
}

// ==== Action context: which integrations can actually fire + vuln->repo map ====
let actionCtx = { loaded: false, slack: false, github: false, vulnRepos: {} };

async function loadActionContext() {
  try {
    const res = await fetch("/api/ui/actions");
    if (!res.ok) return;
    const data = await res.json();
    actionCtx = {
      loaded: true,
      slack: Boolean(data.slack && data.slack.enabled),
      github: Boolean(data.github && data.github.enabled),
      vulnRepos: data.vuln_repos || {},
    };
  } catch (err) {
    /* menu falls back to chat-only actions */
  }
}
loadActionContext();
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) loadActionContext();
});

const MENU_ICONS = {
  explain:
    '<circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" />',
  deepen:
    '<polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />',
  slack_msg: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />',
  github_issue: '<circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="3.5" />',
  github_link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />',
  copy: '<rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />',
  report:
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" />',
  help:
    '<path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><circle cx="12" cy="12" r="10" /><line x1="12" y1="17" x2="12.01" y2="17" />',
  other: '<circle cx="5" cy="12" r="1" /><circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" />',
};

const CHAT_MSG_BASE = [
  ["slack_msg", "Slack this"],
  ["copy", "Copy"],
  ["report", "Report on this"],
  ["deepen", "Dig deeper"],
  ["other", "Other…"],
];

function itemExternalIds(item) {
  const ids = new Set();
  if (item.external_id) ids.add(item.external_id);
  const text = item.text || "";
  for (const ext of Object.keys(actionCtx.vulnRepos)) {
    if (ext && text.includes(ext)) ids.add(ext);
  }
  return [...ids];
}

function menuOptionsFor(item) {
  const ids = itemExternalIds(item);
  const repos = ids.filter((ext) => actionCtx.vulnRepos[ext]);
  const isChat = item.kind === "chat_msg";
  let options;
  if (isChat) {
    options = CHAT_MSG_BASE;
  } else if (item.kind === "kpi" || item.kind === "severity" || item.kind === "report") {
    options = [
      ["explain", "Explain this"],
      ["report", "Report on this"],
      ["slack_msg", "Slack this"],
      ["other", "Other…"],
    ];
  } else {
    // vuln / commitment
    options = [
      ["github_issue", "GitHub issue"],
      ["github_link", "Find PRs/commits"],
      ["slack_msg", "Slack this"],
      ["explain", "Explain this"],
      ["report", "Report on this"],
      ["deepen", "Dig deeper"],
      ["help", "Help"],
      ["other", "Other…"],
    ];
  }
  return options.filter(([action, label]) => {
    if (action === "slack_msg") return actionCtx.slack;
    if (action === "github_issue" || action === "github_link") return actionCtx.github && repos.length;
    return true;
  });
}

function renderCursorMenu(item) {
  const options = menuOptionsFor(item);
  cursorMenuEl.innerHTML = options
    .map(
      ([action, label]) => `
    <button class="cursor-option flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-xs font-medium text-slate-600 hover:bg-indigo-50 hover:text-indigo-700" data-action="${action}">
      <svg class="text-slate-400" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${MENU_ICONS[action] || ""}</svg>
      ${label}
    </button>`
    )
    .join("");
}

function pinCursorMenu(itemEl) {
  menuItem = itemEl;
  renderCursorMenu(parseItem(itemEl));
  const x = Math.min(cursorPos.x + 18, window.innerWidth - 200);
  const y = Math.min(cursorPos.y + 18, window.innerHeight - 180);
  cursorMenuEl.style.left = `${x}px`;
  cursorMenuEl.style.top = `${y}px`;
  cursorMenuEl.classList.remove("hidden");
}

function unpinCursorMenu() {
  menuItem = null;
  cursorMenuEl.classList.add("hidden");
}



function resetCursor() {
  clearTimeout(dwellTimer);
  clearTimeout(hideTimer);
  dwellTimer = null;
  hoverItem = null;
  setAgentGlow(null);
  unpinCursorMenu();
  agentAnchor = null;
  stopCursor();
  agentCursorEl.classList.add("hidden");
}

function setAgentGlow(item) {
  document.querySelectorAll(".dash-item.agent-hover, .chat-msg-item.agent-hover, .msg-section.agent-hover").forEach((el) => el.classList.remove("agent-hover"));
  if (item) item.classList.add("agent-hover");
}

function hoverableFrom(event) {
  // Resolve the deepest hoverable unit: a response section beats its whole
  // bubble so the menu tracks individual sections instead of the message.
  const section = event.target.closest(".msg-section");
  if (section) return section;
  const dash = event.target.closest(".dash-item");
  if (dash) return dash;
  const bubble = event.target.closest(".chat-msg-item");
  // Sectioned bubbles delegate hover to their sections; padding between them is a gap.
  if (bubble && bubble.dataset.item) return bubble;
  return null;
}

function roamContainer() {
  return currentView === "dashboard" ? dashboardViewEl : historyEl;
}

dashboardViewEl.addEventListener("mouseover", onRoamOver);
historyEl.addEventListener("mouseover", onRoamOver);
function onRoamOver(event) {
  const item = hoverableFrom(event);
  if (!item) return;
  if (hoverItem === item && menuItem === item) return;
  clearTimeout(hideTimer);
  clearTimeout(dwellTimer);
  // Repin on the newly hovered element so the menu follows section-to-section moves.
  if (menuItem !== item) unpinCursorMenu();
  hoverItem = item;
  setAgentGlow(item);
  dwellTimer = setTimeout(() => {
    if (hoverItem === item) pinCursorMenu(item);
  }, 300);
}

dashboardViewEl.addEventListener("mousemove", onRoamMove);
historyEl.addEventListener("mousemove", onRoamMove);
function onRoamMove(event) {
  if (typingBubble || streamBubble) return; // agent is working; don't steal it
  agentAnchor = null;
  agentLerpFactor = 0.18;
  agentCursorEl.classList.remove("agent-spring");
  agentCursorEl.classList.add("agent-follow");
  cursorTarget = { x: event.clientX, y: event.clientY };
  if (!cursorActive) startCursor(event.clientX, event.clientY);
}

dashboardViewEl.addEventListener("mouseout", onRoamOut);
historyEl.addEventListener("mouseout", onRoamOut);
function onRoamOut(event) {
  const item = hoverableFrom(event);
  if (!item) return;
  const to = event.relatedTarget;
  if (to && (item.contains(to) || cursorMenuEl.contains(to))) return;
  // Walking out of a nested hoverable (e.g. a section inside a bubble) leaves
  // relatedTarget outside us but a parent hoverable below — skip the dismiss.
  if (to && to.closest && to.closest(".dash-item, .chat-msg-item, .msg-section")) return;
  clearTimeout(dwellTimer);
  if (menuItem !== item) {
    hoverItem = null;
    setAgentGlow(null);
  }
  scheduleCursorHide();
}

function scheduleCursorHide() {
  clearTimeout(hideTimer);
  hideTimer = setTimeout(() => {
    if (!hoverItem) resetCursor();
  }, 200);
}

// mouseout doesn't fire when moving from an item into a non-hoverable gap
// (container padding, space between bubbles), which used to leave the menu
// stuck open. Watch the pointer: if it's over neither the item nor the menu,
// start the dismiss timer.
historyEl.addEventListener("mousemove", onGapWatch);
dashboardViewEl.addEventListener("mousemove", onGapWatch);
cursorMenuEl.addEventListener("mousemove", () => clearTimeout(hideTimer));
function onGapWatch(event) {
  const overItem = hoverableFrom(event);
  if (overItem) {
    clearTimeout(hideTimer);
    return;
  }
  if (menuItem || hoverItem) {
    hoverItem = null;
    setAgentGlow(null);
    scheduleCursorHide();
  }
}

cursorMenuEl.addEventListener("mouseleave", () => {
  if (!hoverItem) {
    unpinCursorMenu();
    setAgentGlow(null);
  }
  scheduleCursorHide();
});
cursorMenuEl.addEventListener("mouseenter", () => clearTimeout(hideTimer));

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") resetCursor();
});

cursorMenuEl.addEventListener("click", (event) => {
  const btn = event.target.closest(".cursor-option");
  if (!btn || !menuItem) return;
  const item = parseItem(menuItem);
  const action = btn.dataset.action;
  resetCursor();
  if (action === "slack_msg" || action === "github_issue" || action === "github_link") {
    const text = item.text || "";
    const quoted = text.length > 500 ? `${text.slice(0, 500)}…` : text;
    const ids = itemExternalIds(item);
    let label = `${action === "slack_msg" ? "Slack" : "GitHub"}: ${item.external_id || item.title || "section"}`;
    let prompt;
    if (action === "slack_msg") {
      const tie = ids.length ? ` tying it to ${ids[0]}` : "";
      prompt = text
        ? `Post this Slack update${tie} via send_slack_update, formatted as a short stakeholder-ready message:\n\n> ${quoted.replace(/\n/g, "\n> ")}`
        : `Post a Slack update about ${item.external_id || item.title} summarizing its current status and next step via send_slack_update.`;
    } else {
      const ext = ids.find((e) => actionCtx.vulnRepos[e]) || item.external_id || item.title;
      const repo = ids.map((e) => actionCtx.vulnRepos[e]).find(Boolean);
      prompt =
        action === "github_issue"
          ? `Create a GitHub issue to track remediation of ${ext} in its linked repo${repo ? ` (${repo})` : ""}.`
          : `Search the linked repo of ${ext}${repo ? ` (${repo})` : ""} for PRs and commits referencing it and link them into the ledger.`;
    }
    if (item.kind === "chat_msg") {
      // Fire in the current conversation — the hovered section already has its context here.
      if (!socket || socket.readyState !== WebSocket.OPEN) {
        renderSystemMessage("Not connected to the server.");
        return;
      }
      appendUserMessage(label);
      socket.send(JSON.stringify({ type: "user_message", text: prompt }));
      return;
    }
    spawnChat({ label, prompt });
    return;
  }
  if (item.kind === "chat_msg") {
    runChatMsgAction(item, action);
  } else {
    runDashboardAction(item, action);
  }
});

async function runChatMsgAction(item, action) {
  const text = item.text || "";
  if (action === "copy") {
    try {
      await navigator.clipboard.writeText(text);
      showToast({ title: "Copied to clipboard" });
    } catch (err) {
      showToast({ title: "Copy failed" });
    }
    return;
  }
  const excerpt = text.length > 60 ? `${text.slice(0, 60)}…` : text;
  const quoted = text.length > 800 ? `${text.slice(0, 800)}…` : text;
  if (action === "other") {
    inputEl.value = `About your earlier reply: `;
    autogrowInput();
    inputEl.focus();
    return;
  }
  let prompt;
  if (action === "report") {
    prompt = `Draft a status update based on this part of your earlier reply — key facts, risks, and next steps. Suggest a report artifact if one would help. The excerpt:\n\n> ${quoted.replace(/\n/g, "\n> ")}`;
  } else {
    // deepen / explain / help all mean: expand on this message
    prompt = `Go deeper on this part of your earlier reply. Expand with more detail, data, and concrete next steps:\n\n> ${quoted.replace(/\n/g, "\n> ")}`;
  }
  appendUserMessage(action === "report" ? `Report on this: ${excerpt}` : `Go deeper: ${excerpt}`);
  socket.send(JSON.stringify({ type: "user_message", text: prompt }));
}

function runDashboardAction(item, action) {
  const kind = item.kind || "vuln";
  const title = item.title || "this";
  if (kind === "kpi") {
    const ref = `the "${title}" metric (currently ${item.value})`;
    if (action === "other") return spawnChat({ prefill: `About the ${title} metric: ` });
    if (action === "report") return spawnChat({ label: `Report: ${title} metric`, prompt: `Draft a short status update focused on ${ref}. Break down what's behind the number, compare severity mix, and suggest a report artifact if useful.` });
    return spawnChat({ label: `Dig into: ${title}`, prompt: `Dig into ${ref}. What is driving this number? List the most important items behind it and the fastest ways to move it.` });
  }
  if (kind === "severity") {
    const ref = `the ${title} severity band (${item.value} open/in-progress)`;
    if (action === "other") return spawnChat({ prefill: `About ${item.severity} severity: ` });
    if (action === "report") return spawnChat({ label: `Report: ${title}`, prompt: `Draft a status update covering ${ref}. Highlight the worst offenders and suggest a report artifact if useful.` });
    return spawnChat({ label: `Filter: ${title}`, prompt: `List the ${item.severity} severity open and in-progress vulnerabilities, ordered by priority. Call out anything overdue and the quickest wins.` });
  }
  if (kind === "report") {
    if (action === "other") return spawnChat({ prefill: `About the ${title} report: ` });
    return spawnChat({ label: `Report: ${title}`, prompt: `Generate a ${item.format || "pdf"} status report suggestion and explain briefly what it contains and who it's for.` });
  }
  // vuln / commitment
  const ref = item.external_id ? `${item.external_id} (${title})` : title;
  const where = item.asset ? ` on asset ${item.asset}` : "";
  if (action === "explain") {
    spawnChat({ label: `Explain ${item.external_id || title}`, prompt: `Explain ${ref}${where}: what it is, its impact, and remediation options.` });
  } else if (action === "report") {
    spawnChat({ label: `Report: ${item.external_id || title}`, prompt: `Draft a status update for ${ref}${where} — current status, priority, and next steps. Suggest a report artifact if one would help.` });
  } else if (action === "deepen") {
    spawnChat({ label: `Dig into ${item.external_id || title}`, prompt: `Dig deeper into ${ref}${where}: root cause hypotheses, affected components, related vulnerabilities, and a concrete remediation plan.` });
  } else if (action === "help") {
    spawnChat({ label: `Help: ${item.external_id || title}`, prompt: `I need help with ${ref}${where}. What is the recommended next step?` });
  } else if (action === "other") {
    spawnChat({ prefill: `About ${ref}: ` });
  }
}

// ==== Mention badges -> chat popover ====
function chatsBadge(chats) {
  if (!chats || !chats.length) return "";
  return `
    <button class="chats-badge inline-flex shrink-0 items-center gap-1 rounded-full border border-indigo-200 bg-indigo-50 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-600 transition hover:bg-indigo-100" data-chats='${escapeHTML(JSON.stringify(chats))}' title="Referenced in ${chats.length} chat${chats.length > 1 ? "s" : ""}">
      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>
      ${chats.length}
    </button>`;
}

document.addEventListener("click", (event) => {
  const badge = event.target.closest(".chats-badge");
  if (openPopover && (!badge || badge._popover !== openPopover)) {
    openPopover.remove();
    openPopover = null;
  }
  if (!badge) return;
  event.stopPropagation();
  let chats = [];
  try {
    chats = JSON.parse(badge.dataset.chats || "[]");
  } catch (err) {
    return;
  }
  const pop = document.createElement("div");
  pop.className = "chat-popover absolute z-50 w-56 rounded-xl border border-slate-200 bg-white p-1.5 shadow-xl";
  pop.innerHTML = chats
    .map(
      (c) => `
      <button class="popover-chat flex w-full flex-col rounded-lg px-2.5 py-1.5 text-left hover:bg-indigo-50" data-id="${escapeHTML(c.id)}">
        <span class="truncate text-xs font-medium text-slate-700">${escapeHTML(c.title)}</span>
        <span class="font-mono text-[10px] text-slate-400">${escapeHTML(c.id)}</span>
      </button>`
    )
    .join("");
  document.body.appendChild(pop);
  const rect = badge.getBoundingClientRect();
  pop.style.left = `${Math.min(rect.left, window.innerWidth - 240)}px`;
  pop.style.top = `${rect.bottom + 6 + window.scrollY}px`;
  pop.querySelectorAll(".popover-chat").forEach((btn) => {
    btn.addEventListener("click", () => {
      pop.remove();
      openPopover = null;
      resumeChat(btn.dataset.id);
    });
  });
  badge._popover = pop;
  openPopover = pop;
});

// ==== Settings ====
const settingsGroupsEl = document.getElementById("settings-groups");
const settingsUpdatedEl = document.getElementById("settings-updated");
const settingsSaveBtn = document.getElementById("settings-save");
const slackTestResultEl = document.getElementById("slack-test-result");
const githubTestResultEl = document.getElementById("github-test-result");

async function loadSettings() {
  settingsUpdatedEl.textContent = "Loading…";
  try {
    const res = await fetch("/api/settings");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderSettings(await res.json());
  } catch (err) {
    settingsUpdatedEl.textContent = "Failed to load settings.";
  }
}

function settingInputHtml(field) {
  const value = field.value ?? "";
  const base =
    "setting-input w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs outline-none placeholder:text-slate-400 focus:border-indigo-400";
  if (field.type === "bool") {
    return `<label class="setting-input flex items-center gap-2 py-1.5 text-xs text-slate-600" data-setting-key="${field.key}" data-kind="bool">
      <input type="checkbox" class="h-3.5 w-3.5 accent-indigo-600" ${value.toLowerCase() === "true" ? "checked" : ""} />
      enabled
    </label>`;
  }
  if (field.type === "color") {
    const color = /^#[0-9a-fA-F]{6}$/.test(value) ? value : "#111827";
    return `<div class="flex items-center gap-2">
      <input type="color" value="${color}" class="setting-input h-8 w-10 shrink-0 cursor-pointer rounded-md border border-slate-200 bg-white p-1" data-setting-key="${field.key}" />
      <span class="font-mono text-[11px] text-slate-400">${escapeHTML(value)}</span>
    </div>`;
  }
  if (field.secret) {
    return `<div class="flex items-center gap-1.5">
      <input type="password" value="${escapeHTML(value)}" placeholder="${escapeHTML(field.hint || "")}" class="${base}" data-setting-key="${field.key}" autocomplete="off" />
      <button type="button" class="setting-reveal shrink-0 rounded-lg border border-slate-200 px-2 py-1.5 text-[11px] text-slate-500 hover:bg-slate-50" title="Show/hide">show</button>
    </div>`;
  }
  if (field.type === "number") {
    return `<input type="number" value="${escapeHTML(value)}" class="${base}" data-setting-key="${field.key}" />`;
  }
  const datalist = field.options === "models" ? ' list="settings-model-options"' : "";
  return `<input type="text" value="${escapeHTML(value)}" placeholder="${escapeHTML(field.hint || "")}" class="${base}" data-setting-key="${field.key}"${datalist} />`;
}

function renderSettings(data) {
  document.getElementById("settings-env-path").textContent = data.env_file || ".env";
  settingsUpdatedEl.textContent = data.env_file_exists
    ? `Editing ${data.env_file}`
    : `${data.env_file} will be created on save.`;
  const suggestions = (data.model_suggestions || [])
    .map((m) => `<option value="${escapeHTML(m)}"></option>`)
    .join("");

  settingsGroupsEl.innerHTML =
    `<datalist id="settings-model-options">${suggestions}</datalist>` +
    (data.groups || [])
      .map((group) => {
        const fields = group.fields
          .map(
            (field) => `
          <label class="block">
            <span class="mb-1 block text-xs font-medium text-slate-600">${escapeHTML(field.label)}</span>
            ${settingInputHtml(field)}
            ${field.hint && !field.secret ? `<span class="mt-0.5 block text-[10px] text-slate-400">${escapeHTML(field.hint)}</span>` : ""}
          </label>`
          )
          .join("");
        const brandPreview =
          group.id === "whitelabel"
            ? `<div class="rounded-xl border border-slate-200 bg-slate-50 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Live preview</p>
                <div id="brand-preview" class="mt-2 rounded-lg border border-slate-200 bg-white p-3">
                  <div class="flex items-center gap-2">
                    <span id="brand-swatch" class="h-6 w-6 rounded-md"></span>
                    <div>
                      <p id="brand-company" class="text-xs font-semibold text-slate-700"></p>
                      <p id="brand-title" class="text-[10px] text-slate-400"></p>
                    </div>
                  </div>
                </div>
                <p class="mt-2 font-mono text-[10px] text-slate-400" id="brand-colors"></p>
              </div>`
            : "";
        return `<section class="settings-group rounded-2xl border border-slate-200 bg-white p-4" data-group="${group.id}">
          <h3 class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">${escapeHTML(group.title)}</h3>
          <p class="mt-0.5 text-xs text-slate-400">${escapeHTML(group.description)}</p>
          <div class="mt-3 grid gap-4 sm:grid-cols-2">${fields}${brandPreview}</div>
        </section>`;
      })
      .join("");

  settingsGroupsEl.querySelectorAll(".setting-reveal").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = btn.previousElementSibling || btn.parentElement.querySelector("input");
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      btn.textContent = showing ? "show" : "hide";
    });
  });

  const group = settingsGroupsEl.querySelector('[data-group="whitelabel"]');
  if (group) {
    const sync = () => {
      const get = (k) => {
        const el = group.querySelector(`[data-setting-key="${k}"]`);
        return el ? el.value : "";
      };
      document.getElementById("brand-company").textContent = get("REPORT_COMPANY_NAME") || "vulngent";
      document.getElementById("brand-title").textContent = get("REPORT_TITLE") || "Vulnerability Remediation Report";
      const primary = get("REPORT_PRIMARY_COLOR") || "#111827";
      const accent = get("REPORT_ACCENT_COLOR") || "#2563EB";
      document.getElementById("brand-swatch").style.background = primary;
      document.getElementById("brand-colors").textContent = `${primary} · ${accent}`;
      document.getElementById("brand-preview").style.borderTopColor = accent;
      document.getElementById("brand-preview").style.borderTopWidth = "3px";
    };
    group.querySelectorAll("input").forEach((el) => el.addEventListener("input", sync));
    sync();
  }

  settingsGroupsEl.querySelectorAll("input").forEach((el) =>
    el.addEventListener("input", () => {
      if (el.type === "color" && el.nextElementSibling) el.nextElementSibling.textContent = el.value;
    })
  );
}

async function saveSettings() {
  const values = {};
  settingsGroupsEl.querySelectorAll("[data-setting-key]").forEach((el) => {
    if (el.dataset.kind === "bool") {
      values[el.dataset.settingKey] = el.querySelector("input").checked ? "true" : "false";
    } else {
      values[el.dataset.settingKey] = el.value;
    }
  });
  settingsSaveBtn.disabled = true;
  try {
    const res = await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ values }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || `HTTP ${res.status}`);
    showToast({ title: "Settings saved", body: ".env updated — applies to new operations." });
  } catch (err) {
    showToast({ title: "Save failed", body: err.message });
  } finally {
    settingsSaveBtn.disabled = false;
  }
}

settingsSaveBtn.addEventListener("click", saveSettings);
document.getElementById("settings-reload").addEventListener("click", loadSettings);

function renderIntegrationResult(el, ok, html) {
  el.classList.remove("hidden");
  el.className = el.className.replace(/border-(emerald|red)-200/g, "").trim();
  el.classList.add("rounded-xl", "border", "p-3", "text-xs");
  if (ok) el.classList.add("border-emerald-200", "bg-emerald-50", "text-emerald-800");
  else el.classList.add("border-red-200", "bg-red-50", "text-red-700");
  el.innerHTML = html;
}

document.getElementById("slack-test-send").addEventListener("click", async () => {
  const btn = document.getElementById("slack-test-send");
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const res = await fetch("/api/settings/test/slack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        channel: document.getElementById("slack-test-channel").value || null,
        message: document.getElementById("slack-test-message").value || null,
      }),
    });
    const data = await res.json();
    if (!data.ok) {
      renderIntegrationResult(slackTestResultEl, false, escapeHTML(data.error || "Slack test failed."));
    } else {
      const head = `<p class="font-semibold">✓ Connected to ${escapeHTML(data.team || "Slack")} as @${escapeHTML(data.bot || "bot")}</p>`;
      const sent = data.sent
        ? `<div class="mt-2 rounded-lg border border-emerald-200 bg-white p-2.5 text-slate-700">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Posted to ${escapeHTML(data.sent.channel)} · ts ${escapeHTML(data.sent.ts)}</p>
            <p class="mt-1 whitespace-pre-wrap font-mono text-[11px]">${escapeHTML(data.sent.message)}</p>
          </div>`
        : `<p class="mt-1 text-[11px]">Token verified. Enter a channel to post a real message.</p>`;
      renderIntegrationResult(slackTestResultEl, true, head + sent);
    }
  } catch (err) {
    renderIntegrationResult(slackTestResultEl, false, `Request failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Check token / send test";
  }
});

document.getElementById("github-test-run").addEventListener("click", async () => {
  const btn = document.getElementById("github-test-run");
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const res = await fetch("/api/settings/test/github", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo: document.getElementById("github-test-repo").value || null }),
    });
    const data = await res.json();
    if (!data.ok) {
      renderIntegrationResult(githubTestResultEl, false, escapeHTML(data.error || "GitHub test failed."));
    } else {
      let html = `<p class="font-semibold">✓ Token valid — authenticated as @${escapeHTML(data.login)}</p>`;
      if (data.repo) {
        const p = data.repo.permissions || {};
        html += `<p class="mt-1 text-[11px]">Repo ${escapeHTML(data.repo.full_name)} (${data.repo.private ? "private" : "public"}): pull ✓, push ${p.push ? "✓" : "✗"}, admin ${p.admin ? "✓" : "✗"}. Agents need push to file issues and read PRs/commits.</p>`;
      } else {
        html += `<p class="mt-1 text-[11px]">Enter a repo above to check access against it.</p>`;
      }
      renderIntegrationResult(githubTestResultEl, true, html);
    }
  } catch (err) {
    renderIntegrationResult(githubTestResultEl, false, `Request failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run check";
  }
});

const phoenixTestResultEl = document.getElementById("phoenix-test-result");
document.getElementById("phoenix-test-run").addEventListener("click", async () => {
  const btn = document.getElementById("phoenix-test-run");
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const res = await fetch("/api/settings/test/phoenix", { method: "POST" });
    const data = await res.json();
    if (!data.ok) {
      renderIntegrationResult(phoenixTestResultEl, false, escapeHTML(data.error || "Phoenix test failed."));
    } else {
      let html = `<p class="font-semibold">✓ Connected to ${escapeHTML(data.endpoint)}${data.authenticated ? " (authenticated)" : " (no API key)"}</p>`;
      html += `<p class="mt-1 text-[11px]">${data.project_count} project(s). Configured project "${escapeHTML(data.configured_project)}" ${data.configured_project_found ? "found ✓" : "not found ✗ — traces will not be read until it exists."}</p>`;
      if (!data.tracing_installed) {
        html += `<p class="mt-1 text-[11px]">Trace export not installed — run <code class="font-mono">uv sync --extra phoenix</code> to send vulngent's own spans.</p>`;
      } else if (!data.tracing_enabled) {
        html += `<p class="mt-1 text-[11px]">Trace export installed but disabled — enable "Send traces to Phoenix" above, then restart.</p>`;
      } else {
        html += `<p class="mt-1 text-[11px]">Trace export installed and enabled ✓</p>`;
      }
      renderIntegrationResult(phoenixTestResultEl, data.configured_project_found, html);
    }
  } catch (err) {
    renderIntegrationResult(phoenixTestResultEl, false, `Request failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run check";
  }
});
