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
let sessionUsage = { input_tokens: 0, output_tokens: 0 };
let inspectorCalls = [];
const INSPECTOR_KEY = "vulngent.inspector.collapsed";
let inspectorCollapsed = localStorage.getItem(INSPECTOR_KEY) === "1";

// ==== Views ====
const VIEWS = {
  chat: { title: "Remediation Chat", subtitle: "Ask about assets, vulnerabilities, or plan actions." },
  dashboard: { title: "Dashboard", subtitle: "Ledger posture at a glance." },
  reports: { title: "Reports", subtitle: "Generate shareable status reports." },
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
  if (view === "dashboard") loadDashboard();
}

document.querySelectorAll(".nav-item[data-view]").forEach((btn) => {
  btn.addEventListener("click", () => setView(btn.dataset.view));
});
setView("chat");

// ==== Inspector panel ====
function applyInspectorVisibility() {
  const hidden = inspectorCollapsed || currentView !== "chat";
  inspectorEl.classList.toggle("hidden", hidden);
  inspectorEl.classList.toggle("lg:flex", !hidden);
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
connect();

function handleSocketMessage(event) {
  const payload = JSON.parse(event.data);
  switch (payload.type) {
    case "session":
      handleNewSession(payload);
      break;
    case "agent_response":
      removeTypingIndicator();
      renderAgentMessage(payload.entry);
      if (payload.session_usage) updateSessionUsage(payload.session_usage);
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
  } else {
    removeTypingIndicator();
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

let typingBubble = null;
function showTypingIndicator() {
  if (typingBubble) return;
  hideEmptyState();
  typingBubble = document.createElement("article");
  typingBubble.className = "chat-message flex items-start gap-2.5";
  typingBubble.innerHTML = `
    ${avatarSvg()}
    <div class="flex items-center gap-1 rounded-2xl rounded-tl-sm border border-slate-200 bg-white px-3.5 py-2.5 shadow-sm">
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

function appendUserMessage(text) {
  hideEmptyState();
  const wrapper = document.createElement("article");
  wrapper.className = "chat-message flex justify-end";
  const bubble = document.createElement("div");
  bubble.className =
    "bubble-user max-w-[80%] whitespace-pre-wrap rounded-2xl rounded-tr-sm bg-slate-900 px-3.5 py-2.5 text-sm leading-relaxed text-slate-50 shadow-sm";
  bubble.textContent = text;
  wrapper.appendChild(bubble);
  historyEl.appendChild(wrapper);
  scrollToBottom();
}

function renderAgentMessage(entry) {
  hideEmptyState();
  const wrapper = document.createElement("article");
  wrapper.className = "chat-message flex items-start gap-2.5";

  const bubble = document.createElement("div");
  bubble.className = "max-w-[80%] rounded-2xl rounded-tl-sm border border-slate-200 bg-white px-3.5 py-2.5 text-sm shadow-sm";
  bubble.innerHTML = `<div class="markdown">${renderMarkdown(entry.message)}</div>`;

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

  wrapper.innerHTML = avatarSvg();
  wrapper.appendChild(bubble);
  historyEl.appendChild(wrapper);
  scrollToBottom();

  updateInspector(entry.tool_calls ?? []);
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

// ==== Tool inspector ====
function updateInspector(calls) {
  inspectorCalls = calls ?? [];
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
    card.className = `rounded-xl border bg-white shadow-sm ${isError ? "border-red-200" : "border-slate-200"}`;
    card.innerHTML = `
      <div class="flex items-center gap-2 px-3 pt-2.5">
        <span class="h-1.5 w-1.5 shrink-0 rounded-full ${isError ? "bg-red-500" : "bg-emerald-500"}"></span>
        <p class="truncate font-mono text-xs font-semibold text-slate-700" title="${escapeHTML(call.name)}">${escapeHTML(call.name)}</p>
        <span class="ml-auto shrink-0 text-[10px] text-slate-300">#${index + 1}</span>
      </div>
      <div class="px-3 pb-2.5 pt-1">
        ${toolSection("Arguments", formatPayload(call.arguments), true)}
        ${toolSection(isError ? "Error" : "Result", formatPayload(call.result_parsed ?? call.result), !isError)}
      </div>`;
    toolCallsEl.appendChild(card);
  });
  toolCallsEl.scrollTop = toolCallsEl.scrollHeight;
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
document.getElementById("dashboard-refresh").addEventListener("click", () => loadDashboard());

async function loadDashboard() {
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
      <div class="rounded-2xl border ${k.alert ? "border-red-200 bg-red-50" : "border-slate-200 bg-white"} p-3.5">
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
          <div class="flex items-center gap-3">
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
        <div class="flex items-center gap-2.5 py-2.5">
          <span class="shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase text-white" style="background:${SEVERITY_COLORS[v.severity] || "#64748B"}">${v.severity}</span>
          <div class="min-w-0 flex-1">
            <p class="truncate text-xs font-medium text-slate-700" title="${escapeHTML(v.title)}">${escapeHTML(v.title)}</p>
            <p class="truncate font-mono text-[10px] text-slate-400">${escapeHTML(v.external_id)}${v.asset ? ` · ${escapeHTML(v.asset)}` : ""}</p>
          </div>
          ${v.days_overdue != null ? `<span class="shrink-0 rounded-full bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-600">${v.days_overdue}d late</span>` : ""}
          <span class="shrink-0 text-xs font-semibold text-slate-500">${v.priority_score != null ? v.priority_score.toFixed(1) : "—"}</span>
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No actionable vulnerabilities.</p>';

  document.getElementById("dashboard-commitments").innerHTML = (data.commitments_due || []).length
    ? data.commitments_due
        .map(
          (c) => `
        <div class="py-2.5">
          <p class="text-xs font-medium text-slate-700">${escapeHTML(c.description)}</p>
          <p class="mt-0.5 font-mono text-[10px] text-slate-400">${escapeHTML(c.external_id)} · due ${escapeHTML(c.due_date)} · ${escapeHTML(c.status)}</p>
        </div>`
        )
        .join("")
    : '<p class="py-3 text-xs text-slate-400">No commitments due in the next 7 days.</p>';
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

async function generateReport(format) {
  try {
    const res = await fetch(`/api/reports/generate?format=${encodeURIComponent(format)}`);
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
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = (match && match[1]) || `vulngent-report.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
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
