from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from autogen_agentchat.base import TaskResult
from autogen_agentchat.messages import (
    TextMessage,
    ThoughtEvent,
    ToolCallExecutionEvent,
    ToolCallRequestEvent,
    ToolCallSummaryMessage,
)
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from vulngent.agents import tools as agent_tools
from vulngent.agents.conversational import ConversationalAgent
from vulngent.chat.confirmation import ConfirmationManager, PendingAction, use_confirmation_manager
from vulngent.chat.settings_api import router as settings_router
from sqlalchemy import select

from vulngent.config import get_settings
from vulngent.db import repository as repo
from vulngent.db.models import Asset, ChatMention, ChatMessage, ChatThread, Vulnerability, VulnStatus
from vulngent.db.session import get_session
from vulngent.report_data import collect_report_data
from vulngent.reporting import SUPPORTED_FORMATS, render_report

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(settings_router)

WRITE_TOOL_REGISTRY: dict[str, Callable[..., str]] = {
    "create_github_issue_for_vuln": agent_tools.create_github_issue_for_vuln,
    "send_slack_update": agent_tools.send_slack_update,
    "send_email_update": agent_tools.send_email_update,
    "record_inbound_reply": agent_tools.record_inbound_reply,
    "record_commitment": agent_tools.record_commitment,
    "update_commitment_status": agent_tools.update_commitment_status,
    "add_remediation_step": agent_tools.add_remediation_step,
    "update_remediation_step_status": agent_tools.update_remediation_step_status,
    "set_vulnerability_status": agent_tools.set_vulnerability_status,
    "link_github_prs_and_commits": agent_tools.link_github_prs_and_commits,
    "sync_jira_ticket": agent_tools.sync_jira_ticket,
}

SendJSON = Callable[[dict[str, Any]], Awaitable[None]]

_SECTION_RE = re.compile(r"\[SECTION:([a-z0-9_]+)\](.*?)\[/SECTION\]", re.DOTALL | re.IGNORECASE)


def split_sections(text: str) -> tuple[str, list[dict[str, str]]]:
    """Extract [SECTION:key]...[/SECTION] blocks the model emits.

    Returns (clean_markdown, sections). With no markers, the whole reply is one
    implicit section so the UI can still offer section-level follow-ups."""
    sections = [{"key": m.group(1).lower(), "content": m.group(2).strip()} for m in _SECTION_RE.finditer(text)]
    if not sections:
        return text, []
    clean = _SECTION_RE.sub(lambda m: m.group(2).strip(), text)
    clean = re.sub(r"\n{3,}", "\n\n", clean).strip()
    return clean, sections


@app.middleware("http")
async def no_cache_html_static(request: Any, call_next: Any) -> Any:
    """HTML/JS change constantly during local dev; without this the browser can pair a
    stale cached app.js with fresh index.html (and vice versa), which kills the script
    before it ever opens the WebSocket. no-cache forces revalidation (ETag -> cheap 304)."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/", response_class=FileResponse)
async def homepage() -> FileResponse:
    return FileResponse(INDEX_HTML)


@app.get("/api/sessions")
async def list_chat_sessions() -> dict[str, Any]:
    return await asyncio.to_thread(_collect_sessions)


def _collect_sessions() -> dict[str, Any]:
    with get_session() as session:
        threads = session.execute(select(ChatThread).order_by(ChatThread.updated_at.desc()).limit(50)).scalars().all()
        return {
            "sessions": [
                {
                    "id": t.id,
                    "title": t.title or t.id,
                    "model": t.model,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                    "updated_at": t.updated_at.isoformat() if t.updated_at else None,
                    "message_count": len(t.messages),
                }
                for t in threads
            ]
        }


@app.get("/api/dashboard")
async def dashboard() -> dict[str, Any]:
    return await asyncio.to_thread(_collect_dashboard)


def _collect_dashboard() -> dict[str, Any]:
    with get_session() as session:
        open_vulns = repo.list_vulnerabilities(session, status=VulnStatus.OPEN)
        in_progress = repo.list_vulnerabilities(session, status=VulnStatus.IN_PROGRESS)
        remediated = repo.list_vulnerabilities(session, status=VulnStatus.REMEDIATED)
        overdue = repo.list_overdue_vulnerabilities(session)
        assets = repo.list_assets(session)
        due_soon = repo.list_commitments_due(session, within_days=7)
        actionable = open_vulns + in_progress
        by_severity: dict[str, int] = {}
        for v in actionable:
            by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1
        top = sorted(actionable, key=lambda v: v.priority_score or 0, reverse=True)[:8]

        # vuln_id -> chats that have referenced it (deduped by thread)
        thread_titles = {t.id: (t.title or t.id) for t in session.execute(select(ChatThread)).scalars().all()}
        chats_by_vuln: dict[int, list[dict[str, str]]] = {}
        seen: set[tuple[int, str]] = set()
        for m in session.execute(select(ChatMention)).scalars().all():
            if (m.vulnerability_id, m.thread_id) in seen:
                continue
            seen.add((m.vulnerability_id, m.thread_id))
            chats_by_vuln.setdefault(m.vulnerability_id, []).append(
                {"id": m.thread_id, "title": thread_titles.get(m.thread_id, m.thread_id)}
            )
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "counts": {
                "open": len(open_vulns),
                "in_progress": len(in_progress),
                "overdue": len(overdue),
                "remediated": len(remediated),
                "assets": len(assets),
                "commitments_due": len(due_soon),
            },
            "by_severity": by_severity,
            "top_vulns": [
                {
                    "id": v.id,
                    "external_id": v.external_id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "status": v.status.value,
                    "priority_score": v.priority_score,
                    "asset": v.asset.name if v.asset else None,
                    "days_overdue": repo.days_overdue(v),
                    "chats": chats_by_vuln.get(v.id, []),
                }
                for v in top
            ],
            "commitments_due": [
                {
                    "vulnerability_id": c.vulnerability_id,
                    "external_id": c.vulnerability.external_id if c.vulnerability else "-",
                    "description": c.description,
                    "due_date": c.committed_date.date().isoformat(),
                    "status": c.status.value,
                    "chats": chats_by_vuln.get(c.vulnerability_id, []),
                }
                for c in due_soon
            ],
        }


@app.get("/api/ui/actions")
async def action_context() -> dict[str, Any]:
    """Capabilities of hover-menu actions + repo mapping for contextual GitHub actions."""
    return await asyncio.to_thread(_collect_action_context)


def _collect_action_context() -> dict[str, Any]:
    settings = get_settings()
    with get_session() as session:
        vulns = session.execute(select(Vulnerability.id, Vulnerability.external_id, Vulnerability.asset_id)).all()
        repos = session.execute(select(Asset.id, Asset.repo_full_name).where(Asset.repo_full_name.isnot(None))).all()
    repo_by_asset = {asset_id: repo for asset_id, repo in repos}
    vuln_map = {
        ext_id: repo_by_asset.get(asset_id)
        for vuln_id, ext_id, asset_id in vulns
        if repo_by_asset.get(asset_id)
    }
    return {
        "slack": {"enabled": bool(settings.slack_bot_token), "default_channel": settings.slack_default_channel or ""},
        "github": {"enabled": bool(settings.github_token)},
        "vuln_repos": vuln_map,
    }


_REPORT_MEDIA_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@app.get("/api/reports/generate")
async def generate_report(format: str = "md") -> Response:
    fmt = format.lower().strip()
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Unsupported report format '{format}'.")

    def _render() -> tuple[Any, Any]:
        with get_session() as session:
            data = collect_report_data(session)
        return data, render_report(data, fmt)

    data, rendered = await asyncio.to_thread(_render)
    if fmt in ("md", "markdown", "txt"):
        return PlainTextResponse(str(rendered), media_type="text/markdown")
    filename = f"vulngent-report-{data.generated_at:%Y%m%d}.{fmt}"
    return Response(
        content=bytes(rendered),
        media_type=_REPORT_MEDIA_TYPES[fmt],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class ChatSession:
    def __init__(self) -> None:
        self.session_id = uuid.uuid4().hex[:8]
        self.agent = ConversationalAgent()
        self.history: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._confirmation_manager = ConfirmationManager()
        self.total_usage = {"input_tokens": 0, "output_tokens": 0}
        self._mentioned_vuln_ids: set[int] = set()
        self._pending_state_coro: Any = None

    @property
    def model_name(self) -> str:
        return self.agent.model_name

    @property
    def pending_action(self) -> bool:
        return self._confirmation_manager.pending_action is not None

    def reset(self) -> None:
        self.session_id = uuid.uuid4().hex[:8]
        self.agent = ConversationalAgent()
        self.history.clear()
        self._confirmation_manager.clear()
        self.total_usage = {"input_tokens": 0, "output_tokens": 0}
        self._mentioned_vuln_ids: set[int] = set()

    # --- persistence -------------------------------------------------------

    def load_thread(self, thread_id: str) -> list[dict[str, Any]]:
        """Restore a persisted thread: history for the UI + agent memory. Returns entries."""
        self.reset()
        with get_session() as session:
            thread = session.get(ChatThread, thread_id)
            if thread is None:
                raise KeyError(thread_id)
            self.session_id = thread.id
            rows = session.execute(
                select(ChatMessage).where(ChatMessage.thread_id == thread.id).order_by(ChatMessage.id)
            ).scalars().all()
            entries = [json.loads(m.payload) for m in rows]
            self.history = [e for e in entries if e.get("role") == "assistant"]
            self._mentioned_vuln_ids = {
                m.vulnerability_id
                for m in session.execute(
                    select(ChatMention).where(ChatMention.thread_id == thread.id)
                ).scalars().all()
            }
        self.total_usage = {"input_tokens": 0, "output_tokens": 0}
        return entries

    async def restore_agent_state(self, thread_id: str) -> None:
        with get_session() as session:
            thread = session.get(ChatThread, thread_id)
            agent_state = json.loads(thread.agent_state) if thread and thread.agent_state else None
        if agent_state:
            try:
                await self.agent._agent.load_state(agent_state)
            except Exception:
                pass  # stale/incompatible state -> start with fresh memory but keep UI history

    def persist_user_message(self, text: str) -> None:
        entry = {"role": "user", "message": text, "timestamp": datetime.now(timezone.utc).isoformat()}
        self._persist_message("user", entry, title=text)
        self._record_mentions([text])

    def persist_assistant_entry(self, entry: dict[str, Any]) -> None:
        self._persist_message("assistant", entry)
        texts = [entry.get("message") or ""]
        for call in entry.get("tool_calls") or []:
            texts.append(json.dumps(call.get("arguments"), default=str))
            texts.append(str(call.get("result") or ""))
        self._record_mentions(texts)
        self._persist_agent_state()

    def _persist_message(self, role: str, entry: dict[str, Any], title: str = "") -> None:
        now = datetime.now(timezone.utc)
        with get_session() as session:
            thread = session.get(ChatThread, self.session_id)
            if thread is None:
                thread = ChatThread(id=self.session_id, model=self.model_name)
                session.add(thread)
            if not thread.title and title:
                thread.title = title[:80]
            thread.updated_at = now
            session.add(ChatMessage(thread_id=self.session_id, role=role, payload=json.dumps(entry)))
            session.commit()

    def _persist_agent_state(self) -> None:
        try:
            state_coro = self.agent._agent.save_state()
        except Exception:
            return
        self._pending_state_coro = state_coro

    async def flush_agent_state(self) -> None:
        coro = getattr(self, "_pending_state_coro", None)
        if coro is None:
            return
        self._pending_state_coro = None
        try:
            state = await coro
        except Exception:
            return
        with get_session() as session:
            thread = session.get(ChatThread, self.session_id)
            if thread is not None:
                thread.agent_state = json.dumps(state)
                session.commit()

    def _record_mentions(self, texts: list[str]) -> None:
        with get_session() as session:
            vulns = session.execute(select(Vulnerability.id, Vulnerability.external_id)).all()
            new_ids: set[int] = set()
            for vid, ext_id in vulns:
                if vid in self._mentioned_vuln_ids:
                    continue
                for text in texts:
                    if text and (ext_id in text or f"#{vid}" in text):
                        new_ids.add(vid)
                        break
            for vid in new_ids:
                session.add(ChatMention(thread_id=self.session_id, vulnerability_id=vid))
            if new_ids:
                session.commit()
        self._mentioned_vuln_ids |= new_ids

    @staticmethod
    def _track_usage(event: Any, usage: dict[str, int]) -> None:
        models_usage = getattr(event, "models_usage", None)
        if models_usage is None:
            return
        usage["input_tokens"] += models_usage.prompt_tokens
        usage["output_tokens"] += models_usage.completion_tokens

    async def _stream_text(self, text: str, send_json: SendJSON, delay: float = 0.012) -> None:
        """Typewriter-pump a complete TextMessage as deltas so the UI can stream it.

        AutoGen emits whole messages (no token stream), so we synthesize deltas;
        the final agent_response still carries the authoritative full text."""
        await send_json({"type": "stream_start"})
        size = 6
        for i in range(0, len(text), size):
            await send_json({"type": "stream_delta", "delta": text[i : i + size]})
            await asyncio.sleep(delay)

    async def process_user_message(self, text: str, send_json: SendJSON) -> dict[str, Any]:
        tool_requests: list[Any] = []
        tool_calls: list[dict[str, Any]] = []
        processed_requests = 0
        tool_summary: str | None = None
        thoughts: list[str] = []
        final_text = ""
        usage = {"input_tokens": 0, "output_tokens": 0}

        async with self._lock:
            with use_confirmation_manager(self._confirmation_manager):
                async for event in self.agent.run_stream(task=text, output_task_messages=False):
                    self._track_usage(event, usage)
                    if isinstance(event, TextMessage):
                        final_text = event.content
                        await self._stream_text(final_text, send_json)
                    elif isinstance(event, ThoughtEvent):
                        thoughts.append(event.content)
                        await send_json({"type": "thought", "content": event.content})
                    elif isinstance(event, ToolCallRequestEvent):
                        tool_requests.extend(event.content)
                    elif isinstance(event, ToolCallExecutionEvent):
                        for result in event.content:
                            if processed_requests >= len(tool_requests):
                                break
                            call = tool_requests[processed_requests]
                            processed_requests += 1
                            entry = self._build_tool_entry(call, result)
                            tool_calls.append(entry)
                            await send_json({"type": "tool_call_progress", "call": entry})
                            if call.name == "suggest_report" and isinstance(entry["arguments"], dict):
                                await send_json({"type": "report_suggestion", "report": {
                                    "format": entry["arguments"].get("report_format", "pdf"),
                                    "reason": entry["arguments"].get("reason", ""),
                                }})
                            if call.name == "plan_write_action" and self._confirmation_manager.needs_notification:
                                await send_json({"type": "confirmation_needed", "plan": self._confirmation_payload()})
                                self._confirmation_manager.mark_notified()
                                await send_json({"type": "status", "status": "awaiting_confirmation"})
                    elif isinstance(event, ToolCallSummaryMessage):
                        tool_summary = event.content
                    elif isinstance(event, TaskResult):
                        break

        response = final_text or tool_summary or "(no response)"
        clean_message, sections = split_sections(response)
        self.total_usage["input_tokens"] += usage["input_tokens"]
        self.total_usage["output_tokens"] += usage["output_tokens"]
        entry = {
            "role": "assistant",
            "message": clean_message,
            "sections": sections,
            "tool_summary": tool_summary,
            "tool_calls": tool_calls,
            "thoughts": thoughts,
            "usage": {**usage, "model": self.model_name},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.history.append(entry)
        self.persist_assistant_entry(entry)
        await self.flush_agent_state()
        return entry

    async def handle_confirmation_response(self, decision: bool, send_json: SendJSON) -> None:
        async with self._lock:
            pending = self._confirmation_manager.pending_action
            if not pending:
                await send_json({"type": "error", "message": "No action waiting for confirmation."})
                return
            if not decision:
                entry = {
                    "role": "assistant",
                    "message": f"Action '{pending.summary or pending.tool_name}' was cancelled.",
                    "tool_summary": None,
                    "tool_calls": [],
                    "thoughts": [],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.history.append(entry)
                self.persist_assistant_entry(entry)
                await self.flush_agent_state()
                self._confirmation_manager.clear()
                await send_json({"type": "agent_response", "entry": entry})
                await send_json({"type": "confirmation_cleared"})
                await send_json({"type": "status", "status": "ready"})
                return

            await send_json({"type": "status", "status": "thinking"})
            result_text, call_entry = await self._perform_write_tool(pending)
            self._confirmation_manager.clear()
            await send_json({"type": "tool_call_progress", "call": call_entry})
            await self._stream_text(result_text, send_json)
            entry = {
                "role": "assistant",
                "message": result_text,
                "tool_summary": None,
                "tool_calls": [call_entry],
                "thoughts": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.history.append(entry)
            self.persist_assistant_entry(entry)
            await self.flush_agent_state()
            await send_json({"type": "agent_response", "entry": entry})
            await send_json({"type": "confirmation_cleared"})
            await send_json({"type": "status", "status": "ready"})

    async def _perform_write_tool(self, action: PendingAction) -> tuple[str, dict[str, Any]]:
        tool = WRITE_TOOL_REGISTRY.get(action.tool_name)
        call_id = f"manual-{uuid.uuid4().hex[:8]}"
        if tool is None:
            result_text = f"ERROR: unknown write tool '{action.tool_name}'."
            return result_text, self._build_manual_call_entry(action.tool_name, action.arguments, result_text, True, call_id)
        try:
            result_text = await asyncio.to_thread(lambda: tool(**action.arguments))
        except Exception as exc:
            result_text = f"ERROR: {exc}"
            is_error = True
        else:
            is_error = isinstance(result_text, str) and result_text.startswith("ERROR")
        return result_text, self._build_manual_call_entry(action.tool_name, action.arguments, result_text, is_error, call_id)

    def _build_tool_entry(self, call: Any, result: Any) -> dict[str, Any]:
        arguments = self._maybe_parse_json(call.arguments)
        parsed_result = self._maybe_parse_json(result.content)
        return {
            "name": call.name,
            "arguments": arguments,
            "result": result.content,
            "result_parsed": parsed_result,
            "is_error": result.is_error,
            "call_id": call.id,
        }

    def _build_manual_call_entry(self, name: str, arguments: dict[str, Any], result: str, is_error: bool, call_id: str) -> dict[str, Any]:
        return {
            "name": name,
            "arguments": arguments,
            "result": result,
            "result_parsed": self._maybe_parse_json(result),
            "is_error": is_error,
            "call_id": call_id,
        }

    @staticmethod
    def _maybe_parse_json(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    def _confirmation_payload(self) -> dict[str, Any]:
        action = self._confirmation_manager.pending_action
        if not action:
            return {}
        return {
            "tool_name": action.tool_name,
            "summary": action.summary or action.tool_name,
            "arguments": action.arguments,
        }


def _session_payload(session: ChatSession) -> dict[str, Any]:
    return {"type": "session", "session_id": session.session_id, "model": session.model_name}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    session = ChatSession()
    await websocket.send_json(_session_payload(session))
    try:
        while True:
            try:
                payload = await websocket.receive_json()
            except ValueError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON payload."})
                continue
            msg_type = payload.get("type")
            if msg_type == "new_chat":
                session.reset()
                await websocket.send_json(_session_payload(session))
                await websocket.send_json({"type": "status", "status": "ready"})
                continue
            if msg_type == "resume_session":
                thread_id = str(payload.get("session_id") or "").strip()
                async with session._lock:
                    try:
                        entries = session.load_thread(thread_id)
                        await session.restore_agent_state(thread_id)
                    except KeyError:
                        await websocket.send_json({"type": "error", "message": f"Unknown chat session '{thread_id}'."})
                        continue
                await websocket.send_json(_session_payload(session))
                await websocket.send_json({"type": "history", "entries": entries})
                await websocket.send_json({"type": "status", "status": "ready"})
                continue
            if msg_type == "confirmation_response":
                decision = bool(payload.get("decision"))
                await session.handle_confirmation_response(decision, websocket.send_json)
                continue
            if msg_type != "user_message":
                await websocket.send_json({"type": "error", "message": "Unsupported message type."})
                continue
            text = (payload.get("text") or "").strip()
            if not text:
                continue
            if session.pending_action and text.lower() in {"yes", "y", "sure", "confirm"}:
                await session.handle_confirmation_response(True, websocket.send_json)
                continue
            if session.pending_action and text.lower() in {"no", "n", "cancel"}:
                await session.handle_confirmation_response(False, websocket.send_json)
                continue
            await websocket.send_json({"type": "status", "status": "thinking"})
            session.persist_user_message(text)
            entry = await session.process_user_message(text, websocket.send_json)
            await websocket.send_json({"type": "agent_response", "entry": entry, "session_usage": session.total_usage})
            await websocket.send_json({"type": "status", "status": "ready"})
    except WebSocketDisconnect:
        pass
