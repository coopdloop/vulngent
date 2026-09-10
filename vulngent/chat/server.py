from __future__ import annotations

import asyncio
import json
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
from vulngent.db import repository as repo
from vulngent.db.models import VulnStatus
from vulngent.db.session import get_session
from vulngent.report_data import collect_report_data
from vulngent.reporting import SUPPORTED_FORMATS, render_report

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"

app = FastAPI()
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

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
                }
                for c in due_soon
            ],
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

    @staticmethod
    def _track_usage(event: Any, usage: dict[str, int]) -> None:
        models_usage = getattr(event, "models_usage", None)
        if models_usage is None:
            return
        usage["input_tokens"] += models_usage.prompt_tokens
        usage["output_tokens"] += models_usage.completion_tokens

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
        self.total_usage["input_tokens"] += usage["input_tokens"]
        self.total_usage["output_tokens"] += usage["output_tokens"]
        entry = {
            "role": "assistant",
            "message": response,
            "tool_summary": tool_summary,
            "tool_calls": tool_calls,
            "thoughts": thoughts,
            "usage": {**usage, "model": self.model_name},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.history.append(entry)
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
                self._confirmation_manager.clear()
                await send_json({"type": "agent_response", "entry": entry})
                await send_json({"type": "confirmation_cleared"})
                await send_json({"type": "status", "status": "ready"})
                return

            await send_json({"type": "status", "status": "thinking"})
            result_text, call_entry = await self._perform_write_tool(pending)
            self._confirmation_manager.clear()
            await send_json({"type": "tool_call_progress", "call": call_entry})
            entry = {
                "role": "assistant",
                "message": result_text,
                "tool_summary": None,
                "tool_calls": [call_entry],
                "thoughts": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.history.append(entry)
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
            entry = await session.process_user_message(text, websocket.send_json)
            await websocket.send_json({"type": "agent_response", "entry": entry, "session_usage": session.total_usage})
            await websocket.send_json({"type": "status", "status": "ready"})
    except WebSocketDisconnect:
        pass
