"""Arize Phoenix integration: true observed LLM usage/cost from traces.

vulngent's built-in usage view (`usage_data.py`) reads token counts recorded by the chat
server, which only sees turns that went through the web UI and prices them from static
Settings rates. Phoenix sees every instrumented model call — CLI runs, agent cycles,
retries, embeddings — and computes cost from its own model pricing table. When Phoenix is
configured we show both, side by side, so the gap between them is visible rather than
silently papered over.

Two Phoenix APIs are used, because neither alone is sufficient:
  * GraphQL  — project-level cost/token rollups (`costSummary`, `tokenCountTotal`).
    Phoenix deliberately does not expose these over REST yet (Arize-ai/phoenix#11008).
  * REST     — `/v1/projects` for discovery and `/v1/projects/{id}/spans` for recent
    spans, used for the per-model breakdown and to prove connectivity.

Auth is bearer-token (`PHOENIX_API_KEY`), and is optional: self-hosted deployments with
auth disabled work with no key at all.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from vulngent.config import get_settings

#: OpenInference semantic-convention span attributes carrying usage.
ATTR_MODEL = "llm.model_name"
ATTR_PROMPT_TOKENS = "llm.token_count.prompt"
ATTR_COMPLETION_TOKENS = "llm.token_count.completion"

_PROJECT_COST_QUERY = """
query VulngentProjectCost($id: ID!, $timeRange: TimeRange) {
  node(id: $id) {
    ... on Project {
      id
      name
      traceCount(timeRange: $timeRange)
      tokenCountTotal(timeRange: $timeRange)
      tokenCountPrompt(timeRange: $timeRange)
      tokenCountCompletion(timeRange: $timeRange)
      costSummary(timeRange: $timeRange) {
        total { cost }
        prompt { cost }
        completion { cost }
      }
    }
  }
}
"""


class PhoenixNotConfigured(RuntimeError):
    pass


class PhoenixError(RuntimeError):
    pass


@dataclass
class PhoenixProjectUsage:
    project: str
    project_id: str
    trace_count: int | None
    total_tokens: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    total_cost: float | None
    prompt_cost: float | None
    completion_cost: float | None
    by_model: list[dict[str, Any]] = field(default_factory=list)
    span_sample: int = 0
    #: Fields Phoenix couldn't supply (older server, cost tracking off, etc.).
    degraded: list[str] = field(default_factory=list)


class PhoenixClient:
    def __init__(self, endpoint: str | None = None, api_key: str | None = None, timeout: float = 10.0) -> None:
        settings = get_settings()
        endpoint = (endpoint if endpoint is not None else settings.phoenix_endpoint or "").strip()
        if not endpoint:
            raise PhoenixNotConfigured("PHOENIX_ENDPOINT is not set.")
        self.endpoint = endpoint.rstrip("/")
        self.api_key = (api_key if api_key is not None else settings.phoenix_api_key or "").strip()
        self.timeout = timeout

    # --- transport ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(self, path: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
        url = f"{self.endpoint}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:200]
            if exc.code in (401, 403):
                raise PhoenixError(
                    f"Phoenix rejected the credentials (HTTP {exc.code}). Check PHOENIX_API_KEY."
                ) from exc
            raise PhoenixError(f"Phoenix {method} {path} failed: HTTP {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise PhoenixError(f"Could not reach Phoenix at {self.endpoint}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise PhoenixError(f"Phoenix returned a non-JSON response from {path}.") from exc

    def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        payload = self._request("/graphql", method="POST", body={"query": query, "variables": variables})
        if isinstance(payload, dict) and payload.get("errors"):
            messages = "; ".join(str(e.get("message", e)) for e in payload["errors"])
            raise PhoenixError(f"Phoenix GraphQL error: {messages}")
        return (payload or {}).get("data") or {}

    # --- API ---------------------------------------------------------------

    def list_projects(self) -> list[dict[str, str]]:
        payload = self._request("/v1/projects?limit=100")
        rows = payload.get("data", []) if isinstance(payload, dict) else []
        return [
            {"id": str(r.get("id", "")), "name": str(r.get("name", ""))}
            for r in rows
            if isinstance(r, dict)
        ]

    def resolve_project(self, name: str) -> dict[str, str] | None:
        """Phoenix's GraphQL node() needs the global ID, but humans configure a name."""
        projects = self.list_projects()
        for p in projects:
            if p["name"] == name:
                return p
        return None

    def project_usage(self, project_name: str | None = None, *, window_days: int | None = 30) -> PhoenixProjectUsage:
        settings = get_settings()
        name = project_name or settings.phoenix_project_name or "default"
        project = self.resolve_project(name)
        if project is None:
            known = ", ".join(p["name"] for p in self.list_projects()[:10]) or "none"
            raise PhoenixError(f"Phoenix project '{name}' not found. Available: {known}.")

        variables: dict[str, Any] = {"id": project["id"]}
        if window_days:
            import datetime as dt

            start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=window_days)
            variables["timeRange"] = {"start": start.isoformat()}

        degraded: list[str] = []
        node: dict[str, Any] = {}
        try:
            node = (self._graphql(_PROJECT_COST_QUERY, variables) or {}).get("node") or {}
        except PhoenixError as exc:
            # Older Phoenix builds lack some of these fields; the span breakdown below
            # still works, so degrade rather than failing the whole panel.
            degraded.append(str(exc))

        cost = node.get("costSummary") or {}

        def _cost_of(key: str) -> float | None:
            section = cost.get(key) or {}
            value = section.get("cost")
            return float(value) if isinstance(value, (int, float)) else None

        by_model, sampled = self._model_breakdown(project["id"], window_days=window_days, degraded=degraded)

        return PhoenixProjectUsage(
            project=project["name"],
            project_id=project["id"],
            trace_count=node.get("traceCount"),
            total_tokens=node.get("tokenCountTotal"),
            prompt_tokens=node.get("tokenCountPrompt"),
            completion_tokens=node.get("tokenCountCompletion"),
            total_cost=_cost_of("total"),
            prompt_cost=_cost_of("prompt"),
            completion_cost=_cost_of("completion"),
            by_model=by_model,
            span_sample=sampled,
            degraded=degraded,
        )

    def _model_breakdown(
        self, project_id: str, *, window_days: int | None, degraded: list[str], limit: int = 1000
    ) -> tuple[list[dict[str, Any]], int]:
        """Aggregate a recent span sample per model. Phoenix has no per-model rollup API,
        so this is an explicitly bounded sample rather than a claim about all history."""
        params: dict[str, str] = {"limit": str(limit)}
        if window_days:
            import datetime as dt

            params["start_time"] = (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=window_days)
            ).isoformat()
        query = urllib.parse.urlencode(params)
        try:
            payload = self._request(f"/v1/projects/{urllib.parse.quote(project_id, safe='')}/spans?{query}")
        except PhoenixError as exc:
            degraded.append(f"span breakdown unavailable: {exc}")
            return [], 0

        acc: dict[str, dict[str, int]] = {}
        spans = payload.get("data", []) if isinstance(payload, dict) else []
        for span in spans:
            attrs = (span or {}).get("attributes") or {}
            model = attrs.get(ATTR_MODEL)
            if not model:
                continue
            row = acc.setdefault(str(model), {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
            row["calls"] += 1
            row["prompt_tokens"] += int(attrs.get(ATTR_PROMPT_TOKENS) or 0)
            row["completion_tokens"] += int(attrs.get(ATTR_COMPLETION_TOKENS) or 0)
        by_model = sorted(
            (
                {
                    "model": model,
                    **counts,
                    "total_tokens": counts["prompt_tokens"] + counts["completion_tokens"],
                }
                for model, counts in acc.items()
            ),
            key=lambda r: r["total_tokens"],
            reverse=True,
        )
        return by_model, len(spans)

    def check(self) -> dict[str, Any]:
        """Connectivity/permission probe for the Settings test button."""
        projects = self.list_projects()
        settings = get_settings()
        target = settings.phoenix_project_name or "default"
        found = any(p["name"] == target for p in projects)
        return {
            "ok": True,
            "endpoint": self.endpoint,
            "authenticated": bool(self.api_key),
            "project_count": len(projects),
            "projects": [p["name"] for p in projects[:20]],
            "configured_project": target,
            "configured_project_found": found,
        }
