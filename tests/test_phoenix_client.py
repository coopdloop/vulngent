from __future__ import annotations

import json
import urllib.error
from io import BytesIO

import pytest

from vulngent.config import get_settings
from vulngent.integrations.phoenix_client import (
    PhoenixClient,
    PhoenixError,
    PhoenixNotConfigured,
)


@pytest.fixture(autouse=True)
def phoenix_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "phoenix_endpoint", "http://phoenix.test:6006", raising=False)
    monkeypatch.setattr(settings, "phoenix_api_key", "secret-key", raising=False)
    monkeypatch.setattr(settings, "phoenix_project_name", "vulngent", raising=False)
    return settings


class _FakeResponse(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _install_transport(monkeypatch, handler):
    """Patch urllib at the seam so tests exercise real request building (URLs, headers,
    bearer auth, JSON bodies) instead of mocking PhoenixClient's own methods."""
    seen: list[dict] = []

    def fake_urlopen(req, timeout=None):
        body = req.data.decode() if req.data else None
        record = {
            "url": req.full_url,
            "method": req.get_method(),
            "headers": {k.lower(): v for k, v in req.headers.items()},
            "body": json.loads(body) if body else None,
        }
        seen.append(record)
        return _FakeResponse(json.dumps(handler(record)).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return seen


PROJECTS = {"data": [{"id": "UHJvamVjdDox", "name": "vulngent"}, {"id": "UHJvamVjdDoy", "name": "other"}]}

GQL_OK = {
    "data": {
        "node": {
            "id": "UHJvamVjdDox",
            "name": "vulngent",
            "traceCount": 42,
            "tokenCountTotal": 5000,
            "tokenCountPrompt": 4000,
            "tokenCountCompletion": 1000,
            "costSummary": {
                "total": {"cost": 1.25},
                "prompt": {"cost": 1.0},
                "completion": {"cost": 0.25},
            },
        }
    }
}

SPANS = {
    "data": [
        {
            "attributes": {
                "llm.model_name": "claude-sonnet-4.5",
                "llm.token_count.prompt": 100,
                "llm.token_count.completion": 20,
            }
        },
        {
            "attributes": {
                "llm.model_name": "claude-sonnet-4.5",
                "llm.token_count.prompt": 50,
                "llm.token_count.completion": 10,
            }
        },
        {"attributes": {"llm.model_name": "gpt-4o", "llm.token_count.prompt": 10}},
        {"attributes": {"some.other.span": 1}},  # non-LLM span, must be skipped
    ]
}


def _router(record):
    url = record["url"]
    if "/graphql" in url:
        return GQL_OK
    if "/spans" in url:
        return SPANS
    if "/v1/projects" in url:
        return PROJECTS
    raise AssertionError(f"unexpected URL {url}")


def test_missing_endpoint_raises_not_configured(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "phoenix_endpoint", "", raising=False)
    with pytest.raises(PhoenixNotConfigured):
        PhoenixClient()


def test_project_usage_reads_cost_and_token_rollups(monkeypatch):
    seen = _install_transport(monkeypatch, _router)

    usage = PhoenixClient().project_usage(window_days=30)

    assert usage.project == "vulngent"
    assert usage.trace_count == 42
    assert usage.total_tokens == 5000
    assert usage.total_cost == pytest.approx(1.25)
    assert usage.prompt_cost == pytest.approx(1.0)
    assert usage.degraded == []

    gql = next(r for r in seen if "/graphql" in r["url"])
    assert gql["method"] == "POST"
    assert gql["body"]["variables"]["id"] == "UHJvamVjdDox"
    assert "start" in gql["body"]["variables"]["timeRange"]


def test_bearer_token_is_sent_when_api_key_is_set(monkeypatch):
    seen = _install_transport(monkeypatch, _router)

    PhoenixClient().list_projects()

    assert seen[0]["headers"]["authorization"] == "Bearer secret-key"


def test_no_auth_header_when_api_key_is_blank(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "phoenix_api_key", "", raising=False)
    seen = _install_transport(monkeypatch, _router)

    PhoenixClient().list_projects()

    assert "authorization" not in seen[0]["headers"]


def test_model_breakdown_aggregates_spans_and_skips_non_llm(monkeypatch):
    _install_transport(monkeypatch, _router)

    usage = PhoenixClient().project_usage(window_days=30)

    by_model = {m["model"]: m for m in usage.by_model}
    assert by_model["claude-sonnet-4.5"]["calls"] == 2
    assert by_model["claude-sonnet-4.5"]["prompt_tokens"] == 150
    assert by_model["claude-sonnet-4.5"]["total_tokens"] == 180
    assert by_model["gpt-4o"]["total_tokens"] == 10
    assert usage.span_sample == 4
    assert usage.by_model[0]["model"] == "claude-sonnet-4.5"  # sorted by tokens desc


def test_unknown_project_raises_with_available_names(monkeypatch):
    _install_transport(monkeypatch, _router)

    with pytest.raises(PhoenixError) as exc:
        PhoenixClient().project_usage("nope", window_days=None)

    assert "not found" in str(exc.value)
    assert "vulngent" in str(exc.value)


def test_graphql_errors_degrade_instead_of_failing(monkeypatch):
    def handler(record):
        if "/graphql" in record["url"]:
            return {"errors": [{"message": "Cannot query field 'tokenCountTotal'"}]}
        return _router(record)

    _install_transport(monkeypatch, handler)

    usage = PhoenixClient().project_usage(window_days=30)

    # Rollups are unavailable, but the span-derived breakdown still renders.
    assert usage.total_cost is None
    assert usage.by_model, "span breakdown should survive a GraphQL failure"
    assert any("Cannot query field" in d for d in usage.degraded)


def test_auth_failure_is_reported_clearly(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, BytesIO(b"nope"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(PhoenixError) as exc:
        PhoenixClient().list_projects()

    assert "PHOENIX_API_KEY" in str(exc.value)


def test_unreachable_host_is_reported_clearly(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(PhoenixError) as exc:
        PhoenixClient().list_projects()

    assert "Could not reach Phoenix" in str(exc.value)


def test_check_reports_configured_project_presence(monkeypatch):
    _install_transport(monkeypatch, _router)

    result = PhoenixClient().check()

    assert result["ok"] is True
    assert result["authenticated"] is True
    assert result["project_count"] == 2
    assert result["configured_project_found"] is True
