from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import vulngent.chat.settings_api as settings_api
from vulngent.chat.server import app
from vulngent.config import Settings, get_settings


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def env_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    monkeypatch.setattr(settings_api, "ENV_PATH", path)
    monkeypatch.setitem(Settings.model_config, "env_file", str(path))
    get_settings.cache_clear()
    yield path
    get_settings.cache_clear()


def test_read_settings_groups_and_values(client, env_file, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    get_settings.cache_clear()
    res = client.get("/api/settings")
    assert res.status_code == 200
    data = res.json()
    ids = [g["id"] for g in data["groups"]]
    for expected in ("llm", "database", "github", "slack", "email", "jira", "whitelabel"):
        assert expected in ids
    llm = next(g for g in data["groups"] if g["id"] == "llm")
    api_key_field = next(f for f in llm["fields"] if f["key"] == "OPENROUTER_API_KEY")
    assert api_key_field["value"] == "sk-or-test"
    assert api_key_field["secret"] is True
    assert data["model_suggestions"]


def test_update_settings_writes_env_and_refreshes(client, env_file):
    env_file.write_text("OPENROUTER_MODEL=old-model\n# comment\nSMTP_PORT=587\n")
    res = client.put(
        "/api/settings",
        json={"values": {"OPENROUTER_MODEL": "new-model", "SMTP_PORT": "2525", "GITHUB_TOKEN": "tok"}},
    )
    assert res.status_code == 200
    assert res.json()["ok"] is True
    text = env_file.read_text()
    assert "OPENROUTER_MODEL=new-model" in text
    assert "# comment" in text
    assert "SMTP_PORT=2525" in text
    assert "GITHUB_TOKEN=tok" in text
    assert get_settings().openrouter_model == "new-model"


def test_update_settings_rejects_unknown_keys(client, env_file):
    res = client.put("/api/settings", json={"values": {"NOT_A_SETTING": "x"}})
    assert res.status_code == 200
    payload = res.json()
    assert payload["ok"] is False
    assert "NOT_A_SETTING" in payload["error"]
    assert not env_file.exists()


def test_update_settings_quotes_values_with_spaces(client, env_file):
    res = client.put("/api/settings", json={"values": {"REPORT_FOOTER_TEXT": "Confidential doc #1"}})
    assert res.json()["ok"] is True
    line = next(l for l in env_file.read_text().splitlines() if l.startswith("REPORT_FOOTER_TEXT="))
    assert line == 'REPORT_FOOTER_TEXT="Confidential doc #1"'
    assert get_settings().report_footer_text == "Confidential doc #1"


def test_slack_test_requires_token(client, env_file, monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "")
    get_settings.cache_clear()
    res = client.post("/api/settings/test/slack", json={})
    assert res.json() == {"ok": False, "error": "SLACK_BOT_TOKEN is not set."}


def test_github_test_requires_token(client, env_file, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "")
    get_settings.cache_clear()
    res = client.post("/api/settings/test/github", json={})
    assert res.json() == {"ok": False, "error": "GITHUB_TOKEN is not set."}
