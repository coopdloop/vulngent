"""Slack integration: outreach messages and reading stakeholder replies."""

from __future__ import annotations

from dataclasses import dataclass

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from vulngent.config import get_settings


class SlackNotConfigured(RuntimeError):
    pass


@dataclass
class SlackMessage:
    user: str | None
    text: str
    ts: str


class SlackClient:
    def __init__(self, token: str | None = None) -> None:
        settings = get_settings()
        token = token or settings.slack_bot_token
        if not token:
            raise SlackNotConfigured("SLACK_BOT_TOKEN is not set.")
        self._client = WebClient(token=token)

    def send_message(self, channel: str, text: str, thread_ts: str | None = None) -> str:
        try:
            resp = self._client.chat_postMessage(channel=channel, text=text, thread_ts=thread_ts)
        except SlackApiError as exc:
            raise RuntimeError(f"Slack send failed: {exc.response['error']}") from exc
        return resp["ts"]

    def send_dm(self, user_id: str, text: str) -> str:
        try:
            im = self._client.conversations_open(users=user_id)
            channel_id = im["channel"]["id"]
            return self.send_message(channel_id, text)
        except SlackApiError as exc:
            raise RuntimeError(f"Slack DM failed: {exc.response['error']}") from exc

    def get_thread_replies(self, channel: str, thread_ts: str) -> list[SlackMessage]:
        try:
            resp = self._client.conversations_replies(channel=channel, ts=thread_ts)
        except SlackApiError as exc:
            raise RuntimeError(f"Slack read failed: {exc.response['error']}") from exc
        messages = resp.get("messages", [])
        return [SlackMessage(user=m.get("user"), text=m.get("text", ""), ts=m["ts"]) for m in messages]
