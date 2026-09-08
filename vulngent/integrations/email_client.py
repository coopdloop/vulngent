"""Email integration (SMTP): outreach to stakeholders who aren't on Slack/GitHub."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from vulngent.config import get_settings


class EmailNotConfigured(RuntimeError):
    pass


class EmailClient:
    def __init__(self) -> None:
        settings = get_settings()
        if not (settings.smtp_host and settings.smtp_from_address):
            raise EmailNotConfigured("SMTP_HOST / SMTP_FROM_ADDRESS are not set.")
        self._settings = settings

    def send_email(self, to_address: str, subject: str, body: str) -> None:
        settings = self._settings
        msg = EmailMessage()
        msg["From"] = settings.smtp_from_address
        msg["To"] = to_address
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
