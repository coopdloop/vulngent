"""Google Sign-In auth: verify the ID token from the browser, mint a session cookie.

Uses Google Identity Services on the frontend (renders the official button with the
public client id). The browser sends the resulting ID token (a signed JWT) here; we
verify it against Google's certs, upsert a User, and store the user id in a signed
session cookie (Starlette SessionMiddleware). No client secret is required for this
flow — the ID token is self-contained and verifiable.

When no google_client_id is configured, auth_enabled is False and the whole layer is a
no-op so local dev keeps working unauthenticated."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from sqlalchemy import select

from vulngent.config import get_settings
from vulngent.db.models import User
from vulngent.db.session import get_session

router = APIRouter(prefix="/api/auth", tags=["auth"])

_GOOGLE_REQUEST = google_requests.Request()


def session_secret() -> str:
    """Stable secret if configured, else an ephemeral per-process one (dev)."""
    settings = get_settings()
    if settings.session_secret:
        return settings.session_secret
    global _EPHEMERAL_SECRET
    try:
        return _EPHEMERAL_SECRET
    except NameError:
        _EPHEMERAL_SECRET = secrets.token_urlsafe(48)
        return _EPHEMERAL_SECRET


def _public_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture_url,
    }


def current_user(request: Request) -> dict[str, Any] | None:
    """Return the logged-in user dict from the session cookie, or None.

    When auth is disabled, returns None and callers treat everything as public."""
    if not get_settings().auth_enabled:
        return None
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    with get_session() as session:
        user = session.get(User, user_id)
        return _public_user(user) if user else None


def require_user(request: Request) -> dict[str, Any] | None:
    """FastAPI dependency: enforce login when auth is enabled."""
    settings = get_settings()
    if not settings.auth_enabled:
        return None
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def _verify_google_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        claims = google_id_token.verify_oauth2_token(
            token, _GOOGLE_REQUEST, settings.google_client_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {exc}") from exc

    if not claims.get("email_verified", False):
        raise HTTPException(status_code=403, detail="Google account email is not verified.")

    allowed = settings.google_allowed_domain.strip().lower()
    if allowed and claims.get("hd", "").lower() != allowed:
        raise HTTPException(status_code=403, detail=f"Only {allowed} accounts are allowed.")
    return claims


@router.get("/config")
async def auth_config() -> dict[str, Any]:
    """Public: tells the frontend whether/how to show the sign-in button."""
    settings = get_settings()
    return {
        "enabled": settings.auth_enabled,
        "client_id": settings.google_client_id,
        "allowed_domain": settings.google_allowed_domain,
    }


@router.get("/me")
async def me(request: Request) -> dict[str, Any]:
    return {"enabled": get_settings().auth_enabled, "user": current_user(request)}


@router.post("/google")
async def login_google(request: Request) -> dict[str, Any]:
    settings = get_settings()
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Auth is not configured on this server.")
    body = await request.json()
    token = (body or {}).get("credential")
    if not token:
        raise HTTPException(status_code=400, detail="Missing Google credential.")

    claims = _verify_google_token(token)
    sub = claims["sub"]
    with get_session() as session:
        user = session.execute(select(User).where(User.google_sub == sub)).scalar_one_or_none()
        if user is None:
            user = User(google_sub=sub)
            session.add(user)
        user.email = claims.get("email", user.email or "")
        user.name = claims.get("name", "") or user.name
        user.picture_url = claims.get("picture", "") or user.picture_url
        session.flush()
        payload = _public_user(user)

    request.session["user_id"] = payload["id"]
    return {"user": payload}


@router.post("/logout")
async def logout(request: Request) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}
