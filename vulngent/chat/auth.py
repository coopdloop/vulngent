"""Sign-in with Google and Microsoft: verify the provider ID token from the browser,
mint a session cookie.

Both providers use a client-side token flow (Google Identity Services / MSAL.js). The
browser sends the resulting ID token (a signed JWT) here; we verify it against the
provider's published signing keys, upsert a User, and store the user id in a signed
session cookie (Starlette SessionMiddleware). No client secret is required.

When no provider client id is configured, auth_enabled is False and the whole layer is a
no-op so local dev keeps working unauthenticated."""

from __future__ import annotations

import secrets
from typing import Any

import jwt
from fastapi import APIRouter, HTTPException, Request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jwt import PyJWKClient
from sqlalchemy import select

from vulngent.config import get_settings
from vulngent.db.models import User
from vulngent.db.session import get_session

router = APIRouter(prefix="/api/auth", tags=["auth"])

_GOOGLE_REQUEST = google_requests.Request()
_MS_JWKS_CACHE: dict[str, PyJWKClient] = {}


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
        "provider": user.provider,
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
    if not get_settings().auth_enabled:
        return None
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


# --- Google -----------------------------------------------------------------

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

    return {
        "subject": claims["sub"],
        "email": claims.get("email", ""),
        "name": claims.get("name", ""),
        "picture": claims.get("picture", ""),
    }


# --- Microsoft (Azure AD / Entra ID) ----------------------------------------

def _ms_jwks_client(tenant: str) -> PyJWKClient:
    if tenant not in _MS_JWKS_CACHE:
        uri = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        _MS_JWKS_CACHE[tenant] = PyJWKClient(uri)
    return _MS_JWKS_CACHE[tenant]


def _verify_microsoft_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    tenant = settings.microsoft_tenant or "common"
    try:
        signing_key = _ms_jwks_client(tenant).get_signing_key_from_jwt(token)
        # v2.0 tokens use issuer https://login.microsoftonline.com/{tid}/v2.0;
        # 'common'/'organizations' vary the tid per-user, so verify issuer loosely.
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.microsoft_client_id,
            options={"verify_iss": False},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid Microsoft token: {exc}") from exc

    issuer = str(claims.get("iss", ""))
    if not issuer.startswith("https://login.microsoftonline.com/"):
        raise HTTPException(status_code=401, detail="Unexpected Microsoft token issuer.")

    email = claims.get("email") or claims.get("preferred_username") or ""
    return {
        "subject": claims["sub"],
        "email": email,
        "name": claims.get("name", ""),
        "picture": "",  # Microsoft ID tokens don't carry a photo URL
    }


# --- Shared login / routes --------------------------------------------------

def _login(provider: str, profile: dict[str, Any], request: Request) -> dict[str, Any]:
    with get_session() as session:
        user = session.execute(
            select(User).where(User.provider == provider, User.subject == profile["subject"])
        ).scalar_one_or_none()
        if user is None:
            user = User(provider=provider, subject=profile["subject"])
            session.add(user)
        user.email = profile.get("email") or user.email or ""
        user.name = profile.get("name") or user.name
        if profile.get("picture"):
            user.picture_url = profile["picture"]
        session.flush()
        payload = _public_user(user)

    request.session["user_id"] = payload["id"]
    return payload


@router.get("/config")
async def auth_config() -> dict[str, Any]:
    """Public: tells the frontend which sign-in buttons to show."""
    settings = get_settings()
    return {
        "enabled": settings.auth_enabled,
        "google": {"enabled": settings.google_enabled, "client_id": settings.google_client_id},
        "microsoft": {
            "enabled": settings.microsoft_enabled,
            "client_id": settings.microsoft_client_id,
            "tenant": settings.microsoft_tenant,
        },
        "allowed_domain": settings.google_allowed_domain,
    }


@router.get("/me")
async def me(request: Request) -> dict[str, Any]:
    return {"enabled": get_settings().auth_enabled, "user": current_user(request)}


@router.post("/google")
async def login_google(request: Request) -> dict[str, Any]:
    settings = get_settings()
    if not settings.google_enabled:
        raise HTTPException(status_code=400, detail="Google auth is not configured on this server.")
    body = await request.json()
    token = (body or {}).get("credential")
    if not token:
        raise HTTPException(status_code=400, detail="Missing Google credential.")
    profile = _verify_google_token(token)
    return {"user": _login("google", profile, request)}


@router.post("/microsoft")
async def login_microsoft(request: Request) -> dict[str, Any]:
    settings = get_settings()
    if not settings.microsoft_enabled:
        raise HTTPException(status_code=400, detail="Microsoft auth is not configured on this server.")
    body = await request.json()
    token = (body or {}).get("id_token") or (body or {}).get("credential")
    if not token:
        raise HTTPException(status_code=400, detail="Missing Microsoft id token.")
    profile = _verify_microsoft_token(token)
    return {"user": _login("microsoft", profile, request)}


@router.post("/logout")
async def logout(request: Request) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}
