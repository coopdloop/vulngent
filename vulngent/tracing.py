"""Optional OpenTelemetry tracing into Arize Phoenix.

Kept deliberately soft: the tracing packages are an optional extra, so every failure
path here degrades to "no tracing" rather than breaking the app. Without this, Phoenix
can still be configured read-only (the dashboard reads whatever another process traced),
but with it vulngent's own model calls show up in Phoenix with real token counts.

Call `setup_tracing()` once at process start (CLI and chat server both do).
"""

from __future__ import annotations

import logging

from vulngent.config import get_settings

logger = logging.getLogger(__name__)

_STARTED = False


def setup_tracing() -> bool:
    """Instrument OpenAI-compatible calls and export spans to Phoenix. Returns True if on.

    Idempotent: repeated calls (CLI command + server import) are no-ops."""
    global _STARTED
    if _STARTED:
        return True

    settings = get_settings()
    if not (settings.phoenix_tracing_enabled and settings.phoenix_endpoint):
        return False

    try:
        from phoenix.otel import register
    except ImportError:
        logger.warning(
            "PHOENIX_TRACING_ENABLED is set but arize-phoenix-otel is not installed; "
            "install the extra with `uv sync --extra phoenix` to emit traces."
        )
        return False

    try:
        kwargs = {
            "project_name": settings.phoenix_project_name or "vulngent",
            "endpoint": f"{settings.phoenix_endpoint.rstrip('/')}/v1/traces",
            "auto_instrument": True,
            "batch": True,
        }
        if settings.phoenix_api_key:
            kwargs["headers"] = {"Authorization": f"Bearer {settings.phoenix_api_key}"}
        tracer_provider = register(**kwargs)
    except Exception as exc:  # noqa: BLE001 - never let telemetry break the app
        logger.warning("Phoenix tracing setup failed (%s); continuing without tracing.", exc)
        return False

    # auto_instrument picks up installed OpenInference instrumentors, but the agents talk
    # to OpenRouter through the OpenAI SDK, so instrument it explicitly when available.
    try:
        from openinference.instrumentation.openai import OpenAIInstrumentor

        OpenAIInstrumentor().instrument(tracer_provider=tracer_provider)
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenAI instrumentation failed: %s", exc)

    _STARTED = True
    logger.info("Phoenix tracing enabled -> %s", settings.phoenix_endpoint)
    return True
