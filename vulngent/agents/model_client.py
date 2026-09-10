"""Model client factory: Claude via OpenRouter, using AutoGen's OpenAI-compatible client.

OpenRouter exposes an OpenAI-compatible /chat/completions endpoint that can route to
Claude models (e.g. "anthropic/claude-sonnet-4.5", "anthropic/claude-opus-4.1"). We point
autogen-ext's OpenAIChatCompletionClient at it via base_url and describe the model's
capabilities explicitly with `model_info`, since OpenRouter's model ids aren't in
autogen's built-in OpenAI model registry.
"""

from __future__ import annotations

from autogen_core.models import ModelFamily, ModelInfo
from autogen_ext.models.openai import OpenAIChatCompletionClient

from vulngent.config import get_settings


def build_model_client(model: str | None = None) -> OpenAIChatCompletionClient:
    settings = get_settings()
    if not settings.openrouter_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set.")

    model_info: ModelInfo = {
        "vision": False,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
        "family": ModelFamily.CLAUDE_4_SONNET,
        # Claude (and OpenRouter) accept any number of system messages; the chat agent
        # injects a section-format system message per turn on top of the base one.
        "multiple_system_messages": True,
    }

    return OpenAIChatCompletionClient(
        model=model or settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        model_info=model_info,
    )
