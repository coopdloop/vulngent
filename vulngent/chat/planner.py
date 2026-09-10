from __future__ import annotations

import json
from typing import Any

from vulngent.chat.confirmation import get_current_confirmation_manager


def plan_write_action(tool_name: str, arguments: dict[str, Any] | None = None, summary: str | None = None) -> str:
    """Record a planned side-effecting action and return its details for the analyst's confirmation."""
    manager = get_current_confirmation_manager()
    if manager is None:
        return json.dumps({"error": "unable to record action: no active chat session"})
    args = dict(arguments) if arguments else {}
    manager.set_pending_action(tool_name, args, summary)
    payload = {
        "status": "pending_confirmation",
        "tool_name": tool_name,
        "arguments": args,
        "summary": summary or "",
    }
    return json.dumps(payload)
