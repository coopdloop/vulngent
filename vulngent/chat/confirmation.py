from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, ContextManager


@dataclass
class PendingAction:
    tool_name: str
    arguments: dict[str, Any]
    summary: str | None = None


class ConfirmationManager:
    def __init__(self) -> None:
        self.pending_action: PendingAction | None = None
        self._notified: bool = False

    def set_pending_action(self, tool_name: str, arguments: dict[str, Any], summary: str | None) -> PendingAction:
        self.pending_action = PendingAction(tool_name=tool_name, arguments=arguments.copy(), summary=summary)
        self._notified = False
        return self.pending_action

    def clear(self) -> None:
        self.pending_action = None
        self._notified = False

    def mark_notified(self) -> None:
        self._notified = True

    @property
    def needs_notification(self) -> bool:
        return self.pending_action is not None and not self._notified


_current_manager: ContextVar[ConfirmationManager | None] = ContextVar("current_confirmation_manager", default=None)


def get_current_confirmation_manager() -> ConfirmationManager | None:
    return _current_manager.get()


@contextmanager
def use_confirmation_manager(manager: ConfirmationManager) -> ContextManager[None]:
    token = _current_manager.set(manager)
    try:
        yield
    finally:
        _current_manager.reset(token)
