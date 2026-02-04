"""Interceptors for tool and resource access."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from .policy import Action, ActionType, PolicyEngine, SandboxContext


def wrap_tool(
    tool_name: str,
    func: Callable[..., Any],
    engine: PolicyEngine,
    context: Optional[SandboxContext] = None,
) -> Callable[..., Any]:
    """Wrap a callable tool with sandbox enforcement."""

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        action = Action(
            action_type=ActionType.TOOL_CALL,
            name=tool_name,
            params={"args": args, "kwargs": kwargs},
        )
        engine.enforce(action, context)
        return func(*args, **kwargs)

    return wrapper


def enforce_network(
    url: str,
    engine: PolicyEngine,
    context: Optional[SandboxContext] = None,
    params: Optional[dict[str, Any]] = None,
) -> None:
    action = Action(action_type=ActionType.NETWORK, resource=url, params=params or {})
    engine.enforce(action, context)


def enforce_file_read(
    path: str,
    engine: PolicyEngine,
    context: Optional[SandboxContext] = None,
    params: Optional[dict[str, Any]] = None,
) -> None:
    action = Action(action_type=ActionType.FILE_READ, resource=path, params=params or {})
    engine.enforce(action, context)


def enforce_file_write(
    path: str,
    engine: PolicyEngine,
    context: Optional[SandboxContext] = None,
    params: Optional[dict[str, Any]] = None,
) -> None:
    action = Action(action_type=ActionType.FILE_WRITE, resource=path, params=params or {})
    engine.enforce(action, context)
