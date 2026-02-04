"""AutoGen-compatible wrappers for sandbox enforcement."""

from __future__ import annotations

from typing import Any, Callable, Optional

from .intercept import wrap_tool
from .policy import PolicyEngine, SandboxContext


def wrap_autogen_function(
    name: str,
    func: Callable[..., Any],
    engine: PolicyEngine,
    context: Optional[SandboxContext] = None,
) -> Callable[..., Any]:
    """Wrap a function intended for AutoGen tool use."""
    return wrap_tool(name, func, engine, context)
