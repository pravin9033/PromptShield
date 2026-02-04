"""LangChain tool wrappers for sandbox enforcement."""

from __future__ import annotations

from typing import Any, Optional

from .intercept import wrap_tool
from .policy import PolicyEngine, SandboxContext


def wrap_langchain_tool(
    tool: Any,
    engine: PolicyEngine,
    context: Optional[SandboxContext] = None,
    name: Optional[str] = None,
) -> Any:
    """Wrap a LangChain tool-like object with sandbox enforcement."""
    tool_name = name or getattr(tool, "name", tool.__class__.__name__)

    if hasattr(tool, "run"):
        tool.run = wrap_tool(tool_name, tool.run, engine, context)
    elif hasattr(tool, "invoke"):
        tool.invoke = wrap_tool(tool_name, tool.invoke, engine, context)
    else:
        tool.__call__ = wrap_tool(tool_name, tool.__call__, engine, context)

    return tool
