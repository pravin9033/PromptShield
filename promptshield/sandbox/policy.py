"""Policy engine for agent sandboxing."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from typing import Any, Dict, Iterable, Optional, Sequence


class SandboxViolation(RuntimeError):
    """Raised when a sandbox policy blocks an action."""


class ActionType(str, Enum):
    TOOL_CALL = "TOOL_CALL"
    NETWORK = "NETWORK"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    MODEL_CALL = "MODEL_CALL"


@dataclass(frozen=True)
class Action:
    action_type: ActionType
    name: Optional[str] = None
    resource: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxContext:
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class Policy:
    """Base class for sandbox policies."""

    name: str = "policy"

    def evaluate(self, action: Action, context: SandboxContext) -> Optional[Decision]:
        raise NotImplementedError


class AllowListPolicy(Policy):
    """Allow actions only when they match an allowlist (optionally enforced)."""

    def __init__(
        self,
        name: str,
        action_types: Sequence[ActionType],
        allowed_names: Optional[Sequence[str]] = None,
        allowed_resources: Optional[Sequence[str]] = None,
        enforce: bool = True,
    ) -> None:
        self.name = name
        self.action_types = set(action_types)
        self.allowed_names = list(allowed_names or [])
        self.allowed_resources = list(allowed_resources or [])
        self.enforce = enforce

    def evaluate(self, action: Action, context: SandboxContext) -> Optional[Decision]:
        if action.action_type not in self.action_types:
            return None

        if not self.allowed_names and not self.allowed_resources:
            if self.enforce:
                return Decision(False, "allowlist is empty", self.name)
            return None

        if _matches(action.name, self.allowed_names) or _matches(action.resource, self.allowed_resources):
            return Decision(True, "matched allowlist", self.name)

        if self.enforce:
            return Decision(False, "not in allowlist", self.name)
        return None


class DenyListPolicy(Policy):
    """Deny actions that match a denylist."""

    def __init__(
        self,
        name: str,
        action_types: Sequence[ActionType],
        denied_names: Optional[Sequence[str]] = None,
        denied_resources: Optional[Sequence[str]] = None,
    ) -> None:
        self.name = name
        self.action_types = set(action_types)
        self.denied_names = list(denied_names or [])
        self.denied_resources = list(denied_resources or [])

    def evaluate(self, action: Action, context: SandboxContext) -> Optional[Decision]:
        if action.action_type not in self.action_types:
            return None

        if _matches(action.name, self.denied_names) or _matches(action.resource, self.denied_resources):
            return Decision(False, "matched denylist", self.name)

        return None


class PolicyEngine:
    """Evaluate actions against a list of policies."""

    def __init__(self, policies: Iterable[Policy], default_allow: bool = True) -> None:
        self.policies = list(policies)
        self.default_allow = default_allow

    def evaluate(self, action: Action, context: Optional[SandboxContext] = None) -> Decision:
        context = context or SandboxContext()
        allow_decisions = []

        for policy in self.policies:
            decision = policy.evaluate(action, context)
            if decision is None:
                continue
            if not decision.allowed:
                return decision
            allow_decisions.append(decision)

        if allow_decisions:
            return allow_decisions[-1]

        if self.default_allow:
            return Decision(True, "default allow", "default")
        return Decision(False, "default deny", "default")

    def enforce(self, action: Action, context: Optional[SandboxContext] = None) -> Decision:
        decision = self.evaluate(action, context)
        if not decision.allowed:
            raise SandboxViolation(f"{decision.policy}: {decision.reason}")
        return decision


def _matches(value: Optional[str], patterns: Sequence[str]) -> bool:
    if not value:
        return False
    return any(fnmatch(value, pattern) for pattern in patterns)
