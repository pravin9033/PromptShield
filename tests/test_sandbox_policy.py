import pytest

from promptshield.sandbox import (
    Action,
    ActionType,
    AllowListPolicy,
    DenyListPolicy,
    PolicyEngine,
    SandboxViolation,
)


def test_allowlist_enforces_tools():
    engine = PolicyEngine(
        [
            AllowListPolicy(
                name="tools",
                action_types=[ActionType.TOOL_CALL],
                allowed_names=["search"],
            )
        ]
    )

    allowed = engine.evaluate(Action(ActionType.TOOL_CALL, name="search"))
    assert allowed.allowed is True

    with pytest.raises(SandboxViolation):
        engine.enforce(Action(ActionType.TOOL_CALL, name="delete"))


def test_denylist_blocks_paths():
    engine = PolicyEngine(
        [
            DenyListPolicy(
                name="deny-paths",
                action_types=[ActionType.FILE_READ],
                denied_resources=["/etc/*"],
            )
        ]
    )

    with pytest.raises(SandboxViolation):
        engine.enforce(Action(ActionType.FILE_READ, resource="/etc/passwd"))
