import pytest

from promptshield.sandbox import (
    Action,
    ActionType,
    AllowListPolicy,
    BudgetPolicy,
    DenyListPolicy,
    PolicyEngine,
    SandboxContext,
    SandboxSession,
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


def test_budget_policy_limits_calls():
    session = SandboxSession(max_tool_calls=1)
    context = SandboxContext(session=session)
    engine = PolicyEngine([BudgetPolicy()])

    engine.enforce(Action(ActionType.TOOL_CALL, name="search"), context)
    with pytest.raises(SandboxViolation):
        engine.enforce(Action(ActionType.TOOL_CALL, name="search"), context)
