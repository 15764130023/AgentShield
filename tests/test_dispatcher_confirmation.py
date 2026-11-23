from datetime import (
    datetime,
    timezone,
)

from agentshield.confirmation import ConfirmationManager
from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    Identity,
    RiskLevel,
    ToolCall,
    ToolSpec,
)
from agentshield.registry import ToolRegistry


FIXED_NOW = datetime(
    2026,
    11,
    10,
    12,
    0,
    tzinfo=timezone.utc,
)


def _create_dispatcher():
    handler_calls: list[dict[str, object]] = []

    def validate_arguments(
        arguments: dict[str, object],
    ) -> None:
        if set(arguments) != {"value"}:
            raise ValueError("参数不合规")

        if type(arguments["value"]) is not str:
            raise ValueError("参数不合规")

    def handle_tool(
        arguments: dict[str, object],
    ) -> object:
        handler_calls.append(dict(arguments))
        return "executed"

    tool_spec = ToolSpec(
        name="high_risk_test",
        description="测试高风险确认流程",
        risk_level=RiskLevel.HIGH,
        required_permissions={"tool.execute"},
        allowed_targets={"local"},
        requires_confirmation=True,
        parameter_validator=validate_arguments,
        handler=handle_tool,
    )

    registry = ToolRegistry()
    registry.register(tool_spec)

    confirmation_manager = ConfirmationManager(
        ttl_seconds=300,
        clock=lambda: FIXED_NOW,
        id_factory=lambda: "confirm-dispatch-001",
    )

    dispatcher = SecurityDispatcher(
        registry=registry,
        confirmation_manager=confirmation_manager,
    )

    return dispatcher, handler_calls


def _create_identity() -> Identity:
    return Identity(
        user_id="user-001",
        permissions={"tool.execute"},
    )


def _create_tool_call() -> ToolCall:
    return ToolCall(
        request_id="req-dispatch-confirm-001",
        tool_name="high_risk_test",
        arguments={"value": "safe-value"},
    )


def test_dispatch_creates_confirmation_without_execution():
    dispatcher, handler_calls = _create_dispatcher()

    result = dispatcher.dispatch(
        identity=_create_identity(),
        tool_call=_create_tool_call(),
    )

    assert result.decision == Decision.CONFIRM
    assert result.reason_code == "CONFIRMATION_REQUIRED"
    assert result.confirmation_id == "confirm-dispatch-001"
    assert result.result is None
    assert handler_calls == []


def test_confirm_executes_tool_only_once():
    dispatcher, handler_calls = _create_dispatcher()
    identity = _create_identity()

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    assert pending_result.confirmation_id is not None

    confirmed_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=pending_result.confirmation_id,
    )

    assert confirmed_result.decision == Decision.ALLOW
    assert confirmed_result.reason_code == "TOOL_EXECUTED"
    assert confirmed_result.result == "executed"
    assert handler_calls == [
        {"value": "safe-value"},
    ]

    replay_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=pending_result.confirmation_id,
    )

    assert replay_result.decision == Decision.DENY
    assert (
        replay_result.reason_code
        == "CONFIRMATION_ALREADY_USED"
    )
    assert len(handler_calls) == 1


def test_reject_prevents_tool_execution():
    dispatcher, handler_calls = _create_dispatcher()
    identity = _create_identity()

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    assert pending_result.confirmation_id is not None

    rejected_result = dispatcher.reject(
        identity=identity,
        confirmation_id=pending_result.confirmation_id,
    )

    assert rejected_result.decision == Decision.DENY
    assert (
        rejected_result.reason_code
        == "CONFIRMATION_REJECTED"
    )
    assert handler_calls == []

    confirm_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=pending_result.confirmation_id,
    )

    assert confirm_result.decision == Decision.DENY
    assert (
        confirm_result.reason_code
        == "CONFIRMATION_REJECTED"
    )
    assert handler_calls == []


def test_confirm_rechecks_permission_before_execution():
    dispatcher, handler_calls = _create_dispatcher()
    identity = _create_identity()

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    assert pending_result.confirmation_id is not None

    identity.permissions.clear()

    confirmed_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=pending_result.confirmation_id,
    )

    assert confirmed_result.decision == Decision.DENY
    assert (
        confirmed_result.reason_code
        == "PERMISSION_DENIED"
    )
    assert handler_calls == []