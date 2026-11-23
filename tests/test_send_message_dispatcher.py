from agentshield.confirmation import ConfirmationManager
from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    Identity,
    ToolCall,
)
from agentshield.registry import ToolRegistry
from agentshield.tools.send_message import (
    create_send_message_spec,
)


def _create_dispatcher(
    outbox: list[dict[str, object]],
) -> SecurityDispatcher:
    registry = ToolRegistry()

    send_message_spec = create_send_message_spec(
        allowed_recipients={
            "security-reviewer",
            "test-recipient",
        },
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    registry.register(send_message_spec)

    confirmation_manager = ConfirmationManager(
        id_factory=lambda: "confirmation-001",
    )

    return SecurityDispatcher(
        registry=registry,
        confirmation_manager=confirmation_manager,
    )


def _create_send_identity() -> Identity:
    return Identity(
        user_id="user-001",
        permissions={"message.send"},
    )


def _create_send_call(
    recipient: str = "test-recipient",
    content: str = "会议改到下午三点",
) -> ToolCall:
    return ToolCall(
        request_id="request-001",
        tool_name="send_message",
        arguments={
            "recipient": recipient,
            "content": content,
            "reason": "通知测试人员",
        },
    )


def test_send_message_requires_confirmation_before_execution() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)

    result = dispatcher.dispatch(
        identity=_create_send_identity(),
        tool_call=_create_send_call(),
    )

    assert result.decision == Decision.CONFIRM
    assert result.reason_code == "CONFIRMATION_REQUIRED"
    assert result.confirmation_id == "confirmation-001"
    assert result.result is None
    assert outbox == []


def test_confirmed_send_message_executes_once() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)
    identity = _create_send_identity()

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_send_call(),
    )

    assert pending_result.confirmation_id is not None
    assert outbox == []

    confirmed_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=(
            pending_result.confirmation_id
        ),
    )

    assert confirmed_result.decision == Decision.ALLOW
    assert confirmed_result.reason_code == "TOOL_EXECUTED"
    assert len(outbox) == 1

    assert outbox[0] == {
        "message_id": "msg-001",
        "recipient": "test-recipient",
        "content": "会议改到下午三点",
        "reason": "通知测试人员",
        "status": "sent",
    }

    assert isinstance(confirmed_result.result, dict)
    assert confirmed_result.result["message_id"] == "msg-001"
    assert confirmed_result.result["status"] == "sent"
    assert (
        "会议改到下午三点"
        not in str(confirmed_result.result)
    )


def test_confirmation_cannot_be_replayed() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)
    identity = _create_send_identity()

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_send_call(),
    )

    assert pending_result.confirmation_id is not None

    first_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=(
            pending_result.confirmation_id
        ),
    )

    second_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=(
            pending_result.confirmation_id
        ),
    )

    assert first_result.decision == Decision.ALLOW
    assert second_result.decision == Decision.DENY
    assert (
        second_result.reason_code
        == "CONFIRMATION_ALREADY_USED"
    )
    assert len(outbox) == 1


def test_rejected_send_message_is_not_executed() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)
    identity = _create_send_identity()

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_send_call(),
    )

    assert pending_result.confirmation_id is not None

    rejected_result = dispatcher.reject(
        identity=identity,
        confirmation_id=(
            pending_result.confirmation_id
        ),
    )

    assert rejected_result.decision == Decision.DENY
    assert (
        rejected_result.reason_code
        == "CONFIRMATION_REJECTED"
    )
    assert outbox == []

    confirm_after_rejection = dispatcher.confirm(
        identity=identity,
        confirmation_id=(
            pending_result.confirmation_id
        ),
    )

    assert (
        confirm_after_rejection.decision
        == Decision.DENY
    )
    assert (
        confirm_after_rejection.reason_code
        == "CONFIRMATION_REJECTED"
    )
    assert outbox == []


def test_send_message_without_permission_is_denied() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)

    identity = Identity(
        user_id="user-001",
        permissions=set(),
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=_create_send_call(),
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "PERMISSION_DENIED"
    assert result.confirmation_id is None
    assert outbox == []


def test_send_message_to_invalid_recipient_is_denied() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)

    result = dispatcher.dispatch(
        identity=_create_send_identity(),
        tool_call=_create_send_call(
            recipient="attacker@example.com",
        ),
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "INVALID_ARGUMENTS"
    assert result.confirmation_id is None
    assert outbox == []


def test_confirmation_uses_original_argument_snapshot() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)
    identity = _create_send_identity()

    arguments: dict[str, object] = {
        "recipient": "test-recipient",
        "content": "原始消息",
        "reason": "原始原因",
    }

    tool_call = ToolCall(
        request_id="request-001",
        tool_name="send_message",
        arguments=arguments,
    )

    pending_result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert pending_result.confirmation_id is not None
    assert outbox == []

    arguments["recipient"] = "attacker@example.com"
    arguments["content"] = "被篡改的消息"
    arguments["reason"] = "被篡改的原因"

    confirmed_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=(
            pending_result.confirmation_id
        ),
    )

    assert confirmed_result.decision == Decision.ALLOW
    assert len(outbox) == 1

    assert outbox[0]["recipient"] == "test-recipient"
    assert outbox[0]["content"] == "原始消息"
    assert outbox[0]["reason"] == "原始原因"


def test_sensitive_message_is_denied_before_confirmation() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)

    result = dispatcher.dispatch(
        identity=_create_send_identity(),
        tool_call=_create_send_call(
            content=(
                "测试密钥是 "
                "TEST_SECRET_DO_NOT_EXPOSE"
            ),
        ),
    )

    assert result.decision == Decision.DENY
    assert (
        result.reason_code
        == "SENSITIVE_DATA_DETECTED"
    )
    assert result.confirmation_id is None
    assert result.result is None
    assert outbox == []

    assert (
        "TEST_SECRET_DO_NOT_EXPOSE"
        not in result.message
    )


def test_sensitive_reason_is_denied_before_confirmation() -> None:
    outbox: list[dict[str, object]] = []
    dispatcher = _create_dispatcher(outbox)

    tool_call = ToolCall(
        request_id="request-sensitive-reason",
        tool_name="send_message",
        arguments={
            "recipient": "test-recipient",
            "content": "普通测试消息",
            "reason": (
                "使用 TEST_TOKEN_ABC123456789"
            ),
        },
    )

    result = dispatcher.dispatch(
        identity=_create_send_identity(),
        tool_call=tool_call,
    )

    assert result.decision == Decision.DENY
    assert (
        result.reason_code
        == "SENSITIVE_DATA_DETECTED"
    )
    assert result.confirmation_id is None
    assert outbox == []