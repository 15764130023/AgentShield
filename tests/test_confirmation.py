from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from agentshield.confirmation import (
    ConfirmationError,
    ConfirmationManager,
)
from agentshield.models import (
    Identity,
    ToolCall,
)


FIXED_NOW = datetime(
    2026,
    11,
    10,
    12,
    0,
    tzinfo=timezone.utc,
)


def _create_manager() -> ConfirmationManager:
    return ConfirmationManager(
        ttl_seconds=300,
        clock=lambda: FIXED_NOW,
        id_factory=lambda: "confirm-001",
    )


def _create_identity() -> Identity:
    return Identity(
        user_id="user-001",
        permissions={"message.send"},
    )


def _create_tool_call() -> ToolCall:
    return ToolCall(
        request_id="req-message-001",
        tool_name="send_message",
        arguments={
            "recipient": "test-recipient",
            "content": "安全测试已完成",
        },
    )


def test_create_confirmation_returns_id():
    manager = _create_manager()

    confirmation_id = manager.create(
        identity=_create_identity(),
        tool_call=_create_tool_call(),
    )

    assert confirmation_id == "confirm-001"


def test_confirmation_can_be_consumed_only_once():
    manager = _create_manager()
    identity = _create_identity()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    confirmed_call = manager.confirm(
        confirmation_id=confirmation_id,
        identity=identity,
    )

    assert confirmed_call.request_id == "req-message-001"
    assert confirmed_call.tool_name == "send_message"
    assert confirmed_call.arguments == {
        "recipient": "test-recipient",
        "content": "安全测试已完成",
    }

    with pytest.raises(ConfirmationError) as error:
        manager.confirm(
            confirmation_id=confirmation_id,
            identity=identity,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_ALREADY_USED"
    )


def test_other_user_cannot_confirm_request():
    manager = _create_manager()
    owner = _create_identity()

    other_user = Identity(
        user_id="user-002",
        permissions={"message.send"},
    )

    confirmation_id = manager.create(
        identity=owner,
        tool_call=_create_tool_call(),
    )

    with pytest.raises(ConfirmationError) as error:
        manager.confirm(
            confirmation_id=confirmation_id,
            identity=other_user,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_FORBIDDEN"
    )

    confirmed_call = manager.confirm(
        confirmation_id=confirmation_id,
        identity=owner,
    )

    assert confirmed_call.request_id == "req-message-001"


def test_confirmation_expires_at_deadline():
    current_time = [FIXED_NOW]

    manager = ConfirmationManager(
        ttl_seconds=300,
        clock=lambda: current_time[0],
        id_factory=lambda: "confirm-expiring",
    )

    identity = _create_identity()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    current_time[0] = (
        FIXED_NOW + timedelta(seconds=300)
    )

    with pytest.raises(ConfirmationError) as error:
        manager.confirm(
            confirmation_id=confirmation_id,
            identity=identity,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_EXPIRED"
    )


def test_confirmation_copies_tool_arguments():
    manager = _create_manager()
    identity = _create_identity()
    tool_call = _create_tool_call()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=tool_call,
    )

    tool_call.arguments["recipient"] = "changed-recipient"
    tool_call.arguments["content"] = "changed-content"

    confirmed_call = manager.confirm(
        confirmation_id=confirmation_id,
        identity=identity,
    )

    assert confirmed_call.arguments == {
        "recipient": "test-recipient",
        "content": "安全测试已完成",
    }



def test_rejected_confirmation_cannot_be_confirmed():
    manager = _create_manager()
    identity = _create_identity()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    manager.reject(
        confirmation_id=confirmation_id,
        identity=identity,
    )

    with pytest.raises(ConfirmationError) as error:
        manager.confirm(
            confirmation_id=confirmation_id,
            identity=identity,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_REJECTED"
    )


def test_confirmation_cannot_be_rejected_twice():
    manager = _create_manager()
    identity = _create_identity()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    manager.reject(
        confirmation_id=confirmation_id,
        identity=identity,
    )

    with pytest.raises(ConfirmationError) as error:
        manager.reject(
            confirmation_id=confirmation_id,
            identity=identity,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_REJECTED"
    )


def test_other_user_cannot_reject_request():
    manager = _create_manager()
    owner = _create_identity()

    other_user = Identity(
        user_id="user-002",
        permissions={"message.send"},
    )

    confirmation_id = manager.create(
        identity=owner,
        tool_call=_create_tool_call(),
    )

    with pytest.raises(ConfirmationError) as error:
        manager.reject(
            confirmation_id=confirmation_id,
            identity=other_user,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_FORBIDDEN"
    )

    confirmed_call = manager.confirm(
        confirmation_id=confirmation_id,
        identity=owner,
    )

    assert confirmed_call.request_id == "req-message-001"


def test_expired_confirmation_cannot_be_rejected():
    current_time = [FIXED_NOW]

    manager = ConfirmationManager(
        ttl_seconds=300,
        clock=lambda: current_time[0],
        id_factory=lambda: "confirm-expiring",
    )

    identity = _create_identity()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    current_time[0] = (
        FIXED_NOW + timedelta(seconds=300)
    )

    with pytest.raises(ConfirmationError) as error:
        manager.reject(
            confirmation_id=confirmation_id,
            identity=identity,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_EXPIRED"
    )


def test_consumed_confirmation_cannot_be_rejected():
    manager = _create_manager()
    identity = _create_identity()

    confirmation_id = manager.create(
        identity=identity,
        tool_call=_create_tool_call(),
    )

    manager.confirm(
        confirmation_id=confirmation_id,
        identity=identity,
    )

    with pytest.raises(ConfirmationError) as error:
        manager.reject(
            confirmation_id=confirmation_id,
            identity=identity,
        )

    assert (
        error.value.reason_code
        == "CONFIRMATION_ALREADY_USED"
    )