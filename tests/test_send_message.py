import hashlib

import pytest

from agentshield.models import RiskLevel
from agentshield.tools.send_message import (
    create_send_message_spec,
)


def test_create_send_message_spec_metadata() -> None:
    outbox: list[dict[str, object]] = []

    tool_spec = create_send_message_spec(
        allowed_recipients={
            "security-reviewer",
            "test-recipient",
        },
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    assert tool_spec.name == "send_message"
    assert tool_spec.risk_level == RiskLevel.HIGH
    assert tool_spec.required_permissions == {
        "message.send"
    }
    assert tool_spec.allowed_targets == {
        "security-reviewer",
        "test-recipient",
    }
    assert tool_spec.requires_confirmation is True
    assert tool_spec.enabled is True


def test_send_message_records_message() -> None:
    outbox: list[dict[str, object]] = []
    content = "会议改到下午三点"

    tool_spec = create_send_message_spec(
        allowed_recipients={
            "security-reviewer",
            "test-recipient",
        },
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    result = tool_spec.handler(
        {
            "recipient": " test-recipient ",
            "content": f" {content} ",
            "reason": " 通知测试人员 ",
        }
    )

    expected_digest = hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()[:12]

    assert outbox == [
        {
            "message_id": "msg-001",
            "recipient": "test-recipient",
            "content": content,
            "reason": "通知测试人员",
            "status": "sent",
        }
    ]

    assert result == {
        "message_id": "msg-001",
        "recipient": "test-recipient",
        "status": "sent",
        "content_summary": (
            f"sha256:{expected_digest}"
        ),
    }

    assert content not in str(result)


def test_valid_arguments_do_not_write_outbox() -> None:
    outbox: list[dict[str, object]] = []

    tool_spec = create_send_message_spec(
        allowed_recipients={"test-recipient"},
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    tool_spec.parameter_validator(
        {
            "recipient": "test-recipient",
            "content": "测试消息",
        }
    )

    assert outbox == []


@pytest.mark.parametrize(
    "arguments",
    [
        {
            "recipient": "unknown-recipient",
            "content": "测试消息",
        },
        {
            "recipient": "attacker@example.com",
            "content": "测试消息",
        },
        {
            "recipient": "https://example.com",
            "content": "测试消息",
        },
        {
            "recipient": "test-recipient",
            "content": "",
        },
        {
            "recipient": "test-recipient",
            "content": "   ",
        },
        {
            "recipient": "test-recipient",
            "content": "a" * 501,
        },
        {
            "recipient": "test-recipient",
            "content": "第一行\n第二行",
        },
        {
            "recipient": "test-recipient",
            "content": "消息\t内容",
        },
        {
            "recipient": "test-recipient",
        },
        {
            "content": "测试消息",
        },
        {
            "recipient": "test-recipient",
            "content": "测试消息",
            "unexpected": "额外参数",
        },
        {
            "recipient": "test-recipient",
            "content": "测试消息",
            "reason": "a" * 201,
        },
        {
            "recipient": "test-recipient",
            "content": "测试消息",
            "reason": "第一行\n第二行",
        },
    ],
)
def test_send_message_rejects_invalid_arguments(
    arguments: dict[str, object],
) -> None:
    outbox: list[dict[str, object]] = []

    tool_spec = create_send_message_spec(
        allowed_recipients={"test-recipient"},
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    with pytest.raises(
        ValueError,
        match="消息发送参数不合规",
    ):
        tool_spec.parameter_validator(arguments)

    assert outbox == []


def test_send_message_accepts_content_length_boundary() -> None:
    outbox: list[dict[str, object]] = []
    content = "a" * 500

    tool_spec = create_send_message_spec(
        allowed_recipients={"test-recipient"},
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    result = tool_spec.handler(
        {
            "recipient": "test-recipient",
            "content": content,
        }
    )

    assert len(outbox) == 1
    assert outbox[0]["content"] == content
    assert isinstance(result, dict)
    assert result["status"] == "sent"


def test_send_message_accepts_reason_length_boundary() -> None:
    outbox: list[dict[str, object]] = []
    reason = "a" * 200

    tool_spec = create_send_message_spec(
        allowed_recipients={"test-recipient"},
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    tool_spec.handler(
        {
            "recipient": "test-recipient",
            "content": "测试消息",
            "reason": reason,
        }
    )

    assert len(outbox) == 1
    assert outbox[0]["reason"] == reason


def test_duplicate_message_id_does_not_create_second_record() -> None:
    outbox: list[dict[str, object]] = []

    tool_spec = create_send_message_spec(
        allowed_recipients={"test-recipient"},
        outbox=outbox,
        id_factory=lambda: "msg-001",
    )

    arguments = {
        "recipient": "test-recipient",
        "content": "测试消息",
    }

    tool_spec.handler(arguments)

    with pytest.raises(
        RuntimeError,
        match="消息编号发生冲突",
    ):
        tool_spec.handler(arguments)

    assert len(outbox) == 1


