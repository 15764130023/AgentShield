import hashlib
import secrets
from collections.abc import Callable

from agentshield.models import RiskLevel, ToolSpec
from agentshield.sensitive_data import (
    ensure_no_sensitive_data,
)


_SAFE_ERROR_MESSAGE = "消息发送参数不合规"
_CONFIG_ERROR_MESSAGE = "消息发送配置不合规"

_MAX_CONTENT_LENGTH = 500
_MAX_REASON_LENGTH = 200


def _normalize_required_text(
    value: object,
) -> str:
    if type(value) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if any(
        not character.isprintable()
        for character in value
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    normalized_value = value.strip()

    if not normalized_value:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return normalized_value


def _normalize_optional_text(
    value: object,
) -> str:
    if type(value) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if any(
        not character.isprintable()
        for character in value
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return value.strip()


def _extract_arguments(
    arguments: dict[str, object],
    allowed_recipients: set[str],
) -> tuple[str, str, str]:
    if type(arguments) is not dict:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    argument_names = set(arguments)

    if (
        argument_names != {
            "recipient",
            "content",
        }
        and argument_names != {
            "recipient",
            "content",
            "reason",
        }
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    recipient = _normalize_required_text(
        arguments["recipient"]
    )

    if recipient not in allowed_recipients:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    content = _normalize_required_text(
        arguments["content"]
    )

    if len(content) > _MAX_CONTENT_LENGTH:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    reason = _normalize_optional_text(
        arguments.get("reason", "")
    )

    if len(reason) > _MAX_REASON_LENGTH:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return recipient, content, reason


def _normalize_allowed_recipients(
    allowed_recipients: set[str],
) -> set[str]:
    if (
        type(allowed_recipients) is not set
        or not allowed_recipients
    ):
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    normalized_recipients: set[str] = set()

    for recipient in allowed_recipients:
        if type(recipient) is not str:
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        if any(
            not character.isprintable()
            for character in recipient
        ):
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        normalized_recipient = recipient.strip()

        if not normalized_recipient:
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        if normalized_recipient in normalized_recipients:
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        normalized_recipients.add(
            normalized_recipient
        )

    return normalized_recipients


def _create_content_summary(
    content: str,
) -> str:
    content_digest = hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()[:12]

    return f"sha256:{content_digest}"


def _create_message_id(
    id_factory: Callable[[], str],
    outbox: list[dict[str, object]],
) -> str:
    message_id = id_factory()

    if type(message_id) is not str:
        raise RuntimeError("消息编号生成器返回值不合规")

    normalized_message_id = message_id.strip()

    if not normalized_message_id:
        raise RuntimeError("消息编号生成器返回值不合规")

    if any(
        not character.isprintable()
        for character in normalized_message_id
    ):
        raise RuntimeError("消息编号生成器返回值不合规")

    if any(
        record.get("message_id")
        == normalized_message_id
        for record in outbox
        if type(record) is dict
    ):
        raise RuntimeError("消息编号发生冲突")

    return normalized_message_id


def create_send_message_spec(
    allowed_recipients: set[str],
    outbox: list[dict[str, object]],
    id_factory: Callable[[], str] | None = None,
) -> ToolSpec:
    normalized_recipients = (
        _normalize_allowed_recipients(
            allowed_recipients
        )
    )

    if type(outbox) is not list:
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    if id_factory is None:
        id_factory = lambda: secrets.token_urlsafe(12)

    if not callable(id_factory):
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    def validate_arguments(
        arguments: dict[str, object],
    ) -> None:
        _, content, reason = _extract_arguments(
            arguments=arguments,
            allowed_recipients=normalized_recipients,
        )

        ensure_no_sensitive_data(content)
        ensure_no_sensitive_data(reason)

    def handle_send_message(
        arguments: dict[str, object],
    ) -> object:
        recipient, content, reason = _extract_arguments(
            arguments=arguments,
            allowed_recipients=normalized_recipients,
        )

        message_id = _create_message_id(
            id_factory=id_factory,
            outbox=outbox,
        )

        content_summary = _create_content_summary(
            content
        )

        message_record: dict[str, object] = {
            "message_id": message_id,
            "recipient": recipient,
            "content": content,
            "reason": reason,
            "status": "sent",
        }

        outbox.append(message_record)

        return {
            "message_id": message_id,
            "recipient": recipient,
            "status": "sent",
            "content_summary": content_summary,
        }

    return ToolSpec(
        name="send_message",
        description="向固定测试目标模拟发送消息",
        risk_level=RiskLevel.HIGH,
        required_permissions={"message.send"},
        allowed_targets=set(normalized_recipients),
        requires_confirmation=True,
        parameter_validator=validate_arguments,
        handler=handle_send_message,
    )