from pathlib import Path

from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    Identity,
    RiskLevel,
    ToolCall,
)
from agentshield.registry import ToolRegistry
from agentshield.tools.read_file import (
    create_read_file_spec,
)


def test_read_file_spec_has_expected_security_metadata(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    spec = create_read_file_spec(allowed_root)

    assert spec.name == "read_file"
    assert spec.risk_level == RiskLevel.MEDIUM
    assert spec.required_permissions == {"file.read"}
    assert spec.allowed_targets == {str(allowed_root)}
    assert spec.requires_confirmation is True
    assert spec.enabled is True


def test_read_file_spec_handler_reads_allowed_file(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        "安全测试报告",
        encoding="utf-8",
    )

    spec = create_read_file_spec(allowed_root)

    result = spec.handler(
        {
            "path": "report.txt",
        }
    )

    assert result == "安全测试报告"


def test_dispatcher_requests_confirmation_before_reading_file(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        "安全测试报告",
        encoding="utf-8",
    )

    spec = create_read_file_spec(allowed_root)

    handler_was_called = False

    def track_handler(
        arguments: dict[str, object],
    ) -> object:
        nonlocal handler_was_called
        handler_was_called = True
        return "不应该执行到这里"

    spec.handler = track_handler

    registry = ToolRegistry()
    registry.register(spec)

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"file.read"},
    )

    tool_call = ToolCall(
        request_id="req-read-001",
        tool_name="read_file",
        arguments={"path": "report.txt"},
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.CONFIRM
    assert result.reason_code == "CONFIRMATION_REQUIRED"
    assert result.result is None
    assert handler_was_called is False


def test_dispatcher_denies_read_file_without_permission(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        "安全测试报告",
        encoding="utf-8",
    )

    registry = ToolRegistry()
    registry.register(
        create_read_file_spec(allowed_root)
    )

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions=set(),
    )

    tool_call = ToolCall(
        request_id="req-read-002",
        tool_name="read_file",
        arguments={"path": "report.txt"},
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "PERMISSION_DENIED"
    assert result.result is None


def test_dispatcher_denies_path_traversal_before_confirmation(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    private_root = tmp_path / "private"
    private_root.mkdir()

    secret_file = private_root / "secret.txt"
    secret_file.write_text(
        "TEST_SECRET_DO_NOT_EXPOSE",
        encoding="utf-8",
    )

    registry = ToolRegistry()
    registry.register(
        create_read_file_spec(allowed_root)
    )

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"file.read"},
    )

    tool_call = ToolCall(
        request_id="req-read-003",
        tool_name="read_file",
        arguments={
            "path": "../private/secret.txt",
        },
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "INVALID_ARGUMENTS"
    assert result.result is None