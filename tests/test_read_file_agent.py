from pathlib import Path

from agentshield.agent import (
    ProtectedAgent,
    UnprotectedAgent,
)
from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    DecisionResult,
    Identity,
)
from agentshield.planner import MockPlanner
from agentshield.registry import ToolRegistry
from agentshield.tools.read_file import (
    create_read_file_spec,
)


def _create_read_file_agents(
    allowed_root: Path,
) -> tuple[ProtectedAgent, UnprotectedAgent]:
    registry = ToolRegistry()
    registry.register(
        create_read_file_spec(allowed_root)
    )

    planner = MockPlanner()
    dispatcher = SecurityDispatcher(registry)

    protected_agent = ProtectedAgent(
        planner=planner,
        dispatcher=dispatcher,
    )

    unprotected_agent = UnprotectedAgent(
        planner=planner,
        registry=registry,
    )

    return protected_agent, unprotected_agent


def test_protected_read_requires_confirmation_but_unprotected_reads(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        "安全测试报告",
        encoding="utf-8",
    )

    protected_agent, unprotected_agent = (
        _create_read_file_agents(allowed_root)
    )

    identity = Identity(
        user_id="user-001",
        permissions={"file.read"},
    )

    protected_result = protected_agent.run(
        user_input="读取: report.txt",
        request_id="req-read-agent-001",
        identity=identity,
    )

    unprotected_result = unprotected_agent.run(
        user_input="读取: report.txt",
        request_id="req-read-agent-001",
        identity=identity,
    )

    assert isinstance(
        protected_result,
        DecisionResult,
    )
    assert protected_result.decision == Decision.CONFIRM
    assert (
        protected_result.reason_code
        == "CONFIRMATION_REQUIRED"
    )
    assert protected_result.result is None

    assert isinstance(
        unprotected_result,
        DecisionResult,
    )
    assert unprotected_result.decision == Decision.ALLOW
    assert (
        unprotected_result.reason_code
        == "UNPROTECTED_TOOL_EXECUTED"
    )
    assert unprotected_result.result == "安全测试报告"


def test_unprotected_read_bypasses_permission_check(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        "安全测试报告",
        encoding="utf-8",
    )

    protected_agent, unprotected_agent = (
        _create_read_file_agents(allowed_root)
    )

    identity = Identity(
        user_id="user-without-file-permission",
        permissions=set(),
    )

    protected_result = protected_agent.run(
        user_input="读取: report.txt",
        request_id="req-read-agent-002",
        identity=identity,
    )

    unprotected_result = unprotected_agent.run(
        user_input="读取: report.txt",
        request_id="req-read-agent-002",
        identity=identity,
    )

    assert isinstance(
        protected_result,
        DecisionResult,
    )
    assert protected_result.decision == Decision.DENY
    assert (
        protected_result.reason_code
        == "PERMISSION_DENIED"
    )
    assert protected_result.result is None

    assert isinstance(
        unprotected_result,
        DecisionResult,
    )
    assert unprotected_result.decision == Decision.ALLOW
    assert (
        unprotected_result.reason_code
        == "UNPROTECTED_TOOL_EXECUTED"
    )
    assert unprotected_result.result == "安全测试报告"


def test_even_unprotected_read_cannot_escape_allowed_root(
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

    protected_agent, unprotected_agent = (
        _create_read_file_agents(allowed_root)
    )

    identity = Identity(
        user_id="user-001",
        permissions={"file.read"},
    )

    protected_result = protected_agent.run(
        user_input="读取: ../private/secret.txt",
        request_id="req-read-agent-003",
        identity=identity,
    )

    unprotected_result = unprotected_agent.run(
        user_input="读取: ../private/secret.txt",
        request_id="req-read-agent-003",
        identity=identity,
    )

    assert isinstance(
        protected_result,
        DecisionResult,
    )
    assert protected_result.decision == Decision.DENY
    assert (
        protected_result.reason_code
        == "INVALID_ARGUMENTS"
    )
    assert protected_result.result is None

    assert isinstance(
        unprotected_result,
        DecisionResult,
    )
    assert unprotected_result.decision == Decision.DENY
    assert (
        unprotected_result.reason_code
        == "UNPROTECTED_TOOL_FAILED"
    )
    assert unprotected_result.result is None
    assert "TEST_SECRET" not in unprotected_result.message


def test_protected_read_redacts_sensitive_output_but_unprotected_returns_raw(
    tmp_path: Path,
) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        (
            "公开内容 "
            "TEST_SECRET_DO_NOT_EXPOSE"
        ),
        encoding="utf-8",
    )

    registry = ToolRegistry()
    registry.register(
        create_read_file_spec(allowed_root)
    )

    planner = MockPlanner()
    dispatcher = SecurityDispatcher(registry)

    protected_agent = ProtectedAgent(
        planner=planner,
        dispatcher=dispatcher,
    )

    unprotected_agent = UnprotectedAgent(
        planner=planner,
        registry=registry,
    )

    identity = Identity(
        user_id="user-001",
        permissions={"file.read"},
    )

    protected_result = protected_agent.run(
        user_input="读取: report.txt",
        request_id="req-output-read-001",
        identity=identity,
    )

    assert isinstance(
        protected_result,
        DecisionResult,
    )
    assert (
        protected_result.decision
        == Decision.CONFIRM
    )
    assert protected_result.confirmation_id is not None
    assert protected_result.result is None

    confirmed_result = dispatcher.confirm(
        identity=identity,
        confirmation_id=(
            protected_result.confirmation_id
        ),
    )

    assert confirmed_result.decision == Decision.ALLOW
    assert (
        confirmed_result.reason_code
        == "OUTPUT_REDACTED"
    )
    assert confirmed_result.result == (
        "公开内容 [REDACTED:TEST_SECRET]"
    )
    assert (
        "TEST_SECRET_DO_NOT_EXPOSE"
        not in str(confirmed_result.result)
    )

    unprotected_result = unprotected_agent.run(
        user_input="读取: report.txt",
        request_id="req-output-read-001",
        identity=identity,
    )

    assert isinstance(
        unprotected_result,
        DecisionResult,
    )
    assert (
        unprotected_result.decision
        == Decision.ALLOW
    )
    assert (
        unprotected_result.reason_code
        == "UNPROTECTED_TOOL_EXECUTED"
    )
    assert unprotected_result.result == (
        "公开内容 TEST_SECRET_DO_NOT_EXPOSE"
    )