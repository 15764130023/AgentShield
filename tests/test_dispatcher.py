from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    Identity,
    RiskLevel,
    ToolCall,
    ToolSpec,
)
from agentshield.registry import ToolRegistry


def test_dispatcher_denies_unknown_tool():
    registry = ToolRegistry()
    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-001",
        tool_name="unknown_tool",
        arguments={},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.DENY
    assert result.reason_code == "TOOL_NOT_FOUND"
    assert result.result is None


def _make_calculator_spec(
    enabled: bool = True,
    requires_confirmation: bool = False,
    handler_should_fail: bool = False,
    handler_result: object = "ok",
) -> ToolSpec:
    def validate_arguments(arguments: dict[str, object]) -> None:
        if set(arguments) != {"expression"}:
            raise ValueError("参数不合规")

        expression = arguments["expression"]

        if not isinstance(expression, str):
            raise TypeError("参数不合规")

    def handle_tool(arguments: dict[str, object]) -> object:
        if handler_should_fail:
            raise RuntimeError(
                "内部错误：C:\\private\\secret.txt"
            )

        return handler_result

    return ToolSpec(
        name="calculator",
        description="执行受限数学计算",
        risk_level=RiskLevel.LOW,
        required_permissions={"calculator.use"},
        allowed_targets=set(),
        requires_confirmation=requires_confirmation,
        parameter_validator=validate_arguments,
        handler=handle_tool,
        enabled=enabled,
    )


def test_dispatcher_denies_disabled_tool():
    registry = ToolRegistry()
    registry.register(_make_calculator_spec(enabled=False))

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-002",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.DENY
    assert result.reason_code == "TOOL_DISABLED"
    assert result.result is None


def test_dispatcher_denies_invalid_arguments():
    registry = ToolRegistry()
    registry.register(_make_calculator_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-003",
        tool_name="calculator",
        arguments={},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.DENY
    assert result.reason_code == "INVALID_ARGUMENTS"
    assert result.message == "工具参数不合规"
    assert result.result is None


def test_dispatcher_denies_missing_permission():
    registry = ToolRegistry()
    registry.register(_make_calculator_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions=set(),
    )

    tool_call = ToolCall(
        request_id="req-004",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.DENY
    assert result.reason_code == "PERMISSION_DENIED"
    assert result.message == "当前身份没有调用该工具的权限"
    assert result.result is None


def test_dispatcher_requests_confirmation_before_execution():
    registry = ToolRegistry()
    registry.register(
        _make_calculator_spec(requires_confirmation=True)
    )

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-005",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.CONFIRM
    assert result.reason_code == "CONFIRMATION_REQUIRED"
    assert result.message == "该工具调用需要人工确认"
    assert result.result is None


def test_dispatcher_executes_allowed_tool():
    registry = ToolRegistry()
    registry.register(_make_calculator_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-006",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.ALLOW
    assert result.reason_code == "TOOL_EXECUTED"
    assert result.message == "工具执行成功"
    assert result.result == "ok"


def test_dispatcher_returns_safe_error_when_handler_fails():
    registry = ToolRegistry()
    registry.register(
        _make_calculator_spec(handler_should_fail=True)
    )

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-007",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.DENY
    assert result.reason_code == "TOOL_EXECUTION_FAILED"
    assert result.message == "工具执行失败"
    assert result.result is None
    assert "secret.txt" not in result.message


def test_dispatcher_redacts_sensitive_tool_output():
    registry = ToolRegistry()

    registry.register(
        _make_calculator_spec(
            handler_result={
                "message": (
                    "联系 alice@example.com，"
                    "密钥是 "
                    "TEST_SECRET_DO_NOT_EXPOSE"
                ),
            }
        )
    )

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-output-001",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.ALLOW
    assert result.reason_code == "OUTPUT_REDACTED"
    assert result.message == (
        "工具执行成功，敏感信息已脱敏"
    )

    assert result.result == {
        "message": (
            "联系 [REDACTED:EMAIL]，"
            "密钥是 [REDACTED:TEST_SECRET]"
        ),
    }

    assert (
        "alice@example.com"
        not in str(result.result)
    )
    assert (
        "TEST_SECRET_DO_NOT_EXPOSE"
        not in str(result.result)
    )


def test_dispatcher_blocks_output_that_cannot_be_safely_processed():
    registry = ToolRegistry()

    registry.register(
        _make_calculator_spec(
            handler_result={
                "unsupported",
                "set",
            }
        )
    )

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-output-002",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "OUTPUT_BLOCKED"
    assert result.message == (
        "工具输出无法安全返回"
    )
    assert result.result is None