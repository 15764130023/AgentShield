from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import Decision, Identity, ToolCall
from agentshield.registry import ToolRegistry
from agentshield.tools.calculator import create_calculator_spec


def test_dispatcher_executes_real_calculator():
    registry = ToolRegistry()
    registry.register(create_calculator_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-integration-001",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.ALLOW
    assert result.reason_code == "TOOL_EXECUTED"
    assert result.result == 5


def test_dispatcher_rejects_invalid_real_calculator_expression():
    registry = ToolRegistry()
    registry.register(create_calculator_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    tool_call = ToolCall(
        request_id="req-integration-002",
        tool_name="calculator",
        arguments={"expression": "1 / 0"},
    )

    result = dispatcher.dispatch(identity, tool_call)

    assert result.decision == Decision.DENY
    assert result.reason_code == "INVALID_ARGUMENTS"
    assert result.message == "工具参数不合规"
    assert result.result is None