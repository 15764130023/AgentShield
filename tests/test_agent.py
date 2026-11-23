from agentshield.agent import ProtectedAgent, UnprotectedAgent
from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import Decision, DecisionResult, Identity
from agentshield.planner import MockPlanner
from agentshield.registry import ToolRegistry
from agentshield.tools.calculator import create_calculator_spec


def test_protected_agent_executes_calculator_request():
    registry = ToolRegistry()
    registry.register(create_calculator_spec())

    dispatcher = SecurityDispatcher(registry)
    planner = MockPlanner()

    agent = ProtectedAgent(
        planner=planner,
        dispatcher=dispatcher,
    )

    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use"},
    )

    result = agent.run(
        user_input="计算: 2 + 3",
        request_id="req-agent-001",
        identity=identity,
    )

    assert isinstance(result, DecisionResult)
    assert result.decision == Decision.ALLOW
    assert result.reason_code == "TOOL_EXECUTED"
    assert result.result == 5


def test_protected_agent_denies_calculator_without_permission():
    registry = ToolRegistry()
    registry.register(create_calculator_spec())

    dispatcher = SecurityDispatcher(registry)
    planner = MockPlanner()

    agent = ProtectedAgent(
        planner=planner,
        dispatcher=dispatcher,
    )

    identity = Identity(
        user_id="user-002",
        permissions=set(),
    )

    result = agent.run(
        user_input="计算: 2 + 3",
        request_id="req-agent-002",
        identity=identity,
    )

    assert isinstance(result, DecisionResult)
    assert result.decision == Decision.DENY
    assert result.reason_code == "PERMISSION_DENIED"
    assert result.result is None


def test_protected_agent_returns_planner_text_without_tool_call():
    registry = ToolRegistry()
    registry.register(create_calculator_spec())

    dispatcher = SecurityDispatcher(registry)
    planner = MockPlanner()

    agent = ProtectedAgent(
        planner=planner,
        dispatcher=dispatcher,
    )

    identity = Identity(
        user_id="user-003",
        permissions=set(),
    )

    result = agent.run(
        user_input="你好",
        request_id="req-agent-003",
        identity=identity,
    )

    assert result == (
        "当前支持“计算: 数学表达式”、"
        "“读取: 相对路径”、"
        "“搜索: 关键词”或"
        "“发送: 收件人 | 消息内容”格式的请求"
    )


def test_same_request_is_denied_protected_but_allowed_unprotected():
    registry = ToolRegistry()
    registry.register(create_calculator_spec())

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
        user_id="user-without-permission",
        permissions=set(),
    )

    protected_result = protected_agent.run(
        user_input="计算: 2 + 3",
        request_id="req-comparison-001",
        identity=identity,
    )

    unprotected_result = unprotected_agent.run(
        user_input="计算: 2 + 3",
        request_id="req-comparison-001",
        identity=identity,
    )

    assert isinstance(protected_result, DecisionResult)
    assert protected_result.decision == Decision.DENY
    assert protected_result.reason_code == "PERMISSION_DENIED"
    assert protected_result.result is None

    assert isinstance(unprotected_result, DecisionResult)
    assert unprotected_result.decision == Decision.ALLOW
    assert (
        unprotected_result.reason_code
        == "UNPROTECTED_TOOL_EXECUTED"
    )
    assert unprotected_result.result == 5
