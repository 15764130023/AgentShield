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
from agentshield.tools.search_knowledge import (
    create_search_knowledge_spec,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KNOWLEDGE_ROOT = (
    PROJECT_ROOT
    / "test_data"
    / "knowledge"
    / "public"
)


class CountingPlanner(MockPlanner):
    def __init__(self) -> None:
        self.plan_call_count = 0

    def plan(
        self,
        user_input: str,
        request_id: str,
    ):
        self.plan_call_count += 1

        return super().plan(
            user_input=user_input,
            request_id=request_id,
        )


def _create_search_agents(
    planner: MockPlanner | None = None,
) -> tuple[ProtectedAgent, UnprotectedAgent]:
    registry = ToolRegistry()

    registry.register(
        create_search_knowledge_spec(
            collections={
                "public": PUBLIC_KNOWLEDGE_ROOT,
            },
            default_collection="public",
        )
    )

    selected_planner = planner or MockPlanner()
    dispatcher = SecurityDispatcher(registry)

    protected_agent = ProtectedAgent(
        planner=selected_planner,
        dispatcher=dispatcher,
    )

    unprotected_agent = UnprotectedAgent(
        planner=selected_planner,
        registry=registry,
    )

    return protected_agent, unprotected_agent


def test_protected_agent_searches_with_permission():
    protected_agent, _ = _create_search_agents()

    identity = Identity(
        user_id="user-with-knowledge-permission",
        permissions={"knowledge.read"},
    )

    result = protected_agent.run(
        user_input="搜索: 工具调用",
        request_id="req-search-agent-001",
        identity=identity,
    )

    assert isinstance(result, DecisionResult)
    assert result.decision == Decision.ALLOW
    assert result.reason_code == "TOOL_EXECUTED"
    assert isinstance(result.result, list)
    assert len(result.result) == 1
    assert (
        result.result[0]["document_id"]
        == "agent_safety"
    )


def test_protected_denies_but_unprotected_searches_without_permission():
    protected_agent, unprotected_agent = (
        _create_search_agents()
    )

    identity = Identity(
        user_id="user-without-knowledge-permission",
        permissions=set(),
    )

    protected_result = protected_agent.run(
        user_input="搜索: 工具调用",
        request_id="req-search-agent-002",
        identity=identity,
    )

    unprotected_result = unprotected_agent.run(
        user_input="搜索: 工具调用",
        request_id="req-search-agent-002",
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
    assert isinstance(unprotected_result.result, list)
    assert len(unprotected_result.result) == 1


def test_polluted_document_blocks_follow_on_action():
    planner = CountingPlanner()

    protected_agent, _ = _create_search_agents(
        planner=planner
    )

    identity = Identity(
        user_id="user-with-knowledge-permission",
        permissions={"knowledge.read"},
    )

    result = protected_agent.run(
        user_input="搜索: 紧急运维通知",
        request_id="req-search-agent-003",
        identity=identity,
    )

    assert isinstance(result, DecisionResult)
    assert result.decision == Decision.DENY
    assert (
        result.reason_code
        == "INDIRECT_PROMPT_INJECTION_DETECTED"
    )
    assert result.result is None

    # 受保护 Agent 只允许初始规划，不执行污染内容中的后续动作。
    assert planner.plan_call_count == 1
