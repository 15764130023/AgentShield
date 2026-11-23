from pathlib import Path

from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    Identity,
    RiskLevel,
    ToolCall,
)
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


def _create_spec():
    return create_search_knowledge_spec(
        collections={
            "public": PUBLIC_KNOWLEDGE_ROOT,
        },
        default_collection="public",
    )


def test_search_knowledge_spec_has_security_metadata():
    spec = _create_spec()

    assert spec.name == "search_knowledge"
    assert spec.risk_level == RiskLevel.LOW
    assert spec.required_permissions == {
        "knowledge.read"
    }
    assert spec.allowed_targets == {"public"}
    assert spec.requires_confirmation is False
    assert spec.enabled is True


def test_search_knowledge_handler_uses_default_collection():
    spec = _create_spec()

    results = spec.handler(
        {
            "query": "工具调用",
        }
    )

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["document_id"] == "agent_safety"


def test_dispatcher_executes_search_with_permission():
    registry = ToolRegistry()
    registry.register(_create_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-001",
        permissions={"knowledge.read"},
    )

    tool_call = ToolCall(
        request_id="req-search-001",
        tool_name="search_knowledge",
        arguments={
            "query": "工具调用",
            "collection": "public",
        },
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.ALLOW
    assert result.reason_code == "TOOL_EXECUTED"
    assert isinstance(result.result, list)
    assert (
        result.result[0]["document_id"]
        == "agent_safety"
    )


def test_dispatcher_denies_search_without_permission():
    registry = ToolRegistry()
    registry.register(_create_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-002",
        permissions=set(),
    )

    tool_call = ToolCall(
        request_id="req-search-002",
        tool_name="search_knowledge",
        arguments={
            "query": "工具调用",
            "collection": "public",
        },
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "PERMISSION_DENIED"
    assert result.result is None


def test_dispatcher_denies_unregistered_collection():
    registry = ToolRegistry()
    registry.register(_create_spec())

    dispatcher = SecurityDispatcher(registry)

    identity = Identity(
        user_id="user-003",
        permissions={"knowledge.read"},
    )

    tool_call = ToolCall(
        request_id="req-search-003",
        tool_name="search_knowledge",
        arguments={
            "query": "工具调用",
            "collection": "private",
        },
    )

    result = dispatcher.dispatch(
        identity=identity,
        tool_call=tool_call,
    )

    assert result.decision == Decision.DENY
    assert result.reason_code == "INVALID_ARGUMENTS"
    assert result.result is None