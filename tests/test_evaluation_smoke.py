"""固定样本的字段契约与实际执行路径保持一致。"""

import json
from pathlib import Path

import pytest

from agentshield.agent import ProtectedAgent
from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import DecisionResult, Identity, ToolCall
from agentshield.planner import MockPlanner
from agentshield.registry import ToolRegistry
from agentshield.tools.calculator import create_calculator_spec
from agentshield.tools.read_file import create_read_file_spec
from agentshield.tools.search_knowledge import create_search_knowledge_spec
from agentshield.tools.send_message import create_send_message_spec


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = json.loads(
    (ROOT / "data/evaluation/smoke-10.json").read_text(encoding="utf-8")
)
CATEGORIES = {
    "normal", "direct_injection", "indirect_injection",
    "unauthorized_tool", "invalid_path_or_arguments", "sensitive_data",
}
FIELDS = {
    "id", "category", "is_attack", "attack_goal", "success_probe",
    "input", "user_id", "permissions",
    "candidate_tool_call", "expected_protected_decision", "expected_reason_code",
}


def test_smoke_sample_set_has_unique_ids_and_all_categories() -> None:
    assert len(SAMPLES) == 10
    assert len({sample["id"] for sample in SAMPLES}) == len(SAMPLES)
    assert {sample["category"] for sample in SAMPLES} == CATEGORIES


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda sample: sample["id"])
def test_smoke_sample_matches_planner_and_protected_path(sample: dict) -> None:
    assert set(sample) == FIELDS
    assert sample["is_attack"] is (sample["category"] != "normal")
    assert isinstance(sample["permissions"], list)
    assert len(sample["permissions"]) == len(set(sample["permissions"]))

    planner = MockPlanner()
    planned = planner.plan(sample["input"], sample["id"])
    assert isinstance(planned, ToolCall)
    assert planned.tool_name == sample["candidate_tool_call"]["tool_name"]
    assert planned.arguments == sample["candidate_tool_call"]["arguments"]

    registry = ToolRegistry()
    registry.register(create_calculator_spec())
    registry.register(create_read_file_spec(ROOT / "test_data/files/allowed"))
    registry.register(create_search_knowledge_spec(
        collections={"public": ROOT / "test_data/knowledge/public"},
        default_collection="public",
    ))
    outbox: list[dict[str, object]] = []
    registry.register(create_send_message_spec(
        allowed_recipients={"test-recipient"}, outbox=outbox,
    ))
    identity = Identity(sample["user_id"], set(sample["permissions"]))
    result = ProtectedAgent(planner, SecurityDispatcher(registry)).run(
        sample["input"], sample["id"], identity,
    )
    assert isinstance(result, DecisionResult)
    assert result.decision.value == sample["expected_protected_decision"]
    assert result.reason_code == sample["expected_reason_code"]
    assert outbox == []  # 测试不会自动批准消息发送。

    if sample["category"] == "indirect_injection":
        assert result.result is None
