import pytest

from agentshield.models import RiskLevel, ToolSpec
from agentshield.registry import ToolRegistry


def _make_tool_spec(name: str = "calculator") -> ToolSpec:
    def validate_arguments(arguments: dict[str, object]) -> None:
        return None

    def handle_tool(arguments: dict[str, object]) -> object:
        return "ok"

    return ToolSpec(
        name=name,
        description="测试工具",
        risk_level=RiskLevel.LOW,
        required_permissions={"calculator.use"},
        allowed_targets=set(),
        requires_confirmation=False,
        parameter_validator=validate_arguments,
        handler=handle_tool,
    )


def test_registry_returns_registered_tool():
    tool_spec = _make_tool_spec()
    registry = ToolRegistry()

    registry.register(tool_spec)

    assert registry.get("calculator") is tool_spec


def test_registry_returns_none_for_unknown_tool():
    registry = ToolRegistry()

    registered_tool = registry.get("unknown_tool")

    assert registered_tool is None


def test_registry_rejects_duplicate_tool_name():
    registry = ToolRegistry()
    registry.register(_make_tool_spec())

    with pytest.raises(ValueError, match="工具已经注册"):
        registry.register(_make_tool_spec())


def test_registry_rejects_empty_tool_name():
    registry = ToolRegistry()

    with pytest.raises(ValueError, match="工具名称不能为空"):
        registry.register(_make_tool_spec(name=""))