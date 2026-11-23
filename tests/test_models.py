from agentshield.models import (
    Decision,
    DecisionResult,
    Identity,
    RiskLevel,
    ToolCall,
    ToolSpec,
)


def test_risk_level_has_expected_values():
    assert RiskLevel.LOW.value == "low"
    assert RiskLevel.MEDIUM.value == "medium"
    assert RiskLevel.HIGH.value == "high"


def test_decision_has_expected_values():
    assert Decision.ALLOW.value == "allow"
    assert Decision.DENY.value == "deny"
    assert Decision.CONFIRM.value == "confirm"


def test_tool_call_stores_request_information():
    call = ToolCall(
        request_id="req-001",
        tool_name="calculator",
        arguments={"expression": "2 + 3"},
    )

    assert call.request_id == "req-001"
    assert call.tool_name == "calculator"
    assert call.arguments == {"expression": "2 + 3"}


def test_identity_stores_user_and_permissions():
    identity = Identity(
        user_id="user-001",
        permissions={"calculator.use", "file.read"},
    )

    assert identity.user_id == "user-001"
    assert "calculator.use" in identity.permissions
    assert "file.read" in identity.permissions
    assert "message.send" not in identity.permissions


def test_decision_result_stores_allowed_result():
    decision_result = DecisionResult(
        decision=Decision.ALLOW,
        reason_code="ALLOWED",
        message="工具调用成功",
        result=5,
    )

    assert decision_result.decision == Decision.ALLOW
    assert decision_result.reason_code == "ALLOWED"
    assert decision_result.message == "工具调用成功"
    assert decision_result.result == 5


def test_decision_result_defaults_result_to_none():
    decision_result = DecisionResult(
        decision=Decision.DENY,
        reason_code="PERMISSION_DENIED",
        message="当前身份没有调用该工具的权限",
    )

    assert decision_result.decision == Decision.DENY
    assert decision_result.result is None


def test_tool_spec_stores_security_configuration():
    def validate_arguments(arguments: dict[str, object]) -> None:
        if "expression" not in arguments:
            raise ValueError("缺少 expression 参数")

    def handle_calculation(arguments: dict[str, object]) -> object:
        return arguments["expression"]

    tool_spec = ToolSpec(
        name="calculator",
        description="执行受限数学计算",
        risk_level=RiskLevel.LOW,
        required_permissions={"calculator.use"},
        allowed_targets=set(),
        requires_confirmation=False,
        parameter_validator=validate_arguments,
        handler=handle_calculation,
    )

    assert tool_spec.name == "calculator"
    assert tool_spec.risk_level == RiskLevel.LOW
    assert tool_spec.required_permissions == {"calculator.use"}
    assert tool_spec.allowed_targets == set()
    assert tool_spec.requires_confirmation is False
    assert tool_spec.enabled is True
    assert tool_spec.parameter_validator is validate_arguments
    assert tool_spec.handler is handle_calculation


def test_tool_spec_can_be_disabled():
    def validate_arguments(arguments: dict[str, object]) -> None:
        return None

    def handle_tool(arguments: dict[str, object]) -> object:
        return "ok"

    tool_spec = ToolSpec(
        name="disabled_tool",
        description="测试禁用工具",
        risk_level=RiskLevel.LOW,
        required_permissions=set(),
        allowed_targets=set(),
        requires_confirmation=False,
        parameter_validator=validate_arguments,
        handler=handle_tool,
        enabled=False,
    )

    assert tool_spec.enabled is False