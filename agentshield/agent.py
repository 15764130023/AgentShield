from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import (
    Decision,
    DecisionResult,
    Identity,
    ToolCall,
)
from agentshield.planner import Planner
from agentshield.registry import ToolRegistry
from agentshield.prompt_injection import (
    detect_prompt_injection,
)


def _contains_suspicious_knowledge_content(value: object) -> bool:
    if type(value) is not list:
        return False

    return any(
        type(item) is dict
        and item.get("content_risk") == "suspicious_instruction"
        for item in value
    )



class ProtectedAgent:
    def __init__(
        self,
        planner: Planner,
        dispatcher: SecurityDispatcher,
    ) -> None:
        self._planner = planner
        self._dispatcher = dispatcher

    def run(
        self,
        user_input: str,
        request_id: str,
        identity: Identity,
    ) -> DecisionResult | str:
        injection_categories = detect_prompt_injection(user_input)

        if injection_categories:
            result = DecisionResult(
                decision=Decision.DENY,
                reason_code="PROMPT_INJECTION_DETECTED",
                message="输入包含可疑指令，已被拒绝",
            )
            self._dispatcher.record_decision(
                request_id=request_id,
                identity=identity,
                result=result,
            )
            return result

        plan_result = self._planner.plan(
            user_input=user_input,
            request_id=request_id,
        )

        if isinstance(plan_result, str):
            return plan_result

        if isinstance(plan_result, ToolCall):
            result = self._dispatcher.dispatch(
                identity=identity,
                tool_call=plan_result,
            )

            if (
                result.decision == Decision.ALLOW
                and _contains_suspicious_knowledge_content(result.result)
            ):
                blocked = DecisionResult(
                    decision=Decision.DENY,
                    reason_code="INDIRECT_PROMPT_INJECTION_DETECTED",
                    message="工具结果包含可疑指令，已阻止后续操作",
                )
                self._dispatcher.record_decision(
                    request_id=request_id,
                    identity=identity,
                    result=blocked,
                )
                return blocked

            return result

        raise TypeError("Planner 返回了不支持的结果类型")


class UnprotectedAgent:
    def __init__(
        self,
        planner: Planner,
        registry: ToolRegistry,
    ) -> None:
        self._planner = planner
        self._registry = registry

    def run(
        self,
        user_input: str,
        request_id: str,
        identity: Identity,
    ) -> DecisionResult | str:
        plan_result = self._planner.plan(
            user_input=user_input,
            request_id=request_id,
        )

        if isinstance(plan_result, str):
            return plan_result

        if not isinstance(plan_result, ToolCall):
            raise TypeError("Planner 返回了不支持的结果类型")

        tool_spec = self._registry.get(plan_result.tool_name)

        if tool_spec is None:
            return DecisionResult(
                decision=Decision.DENY,
                reason_code="TOOL_NOT_FOUND",
                message="请求的工具未注册",
            )

        try:
            result = tool_spec.handler(plan_result.arguments)
        except Exception:
            return DecisionResult(
                decision=Decision.DENY,
                reason_code="UNPROTECTED_TOOL_FAILED",
                message="工具执行失败",
            )

        follow_on = self._planner.plan_follow_on(
            tool_result=result,
            request_id=request_id,
        )
        if follow_on is not None:
            follow_on_spec = self._registry.get(follow_on.tool_name)
            if follow_on_spec is None:
                return DecisionResult(
                    decision=Decision.DENY,
                    reason_code="TOOL_NOT_FOUND",
                    message="后续请求的工具未注册",
                )

            try:
                follow_on_result = follow_on_spec.handler(
                    follow_on.arguments
                )
            except Exception:
                return DecisionResult(
                    decision=Decision.DENY,
                    reason_code="UNPROTECTED_FOLLOW_ON_FAILED",
                    message="无防护模式下的后续工具执行失败",
                )

            return DecisionResult(
                decision=Decision.ALLOW,
                reason_code="UNPROTECTED_FOLLOW_ON_EXECUTED",
                message="后续工具已在无防护模式下执行",
                result=follow_on_result,
            )

        return DecisionResult(
            decision=Decision.ALLOW,
            reason_code="UNPROTECTED_TOOL_EXECUTED",
            message="工具已在无防护模式下执行",
            result=result,
        )
