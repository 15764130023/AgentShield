from agentshield.confirmation import (
    ConfirmationError,
    ConfirmationManager,
)
from agentshield.models import (
    Decision,
    DecisionResult,
    Identity,
    ToolCall,
    ToolSpec,
)
from agentshield.registry import ToolRegistry
from agentshield.sensitive_data import (
    SensitiveDataError,
)
from agentshield.output_guard import (
    protect_output,
)
from agentshield.audit import JsonlAuditLog


class SecurityDispatcher:
    def __init__(
        self,
        registry: ToolRegistry,
        confirmation_manager: ConfirmationManager | None = None,
        *,
        audit_log: JsonlAuditLog | None = None,
    ) -> None:
        self._registry = registry
        self._audit_log = audit_log
        self._confirmation_audit_contexts: dict[
            str,
            tuple[str, ToolSpec],
        ] = {}

        if confirmation_manager is None:
            confirmation_manager = ConfirmationManager()

        self._confirmation_manager = confirmation_manager

    def dispatch(
        self,
        identity: Identity,
        tool_call: ToolCall,
    ) -> DecisionResult:
        tool_spec, failure = self._validate_call(
            identity=identity,
            tool_call=tool_call,
        )

        if failure is not None:
            self.record_decision(
                request_id=tool_call.request_id,
                identity=identity,
                result=failure,
                tool_spec=tool_spec,
            )
            return failure

        if tool_spec is None:
            raise RuntimeError("工具校验结果不完整")

        if tool_spec.requires_confirmation:
            confirmation_id = self._confirmation_manager.create(
                identity=identity,
                tool_call=tool_call,
            )
            self._confirmation_audit_contexts[
                confirmation_id
            ] = (
                tool_call.request_id,
                tool_spec,
            )

            result = DecisionResult(
                decision=Decision.CONFIRM,
                reason_code="CONFIRMATION_REQUIRED",
                message="该工具调用需要人工确认",
                confirmation_id=confirmation_id,
            )

            self.record_decision(
                request_id=tool_call.request_id,
                identity=identity,
                result=result,
                tool_spec=tool_spec,
            )

            return result

        result = self._execute(
            tool_spec=tool_spec,
            tool_call=tool_call,
        )
        self.record_decision(
            request_id=tool_call.request_id,
            identity=identity,
            result=result,
            tool_spec=tool_spec,
        )
        return result

    def record_decision(
        self,
        *,
        request_id: str | None,
        identity: Identity,
        result: DecisionResult,
        tool_spec: ToolSpec | None = None,
    ) -> None:
        if self._audit_log is not None:
            self._audit_log.record(
                request_id=request_id,
                identity=identity,
                result=result,
                tool_spec=tool_spec,
            )

    def confirm(
        self,
        identity: Identity,
        confirmation_id: str,
    ) -> DecisionResult:
        audit_context = None

        if type(confirmation_id) is str:
            audit_context = (
                self._confirmation_audit_contexts.get(
                    confirmation_id.strip()
                )
            )
        try:
            tool_call = self._confirmation_manager.confirm(
                confirmation_id=confirmation_id,
                identity=identity,
            )
        except ConfirmationError as error:
            result = DecisionResult(
                decision=Decision.DENY,
                reason_code=error.reason_code,
                message=str(error),
            )
            if audit_context is None:
                request_id = None
                tool_spec = None
            else:
                request_id, tool_spec = audit_context

            self.record_decision(
                request_id=request_id,
                identity=identity,
                result=result,
                tool_spec=tool_spec,
            )

            return result

        tool_spec, failure = self._validate_call(
            identity=identity,
            tool_call=tool_call,
        )

        if failure is not None:
            self.record_decision(
                request_id=tool_call.request_id,
                identity=identity,
                result=failure,
                tool_spec=tool_spec,
            )
            return failure

        if tool_spec is None:
            raise RuntimeError("工具校验结果不完整")

        result = self._execute(
            tool_spec=tool_spec,
            tool_call=tool_call,
        )

        self.record_decision(
            request_id=tool_call.request_id,
            identity=identity,
            result=result,
            tool_spec=tool_spec,
        )

        return result

    def reject(
        self,
        identity: Identity,
        confirmation_id: str,
    ) -> DecisionResult:
        audit_context = None

        if type(confirmation_id) is str:
            audit_context = (
                self._confirmation_audit_contexts.get(
                    confirmation_id.strip()
                )
            )

        try:
            self._confirmation_manager.reject(
                confirmation_id=confirmation_id,
                identity=identity,
            )
        except ConfirmationError as error:
            result = DecisionResult(
                decision=Decision.DENY,
                reason_code=error.reason_code,
                message=str(error),
            )

            if audit_context is None:
                request_id = None
                tool_spec = None
            else:
                request_id, tool_spec = audit_context

            self.record_decision(
                request_id=request_id,
                identity=identity,
                result=result,
                tool_spec=tool_spec,
            )

            return result

        result = DecisionResult(
            decision=Decision.DENY,
            reason_code="CONFIRMATION_REJECTED",
            message="用户已经拒绝该工具调用",
        )

        if audit_context is not None:
            request_id, tool_spec = audit_context

            self.record_decision(
                request_id=request_id,
                identity=identity,
                result=result,
                tool_spec=tool_spec,
            )

        return result

    def _validate_call(
        self,
        identity: Identity,
        tool_call: ToolCall,
    ) -> tuple[
        ToolSpec | None,
        DecisionResult | None,
    ]:
        tool_spec = self._registry.get(
            tool_call.tool_name
        )

        # 工具根本不存在，所以没有 ToolSpec 可以返回。
        if tool_spec is None:
            return None, DecisionResult(
                decision=Decision.DENY,
                reason_code="TOOL_NOT_FOUND",
                message="请求的工具未注册",
            )

        # 从这里开始，工具已经存在。
        # 即使校验失败，也要返回 tool_spec，供审计日志使用。
        if not tool_spec.enabled:
            return tool_spec, DecisionResult(
                decision=Decision.DENY,
                reason_code="TOOL_DISABLED",
                message="请求的工具当前未启用",
            )

        try:
            tool_spec.parameter_validator(
                tool_call.arguments
            )
        except SensitiveDataError:
            return tool_spec, DecisionResult(
                decision=Decision.DENY,
                reason_code="SENSITIVE_DATA_DETECTED",
                message="参数包含敏感信息，已被拒绝",
            )
        except (TypeError, ValueError):
            return tool_spec, DecisionResult(
                decision=Decision.DENY,
                reason_code="INVALID_ARGUMENTS",
                message="工具参数不合规",
            )

        if not tool_spec.required_permissions.issubset(
            identity.permissions
        ):
            return tool_spec, DecisionResult(
                decision=Decision.DENY,
                reason_code="PERMISSION_DENIED",
                message="当前身份没有调用该工具的权限",
            )

        return tool_spec, None
    def _execute(
        self,
        tool_spec: ToolSpec,
        tool_call: ToolCall,
    ) -> DecisionResult:
        try:
            result = tool_spec.handler(
                tool_call.arguments
            )
        except Exception:
            return DecisionResult(
                decision=Decision.DENY,
                reason_code="TOOL_EXECUTION_FAILED",
                message="工具执行失败",
            )

        try:
            protected_output = protect_output(
                result
            )
        except Exception:
            return DecisionResult(
                decision=Decision.DENY,
                reason_code="OUTPUT_BLOCKED",
                message="工具输出无法安全返回",
            )

        if protected_output.redacted:
            return DecisionResult(
                decision=Decision.ALLOW,
                reason_code="OUTPUT_REDACTED",
                message=(
                    "工具执行成功，敏感信息已脱敏"
                ),
                result=protected_output.value,
            )

        return DecisionResult(
            decision=Decision.ALLOW,
            reason_code="TOOL_EXECUTED",
            message="工具执行成功",
            result=protected_output.value,
        )
