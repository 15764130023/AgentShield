import secrets

from collections.abc import Callable
from copy import deepcopy
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from agentshield.models import (
    ConfirmationStatus,
    Identity,
    PendingConfirmation,
    ToolCall,
)


class ConfirmationError(Exception):
    def __init__(
        self,
        reason_code: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class ConfirmationManager:
    def __init__(
        self,
        ttl_seconds: int = 300,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if type(ttl_seconds) is not int:
            raise ValueError("确认有效期配置不合规")

        if ttl_seconds <= 0:
            raise ValueError("确认有效期配置不合规")

        self._ttl_seconds = ttl_seconds

        self._clock = clock or (
            lambda: datetime.now(timezone.utc)
        )

        self._id_factory = id_factory or (
            lambda: secrets.token_urlsafe(18)
        )

        self._records: dict[
            str,
            PendingConfirmation,
        ] = {}

    def create(
        self,
        identity: Identity,
        tool_call: ToolCall,
    ) -> str:
        if not isinstance(identity, Identity):
            raise TypeError("确认身份类型不合规")

        if not isinstance(tool_call, ToolCall):
            raise TypeError("确认工具调用类型不合规")

        current_time = self._current_time()
        confirmation_id = self._create_confirmation_id()

        pending = PendingConfirmation(
            confirmation_id=confirmation_id,
            request_id=tool_call.request_id,
            user_id=identity.user_id,
            tool_name=tool_call.tool_name,
            arguments=deepcopy(tool_call.arguments),
            created_at=current_time,
            expires_at=(
                current_time
                + timedelta(seconds=self._ttl_seconds)
            ),
            status=ConfirmationStatus.PENDING,
        )

        self._records[confirmation_id] = pending

        return confirmation_id

    def confirm(
        self,
        confirmation_id: str,
        identity: Identity,
    ) -> ToolCall:
        if type(confirmation_id) is not str:
            raise ConfirmationError(
                "CONFIRMATION_NOT_FOUND",
                "确认请求不存在",
            )

        if not isinstance(identity, Identity):
            raise TypeError("确认身份类型不合规")

        normalized_id = confirmation_id.strip()
        pending = self._records.get(normalized_id)

        if pending is None:
            raise ConfirmationError(
                "CONFIRMATION_NOT_FOUND",
                "确认请求不存在",
            )

        if pending.user_id != identity.user_id:
            raise ConfirmationError(
                "CONFIRMATION_FORBIDDEN",
                "当前身份不能确认该请求",
            )

        current_time = self._current_time()

        if (
            pending.status == ConfirmationStatus.PENDING
            and current_time >= pending.expires_at
        ):
            pending.status = ConfirmationStatus.EXPIRED

        if pending.status == ConfirmationStatus.EXPIRED:
            raise ConfirmationError(
                "CONFIRMATION_EXPIRED",
                "确认请求已经过期",
            )

        if pending.status == ConfirmationStatus.CONSUMED:
            raise ConfirmationError(
                "CONFIRMATION_ALREADY_USED",
                "确认请求已经使用",
            )

        if pending.status == ConfirmationStatus.REJECTED:
            raise ConfirmationError(
                "CONFIRMATION_REJECTED",
                "确认请求已经被拒绝",
            )

        pending.status = ConfirmationStatus.CONSUMED

        return ToolCall(
            request_id=pending.request_id,
            tool_name=pending.tool_name,
            arguments=deepcopy(pending.arguments),
        )


    def reject(
        self,
        confirmation_id: str,
        identity: Identity,
    ) -> None:
        if type(confirmation_id) is not str:
            raise ConfirmationError(
                "CONFIRMATION_NOT_FOUND",
                "确认请求不存在",
            )

        if not isinstance(identity, Identity):
            raise TypeError("确认身份类型不合规")

        normalized_id = confirmation_id.strip()
        pending = self._records.get(normalized_id)

        if pending is None:
            raise ConfirmationError(
                "CONFIRMATION_NOT_FOUND",
                "确认请求不存在",
            )

        if pending.user_id != identity.user_id:
            raise ConfirmationError(
                "CONFIRMATION_FORBIDDEN",
                "当前身份不能拒绝该请求",
            )

        current_time = self._current_time()

        if (
            pending.status == ConfirmationStatus.PENDING
            and current_time >= pending.expires_at
        ):
            pending.status = ConfirmationStatus.EXPIRED

        if pending.status == ConfirmationStatus.EXPIRED:
            raise ConfirmationError(
                "CONFIRMATION_EXPIRED",
                "确认请求已经过期",
            )

        if pending.status == ConfirmationStatus.CONSUMED:
            raise ConfirmationError(
                "CONFIRMATION_ALREADY_USED",
                "确认请求已经使用",
            )

        if pending.status == ConfirmationStatus.REJECTED:
            raise ConfirmationError(
                "CONFIRMATION_REJECTED",
                "确认请求已经被拒绝",
            )

        pending.status = ConfirmationStatus.REJECTED

    def _current_time(self) -> datetime:
        current_time = self._clock()

        if not isinstance(current_time, datetime):
            raise RuntimeError("确认时钟返回值不合规")

        if (
            current_time.tzinfo is None
            or current_time.utcoffset() is None
        ):
            raise RuntimeError("确认时钟必须包含时区")

        return current_time

    def _create_confirmation_id(self) -> str:
        confirmation_id = self._id_factory()

        if type(confirmation_id) is not str:
            raise RuntimeError("确认编号生成器返回值不合规")

        normalized_id = confirmation_id.strip()

        if not normalized_id:
            raise RuntimeError("确认编号生成器返回值不合规")

        if any(
            not character.isprintable()
            for character in normalized_id
        ):
            raise RuntimeError("确认编号生成器返回值不合规")

        if normalized_id in self._records:
            raise RuntimeError("确认编号发生冲突")

        return normalized_id
