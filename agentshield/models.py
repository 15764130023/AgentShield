from enum import Enum
from dataclasses import dataclass
from collections.abc import Callable
from datetime import datetime


class RiskLevel(str, Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'


class Decision(str, Enum):
    ALLOW = "allow"        # 允许执行
    DENY = "deny"          # 拒绝执行
    CONFIRM = "confirm"    # 需要人工确认


@dataclass
class ToolCall:
    request_id:str
    tool_name:str
    arguments:dict[str, object]


@dataclass
class Identity:
    user_id:str
    permissions:set[str]


@dataclass
class DecisionResult:
    decision: Decision
    reason_code: str
    message: str
    result: object | None = None
    confirmation_id: str | None = None


@dataclass
class ToolSpec:
    name:str
    description:str
    risk_level:RiskLevel
    required_permissions:set[str]
    allowed_targets:set[str]
    requires_confirmation: bool
    parameter_validator: Callable[[dict[str, object]], None]
    handler: Callable[[dict[str, object]], object]
    enabled: bool = True


class ConfirmationStatus(str, Enum):
    PENDING = "pending"
    CONSUMED = "consumed"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class PendingConfirmation:
    confirmation_id: str
    request_id: str
    user_id: str
    tool_name: str
    arguments: dict[str, object]
    created_at: datetime
    expires_at: datetime
    status: ConfirmationStatus = ConfirmationStatus.PENDING
