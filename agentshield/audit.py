import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from agentshield.models import DecisionResult, Identity, ToolSpec
from agentshield.sensitive_data import redact_sensitive_data


class JsonlAuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def record(
        self,
        *,
        request_id: str | None,
        identity: Identity,
        result: DecisionResult,
        tool_spec: ToolSpec | None = None,
    ) -> None:
        if request_id is None:
            safe_request_id = None
        else:
            safe_request_id, _ = redact_sensitive_data(
                request_id
            )

        safe_user_id, _ = redact_sensitive_data(
            identity.user_id
        )

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": safe_request_id,
            "user_id": safe_user_id,
            "tool_name": tool_spec.name if tool_spec is not None else None,
            "risk_level": (
                tool_spec.risk_level.value if tool_spec is not None else None
            ),
            "decision": result.decision.value,
            "reason_code": result.reason_code,
        }

        line = json.dumps(event, ensure_ascii=False) + "\n"
        with self._lock, self._path.open("a", encoding="utf-8", newline="\n") as log:
            log.write(line)