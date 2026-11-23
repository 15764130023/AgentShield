"""确定性本地演示：python -m agentshield.cli --help。"""

import argparse
import json
from pathlib import Path
from uuid import uuid4

from agentshield.agent import ProtectedAgent, UnprotectedAgent
from agentshield.audit import JsonlAuditLog
from agentshield.dispatcher import SecurityDispatcher
from agentshield.models import Decision, DecisionResult, Identity
from agentshield.online_planner import (
    KimiOnlinePlanner,
)
from agentshield.planner import MockPlanner, Planner
from agentshield.registry import ToolRegistry
from agentshield.tools.calculator import create_calculator_spec
from agentshield.tools.read_file import create_read_file_spec
from agentshield.tools.search_knowledge import create_search_knowledge_spec
from agentshield.tools.send_message import create_send_message_spec


def _format_result(result: DecisionResult | str) -> dict[str, object]:
    if isinstance(result, str):
        return {"message": result}

    record: dict[str, object] = {
        "decision": result.decision.value,
        "reason_code": result.reason_code,
        "message": result.message,
    }
    if result.result is not None:
        record["result"] = result.result
    if result.confirmation_id is not None:
        record["confirmation_id"] = result.confirmation_id
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentShield 本地模拟演示")
    parser.add_argument(
        "--input", default="计算: 2 + 3", dest="user_input",
        help="例如：计算: 2 + 3；读取: report.txt；搜索: 安全；发送: test-recipient | 你好",
    )
    parser.add_argument(
        "--mode", choices=("protected", "unprotected", "both"), default="both",
    )
    parser.add_argument(
        "--planner",
        choices=("mock", "kimi"),
        default="mock",
        help=(
            "mock 使用确定性规划器；"
            "kimi 使用在线模型"
        ),
    )
    parser.add_argument(
        "--model",
        default="kimi-k3.1-pro",
        help="Kimi 模型名称",
    )
    parser.add_argument(
        "--confirmation", choices=("pending", "approve", "reject"),
        default="pending", help="仅对有防护模式中的待确认调用生效",
    )
    parser.add_argument(
        "--audit", type=Path, help="可选的 JSON Lines 审计日志路径",
    )
    args = parser.parse_args(argv)

    if (
        args.planner == "kimi"
        and args.mode != "protected"
    ):
        parser.error(
            "Kimi 在线规划器当前仅支持 "
            "--mode protected"
        )

    project_root = Path(__file__).resolve().parent.parent
    outbox: list[dict[str, object]] = []
    registry = ToolRegistry()
    registry.register(create_calculator_spec())
    registry.register(create_read_file_spec(project_root / "test_data/files/allowed"))
    registry.register(create_search_knowledge_spec(
        collections={"public": project_root / "test_data/knowledge/public"},
        default_collection="public",
    ))
    registry.register(create_send_message_spec(
        allowed_recipients={"test-recipient"}, outbox=outbox,
    ))

    planner: Planner

    if args.planner == "mock":
        planner = MockPlanner()
    else:
        try:
            planner = (
                KimiOnlinePlanner.from_environment(
                    model=args.model,
                )
            )
        except RuntimeError as error:
            parser.error(str(error))

    dispatcher = SecurityDispatcher(
        registry, audit_log=JsonlAuditLog(args.audit) if args.audit else None,
    )
    identity = Identity(
        user_id="demo-user",
        permissions={"calculator.use", "file.read", "knowledge.read", "message.send"},
    )
    request_id = f"demo-{uuid4().hex}"
    results: dict[str, object] = {}

    if args.mode in ("protected", "both"):
        result = ProtectedAgent(planner, dispatcher).run(
            args.user_input, request_id, identity,
        )
        protected = _format_result(result)
        if (
            isinstance(result, DecisionResult)
            and result.decision == Decision.CONFIRM
            and result.confirmation_id is not None
            and args.confirmation != "pending"
        ):
            if args.confirmation == "approve":
                followup = dispatcher.confirm(identity, result.confirmation_id)
            else:
                followup = dispatcher.reject(identity, result.confirmation_id)
            protected["confirmation_result"] = _format_result(followup)
        results["protected"] = protected

    if args.mode in ("unprotected", "both"):
        result = UnprotectedAgent(planner, registry).run(
            args.user_input, request_id, identity,
        )
        results["unprotected"] = _format_result(result)

    results["simulated_outbox_count"] = len(outbox)
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
