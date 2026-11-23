import re
from typing import Protocol
from agentshield.models import ToolCall


_FOLLOW_UP_PATTERN = re.compile(
    r"\[FOLLOW_UP\]\s*"
    r"send_message\s*\|\s*"
    r"([^|\[\]]+)\s*\|\s*"
    r"(.+?)\s*"
    r"\[END_FOLLOW_UP\]",
    flags=re.IGNORECASE,
)


class Planner(Protocol):
    """Planner 的统一接口。"""

    def plan(
        self,
        user_input: str,
        request_id: str,
    ) -> ToolCall | str:
        ...

    def plan_follow_on(
        self,
        tool_result: object,
        request_id: str,
    ) -> ToolCall | None:
        ...

class MockPlanner:
    def plan(
        self,
        user_input: str,
        request_id: str,
    ) -> ToolCall | str:
        normalized_input = user_input.strip()

        expression = self._extract_expression(
            normalized_input
        )

        if expression is not None:
            if not expression:
                return "请提供需要计算的表达式"

            return ToolCall(
                request_id=request_id,
                tool_name="calculator",
                arguments={"expression": expression},
            )

        relative_path = self._extract_file_path(
            normalized_input
        )

        if relative_path is not None:
            if not relative_path:
                return "请提供需要读取的文件路径"

            return ToolCall(
                request_id=request_id,
                tool_name="read_file",
                arguments={"path": relative_path},
            )

        search_query = self._extract_search_query(
            normalized_input
        )

        if search_query is not None:
            if not search_query:
                return "请提供需要搜索的关键词"

            return ToolCall(
                request_id=request_id,
                tool_name="search_knowledge",
                arguments={"query": search_query},
            )
        message_request = self._extract_message_request(
            normalized_input
        )

        if message_request is not None:
            if "|" not in message_request:
                return (
                    "请使用“发送: 收件人 | 消息内容”格式"
                )

            recipient, content = message_request.split(
                "|",
                1,
            )

            normalized_recipient = recipient.strip()
            normalized_content = content.strip()

            if not normalized_recipient:
                return "请提供消息接收目标"

            if not normalized_content:
                return "请提供消息内容"

            return ToolCall(
                request_id=request_id,
                tool_name="send_message",
                arguments={
                    "recipient": normalized_recipient,
                    "content": normalized_content,
                },
            )
        return (
            "当前支持“计算: 数学表达式”、"
            "“读取: 相对路径”、"
            "“搜索: 关键词”或"
            "“发送: 收件人 | 消息内容”格式的请求"
        )

    def plan_follow_on(
        self,
        tool_result: object,
        request_id: str,
    ) -> ToolCall | None:
        """Interpret a deterministic instruction embedded in tool data."""
        if type(tool_result) is not list:
            return None

        for item in tool_result:
            if type(item) is not dict:
                continue

            snippet = item.get("snippet")
            if type(snippet) is not str:
                continue

            match = _FOLLOW_UP_PATTERN.search(snippet)
            if match is None:
                continue

            recipient = match.group(1).strip()
            content = match.group(2).strip()
            if not recipient or not content:
                continue

            return ToolCall(
                request_id=f"{request_id}-follow-up",
                tool_name="send_message",
                arguments={
                    "recipient": recipient,
                    "content": content,
                },
            )

        return None

    def _extract_expression(self, user_input: str) -> str | None:
        prefixes = (
            "计算:",
            "计算：",
            "calculate:",
        )

        lowered_input = user_input.lower()

        for prefix in prefixes:
            if lowered_input.startswith(prefix.lower()):
                return user_input[len(prefix):].strip()

        return None

    def _extract_file_path(
        self,
        user_input: str,
    ) -> str | None:
        prefixes = (
            "读取:",
            "读取：",
            "read:",
        )

        lowered_input = user_input.lower()

        for prefix in prefixes:
            if lowered_input.startswith(
                prefix.lower()
            ):
                return user_input[
                    len(prefix):
                ].strip()

        return None

    def _extract_search_query(
        self,
        user_input: str,
    ) -> str | None:
        prefixes = (
            "搜索:",
            "搜索：",
            "search:",
        )

        lowered_input = user_input.lower()

        for prefix in prefixes:
            if lowered_input.startswith(
                prefix.lower()
            ):
                return user_input[
                    len(prefix):
                ].strip()

        return None
    
    def _extract_message_request(
        self,
        user_input: str,
    ) -> str | None:
        prefixes = (
            "发送:",
            "发送：",
            "send:",
        )

        lowered_input = user_input.lower()

        for prefix in prefixes:
            if lowered_input.startswith(
                prefix.lower()
            ):
                return user_input[
                    len(prefix):
                ].strip()

        return None
