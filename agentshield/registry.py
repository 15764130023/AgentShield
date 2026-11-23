from agentshield.models import ToolSpec


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool_spec: ToolSpec) -> None:
        if not tool_spec.name:
            raise ValueError("工具名称不能为空")

        if tool_spec.name in self._tools:
            raise ValueError("工具已经注册")

        self._tools[tool_spec.name] = tool_spec

    def get(self, tool_name: str) -> ToolSpec | None:
        return self._tools.get(tool_name)