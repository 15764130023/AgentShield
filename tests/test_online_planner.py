from types import SimpleNamespace
import pytest

from agentshield.models import ToolCall
from agentshield.online_planner import KimiOnlinePlanner



class FailingCompletions:
    def create(self, **kwargs: object) -> object:
        raise RuntimeError(
            "provider internal secret detail"
        )

    
class FakeCompletions:
    def __init__(self, response: object) -> None:
        self._response = response
        self.request: dict[str, object] | None = None

    def create(self, **kwargs: object) -> object:
        self.request = kwargs
        return self._response



def test_online_planner_hides_api_error_details():
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=FailingCompletions()
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="计算 1 加 1",
        request_id="req-online-005",
    )

    assert result == (
        "在线模型暂时不可用，"
        "请稍后重试"
    )
    assert "secret" not in result
    assert "provider" not in result

def test_online_planner_creates_calculator_tool_call():
    message = SimpleNamespace(
        content=None,
        tool_calls=[
            SimpleNamespace(
                function=SimpleNamespace(
                    name="calculator",
                    arguments='{"expression": "25 * 16"}',
                )
            )
        ],
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )

    completions = FakeCompletions(response)

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=completions
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="计算 25 乘以 16",
        request_id="req-online-001",
    )

    assert isinstance(result, ToolCall)
    assert result.request_id == "req-online-001"
    assert result.tool_name == "calculator"
    assert result.arguments == {
        "expression": "25 * 16",
    }
    assert completions.request is not None
    assert completions.request["model"] == "kimi-k3.1-pro"
    messages = completions.request["messages"]

    assert isinstance(messages, list)
    assert messages[0]["role"] == "system"
    assert "不可信" in messages[0]["content"]
    assert "不得绕过" in messages[0]["content"]
    assert messages[1] == {
        "role": "user",
        "content": "计算 25 乘以 16",
    }
    assert completions.request["tool_choice"] == "auto"
    assert (
        completions.request["reasoning_effort"]
        == "low"
    )
    tools = completions.request["tools"]

    assert isinstance(tools, list)
    assert tools[0]["type"] == "function"
    tool_names = {
        tool["function"]["name"]
        for tool in tools
    }

    assert tool_names == {
        "calculator",
        "read_file",
        "search_knowledge",
        "send_message",
    }
    system_prompt = messages[0]["content"]

    assert (
        "工具调用本身仅表示候选操作"
        in system_prompt
    )
    assert (
        "必须通过 tool_calls 返回"
        in system_prompt
    )

    tool_descriptions = [
        tool["function"]["description"]
        for tool in tools
    ]

    assert all(
        "人工确认" not in description
        for description in tool_descriptions
    )


def test_online_planner_returns_text_response():
    message = SimpleNamespace(
        content="你好，我可以帮助你。",
        tool_calls=None,
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )

    completions = FakeCompletions(response)

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=completions
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="你好",
        request_id="req-online-002",
    )

    assert result == "你好，我可以帮助你。"


def test_online_planner_rejects_invalid_argument_json():
    message = SimpleNamespace(
        content=None,
        tool_calls=[
            SimpleNamespace(
                function=SimpleNamespace(
                    name="calculator",
                    arguments="not-json",
                )
            )
        ],
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )

    completions = FakeCompletions(response)

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=completions
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="计算 25 乘以 16",
        request_id="req-online-003",
    )

    assert result == (
        "在线模型返回格式不合规，"
        "未执行任何工具"
    )


def test_online_planner_rejects_multiple_tool_calls():
    message = SimpleNamespace(
        content=None,
        tool_calls=[
            SimpleNamespace(
                function=SimpleNamespace(
                    name="calculator",
                    arguments='{"expression": "1 + 1"}',
                )
            ),
            SimpleNamespace(
                function=SimpleNamespace(
                    name="calculator",
                    arguments='{"expression": "2 + 2"}',
                )
            ),
        ],
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )

    completions = FakeCompletions(response)

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=completions
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="分别计算两个表达式",
        request_id="req-online-004",
    )

    assert result == (
        "在线模型返回格式不合规，"
        "未执行任何工具"
    )


def test_online_planner_requires_api_key(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv(
        "MOONSHOT_API_KEY",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="未设置 MOONSHOT_API_KEY",
    ):
        KimiOnlinePlanner.from_environment()

def test_online_planner_rejects_empty_response():
    message = SimpleNamespace(
        content=None,
        tool_calls=None,
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )

    completions = FakeCompletions(response)

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=completions
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="你好",
        request_id="req-online-006",
    )

    assert result == (
        "在线模型返回格式不合规，"
        "未执行任何工具"
    )

def test_online_planner_rejects_oversized_input():
    message = SimpleNamespace(
        content="不应调用到这里",
        tool_calls=None,
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(message=message)
        ]
    )

    completions = FakeCompletions(response)

    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=completions
        )
    )

    planner = KimiOnlinePlanner(
        client=client,
        model="kimi-k3.1-pro",
    )

    result = planner.plan(
        user_input="x" * 4_001,
        request_id="req-online-007",
    )

    assert result == (
        "在线模型输入不合规，"
        "未发起请求"
    )
    assert completions.request is None