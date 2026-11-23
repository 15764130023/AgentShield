from agentshield.models import ToolCall
from agentshield.planner import MockPlanner


def test_planner_creates_calculator_tool_call():
    planner = MockPlanner()

    result = planner.plan(
        user_input="计算: 2 + 3",
        request_id="req-001",
    )

    assert isinstance(result, ToolCall)
    assert result.request_id == "req-001"
    assert result.tool_name == "calculator"
    assert result.arguments == {"expression": "2 + 3"}


def test_planner_returns_answer_for_unsupported_request():
    planner = MockPlanner()

    result = planner.plan(
        user_input="帮我读取文件",
        request_id="req-002",
    )

    assert result == (
        "当前支持“计算: 数学表达式”、"
        "“读取: 相对路径”、"
        "“搜索: 关键词”或"
        "“发送: 收件人 | 消息内容”格式的请求"
    )


def test_planner_requests_expression_when_it_is_missing():
    planner = MockPlanner()

    result = planner.plan(
        user_input="计算:",
        request_id="req-003",
    )

    assert result == "请提供需要计算的表达式"


def test_planner_creates_read_file_tool_call():
    planner = MockPlanner()

    result = planner.plan(
        user_input="读取: reports/report.txt",
        request_id="req-004",
    )

    assert isinstance(result, ToolCall)
    assert result.request_id == "req-004"
    assert result.tool_name == "read_file"
    assert result.arguments == {
        "path": "reports/report.txt",
    }


def test_planner_requests_path_when_it_is_missing():
    planner = MockPlanner()

    result = planner.plan(
        user_input="读取:",
        request_id="req-005",
    )

    assert result == "请提供需要读取的文件路径"


def test_planner_creates_search_knowledge_tool_call():
    planner = MockPlanner()

    result = planner.plan(
        user_input="搜索: 工具调用",
        request_id="req-006",
    )

    assert isinstance(result, ToolCall)
    assert result.request_id == "req-006"
    assert result.tool_name == "search_knowledge"
    assert result.arguments == {
        "query": "工具调用",
    }


def test_planner_requests_query_when_it_is_missing():
    planner = MockPlanner()

    result = planner.plan(
        user_input="搜索:",
        request_id="req-007",
    )

    assert result == "请提供需要搜索的关键词"


def test_planner_creates_send_message_tool_call():
    planner = MockPlanner()

    result = planner.plan(
        user_input=(
            "发送: test-recipient | "
            "会议改到下午三点"
        ),
        request_id="req-008",
    )

    assert isinstance(result, ToolCall)
    assert result.request_id == "req-008"
    assert result.tool_name == "send_message"
    assert result.arguments == {
        "recipient": "test-recipient",
        "content": "会议改到下午三点",
    }


def test_planner_supports_full_width_send_prefix():
    planner = MockPlanner()

    result = planner.plan(
        user_input=(
            "发送：security-reviewer | "
            "请检查安全报告"
        ),
        request_id="req-009",
    )

    assert isinstance(result, ToolCall)
    assert result.tool_name == "send_message"
    assert result.arguments == {
        "recipient": "security-reviewer",
        "content": "请检查安全报告",
    }


def test_planner_supports_english_send_prefix():
    planner = MockPlanner()

    result = planner.plan(
        user_input=(
            "send: test-recipient | "
            "test message"
        ),
        request_id="req-010",
    )

    assert isinstance(result, ToolCall)
    assert result.tool_name == "send_message"
    assert result.arguments == {
        "recipient": "test-recipient",
        "content": "test message",
    }


def test_planner_requires_send_separator():
    planner = MockPlanner()

    result = planner.plan(
        user_input=(
            "发送: test-recipient 测试消息"
        ),
        request_id="req-011",
    )

    assert result == (
        "请使用“发送: 收件人 | 消息内容”格式"
    )


def test_planner_requires_message_recipient():
    planner = MockPlanner()

    result = planner.plan(
        user_input="发送: | 测试消息",
        request_id="req-012",
    )

    assert result == "请提供消息接收目标"


def test_planner_requires_message_content():
    planner = MockPlanner()

    result = planner.plan(
        user_input="发送: test-recipient |",
        request_id="req-013",
    )

    assert result == "请提供消息内容"


def test_planner_splits_only_first_separator():
    planner = MockPlanner()

    result = planner.plan(
        user_input=(
            "发送: test-recipient | "
            "状态为 ready | running"
        ),
        request_id="req-014",
    )

    assert isinstance(result, ToolCall)
    assert result.arguments == {
        "recipient": "test-recipient",
        "content": "状态为 ready | running",
    }