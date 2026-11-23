import re


_PATTERN_FLAGS = re.IGNORECASE


_INJECTION_PATTERNS: tuple[
    tuple[str, re.Pattern[str]],
    ...,
] = (
    (
        "instruction_override",
        re.compile(
            r"(?:忽略|无视|覆盖|丢弃)"
            r".{0,24}"
            r"(?:指令|规则|要求|限制)",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"\b"
            r"(?:ignore|disregard|override|forget)"
            r"\s+"
            r"(?:(?:all|any|the|your)\s+)*"
            r"(?:previous|prior|earlier|system|developer)?"
            r"\s*"
            r"(?:instructions?|rules?|constraints?)"
            r"\b",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "permission_bypass",
        re.compile(
            r"(?:绕过|跳过|关闭|禁用|规避)"
            r".{0,24}"
            r"(?:权限|安全检查|策略|限制|验证|确认|审批)",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "permission_bypass",
        re.compile(
            r"\b"
            r"(?:bypass|disable|skip|evade)"
            r"\s+"
            r"(?:the\s+)?"
            r"(?:"
            r"permission|authorization|security|"
            r"policy|confirmation|approval"
            r")"
            r"(?:\s+(?:checks?|controls?|rules?))?"
            r"\b",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"(?:显示|输出|泄露|透露|打印|告诉我)"
            r".{0,24}"
            r"(?:系统提示词|系统提示|隐藏指令|开发者指令)",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"\b"
            r"(?:reveal|show|print|display|leak|expose)"
            r"\s+"
            r"(?:the\s+)?"
            r"(?:system|developer)"
            r"\s+"
            r"(?:prompt|message|instructions?)"
            r"\b",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "unsafe_tool_request",
        re.compile(
            r"(?:调用|执行|使用)"
            r".{0,16}"
            r"(?:send_message|未注册工具)"
            r".{0,32}"
            r"(?:无需|跳过|绕过|避开)"
            r".{0,16}"
            r"(?:确认|权限|审批)",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "unsafe_tool_request",
        re.compile(
            r"(?:无需|跳过|绕过|避开)"
            r".{0,16}"
            r"(?:确认|权限|审批)"
            r".{0,32}"
            r"(?:调用|执行|使用)"
            r".{0,16}"
            r"(?:send_message|工具)",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "unsafe_tool_request",
        re.compile(
            r"\b"
            r"(?:call|use|execute)"
            r"\s+"
            r"(?:the\s+)?"
            r"(?:send_message|an?\s+unregistered\s+tool)"
            r"\b"
            r".{0,40}"
            r"\b(?:without|bypass|skip)\b"
            r".{0,20}"
            r"\b(?:permission|confirmation|approval)\b",
            flags=_PATTERN_FLAGS,
        ),
    ),
    (
        "unsafe_tool_request",
        re.compile(
            r"\b(?:without|bypass|skip)\b"
            r".{0,20}"
            r"\b(?:permission|confirmation|approval)\b"
            r".{0,40}"
            r"\b(?:call|use|execute)"
            r"\s+"
            r"(?:the\s+)?"
            r"(?:send_message|tool)"
            r"\b",
            flags=_PATTERN_FLAGS,
        ),
    ),
)


def _normalize_text(
    text: str,
) -> str:
    return " ".join(text.split())


def detect_prompt_injection(
    text: str,
) -> set[str]:
    if type(text) is not str:
        raise TypeError(
            "Prompt Injection 检测输入类型不合规"
        )

    normalized_text = _normalize_text(text)

    detected_categories: set[str] = set()

    for category, pattern in _INJECTION_PATTERNS:
        if pattern.search(normalized_text) is not None:
            detected_categories.add(category)

    return detected_categories