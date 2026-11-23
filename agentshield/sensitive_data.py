import re


class SensitiveDataError(ValueError):
    def __init__(
        self,
        categories: set[str],
    ) -> None:
        self.categories = tuple(
            sorted(categories)
        )

        super().__init__(
            "请求包含敏感信息，已被拒绝"
        )


_SENSITIVE_PATTERNS: tuple[
    tuple[str, re.Pattern[str]],
    ...,
] = (
    (
        "test_secret",
        re.compile(
            r"\bTEST_SECRET_[A-Z0-9_]+\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "token",
        re.compile(
            r"\bTEST_TOKEN_[A-Z0-9_]+\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "token",
        re.compile(
            r"\bBearer\s+"
            r"[A-Z0-9._~+/=-]{12,}",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "api_key",
        re.compile(
            r"\b(?:"
            r"TEST_API_KEY_[A-Z0-9_]+"
            r"|"
            r"sk-test-[A-Z0-9_-]{12,}"
            r")\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "email",
        re.compile(
            r"\b"
            r"[A-Z0-9._%+-]+"
            r"@"
            r"[A-Z0-9.-]+"
            r"\."
            r"[A-Z]{2,}"
            r"\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "phone",
        re.compile(
            r"(?<!\d)"
            r"1[3-9]\d{9}"
            r"(?!\d)"
        ),
    ),
)


def detect_sensitive_data(
    text: str,
) -> set[str]:
    if type(text) is not str:
        raise TypeError("敏感信息检测输入类型不合规")

    detected_categories: set[str] = set()

    for category, pattern in _SENSITIVE_PATTERNS:
        if pattern.search(text) is not None:
            detected_categories.add(category)

    return detected_categories


def ensure_no_sensitive_data(
    text: str,
) -> None:
    detected_categories = detect_sensitive_data(
        text
    )

    if detected_categories:
        raise SensitiveDataError(
            detected_categories
        )


def redact_sensitive_data(
    text: str,
) -> tuple[str, set[str]]:
    if type(text) is not str:
        raise TypeError(
            "敏感信息脱敏输入类型不合规"
        )

    redacted_text = text
    redacted_categories: set[str] = set()

    for category, pattern in _SENSITIVE_PATTERNS:
        replacement = (
            f"[REDACTED:{category.upper()}]"
        )

        redacted_text, replacement_count = (
            pattern.subn(
                replacement,
                redacted_text,
            )
        )

        if replacement_count > 0:
            redacted_categories.add(category)

    return redacted_text, redacted_categories