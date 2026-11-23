import pytest

from agentshield.sensitive_data import (
    SensitiveDataError,
    detect_sensitive_data,
    ensure_no_sensitive_data,
    redact_sensitive_data,
)

@pytest.mark.parametrize(
    (
        "text",
        "expected_category",
    ),
    [
        (
            "密钥是 TEST_SECRET_DO_NOT_EXPOSE",
            "test_secret",
        ),
        (
            "令牌是 TEST_TOKEN_ABC123456789",
            "token",
        ),
        (
            "Authorization: Bearer abcdefghijklmnop",
            "token",
        ),
        (
            "API Key 是 TEST_API_KEY_ABC123456789",
            "api_key",
        ),
        (
            "API Key 是 sk-test-abcdefghijklmnop",
            "api_key",
        ),
        (
            "联系 alice@example.com",
            "email",
        ),
        (
            "联系电话 13800138000",
            "phone",
        ),
    ],
)
def test_detect_sensitive_data(
    text: str,
    expected_category: str,
) -> None:
    result = detect_sensitive_data(text)

    assert expected_category in result


def test_normal_text_has_no_sensitive_data() -> None:
    result = detect_sensitive_data(
        "会议改到下午三点，请及时参加"
    )

    assert result == set()


def test_detects_multiple_sensitive_categories() -> None:
    result = detect_sensitive_data(
        "请联系 alice@example.com，"
        "电话是 13800138000"
    )

    assert result == {
        "email",
        "phone",
    }


def test_sensitive_error_does_not_include_original_value() -> None:
    sensitive_value = (
        "TEST_SECRET_DO_NOT_EXPOSE"
    )

    with pytest.raises(
        SensitiveDataError
    ) as error_info:
        ensure_no_sensitive_data(
            sensitive_value
        )

    error = error_info.value

    assert error.categories == (
        "test_secret",
    )
    assert sensitive_value not in str(error)


@pytest.mark.parametrize(
    (
        "sensitive_value",
        "expected_category",
    ),
    [
        (
            "TEST_SECRET_DO_NOT_EXPOSE",
            "test_secret",
        ),
        (
            "TEST_TOKEN_ABC123456789",
            "token",
        ),
        (
            "Bearer abcdefghijklmnop",
            "token",
        ),
        (
            "TEST_API_KEY_ABC123456789",
            "api_key",
        ),
        (
            "alice@example.com",
            "email",
        ),
        (
            "13800138000",
            "phone",
        ),
    ],
)
def test_redact_sensitive_data(
    sensitive_value: str,
    expected_category: str,
) -> None:
    text = f"before {sensitive_value} after"

    redacted_text, categories = (
        redact_sensitive_data(text)
    )

    assert sensitive_value not in redacted_text
    assert (
        f"[REDACTED:{expected_category.upper()}]"
        in redacted_text
    )
    assert expected_category in categories


def test_redaction_preserves_normal_text() -> None:
    text = "会议改到下午三点"

    redacted_text, categories = (
        redact_sensitive_data(text)
    )

    assert redacted_text == text
    assert categories == set()


def test_redacts_multiple_sensitive_categories() -> None:
    text = (
        "联系人 alice@example.com，"
        "电话 13800138000，"
        "密钥 TEST_SECRET_DO_NOT_EXPOSE"
    )

    redacted_text, categories = (
        redact_sensitive_data(text)
    )

    assert "alice@example.com" not in redacted_text
    assert "13800138000" not in redacted_text
    assert (
        "TEST_SECRET_DO_NOT_EXPOSE"
        not in redacted_text
    )

    assert categories == {
        "email",
        "phone",
        "test_secret",
    }


def test_redaction_rejects_non_string_input() -> None:
    with pytest.raises(
        TypeError,
        match="脱敏输入类型不合规",
    ):
        redact_sensitive_data(123)  # type: ignore[arg-type]