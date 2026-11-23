import pytest

from agentshield.output_guard import (
    OutputBlockedError,
    protect_output,
)


def test_protect_output_preserves_normal_value() -> None:
    value = {
        "answer": 5,
        "items": [
            "normal text",
            True,
            None,
        ],
    }

    result = protect_output(value)

    assert result.value == value
    assert result.redacted is False
    assert result.categories == ()


def test_protect_output_redacts_string() -> None:
    result = protect_output(
        "密钥是 TEST_SECRET_DO_NOT_EXPOSE"
    )

    assert result.value == (
        "密钥是 [REDACTED:TEST_SECRET]"
    )
    assert result.redacted is True
    assert result.categories == (
        "test_secret",
    )


def test_protect_output_redacts_nested_values() -> None:
    value = {
        "profile": {
            "email": "alice@example.com",
            "phone": "13800138000",
        },
        "messages": [
            "普通消息",
            "令牌 TEST_TOKEN_ABC123456789",
        ],
    }

    result = protect_output(value)

    assert result.value == {
        "profile": {
            "email": "[REDACTED:EMAIL]",
            "phone": "[REDACTED:PHONE]",
        },
        "messages": [
            "普通消息",
            "令牌 [REDACTED:TOKEN]",
        ],
    }

    assert result.redacted is True
    assert result.categories == (
        "email",
        "phone",
        "token",
    )


def test_protect_output_preserves_tuple_type() -> None:
    result = protect_output(
        (
            "普通消息",
            "alice@example.com",
        )
    )

    assert result.value == (
        "普通消息",
        "[REDACTED:EMAIL]",
    )
    assert isinstance(result.value, tuple)
    assert result.redacted is True


def test_protect_output_blocks_sensitive_dict_key() -> None:
    with pytest.raises(
        OutputBlockedError,
        match="字典键包含敏感信息",
    ):
        protect_output(
            {
                "alice@example.com": "value",
            }
        )


def test_protect_output_blocks_non_string_dict_key() -> None:
    with pytest.raises(
        OutputBlockedError,
        match="字典键类型不合规",
    ):
        protect_output(
            {
                123: "value",
            }
        )


def test_protect_output_blocks_unsupported_type() -> None:
    with pytest.raises(
        OutputBlockedError,
        match="不支持的数据类型",
    ):
        protect_output({"unexpected"})


def test_protect_output_blocks_recursive_container() -> None:
    recursive_list: list[object] = []
    recursive_list.append(recursive_list)

    with pytest.raises(
        OutputBlockedError,
        match="循环引用",
    ):
        protect_output(recursive_list)