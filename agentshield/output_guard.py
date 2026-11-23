from dataclasses import dataclass

from agentshield.sensitive_data import (
    redact_sensitive_data,
)


_MAX_OUTPUT_DEPTH = 20


class OutputBlockedError(ValueError):
    pass


@dataclass(frozen=True)
class OutputProtectionResult:
    value: object
    redacted: bool
    categories: tuple[str, ...]


def protect_output(
    value: object,
) -> OutputProtectionResult:
    detected_categories: set[str] = set()

    protected_value, was_redacted = (
        _protect_value(
            value=value,
            depth=0,
            active_container_ids=set(),
            detected_categories=(
                detected_categories
            ),
        )
    )

    return OutputProtectionResult(
        value=protected_value,
        redacted=was_redacted,
        categories=tuple(
            sorted(detected_categories)
        ),
    )


def _protect_value(
    value: object,
    depth: int,
    active_container_ids: set[int],
    detected_categories: set[str],
) -> tuple[object, bool]:
    if depth > _MAX_OUTPUT_DEPTH:
        raise OutputBlockedError(
            "工具输出嵌套层级过深"
        )

    value_type = type(value)

    if value is None:
        return None, False

    if value_type in {
        bool,
        int,
        float,
    }:
        return value, False

    if value_type is str:
        redacted_text, categories = (
            redact_sensitive_data(value)
        )

        detected_categories.update(categories)

        return redacted_text, bool(categories)

    if value_type is list:
        return _protect_list(
            value=value,
            depth=depth,
            active_container_ids=(
                active_container_ids
            ),
            detected_categories=(
                detected_categories
            ),
        )

    if value_type is tuple:
        return _protect_tuple(
            value=value,
            depth=depth,
            active_container_ids=(
                active_container_ids
            ),
            detected_categories=(
                detected_categories
            ),
        )

    if value_type is dict:
        return _protect_dict(
            value=value,
            depth=depth,
            active_container_ids=(
                active_container_ids
            ),
            detected_categories=(
                detected_categories
            ),
        )

    raise OutputBlockedError(
        "工具输出包含不支持的数据类型"
    )


def _protect_list(
    value: list[object],
    depth: int,
    active_container_ids: set[int],
    detected_categories: set[str],
) -> tuple[list[object], bool]:
    container_id = id(value)

    if container_id in active_container_ids:
        raise OutputBlockedError(
            "工具输出包含循环引用"
        )

    active_container_ids.add(container_id)

    protected_items: list[object] = []
    was_redacted = False

    try:
        for item in value:
            protected_item, item_redacted = (
                _protect_value(
                    value=item,
                    depth=depth + 1,
                    active_container_ids=(
                        active_container_ids
                    ),
                    detected_categories=(
                        detected_categories
                    ),
                )
            )

            protected_items.append(
                protected_item
            )
            was_redacted = (
                was_redacted
                or item_redacted
            )
    finally:
        active_container_ids.remove(
            container_id
        )

    return protected_items, was_redacted


def _protect_tuple(
    value: tuple[object, ...],
    depth: int,
    active_container_ids: set[int],
    detected_categories: set[str],
) -> tuple[tuple[object, ...], bool]:
    container_id = id(value)

    if container_id in active_container_ids:
        raise OutputBlockedError(
            "工具输出包含循环引用"
        )

    active_container_ids.add(container_id)

    protected_items: list[object] = []
    was_redacted = False

    try:
        for item in value:
            protected_item, item_redacted = (
                _protect_value(
                    value=item,
                    depth=depth + 1,
                    active_container_ids=(
                        active_container_ids
                    ),
                    detected_categories=(
                        detected_categories
                    ),
                )
            )

            protected_items.append(
                protected_item
            )
            was_redacted = (
                was_redacted
                or item_redacted
            )
    finally:
        active_container_ids.remove(
            container_id
        )

    return tuple(protected_items), was_redacted


def _protect_dict(
    value: dict[object, object],
    depth: int,
    active_container_ids: set[int],
    detected_categories: set[str],
) -> tuple[dict[str, object], bool]:
    container_id = id(value)

    if container_id in active_container_ids:
        raise OutputBlockedError(
            "工具输出包含循环引用"
        )

    active_container_ids.add(container_id)

    protected_items: dict[str, object] = {}
    was_redacted = False

    try:
        for key, item in value.items():
            if type(key) is not str:
                raise OutputBlockedError(
                    "工具输出字典键类型不合规"
                )

            _, key_categories = (
                redact_sensitive_data(key)
            )

            if key_categories:
                raise OutputBlockedError(
                    "工具输出字典键包含敏感信息"
                )

            protected_item, item_redacted = (
                _protect_value(
                    value=item,
                    depth=depth + 1,
                    active_container_ids=(
                        active_container_ids
                    ),
                    detected_categories=(
                        detected_categories
                    ),
                )
            )

            protected_items[key] = (
                protected_item
            )
            was_redacted = (
                was_redacted
                or item_redacted
            )
    finally:
        active_container_ids.remove(
            container_id
        )

    return protected_items, was_redacted