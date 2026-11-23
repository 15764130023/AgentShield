import re
from pathlib import Path
from agentshield.models import RiskLevel, ToolSpec
from agentshield.tools.read_file import read_text_file
from agentshield.prompt_injection import (
    detect_prompt_injection,
)

_SAFE_ERROR_MESSAGE = "知识库查询参数不合规"
_CONFIG_ERROR_MESSAGE = "知识库配置不合规"
_COLLECTION_ERROR_MESSAGE = "无法访问指定知识库"
_MAX_QUERY_LENGTH = 100
_MAX_TITLE_LENGTH = 100
_MAX_SNIPPET_LENGTH = 200
_MAX_RESULTS = 10



def _normalize_search_text(text: str) -> str:
    return " ".join(text.split())


def _validate_query(query: object) -> str:
    if type(query) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if any(
        not character.isprintable()
        for character in query
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    normalized_query = query.strip()

    if not normalized_query:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if len(normalized_query) > _MAX_QUERY_LENGTH:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return _normalize_search_text(normalized_query)


def _resolve_collection_root(
    collection_root: Path,
) -> Path:
    if not isinstance(collection_root, Path):
        raise ValueError(_COLLECTION_ERROR_MESSAGE)

    try:
        resolved_root = collection_root.resolve(
            strict=True
        )
    except (OSError, RuntimeError):
        raise ValueError(
            _COLLECTION_ERROR_MESSAGE
        ) from None

    if not resolved_root.is_dir():
        raise ValueError(_COLLECTION_ERROR_MESSAGE)

    return resolved_root


def _extract_title(
    content: str,
    fallback_title: str,
) -> str:
    for line in content.splitlines():
        normalized_line = _normalize_search_text(line)

        if normalized_line:
            return normalized_line[:_MAX_TITLE_LENGTH]

    return _normalize_search_text(
        fallback_title
    )[:_MAX_TITLE_LENGTH]


def _detect_content_risk(
    content: str,
) -> str:
    injection_categories = (
        detect_prompt_injection(content)
    )

    if injection_categories:
        return "suspicious_instruction"

    return "untrusted"


def _find_match_index(
    normalized_content: str,
    normalized_query: str,
) -> int | None:
    match = re.search(
        re.escape(normalized_query),
        normalized_content,
        flags=re.IGNORECASE,
    )

    if match is None:
        return None

    return match.start()


def _build_snippet(
    normalized_content: str,
    match_index: int,
) -> str:
    snippet_start = max(0, match_index - 50)
    snippet_end = min(
        len(normalized_content),
        snippet_start + _MAX_SNIPPET_LENGTH,
    )

    return normalized_content[
        snippet_start:snippet_end
    ]


def search_knowledge(
    collection_root: Path,
    query: str,
) -> list[dict[str, str]]:
    normalized_query = _validate_query(query)
    resolved_root = _resolve_collection_root(
        collection_root
    )

    document_paths = sorted(
        resolved_root.glob("*.txt"),
        key=lambda path: path.name.casefold(),
    )

    results: list[dict[str, str]] = []

    for document_path in document_paths:
        content = read_text_file(
            allowed_root=resolved_root,
            relative_path=document_path.name,
        )

        normalized_content = _normalize_search_text(
            content
        )

        match_index = _find_match_index(
            normalized_content=normalized_content,
            normalized_query=normalized_query,
        )

        if match_index is None:
            continue

        result = {
            "document_id": document_path.stem,
            "title": _extract_title(
                content=content,
                fallback_title=document_path.stem,
            ),
            "snippet": _build_snippet(
                normalized_content=normalized_content,
                match_index=match_index,
            ),
            "path": document_path.name,
            "content_risk": _detect_content_risk(
                content
            ),
        }

        results.append(result)

        if len(results) >= _MAX_RESULTS:
            break

    return results


def _extract_search_arguments(
    arguments: dict[str, object],
    default_collection: str,
) -> tuple[str, str]:
    if type(arguments) is not dict:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    argument_names = set(arguments)

    if (
        argument_names != {"query"}
        and argument_names != {
            "query",
            "collection",
        }
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    query = arguments["query"]

    normalized_query = _validate_query(query)

    collection = arguments.get(
        "collection",
        default_collection,
    )

    if type(collection) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if any(
        not character.isprintable()
        for character in collection
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    normalized_collection = collection.strip()

    if not normalized_collection:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return normalized_query, normalized_collection


def create_search_knowledge_spec(
    collections: dict[str, Path],
    default_collection: str,
) -> ToolSpec:
    if type(collections) is not dict or not collections:
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    if type(default_collection) is not str:
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    if any(
        not character.isprintable()
        for character in default_collection
    ):
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    normalized_default_collection = (
        default_collection.strip()
    )

    if not normalized_default_collection:
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    resolved_collections: dict[str, Path] = {}

    for collection_name, collection_root in (
        collections.items()
    ):
        if type(collection_name) is not str:
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        if any(
            not character.isprintable()
            for character in collection_name
        ):
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        normalized_collection_name = (
            collection_name.strip()
        )

        if not normalized_collection_name:
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        if normalized_collection_name in resolved_collections:
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        if not isinstance(collection_root, Path):
            raise ValueError(_CONFIG_ERROR_MESSAGE)

        try:
            resolved_root = _resolve_collection_root(
                collection_root
            )
        except ValueError:
            raise ValueError(
                _CONFIG_ERROR_MESSAGE
            ) from None

        resolved_collections[
            normalized_collection_name
        ] = resolved_root

    if (
        normalized_default_collection
        not in resolved_collections
    ):
        raise ValueError(_CONFIG_ERROR_MESSAGE)

    def validate_arguments(
        arguments: dict[str, object],
    ) -> None:
        _, collection = _extract_search_arguments(
            arguments=arguments,
            default_collection=(
                normalized_default_collection
            ),
        )

        if collection not in resolved_collections:
            raise ValueError(_SAFE_ERROR_MESSAGE)

    def handle_search_knowledge(
        arguments: dict[str, object],
    ) -> object:
        query, collection = _extract_search_arguments(
            arguments=arguments,
            default_collection=(
                normalized_default_collection
            ),
        )

        collection_root = resolved_collections.get(
            collection
        )

        if collection_root is None:
            raise ValueError(_SAFE_ERROR_MESSAGE)

        return search_knowledge(
            collection_root=collection_root,
            query=query,
        )

    return ToolSpec(
        name="search_knowledge",
        description="查询注册的本地知识库",
        risk_level=RiskLevel.LOW,
        required_permissions={"knowledge.read"},
        allowed_targets=set(resolved_collections),
        requires_confirmation=False,
        parameter_validator=validate_arguments,
        handler=handle_search_knowledge,
    )
