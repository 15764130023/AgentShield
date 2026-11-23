from pathlib import Path
import codecs
from agentshield.models import RiskLevel, ToolSpec


_SAFE_ERROR_MESSAGE = "无法访问指定文件"
_ALLOWED_ENCODINGS = {"utf-8"}
_MAX_FILE_SIZE_BYTES = 64 * 1024



def _is_link_or_junction(path: Path) -> bool:
    try:
        return (
            path.is_symlink()
            or path.is_junction()
        )
    except OSError:
        raise ValueError(_SAFE_ERROR_MESSAGE) from None


def _reject_linked_components(
    root: Path,
    requested_path: Path,
) -> None:
    current_path = root

    for path_part in requested_path.parts:
        current_path = current_path / path_part

        if _is_link_or_junction(current_path):
            raise ValueError(_SAFE_ERROR_MESSAGE)



def _resolve_safe_file(
    allowed_root: Path,
    relative_path: str,
    encoding: str = "utf-8",
) -> tuple[Path, str]:
    if type(relative_path) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if not relative_path.strip():
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if type(encoding) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    try:
        normalized_encoding = codecs.lookup(
            encoding
        ).name
    except LookupError:
        raise ValueError(_SAFE_ERROR_MESSAGE) from None

    if normalized_encoding not in _ALLOWED_ENCODINGS:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    requested_path = Path(relative_path)

    if requested_path.is_absolute():
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if ".." in requested_path.parts:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if _is_link_or_junction(allowed_root):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    try:
        resolved_root = allowed_root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(_SAFE_ERROR_MESSAGE) from None

    if not resolved_root.is_dir():
        raise ValueError(_SAFE_ERROR_MESSAGE)

    _reject_linked_components(
        root=resolved_root,
        requested_path=requested_path,
    )

    try:
        resolved_path = (
            resolved_root / requested_path
        ).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(_SAFE_ERROR_MESSAGE) from None

    if not resolved_path.is_relative_to(resolved_root):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if not resolved_path.is_file():
        raise ValueError(_SAFE_ERROR_MESSAGE)

    try:
        file_size = resolved_path.stat().st_size
    except OSError:
        raise ValueError(_SAFE_ERROR_MESSAGE) from None

    if file_size > _MAX_FILE_SIZE_BYTES:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return resolved_path, normalized_encoding


def read_text_file(
    allowed_root: Path,
    relative_path: str,
    encoding: str = "utf-8",
) -> str:
    resolved_path, normalized_encoding = (
        _resolve_safe_file(
            allowed_root=allowed_root,
            relative_path=relative_path,
            encoding=encoding,
        )
    )

    try:
        return resolved_path.read_text(
            encoding=normalized_encoding
        )
    except (LookupError, OSError, UnicodeError):
        raise ValueError(_SAFE_ERROR_MESSAGE) from None


def _extract_read_file_arguments(
    arguments: dict[str, object],
) -> tuple[str, str]:
    argument_names = set(arguments)

    if (
        argument_names != {"path"}
        and argument_names != {"path", "encoding"}
    ):
        raise ValueError(_SAFE_ERROR_MESSAGE)

    relative_path = arguments["path"]
    encoding = arguments.get("encoding", "utf-8")

    if type(relative_path) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    if type(encoding) is not str:
        raise ValueError(_SAFE_ERROR_MESSAGE)

    return relative_path, encoding


def create_read_file_spec(
    allowed_root: Path,
) -> ToolSpec:
    def validate_arguments(
        arguments: dict[str, object],
    ) -> None:
        relative_path, encoding = (
            _extract_read_file_arguments(arguments)
        )

        _resolve_safe_file(
            allowed_root=allowed_root,
            relative_path=relative_path,
            encoding=encoding,
        )

    def handle_read_file(
        arguments: dict[str, object],
    ) -> object:
        relative_path, encoding = (
            _extract_read_file_arguments(arguments)
        )

        return read_text_file(
            allowed_root=allowed_root,
            relative_path=relative_path,
            encoding=encoding,
        )

    return ToolSpec(
        name="read_file",
        description="读取允许目录中的本地文本文件",
        risk_level=RiskLevel.MEDIUM,
        required_permissions={"file.read"},
        allowed_targets={str(allowed_root)},
        requires_confirmation=True,
        parameter_validator=validate_arguments,
        handler=handle_read_file,
    )
