from pathlib import Path

import pytest

from agentshield.tools.read_file import read_text_file


def test_read_file_reads_file_inside_allowed_root(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    report_file = allowed_root / "report.txt"
    report_file.write_text(
        "public test report",
        encoding="utf-8",
    )

    result = read_text_file(
        allowed_root=allowed_root,
        relative_path="report.txt",
    )

    assert result == "public test report"


def test_read_file_rejects_path_traversal(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    private_root = tmp_path / "private"
    private_root.mkdir()

    secret_file = private_root / "secret.txt"
    secret_file.write_text(
        "TEST_SECRET_DO_NOT_EXPOSE",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="../private/secret.txt",
        )


def test_read_file_rejects_absolute_path(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text(
        "outside content",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ) as error:
        read_text_file(
            allowed_root=allowed_root,
            relative_path=str(outside_file),
        )

    assert str(outside_file) not in str(error.value)


def test_read_file_rejects_missing_file(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="missing.txt",
        )


def test_read_file_rejects_directory(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    nested_directory = allowed_root / "reports"
    nested_directory.mkdir()

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="reports",
        )


def test_read_file_rejects_unsupported_encoding(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    text_file = allowed_root / "report.txt"
    text_file.write_text(
        "public report",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="report.txt",
            encoding="latin-1",
        )



def test_read_file_accepts_file_at_size_limit(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    text_file = allowed_root / "maximum.txt"
    text_file.write_bytes(b"a" * (64 * 1024))

    result = read_text_file(
        allowed_root=allowed_root,
        relative_path="maximum.txt",
    )

    assert len(result) == 64 * 1024


def test_read_file_rejects_file_over_size_limit(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    oversized_file = allowed_root / "oversized.txt"
    oversized_file.write_bytes(
        b"a" * (64 * 1024 + 1)
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="oversized.txt",
        )


def _create_symlink_or_skip(
    link_path: Path,
    target_path: Path,
    target_is_directory: bool = False,
) -> None:
    try:
        link_path.symlink_to(
            target_path,
            target_is_directory=target_is_directory,
        )
    except OSError as error:
        pytest.skip(
            f"当前系统无法创建符号链接：{error}"
        )


def test_read_file_rejects_file_symlink(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    real_file = allowed_root / "real.txt"
    real_file.write_text(
        "allowed content",
        encoding="utf-8",
    )

    link_file = allowed_root / "link.txt"
    _create_symlink_or_skip(
        link_path=link_file,
        target_path=real_file,
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="link.txt",
        )


def test_read_file_rejects_symlinked_directory_component(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    real_directory = allowed_root / "real_reports"
    real_directory.mkdir()

    report_file = real_directory / "report.txt"
    report_file.write_text(
        "allowed report",
        encoding="utf-8",
    )

    linked_directory = allowed_root / "linked_reports"
    _create_symlink_or_skip(
        link_path=linked_directory,
        target_path=real_directory,
        target_is_directory=True,
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="linked_reports/report.txt",
        )


def test_read_file_rejects_symlink_outside_allowed_root(
    tmp_path: Path,
):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    private_root = tmp_path / "private"
    private_root.mkdir()

    secret_file = private_root / "secret.txt"
    secret_file.write_text(
        "TEST_SECRET_DO_NOT_EXPOSE",
        encoding="utf-8",
    )

    link_file = allowed_root / "secret-link.txt"
    _create_symlink_or_skip(
        link_path=link_file,
        target_path=secret_file,
    )

    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=allowed_root,
            relative_path="secret-link.txt",
        )