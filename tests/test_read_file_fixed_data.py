from pathlib import Path

import pytest

from agentshield.tools.read_file import read_text_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FILE_TEST_DATA_ROOT = PROJECT_ROOT / "test_data" / "files"
ALLOWED_FILES_ROOT = FILE_TEST_DATA_ROOT / "allowed"


def test_read_file_reads_fixed_allowed_file():
    result = read_text_file(
        allowed_root=ALLOWED_FILES_ROOT,
        relative_path="report.txt",
    )

    assert result == "AgentShield fixed test report.\n"


def test_read_file_rejects_fixed_private_file():
    with pytest.raises(
        ValueError,
        match="无法访问指定文件",
    ):
        read_text_file(
            allowed_root=ALLOWED_FILES_ROOT,
            relative_path="../private/secret.txt",
        )
