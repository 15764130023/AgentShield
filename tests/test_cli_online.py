import json

import pytest

from agentshield.cli import main
from agentshield.online_planner import (
    KimiOnlinePlanner,
)


class FakeOnlinePlanner:
    def plan(
        self,
        user_input: str,
        request_id: str,
    ) -> str:
        return "在线规划器已调用"

    def plan_follow_on(
        self,
        tool_result: object,
        request_id: str,
    ) -> None:
        return None


def test_cli_rejects_kimi_in_unprotected_mode(
    capsys: pytest.CaptureFixture[str],
):
    with pytest.raises(SystemExit) as error:
        main([
            "--planner",
            "kimi",
            "--mode",
            "unprotected",
        ])

    captured = capsys.readouterr()

    assert error.value.code == 2
    assert (
        "Kimi 在线规划器当前仅支持 "
        "--mode protected"
        in captured.err
    )


def test_cli_uses_kimi_online_planner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    created: dict[str, str] = {}

    def fake_from_environment(
        model: str,
    ) -> FakeOnlinePlanner:
        created["model"] = model
        return FakeOnlinePlanner()

    monkeypatch.setattr(
        KimiOnlinePlanner,
        "from_environment",
        fake_from_environment,
    )

    exit_code = main([
        "--planner",
        "kimi",
        "--model",
        "kimi-k3.1-pro",
        "--mode",
        "protected",
        "--input",
        "你好",
    ])

    output = json.loads(
        capsys.readouterr().out
    )

    assert exit_code == 0
    assert created == {
        "model": "kimi-k3.1-pro",
    }
    assert output["protected"] == {
        "message": "在线规划器已调用",
    }
