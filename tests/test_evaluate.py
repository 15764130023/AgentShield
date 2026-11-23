import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from agentshield.evaluate import (
    EvaluationRecord,
    load_samples,
    main,
    run_evaluation,
    save_results,
    summarize_records,
)


ROOT = Path(__file__).resolve().parents[1]
SAMPLES_PATH = ROOT / "data/evaluation/smoke-10.json"
RESULT_FIELDS = {
    "sample_id",
    "category",
    "is_attack",
    "mode",
    "expected_decision",
    "expected_reason_code",
    "actual_decision",
    "reason_code",
    "matched_expectation",
    "attack_succeeded",
    "security_signal",
    "latency_ms",
}


def _decision_signature(record: EvaluationRecord) -> tuple[object, ...]:
    return (
        record.sample_id,
        record.category,
        record.is_attack,
        record.mode,
        record.expected_decision,
        record.expected_reason_code,
        record.actual_decision,
        record.reason_code,
        record.matched_expectation,
        record.attack_succeeded,
        record.security_signal,
    )


def test_run_evaluation_executes_every_sample_in_both_modes() -> None:
    samples = load_samples(SAMPLES_PATH)

    records = run_evaluation(samples, mode="both")

    assert len(records) == 20
    assert {record.mode for record in records} == {
        "protected",
        "unprotected",
    }
    assert {
        record.sample_id for record in records
    } == {sample["id"] for sample in samples}

    protected = [
        record for record in records if record.mode == "protected"
    ]
    assert len(protected) == 10
    assert all(record.matched_expectation is True for record in protected)

    unprotected = [
        record for record in records if record.mode == "unprotected"
    ]
    assert len(unprotected) == 10
    assert all(record.expected_decision is None for record in unprotected)
    assert all(record.expected_reason_code is None for record in unprotected)
    assert all(record.matched_expectation is None for record in unprotected)
    assert all(record.security_signal is False for record in unprotected)
    assert all(
        record.attack_succeeded is None
        for record in records
        if record.category == "normal"
    )
    assert all(record.latency_ms >= 0 for record in records)


def test_repeated_runs_keep_the_same_security_decisions() -> None:
    samples = load_samples(SAMPLES_PATH)

    first = run_evaluation(samples, mode="both")
    second = run_evaluation(samples, mode="both")

    assert [
        _decision_signature(record) for record in first
    ] == [
        _decision_signature(record) for record in second
    ]


def test_comparison_exposes_policy_effect_and_keeps_sandbox_boundary() -> None:
    samples = load_samples(SAMPLES_PATH)

    records = run_evaluation(samples, mode="both")
    by_sample_and_mode = {
        (record.sample_id, record.mode): record
        for record in records
    }

    for sample_id, protected_reason in {
        "D02": "PROMPT_INJECTION_DETECTED",
        "A01": "PERMISSION_DENIED",
        "S01": "SENSITIVE_DATA_DETECTED",
    }.items():
        protected = by_sample_and_mode[(sample_id, "protected")]
        unprotected = by_sample_and_mode[(sample_id, "unprotected")]

        assert protected.actual_decision == "deny"
        assert protected.reason_code == protected_reason
        assert protected.security_signal is True
        assert protected.attack_succeeded is False
        assert unprotected.actual_decision == "allow"
        assert unprotected.reason_code == "UNPROTECTED_TOOL_EXECUTED"
        assert unprotected.attack_succeeded is True

    protected_path = by_sample_and_mode[("P01", "protected")]
    unprotected_path = by_sample_and_mode[("P01", "unprotected")]
    assert protected_path.actual_decision == "deny"
    assert protected_path.reason_code == "INVALID_ARGUMENTS"
    assert unprotected_path.actual_decision == "deny"
    assert unprotected_path.reason_code == "UNPROTECTED_TOOL_FAILED"
    assert protected_path.attack_succeeded is False
    assert unprotected_path.attack_succeeded is False

    indirect_protected = by_sample_and_mode[("I01", "protected")]
    indirect_unprotected = by_sample_and_mode[("I01", "unprotected")]
    assert indirect_protected.security_signal is True
    assert indirect_protected.attack_succeeded is False
    assert indirect_unprotected.attack_succeeded is False


def test_load_samples_rejects_missing_field(tmp_path: Path) -> None:
    samples = json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))
    del samples[0]["category"]
    invalid_path = tmp_path / "missing-field.json"
    invalid_path.write_text(
        json.dumps(samples, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="字段不合规"):
        load_samples(invalid_path)


def test_load_samples_rejects_duplicate_ids(tmp_path: Path) -> None:
    samples = json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))
    samples[1]["id"] = samples[0]["id"]
    invalid_path = tmp_path / "duplicate-ids.json"
    invalid_path.write_text(
        json.dumps(samples, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="编号必须唯一"):
        load_samples(invalid_path)


def test_load_samples_requires_attack_probe_consistency(
    tmp_path: Path,
) -> None:
    samples = json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))
    samples[0]["success_probe"] = "unsafe_tool_executed"
    invalid_path = tmp_path / "normal-with-attack-probe.json"
    invalid_path.write_text(
        json.dumps(samples, ensure_ascii=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="正常样本不得"):
        load_samples(invalid_path)


def test_run_evaluation_rejects_unknown_mode() -> None:
    samples = load_samples(SAMPLES_PATH)

    with pytest.raises(ValueError, match="模式不合规"):
        run_evaluation(samples, mode="unknown")


def test_save_results_is_traceable_and_omits_sample_payloads(
    tmp_path: Path,
) -> None:
    samples = load_samples(SAMPLES_PATH)
    records = run_evaluation(samples, mode="both")
    output_path = tmp_path / "results.json"

    save_results(
        records,
        samples_path=SAMPLES_PATH,
        output_path=output_path,
        mode="both",
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 3
    assert payload["sample_set"] == "smoke-10.json"
    assert payload["sample_set_sha256"] == hashlib.sha256(
        SAMPLES_PATH.read_bytes()
    ).hexdigest()
    assert payload["mode"] == "both"
    assert len(payload["records"]) == 20
    assert all(set(record) == RESULT_FIELDS for record in payload["records"])
    assert "metrics" in payload

    serialized = output_path.read_text(encoding="utf-8")
    for sample in samples:
        assert sample["input"] not in serialized
        assert sample["user_id"] not in serialized
    assert "alice@example.test" not in serialized


def test_smoke_metrics_are_derived_from_records() -> None:
    samples = load_samples(SAMPLES_PATH)
    records = run_evaluation(samples, mode="both")

    metrics = summarize_records(records)

    assert metrics["attack_success"] == {
        "protected": {"successful": 0, "total": 6, "rate": 0.0},
        "unprotected": {"successful": 3, "total": 6, "rate": 0.5},
    }
    assert metrics["security_classification"] == {
        "true_positive": 6,
        "false_positive": 0,
        "true_negative": 4,
        "false_negative": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "false_positive_rate": 0.0,
    }
    assert metrics["policy_match_rate"] == 1.0
    assert metrics["normal_requests"] == {
        "sample_count": 4,
        "allow_count": 2,
        "expected_confirmation_count": 2,
        "false_positive_count": 0,
        "false_positive_rate": 0.0,
    }
    assert metrics["latency"]["protected"]["count"] == 10
    assert metrics["latency"]["unprotected"]["count"] == 10
    assert set(metrics["categories"]) == {
        "direct_injection",
        "indirect_injection",
        "invalid_path_or_arguments",
        "sensitive_data",
        "unauthorized_tool",
    }


def test_unprotected_only_metrics_leave_protected_metrics_undefined() -> None:
    samples = load_samples(SAMPLES_PATH)
    records = run_evaluation(samples, mode="unprotected")

    metrics = summarize_records(records)

    assert metrics["security_classification"] is None
    assert metrics["policy_match_rate"] is None
    assert metrics["normal_requests"] is None
    assert set(metrics["attack_success"]) == {"unprotected"}
    assert set(metrics["latency"]) == {"unprotected"}


def test_latency_quantiles_use_linear_interpolation() -> None:
    sample = load_samples(SAMPLES_PATH)[0]
    base_record = run_evaluation([sample], mode="protected")[0]
    records = [
        replace(
            base_record,
            sample_id=f"latency-{index}",
            latency_ms=latency,
        )
        for index, latency in enumerate((1.0, 2.0, 3.0, 4.0), start=1)
    ]

    latency = summarize_records(records)["latency"]["protected"]

    assert latency == {
        "count": 4,
        "p50_ms": 2.5,
        "p95_ms": 3.85,
    }


def test_save_results_refuses_to_overwrite_samples() -> None:
    with pytest.raises(ValueError, match="不能覆盖"):
        save_results(
            [],
            samples_path=SAMPLES_PATH,
            output_path=SAMPLES_PATH,
            mode="both",
        )


def test_cli_writes_selected_mode_results(tmp_path: Path) -> None:
    output_path = tmp_path / "protected.json"

    exit_code = main([
        "--samples",
        str(SAMPLES_PATH),
        "--output",
        str(output_path),
        "--mode",
        "protected",
    ])

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["mode"] == "protected"
    assert len(payload["records"]) == 10
    assert {record["mode"] for record in payload["records"]} == {
        "protected",
    }
