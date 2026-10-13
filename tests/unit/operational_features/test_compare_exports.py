"""Artificial CSV tables only: no captured traffic, training parity or inference claim."""

import csv
import hashlib
import json
from io import StringIO

import numpy as np
import pytest

from soc_agent.security_ai.operational.compare_exports import (
    ExportRejected,
    compare_exports,
    main,
    official_names,
    parse_export,
)


def export(*, keys=("flow-A",), change=None, reverse=False, extra=False):
    names = official_names()
    columns = tuple(reversed(names)) if reverse else names
    stream = StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(("FlowKey", *columns, *(("Label",) if extra else ())))
    for key in keys:
        values = {n: str(i + 1) for i, n in enumerate(names)}
        if change:
            values.update(change)
        writer.writerow((key, *(values[n] for n in columns), *(("ignored",) if extra else ())))
    return stream.getvalue().encode()


def compare(a, b):
    return compare_exports(a, b, key_columns=("FlowKey",))


def test_exact_values_never_prove_training_parity():
    result = compare(export(), export())
    assert result.numerical_status == "PASS"
    assert result.training_parity_status == "INCONCLUSIVE"
    assert result.inference_status == "NOT_INFERABLE"
    assert result.write_disposition == "WRITE_DENIED"
    assert len(result.row_comparisons[0].features) == 40
    assert all(f.absolute_error == "0" for f in result.row_comparisons[0].features)
    assert not result.mismatched_features


def test_explicit_projection_and_row_order_preserve_model_order():
    ref = export(keys=("a", "b"))
    changed = export(keys=("b", "a"), reverse=True, extra=True)
    result = compare(ref, changed)
    assert result.numerical_status == "PASS"
    assert result.reference_csv_digest != result.candidate_csv_digest
    assert tuple(f.name for f in result.row_comparisons[0].features) == official_names()


def test_mismatch_even_when_float32_rounds_to_same_value():
    name = official_names()[0]
    result = compare(export(), export(change={name: "1.00000001"}))
    assert result.numerical_status == "FAIL"
    assert result.mismatched_features == (name,)
    f = result.row_comparisons[0].features[0]
    assert f.absolute_error == "1E-8" and f.relative_error == "1E-8"
    assert f.float32_equal and not f.numeric_equal
    assert f.candidate_float32_loss


def test_float32_ulp_difference_recorded():
    name = official_names()[0]
    value = str(float(np.nextafter(np.float32(1), np.float32(2))))
    f = compare(export(), export(change={name: value})).row_comparisons[0].features[0]
    assert not f.float32_equal


def test_integer_difference_above_binary64_exact_range_detected():
    name = official_names()[0]
    result = compare(
        export(change={name: "9007199254740992"}),
        export(change={name: "9007199254740993"}),
    )
    assert result.numerical_status == "FAIL"
    assert result.row_comparisons[0].features[0].absolute_error == "1"


@pytest.mark.parametrize(
    "reference,candidate,relative",
    [
        ("0", "1", None),
        ("-2", "-1", "0.5"),
        ("-0", "0", "0"),
    ],
)
def test_zero_and_negative_values(reference, candidate, relative):
    name = official_names()[0]
    f = (
        compare(export(change={name: reference}), export(change={name: candidate}))
        .row_comparisons[0]
        .features[0]
    )
    assert f.relative_error == relative


def test_float32_underflow_is_reported_without_imputation():
    name = official_names()[0]
    f = compare(export(), export(change={name: "1e-100"})).row_comparisons[0].features[0]
    assert f.candidate_float32_loss and not f.float32_equal


def test_missing_extra_flow_keys_fail_even_without_comparable_rows():
    result = compare(export(keys=("a",)), export(keys=("b",)))
    assert result.numerical_status == "FAIL"
    assert result.compared_rows == 0
    assert len(result.missing_key_digests) == len(result.extra_key_digests) == 1
    assert "flow-A" not in result.model_dump_json()


@pytest.mark.parametrize("bad", ["", "NaN", "Inf", "1e100", "1e-99999999", "1_0", " 1", "True"])
def test_invalid_numbers_not_repaired(bad):
    with pytest.raises(ExportRejected):
        parse_export(export(change={official_names()[0]: bad}), key_columns=("FlowKey",))


@pytest.mark.parametrize("keys", [("a", "a"), ("",), (" ",)])
def test_ambiguous_identity_rejected(keys):
    with pytest.raises(ExportRejected):
        parse_export(export(keys=keys), key_columns=("FlowKey",))


def test_duplicate_or_missing_feature_columns_rejected():
    data = export()
    missing = data.replace(official_names()[0].encode(), b"unknown", 1)
    duplicate = data.replace(official_names()[1].encode(), official_names()[0].encode(), 1)
    for bad in (missing, duplicate):
        with pytest.raises(ExportRejected):
            parse_export(bad, key_columns=("FlowKey",))


@pytest.mark.parametrize("bad", [b"", b"\xff", b'a,b\n"unterminated'])
def test_bad_serialization(bad):
    with pytest.raises(ExportRejected):
        parse_export(bad, key_columns=("FlowKey",))


def test_limits_are_bounded(monkeypatch):
    import soc_agent.security_ai.operational.compare_exports as module

    monkeypatch.setattr(module, "MAX_ROWS", 1)
    with pytest.raises(ExportRejected, match="ROW_LIMIT"):
        parse_export(export(keys=("a", "b")), key_columns=("FlowKey",))
    monkeypatch.setattr(module, "MAX_BYTES", 8)
    with pytest.raises(ExportRejected, match="SIZE"):
        parse_export(export(), key_columns=("FlowKey",))


def cli_args(tmp_path, monkeypatch, digest=None):
    import sys

    data = export()
    sha = hashlib.sha256(data).hexdigest()
    ref, candidate, report = (tmp_path / n for n in ("ref.csv", "candidate.csv", "report.json"))
    ref.write_bytes(data)
    candidate.write_bytes(data)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compare",
            "--reference",
            str(ref),
            "--candidate",
            str(candidate),
            "--reference-sha256",
            digest or sha,
            "--candidate-sha256",
            sha,
            "--key",
            "FlowKey",
            "--output",
            str(report),
        ],
    )
    return report


def test_cli_reports_inconclusive_and_never_overwrites(tmp_path, monkeypatch):
    report = cli_args(tmp_path, monkeypatch)
    assert main() == 1
    before = report.read_bytes()
    assert json.loads(before)["training_parity_status"] == "INCONCLUSIVE"
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert report.read_bytes() == before


def test_cli_pinned_input_digest_mismatch(tmp_path, monkeypatch):
    report = cli_args(tmp_path, monkeypatch, "0" * 64)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert not report.exists()


def test_float32_digest_matches_official_contract_matrix():
    from pathlib import Path

    from network_security_ai import NetworkSecurityAIConfig, Top40Contract

    contract = Top40Contract(NetworkSecurityAIConfig(artifact_root=Path(".")))
    names = official_names()
    values = {name: float(i + 1) for i, name in enumerate(names)}
    values[names[0]] = 1.00000001
    matrix = contract.matrix(values)
    expected = hashlib.sha256(matrix.astype("<f4").tobytes()).hexdigest()
    result = compare(export(change={names[0]: "1.00000001"}), export())
    assert result.row_comparisons[0].reference_float32_matrix_digest == expected


def test_signed_zero_bit_difference_not_hidden():
    name = official_names()[0]
    result = compare(export(change={name: "-0"}), export(change={name: "0"}))
    f = result.row_comparisons[0].features[0]
    assert f.numeric_equal and not f.float32_equal
    assert result.numerical_status == "FAIL"


def test_error_reports_do_not_echo_source_values():
    secret = "private-raw-source-text"
    with pytest.raises(ExportRejected) as error:
        parse_export(export(change={official_names()[0]: secret}), key_columns=("FlowKey",))
    assert secret not in str(error.value)
