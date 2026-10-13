"""Diagnostic hashing distinguishes release bytes, JSON payloads and field differences."""

import json

from tests import diagnose_windows_selection as diagnostic

from soc_agent.security_ai.evaluation.data import digest


def test_tree_thresholds_and_leaf_values_are_separately_hashed():
    tree = {"left_children": [1, -1, -1], "split_conditions": [2.0, 0.25, -0.25]}
    original = diagnostic.tree_operational_digests(tree)
    tree["split_conditions"][1] += 0.01
    changed = diagnostic.tree_operational_digests(tree)
    assert original["internal_thresholds"] == changed["internal_thresholds"]
    assert original["leaf_values"] != changed["leaf_values"]
    tree["split_conditions"][0] += 0.01
    assert (
        changed["internal_thresholds"]
        != diagnostic.tree_operational_digests(tree)["internal_thresholds"]
    )


def test_json_whitespace_newlines_and_key_order_do_not_change_selection_hash():
    left = '{"versions":[["python","3.12"]],"label":"합성"}\n'.encode()
    right = '{\r\n "label": "합성", "versions": [["python", "3.12"]]\r\n}'.encode()
    assert left != right
    assert digest(json.loads(left)) == digest(json.loads(right))


def test_version_difference_changes_hash_and_is_reported_as_a_field_path():
    old = {"versions": [["python", "3.12.1"]]}
    new = {"versions": [["python", "3.12.2"]]}
    assert digest(old) != digest(new)
    assert diagnostic.different_fields(old, new) == ["/versions/0/1"]


def test_difference_output_is_bounded_and_omits_values():
    old = {"fields": list(range(100))}
    new = {"fields": ["DO-NOT-PRINT"] * 100}
    result = diagnostic.different_fields(old, new, limit=3)
    assert result == ["/fields/0", "/fields/1", "/fields/2"]
    assert "DO-NOT-PRINT" not in str(result)


def test_raw_file_fingerprint_and_lf_comparison_remain_distinct(tmp_path, monkeypatch):
    source, comparison = tmp_path / "source", tmp_path / "comparison"
    source.mkdir()
    comparison.mkdir()
    (source / "fixture.json").write_bytes(b'{"version":1}\n')
    (comparison / "fixture.json").write_bytes(b'{"version":1}\r\n')
    monkeypatch.setattr(diagnostic, "ROOT", source)
    result = diagnostic.file_fingerprint("fixture.json", comparison)
    assert result["comparison"] == "same_lf_text"
    assert result["sha256_bytes"] == result["sha256_lf"]
    (comparison / "fixture.json").write_bytes(b'{"version":2}\n')
    assert (
        diagnostic.file_fingerprint("fixture.json", comparison)["comparison"] == "different_bytes"
    )


def test_finite_metric_diagnostic_retains_single_ulp_difference():
    import math

    value = 0.25
    changed = math.nextafter(value, math.inf)
    result = diagnostic.numeric_difference(changed, value)
    assert result["difference_in_historical_ulps"] == 1
    assert result["actual_hex"] != result["historical_hex"]
    assert digest(changed) != digest(value)


def test_nonfinite_metric_diagnostic_rejected():
    import pytest

    with pytest.raises(ValueError, match="Nonfinite"):
        diagnostic.numeric_difference(float("nan"), 0.25)


def test_partition_trace_separates_identity_feature_and_source_changes(tmp_path):
    from tests.evaluation_support import network_rows

    from soc_agent.security_ai.evaluation import Partition

    rows, _ = network_rows(tmp_path / "synthetic.csv", count=1)
    original = Partition(role="train", rows=rows, dataset_name="fixture", dataset_version="1")
    row = rows[0].model_copy(update={"row_id": "changed-synthetic-row"})
    altered = original.model_copy(update={"rows": (row, *rows[1:])})
    left, right = diagnostic.partition_trace(original), diagnostic.partition_trace(altered)
    assert left["digest"] != right["digest"]
    assert diagnostic.different_fields(left, right) == ["/digest", "/rows/0/identity"]
    assert "changed-synthetic-row" not in json.dumps(right)


def test_repeated_synthetic_rows_audits_and_order_are_exact(tmp_path):
    from tests.evaluation_support import network_rows

    from soc_agent.security_ai.evaluation import Partition

    path = tmp_path / "development.csv"
    first, _ = network_rows(path, count=3)
    second, _ = network_rows(path, count=3)
    a = Partition(role="train", rows=first, dataset_name="fixture", dataset_version="1")
    b = a.model_copy(update={"rows": second})
    assert diagnostic.partition_trace(a) == diagnostic.partition_trace(b)
    reordered = a.model_copy(update={"rows": tuple(reversed(first))})
    assert reordered.content_digest != a.content_digest
    changed, _ = network_rows(path, count=3, seed=3502)
    assert a.model_copy(update={"rows": changed}).content_digest != a.content_digest


def test_same_partition_and_configuration_freeze_exactly_on_repeated_fit(tmp_path):
    from tests.evaluation_support import network_rows

    from soc_agent.security_ai.anomaly_common import AnomalyTrainingConfig
    from soc_agent.security_ai.evaluation import partitions, select_anomaly

    rows, _ = network_rows(tmp_path / "development.csv", count=10)
    train, validation, _, _ = partitions(rows, dataset_name="fixture", dataset_version="1")
    config = (AnomalyTrainingConfig(n_estimators=4),)
    a = select_anomaly(train, validation, domain="network", configs=config)
    b = select_anomaly(train, validation, domain="network", configs=config)
    assert a.freeze_digest == b.freeze_digest
    assert a.report == b.report


def test_synthetic_probability_comparison_reports_exact_counts_and_magnitude():
    a = {"synthetic_probability_hex": [[v.hex() for v in [0.25, 0.75]]], "classes": ["a", "b"]}
    b = {"synthetic_probability_hex": [[v.hex() for v in [0.5, 0.5]]], "classes": ["a", "b"]}
    result = diagnostic.probability_difference(a, b)
    assert result["different_values"] == 2 and result["different_rows"] == 1
    assert result["maximum_absolute_difference"] == result["mean_absolute_difference"] == 0.25
    assert diagnostic.probability_difference(a, a)["different_values"] == 0
    assert diagnostic.probability_difference(a, {})["status"].startswith("UNAVAILABLE")


def test_missing_trace_is_not_reported_as_same_and_first_stage_is_ordered():
    model = {"actual_versions": [], "actual_freeze_digest": "a", "development_trace": []}
    a = {
        "models": {"network_anomaly": model},
        "synthetic_draw_trace": {"normal_draw_hashes": ["same"], "lognormal_draw_hashes": ["a"]},
    }
    b = {
        "models": {"network_anomaly": model},
        "synthetic_draw_trace": {"normal_draw_hashes": ["same"], "lognormal_draw_hashes": ["b"]},
    }
    result = diagnostic.compare_results(a, b)["network_anomaly"]
    assert result["first_comparable_difference"]["stage"] == "lognormal_draw_hashes"
    assert result["missing_earlier_stages"] == ["rng_initial_state"]


def test_source_float_difference_is_preserved_even_when_model_float32_is_equal():
    import math
    from datetime import UTC, datetime

    import numpy as np

    from soc_agent.security_ai.evaluation import EvaluationRow, Partition
    from soc_agent.security_ai.features import SecurityRecord, SourceReference
    from soc_agent.security_ai.network.classifier import ModelContract
    from soc_agent.security_ai.network.preprocessing import feature_matrix
    from soc_agent.security_ai.network.schema import NetworkFeatureExtractor

    def row(duration):
        record = SecurityRecord(
            record_type="network_flow",
            record_schema_version="1.0.0",
            source="synthetic-fixture",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            source_reference=SourceReference(
                source_type="stream", source_name="synthetic-fixture", record_id="row-1"
            ),
            fields={
                "duration_us": duration,
                "fwd_packets": 1,
                "bwd_packets": 2,
                "fwd_bytes": 3,
                "bwd_bytes": 4,
            },
        )
        return EvaluationRow(
            features=NetworkFeatureExtractor().extract(record),
            label="BENIGN",
            group_id="group-1",
            row_id="row-1",
        )

    a, b = row(1.25), row(math.nextafter(1.25, -math.inf))
    x = Partition(role="train", rows=(a,), dataset_name="fixture", dataset_version="1")
    y = x.model_copy(update={"rows": (b,)})
    assert x.content_digest != y.content_digest
    assert a.features.input_fingerprint != b.features.input_fingerprint
    assert np.array_equal(
        feature_matrix((a.features,), ModelContract(classes=("BENIGN", "DoS"))),
        feature_matrix((b.features,), ModelContract(classes=("BENIGN", "DoS"))),
    )


def test_probability_trace_rejects_changed_class_order_and_nonfinite_values():
    import pytest

    a = {"synthetic_probability_hex": [["0x1.0p-1", "0x1.0p-1"]], "classes": ["a", "b"]}
    with pytest.raises(ValueError, match="alignment"):
        diagnostic.probability_difference(a, dict(a, classes=["b", "a"]))
    with pytest.raises(ValueError, match="Invalid"):
        diagnostic.probability_difference(a, dict(a, synthetic_probability_hex=[["nan", "nan"]]))


def test_old_partition_trace_does_not_confuse_new_metadata_with_data_difference():
    old = [{"role": "train", "digest": "same", "rows": []}]
    new = [dict(old[0], source_indices=[], canonical_utf8_bytes=2)]
    assert diagnostic.partition_comparison_view(old) == diagnostic.partition_comparison_view(new)
    changed = [dict(old[0], digest="changed")]
    assert diagnostic.partition_comparison_view(old) != diagnostic.partition_comparison_view(
        changed
    )


def test_tree_hashes_distinguish_statistics_from_operational_fields():
    tree = {
        "left_children": [1, -1, -1],
        "split_conditions": [0.5, 0.1, -0.1],
        "sum_hessian": [10.0, 5.0, 5.0],
    }
    changed = dict(tree, sum_hessian=[10.0, 5.0, 5.0000000001])
    a, b = diagnostic.tree_field_digests(tree), diagnostic.tree_field_digests(changed)
    assert a["left_children"] == b["left_children"]
    assert a["split_conditions"] == b["split_conditions"]
    assert a["sum_hessian"] != b["sum_hessian"]
    assert digest(tree) != digest(changed)
