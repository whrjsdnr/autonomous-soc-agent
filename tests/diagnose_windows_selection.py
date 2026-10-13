"""Read-only release inspection and in-memory development selection diagnostics.

Run: python -m tests.diagnose_windows_selection [--compare-directory <verification copy>]
Only a temporary synthetic CSV is written. No package, report or release artifact is saved.
"""

import argparse
import hashlib
import importlib
import json
import math
import platform
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import xgboost as xgb

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.evaluation.metrics import probability_matrix, probability_metrics
from soc_agent.security_ai.evaluation.reference_probability import (
    REFERENCE_SOFTMAX,
    reference_softmax,
)
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.network.training import TrainingConfig, fit_classifier
from soc_agent.security_ai.packaging import load_package
from tests.packaging_support import development_models
from tests.scenarios.test_security_ai_fusion import PINS

ROOT = Path(__file__).parents[1]
REPORT = "docs/evaluation/synthetic-phase3-5.json"
SOURCES = (
    "tests/packaging_support.py",
    "tests/unit/security_ai/packaging/conftest.py",
    "tests/scenarios/test_security_ai_packaging.py",
    "src/soc_agent/_json.py",
    "src/soc_agent/security_ai/evaluation/data.py",
    "src/soc_agent/security_ai/evaluation/experiments.py",
    "src/soc_agent/security_ai/network/dataset.py",
    "tests/evaluation_support.py",
    "tests/fixtures/synthetic_network_draws_v1.json",
    "src/soc_agent/security_ai/evaluation/reference_probability.py",
    "src/soc_agent/security_ai/splitting.py",
    "src/soc_agent/security_ai/features/extractor.py",
    "src/soc_agent/security_ai/network/training.py",
    "src/soc_agent/security_ai/network/preprocessing.py",
    "src/soc_agent/security_ai/network/classifier.py",
    "src/soc_agent/security_ai/evaluation/metrics.py",
)


def different_fields(left, right, path="", *, limit=32):
    """Return bounded field names, never raw feature values, predictions or credentials."""
    if type(left) is not type(right):
        return [path or "/"]
    if isinstance(left, dict):
        keys = sorted(left.keys() | right.keys())
        result = []
        for key in keys:
            nested = path + "/" + key
            result.extend(
                [nested]
                if key not in left or key not in right
                else different_fields(left[key], right[key], nested, limit=limit)
            )
            if len(result) >= limit:
                break
        return result[:limit]
    if isinstance(left, list):
        if len(left) != len(right):
            return [path + "/length"]
        result = []
        for index, (a, b) in enumerate(zip(left, right, strict=True)):
            result.extend(different_fields(a, b, path + f"/{index}", limit=limit))
            if len(result) >= limit:
                break
        return result[:limit]
    return [] if left == right else [path or "/"]


def file_fingerprint(relative, comparison=None):
    raw = (ROOT / relative).read_bytes()
    result = {
        "path": relative,
        "bytes": len(raw),
        "sha256_bytes": hashlib.sha256(raw).hexdigest(),
        "sha256_lf": hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
    }
    if comparison is not None:
        other = comparison / relative
        result["comparison"] = (
            "missing"
            if not other.is_file()
            else "same_bytes"
            if other.read_bytes() == raw
            else "same_lf_text"
            if other.read_bytes().replace(b"\r\n", b"\n") == raw.replace(b"\r\n", b"\n")
            else "different_bytes"
        )
    return result


def synthetic_draw_trace():
    # Native math probe, deliberately independent from pinned evaluation input.
    normal = np.random.default_rng(3501)
    lognormal = np.random.default_rng(3501)
    return {
        "usage": "native RNG probe only; evaluation inputs use pinned fixture",
        "rng_initial_state": digest(normal.bit_generator.state),
        "bit_generator": type(normal.bit_generator).__name__,
        "dtype": str(normal.standard_normal(0).dtype),
        "seed": 3501,
        "rows": 400,
        "scale": 0.65,
        "normal_draw_hashes": [digest(normal.standard_normal(5).tolist()) for _ in range(400)],
        "lognormal_draw_hashes": [
            digest(lognormal.lognormal(0, 0.65, 5).tolist()) for _ in range(400)
        ],
    }


def tree_field_digests(tree):
    """Separate topology/weights/statistics without emitting synthetic model parameters."""
    return {field: digest(value) for field, value in sorted(tree.items())}


def tree_operational_digests(tree):
    """Separate XGBoost's shared split_conditions array into thresholds and leaves."""
    leaf = [i for i, child in enumerate(tree["left_children"]) if child == -1]
    internal = [i for i, child in enumerate(tree["left_children"]) if child != -1]
    return {
        "internal_thresholds": digest([[i, tree["split_conditions"][i]] for i in internal]),
        "leaf_values": digest([[i, tree["split_conditions"][i]] for i in leaf]),
    }


def classifier_trace(selection):
    """Optional actual refits: separate prediction differences from metric reduction."""
    train = selection.development[0]
    labels = tuple(row.label for row in train.rows)
    result = []
    for candidate in selection.report.candidates:
        config = TrainingConfig.model_validate_json(candidate.configuration)
        model = fit_classifier(
            tuple(row.features for row in train.rows),
            labels,
            config=config,
            model_version=selection.report.model_version,
        )
        predictions = tuple(model.predict(row.features) for row in train.rows)
        values = probability_matrix(predictions, model.contract.classes)
        repeated = tuple(model.predict(row.features) for row in train.rows)
        assert predictions == repeated, "Repeated inference differs within one host"
        matrix = feature_matrix(tuple(row.features for row in train.rows), model.contract)
        raw_rows, margins = [], []
        for row in matrix:
            data = xgb.DMatrix(
                row.reshape(1, -1),
                nthread=1,
                feature_names=[f.name for f in model.contract.feature_schema.features],
            )
            raw_rows.append(model._booster.predict(data)[0])
            margins.append(model._booster.predict(data, output_margin=True)[0])
        raw_values = np.asarray(raw_rows)
        assert np.array_equal(raw_values.astype(np.float64), values)
        booster_json = json.loads(bytes(model._booster.save_raw(raw_format="json")))
        trees = booster_json["learner"]["gradient_booster"]["model"]["trees"]
        margin_array = np.asarray(margins)
        reference_values = reference_softmax(margin_array)
        numpy_values = np.exp(
            margin_array.astype(np.float64) - margin_array.max(axis=1, keepdims=True)
        )
        numpy_values /= numpy_values.sum(axis=1, keepdims=True)
        evaluation_values = (
            reference_values if selection.probability_transform == REFERENCE_SOFTMAX else values
        )
        metrics = probability_metrics(labels, evaluation_values, model.contract.classes)
        assert metrics == candidate.training_metrics, "Refit metrics differ within one host"
        classes = model.contract.classes
        terms = [
            (float(value) - float(classes[index] == label)) ** 2
            for label, row in zip(labels, values, strict=True)
            for index, value in enumerate(row)
        ]
        result.append(
            {
                "candidate_id": candidate.candidate_id,
                "evaluation_probability_transform": selection.probability_transform,
                "reference_probability_hex": [
                    [float(v).hex() for v in row] for row in reference_values
                ],
                "numpy_softmax_hex": [[float(v).hex() for v in row] for row in numpy_values],
                "reference_brier": probability_metrics(
                    labels, reference_values, model.contract.classes
                ).brier_score,
                "native_brier": probability_metrics(
                    labels, values, model.contract.classes
                ).brier_score,
                "configuration_digest": digest(config.model_dump(mode="json")),
                "training_matrix": {
                    "dtype": str(matrix.dtype),
                    "shape": list(matrix.shape),
                    "rows": [digest(row.tolist()) for row in matrix],
                },
                "classes": list(classes),
                "labels_digest": digest(list(labels)),
                "model_json_digest": digest(booster_json),
                "tree_digests": [digest(tree) for tree in trees],
                "tree_field_digests": [tree_field_digests(tree) for tree in trees],
                "tree_operational_digests": [tree_operational_digests(tree) for tree in trees],
                "raw_probability_dtype": str(raw_values.dtype),
                "margin_rows": [digest(row.tolist()) for row in margins],
                "synthetic_margin_hex": [[float(v).hex() for v in row] for row in margins],
                "probability_dtype": str(values.dtype),
                "probability_rows": [digest(row.tolist()) for row in values],
                "synthetic_probability_hex": [[float(v).hex() for v in row] for row in values],
                "repeat_inference_exact": True,
                "brier_formula": "mean(sum((float64_probability - onehot) ** 2, axis=1))",
                "brier_row_terms": [
                    digest(float(value))
                    for value in np.sum(
                        (values - np.eye(len(classes))[[classes.index(label) for label in labels]])
                        ** 2,
                        axis=1,
                    )
                ],
                "class_predictions": digest([p.predicted_class for p in predictions]),
                "brier_numpy": metrics.brier_score,
                "brier_fsum_diagnostic_only": math.fsum(terms) / len(labels),
            }
        )
    return result


def partition_trace(partition, original_rows=None):
    """Synthetic development lineage only; emit hashes, never source payloads."""
    rows = []
    for row in partition.rows:
        sources = [
            source.model_dump(mode="json", exclude={"record_id"})
            for source in row.features.provenance.sources
        ]
        rows.append(
            {
                "identity": digest([row.row_id, row.group_id, row.label, list(row.event_ids)]),
                "features": digest(list(row.features.feature_values)),
                "fingerprint": row.features.input_fingerprint,
                "sources": digest(sources),
                "columns": [digest(value) for value in row.features.feature_values],
            }
        )
    payload = [
        {
            "row": row.row_id,
            "group": row.group_id,
            "label": row.label,
            "fingerprint": row.features.input_fingerprint,
            "events": list(row.event_ids),
            "sources": [
                source.model_dump(mode="json", exclude={"record_id"})
                for source in row.features.provenance.sources
            ],
        }
        for row in partition.rows
    ]
    serialized = canonical_json_object({"value": payload}).encode("utf-8")
    assert hashlib.sha256(serialized).hexdigest() == partition.content_digest
    result = {"role": partition.role, "digest": partition.content_digest, "rows": rows}
    if original_rows is not None:
        indices = {row.row_id: index for index, row in enumerate(original_rows)}
        result["source_indices"] = [indices[row.row_id] for row in partition.rows]
        result["split_seed"] = partition.split_seed
        result["split_strategy"] = partition.split_strategy
        result["canonical_utf8_bytes"] = len(serialized)
    return result


def numeric_difference(actual, historical):
    """Describe exact finite metric difference; no tolerance or validation override."""
    if not all(math.isfinite(value) for value in (actual, historical)):
        raise ValueError("Nonfinite diagnostic metric")
    return {
        "actual": actual,
        "historical": historical,
        "actual_hex": actual.hex(),
        "historical_hex": historical.hex(),
        "absolute_difference": abs(actual - historical),
        "difference_in_historical_ulps": abs(actual - historical) / math.ulp(historical),
    }


def probability_difference(current, previous):
    """Quantify synthetic probability differences only when both hosts retained values."""
    left = current.get("synthetic_probability_hex")
    right = previous.get("synthetic_probability_hex")
    if left is None or right is None:
        return {"status": "UNAVAILABLE; native probability values not retained"}
    a = np.asarray([[float.fromhex(value) for value in row] for row in left])
    b = np.asarray([[float.fromhex(value) for value in row] for row in right])
    if (
        a.shape != b.shape
        or a.ndim != 2
        or not a.size
        or not np.isfinite(a).all()
        or not np.isfinite(b).all()
        or (a < 0).any()
        or (a > 1).any()
        or (b < 0).any()
        or (b > 1).any()
    ):
        raise ValueError("Invalid cross-host probability trace")
    for field in ("classes", "labels_digest"):
        if field in current and field in previous and current[field] != previous[field]:
            raise ValueError("Probability class/label alignment differs")
    differences = np.abs(a - b)
    return {
        "status": "COMPARED",
        "elements": int(a.size),
        "different_values": int(np.count_nonzero(differences)),
        "different_rows": int(np.count_nonzero(np.any(differences != 0, axis=1))),
        "maximum_absolute_difference": float(differences.max()),
        "mean_absolute_difference": float(differences.mean()),
    }


def stage_comparison(name, current, previous):
    if current is None or previous is None:
        return {"stage": name, "status": "UNAVAILABLE"}
    paths = different_fields(current, previous, limit=16)
    return {
        "stage": name,
        "status": "DIFFERENT" if paths else "SAME",
        "first_difference_path": paths[0] if paths else None,
    }


def partition_comparison_view(trace):
    if trace is None:
        return None
    # Compare the established trace contract; report newer optional stages separately.
    return [{key: item[key] for key in ("role", "digest", "rows")} for item in trace]


def compare_results(current, previous):
    """Locate first cross-host lineage difference without exposing raw training data."""
    result = {
        "synthetic_draw_difference_paths": different_fields(
            current.get("synthetic_draw_trace"), previous.get("synthetic_draw_trace"), limit=16
        )
    }
    for kind, model in current["models"].items():
        old = previous["models"][kind]
        stages = []
        if kind.startswith("network"):
            for key in ("rng_initial_state", "normal_draw_hashes", "lognormal_draw_hashes"):
                stages.append(
                    stage_comparison(
                        key,
                        current.get("synthetic_draw_trace", {}).get(key),
                        previous.get("synthetic_draw_trace", {}).get(key),
                    )
                )
        stages.extend(
            [
                stage_comparison(
                    "source_rows", model.get("source_row_trace"), old.get("source_row_trace")
                ),
                stage_comparison(
                    "partition_rows",
                    partition_comparison_view(model.get("development_trace")),
                    partition_comparison_view(old.get("development_trace")),
                ),
            ]
        )
        for key in ("source_indices", "split_seed", "split_strategy"):
            current_partitions = model.get("development_trace", [])
            old_partitions = old.get("development_trace", [])
            stages.append(
                stage_comparison(
                    key,
                    [p[key] for p in current_partitions]
                    if all(key in p for p in current_partitions)
                    else None,
                    [p[key] for p in old_partitions]
                    if all(key in p for p in old_partitions)
                    else None,
                )
            )
        comparisons = []
        prior_candidates = {c["candidate_id"]: c for c in old.get("classifier_trace", [])}
        for candidate in model.get("classifier_trace", []):
            before = prior_candidates.get(candidate["candidate_id"])
            if before is None:
                comparisons.append(
                    {
                        "candidate_id": candidate["candidate_id"],
                        "status": "UNAVAILABLE; prior candidate trace absent",
                    }
                )
                continue
            compared = {
                "candidate_id": candidate["candidate_id"],
                "probabilities": probability_difference(candidate, before),
            }
            for key in (
                "configuration_digest",
                "training_matrix",
                "model_json_digest",
                "tree_field_digests",
                "tree_operational_digests",
                "margin_rows",
                "raw_probability_dtype",
                "probability_dtype",
                "classes",
                "labels_digest",
                "probability_rows",
                "brier_row_terms",
                "brier_numpy",
            ):
                compared[key] = stage_comparison(key, candidate.get(key), before.get(key))
            compared["changed_probability_row_indices"] = [
                index
                for index, (a, b) in enumerate(
                    zip(candidate["probability_rows"], before["probability_rows"], strict=True)
                )
                if a != b
            ]
            comparisons.append(compared)
        first = next((stage for stage in stages if stage["status"] == "DIFFERENT"), None)
        result[kind] = {
            "stages": stages,
            "first_comparable_difference": first,
            "missing_earlier_stages": [
                stage["stage"]
                for stage in stages[: stages.index(first)]
                if stage["status"] == "UNAVAILABLE"
            ]
            if first
            else [],
            "candidate_comparisons": comparisons,
            "same_versions": model["actual_versions"] == old["actual_versions"],
            "same_freeze_digest": model["actual_freeze_digest"] == old["actual_freeze_digest"],
            "classifier_difference_paths": different_fields(
                model.get("classifier_trace"), old.get("classifier_trace"), limit=16
            ),
            "trace_difference_paths": different_fields(
                model["development_trace"], old.get("development_trace"), limit=16
            ),
        }
    return result


def diagnose(comparison=None, *, trace_candidates=False, reference_probabilities=False):
    historical = json.loads((ROOT / REPORT).read_bytes())
    output = {
        "mode": "DIAGNOSTIC; no release artifacts written",
        "synthetic_input_contract": "pinned synthetic-network-lognormal-draws:v1",
        "evaluation_probability_transform": REFERENCE_SOFTMAX
        if reference_probabilities
        else "native",
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "hash_contract": "SHA-256(UTF-8(canonical_json_object({value: report})))",
        "loaded_modules": {
            name: str(Path(importlib.import_module(name).__file__).resolve())
            for name in (
                "tests.packaging_support",
                "soc_agent._json",
                "soc_agent.security_ai.evaluation.experiments",
                "soc_agent.security_ai.packaging.package",
            )
        },
        "files": [file_fingerprint(path, comparison) for path in (REPORT, *SOURCES)],
        "models": {},
        "synthetic_draw_trace": synthetic_draw_trace(),
    }
    with TemporaryDirectory(prefix="soc-selection-diagnostic-") as directory:
        selected = development_models(
            Path(directory),
            probability_transform=REFERENCE_SOFTMAX if reference_probabilities else "native",
        )
        for kind, pin, _ in PINS:
            selection = selected[kind][0]
            saved = historical["experiments"][kind]
            expected = saved["final_test"]["selection_digest"]
            payload = selection.report.model_dump(mode="json")
            actual = selection.freeze_digest
            assert actual == digest(payload)
            assert digest(saved["selection"]) == expected, "Historical report hash mismatch"
            package_path = "tests/fixtures/security_ai_packages/" + kind
            package = load_package(ROOT / package_path, expected_manifest_digest=pin)
            assert package.manifest.selection_digest == expected, "Package/report lineage mismatch"
            model = {
                "selection_report": payload,
                "actual_freeze_digest": actual,
                "historical_selection_digest": expected,
                "same_selection": actual == expected,
                "actual_versions": payload["versions"],
                "source_row_trace": partition_trace(
                    selection.development[0].model_copy(update={"rows": selected[kind][1]})
                )["rows"],
                "development_trace": [
                    partition_trace(p, selected[kind][1]) for p in selection.development
                ],
                "candidate_training_brier": [
                    numeric_difference(
                        c["training_metrics"]["brier_score"], old["training_metrics"]["brier_score"]
                    )
                    for c, old in zip(
                        payload["candidates"], saved["selection"]["candidates"], strict=True
                    )
                    if c["training_metrics"] is not None and "brier_score" in c["training_metrics"]
                ],
                "historical_versions": saved["selection"]["versions"],
                "different_field_paths": different_fields(payload, saved["selection"]),
                "canonical_hash_input_bytes": len(
                    canonical_json_object({"value": payload}).encode("utf-8")
                ),
                "pinned_package_validation": "PASS",
                "manifest_pin": pin,
                "package_selection_digest": package.manifest.selection_digest,
                "files": [
                    file_fingerprint(package_path + "/" + name, comparison)
                    for name in ("manifest.json", "metadata.json", "model/model.json")
                ],
            }
            if trace_candidates and kind == "network_classifier":
                model["classifier_trace"] = classifier_trace(selection)
            output["models"][kind] = model
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare-directory", type=Path)
    parser.add_argument(
        "--trace-candidates",
        action="store_true",
        help="Refit actual classifier candidates in memory for hashed predictions",
    )
    parser.add_argument("--compare-result", type=Path, help="Prior synthetic diagnostic JSON")
    parser.add_argument(
        "--reference-probabilities",
        action="store_true",
        help="Offline decimal-softmax-binary64:v1 evaluation; not legacy release reproduction",
    )
    args = parser.parse_args()
    try:
        output = diagnose(
            args.compare_directory,
            trace_candidates=args.trace_candidates,
            reference_probabilities=args.reference_probabilities,
        )
        if args.compare_result:
            if args.compare_result.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Diagnostic input too large")
            raw = args.compare_result.read_bytes()
            # Windows PowerShell redirects often use UTF-16; JSON payload is ASCII-safe.
            previous = json.loads(
                raw.decode("utf-16")
                if raw.startswith((b"\xff\xfe", b"\xfe\xff"))
                else raw.decode("utf-8-sig")
            )
            output["cross_host_comparison"] = compare_results(output, previous)
            from tests.selection_equivalence import compare_classifier

            output["selection_equivalence_v1"] = compare_classifier(
                output["models"]["network_classifier"],
                previous["models"]["network_classifier"],
            )
    except (OSError, ValueError, AssertionError, KeyError, TypeError) as error:
        print(json.dumps({"diagnostic": "FAILED", "error_type": type(error).__name__}))
        return 1
    # ASCII serialization stays readable on CP949 consoles without replacing any hash input.
    print(json.dumps(output, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
