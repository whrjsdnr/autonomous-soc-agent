"""Versioned, advisory comparison of synthetic classifier diagnostics, never a loader."""

import math

import numpy as np

from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.evaluation.experiments import SelectionReport
from soc_agent.security_ai.network.training import TrainingConfig

CONTRACT = "synthetic-classifier-equivalence:v1"


def _files(item):
    return {f["path"]: f["sha256_bytes"] for f in item["files"]}


def _split(item):
    return [
        {k: p[k] for k in ("role", "source_indices", "split_seed", "split_strategy")}
        for p in item["development_trace"]
    ]


def _finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Nonfinite diagnostic value")
    if isinstance(value, dict):
        for item in value.values():
            _finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _finite(item)


def _probabilities(trace):
    values = np.asarray(
        [[float.fromhex(v) for v in row] for row in trace["synthetic_probability_hex"]],
        dtype=np.float64,
    )
    if (
        values.ndim != 2
        or not values.size
        or values.shape[1] != len(trace["classes"])
        or not np.isfinite(values).all()
        or ((values < 0) | (values > 1)).any()
        or not np.array_equal(values, values.astype(np.float32).astype(np.float64))
    ):
        raise ValueError("Invalid float32 probabilities")
    if not np.allclose(values.sum(axis=1), 1, rtol=0, atol=values.shape[1] * 2**-24):
        raise ValueError("Invalid probability normalization")
    return values


def _ranking(report):
    scores = [c.validation.classification.macro_f1 for c in report.candidates]
    return [(a > b) - (a < b) for i, a in enumerate(scores) for b in scores[i + 1 :]]


def compare_classifier(left, right):
    """Fail closed on absent evidence; tolerance never accepts artifact differences.

    Only training Brier may differ, bounded by observed probability changes and
    the squared-error identity for labels in [0,1]. Maximum probability distance
    is one float32 ULP, the envelope observed in this synthetic cross-host study.
    All operating points, validation metrics, ranks and policy fields stay exact.
    """
    result = {"contract": CONTRACT, "advisory_only": True, "status": "FAIL"}
    try:
        _finite(left)
        _finite(right)
        a = SelectionReport.model_validate(left["selection_report"])
        b = SelectionReport.model_validate(right["selection_report"])
        for item, report in ((left, a), (right, b)):
            if report.model_dump(mode="json") != item["selection_report"]:
                raise ValueError("Incomplete or noncanonical report")
            if digest(report.model_dump(mode="json")) != item["actual_freeze_digest"]:
                raise ValueError("Selection payload integrity mismatch")
            if item["pinned_package_validation"] != "PASS":
                raise ValueError("Package not verified")
        for key in ("manifest_pin", "package_selection_digest"):
            if left[key] != right[key]:
                raise ValueError("Pinned artifact identity differs")
        if len(_files(left)) != 3 or _files(left) != _files(right):
            raise ValueError("Exact artifact bytes differ")
        result["exact_artifact_integrity"] = "MATCH"
        result["exact_selection_digest"] = (
            left["actual_freeze_digest"] == right["actual_freeze_digest"]
        )
        result["training_provenance_exact"] = a.audits == b.audits
        for item in (left, right):
            if not item["development_trace"]:
                raise ValueError("Missing split evidence")
            for partition in item["development_trace"]:
                for key in ("role", "source_indices", "split_seed", "split_strategy"):
                    if key not in partition:
                        raise ValueError("Missing split evidence")
        if _split(left) != _split(right):
            raise ValueError("Split differs")
        if _ranking(a) != _ranking(b):
            raise ValueError("Candidate ranking or tie differs")
        payload_a, payload_b = a.model_dump(mode="json"), b.model_dump(mode="json")
        for payload in (payload_a, payload_b):
            for audit in payload["audits"]:
                audit.pop("digest")
        traces_a, traces_b = left["classifier_trace"], right["classifier_trace"]
        if len(traces_a) != len(a.candidates) or len(traces_b) != len(b.candidates):
            raise ValueError("Missing candidate trace")
        measurements = []
        for i, (x, y) in enumerate(zip(traces_a, traces_b, strict=True)):
            if any(
                trace.get("evaluation_probability_transform", "native") != "native"
                for trace in (x, y)
            ):
                raise ValueError("v1 comparison supports native probabilities only")
            if (
                x["candidate_id"] != a.candidates[i].candidate_id
                or y["candidate_id"] != b.candidates[i].candidate_id
            ):
                raise ValueError("Candidate trace binding differs")
            for key in (
                "configuration_digest",
                "training_matrix",
                "classes",
                "labels_digest",
                "class_predictions",
                "margin_rows",
            ):
                if not x[key] or x[key] != y[key]:
                    raise ValueError("Training inputs or decisions differ")
            if not x["tree_operational_digests"] or len(x["tree_operational_digests"]) != len(
                y["tree_operational_digests"]
            ):
                raise ValueError("Missing aligned tree evidence")
            for tx, ty in zip(
                x["tree_operational_digests"], y["tree_operational_digests"], strict=True
            ):
                if tx["internal_thresholds"] != ty["internal_thresholds"]:
                    raise ValueError("Learned split threshold differs")
            fields_x, fields_y = x["tree_field_digests"], y["tree_field_digests"]
            if len(fields_x) != len(x["tree_operational_digests"]) or len(fields_x) != len(
                fields_y
            ):
                raise ValueError("Missing topology evidence")
            for tx, ty in zip(fields_x, fields_y, strict=True):
                for field in ("left_children", "right_children", "split_indices", "default_left"):
                    if field not in tx or field not in ty:
                        raise ValueError("Missing topology evidence")
                numeric = {"base_weights", "sum_hessian", "loss_changes", "split_conditions"}
                if {k: v for k, v in tx.items() if k not in numeric} != {
                    k: v for k, v in ty.items() if k not in numeric
                }:
                    raise ValueError("Tree topology differs")
            if x["repeat_inference_exact"] is not True or y["repeat_inference_exact"] is not True:
                raise ValueError("Inference is not repeatable")
            for trace, candidate in ((x, a.candidates[i]), (y, b.candidates[i])):
                config = TrainingConfig.model_validate_json(candidate.configuration)
                if (
                    trace["configuration_digest"] != digest(config.model_dump(mode="json"))
                    or trace["brier_numpy"] != candidate.training_metrics.brier_score
                    or trace["classes"] != list(candidate.training_metrics.classes)
                    or trace["training_matrix"]["dtype"] != "float32"
                    or len(trace["training_matrix"]["rows"]) != candidate.training_rows
                ):
                    raise ValueError("Trace/report binding differs")
            p, q = _probabilities(x), _probabilities(y)
            if p.shape != q.shape or p.shape[0] != a.candidates[i].training_rows:
                raise ValueError("Probability shape differs")
            ulps = np.abs(
                p.astype(np.float32).view(np.uint32).astype(np.int64)
                - q.astype(np.float32).view(np.uint32).astype(np.int64)
            )
            if ulps.max() > 1:
                raise ValueError("Probability envelope exceeded")
            # Class decisions must stay exact, including tied maxima.
            if not np.array_equal(
                p == p.max(axis=1, keepdims=True), q == q.max(axis=1, keepdims=True)
            ):
                raise ValueError("Class boundary changed")
            delta = np.abs(p - q)
            bound = math.fsum(float(v) for v in (2 * delta + delta**2).flat) / p.shape[0]
            ma, mb = (
                payload_a["candidates"][i]["training_metrics"],
                payload_b["candidates"][i]["training_metrics"],
            )
            va, vb = ma.pop("brier_score"), mb.pop("brier_score")
            # No allowance at all when the probabilities are identical.
            allowance = bound + (2 * math.ulp(max(va, vb)) if bound else 0)
            if abs(va - vb) > allowance:
                raise ValueError("Brier difference not supported by probabilities")
            measurements.append(
                {
                    "candidate": x["candidate_id"],
                    "max_float32_ulps": int(ulps.max()),
                    "brier_difference": abs(va - vb),
                    "brier_bound": allowance,
                }
            )
        if payload_a != payload_b:
            raise ValueError("Exact selection or operational policy differs")
        result.update(
            status="EQUIVALENT",
            measurements=measurements,
            numerical_equivalence="EQUIVALENT",
            selection_equivalence="EQUIVALENT",
        )
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        result["reason"] = (
            str(error) if isinstance(error, ValueError) else "Missing/invalid evidence"
        )
    return result
