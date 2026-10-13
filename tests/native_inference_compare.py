"""Offline diagnostic contracts: numeric identity is separate from model decisions."""

import math
from typing import Annotated, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.security_ai.evaluation.metrics import OperatingPoint

CONTRACT = "soc-native-inference:v2"
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Kind = Literal["network_classifier", "network_anomaly", "authentication_anomaly"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Numbers(Record):
    dtype: Literal["float32", "float64"]
    hex: list[list[str]] = Field(min_length=1, max_length=1000)

    def array(self) -> np.ndarray:
        values = [[float.fromhex(v) for v in row] for row in self.hex]
        if not values[0] or len(values[0]) > 64 or any(len(r) != len(values[0]) for r in values):
            raise ValueError("Invalid numeric shape")
        if any(not math.isfinite(v) for r in values for v in r):
            raise ValueError("Nonfinite numeric value")
        with np.errstate(over="ignore"):
            array = np.asarray(values, dtype=self.dtype)
        if not np.isfinite(array).all() or any(
            float(v).hex() != original.hex()
            for v, original in zip(array.flat, (v for row in values for v in row), strict=True)
        ):
            raise ValueError("Values do not match declared dtype")
        return array

    @model_validator(mode="after")
    def valid(self):
        self.array()
        return self


class Boundary(Record):
    space: Literal["raw", "normalized"]
    threshold_hex: str
    values_hex: tuple[str, str, str]
    decisions: tuple[bool, bool, bool]


class ModelTrace(Record):
    kind: Kind
    model_id: str
    model_version: str
    framework: str
    serialization: str
    load_status: Literal["PASS"]
    manifest_sha256: Hash
    selection_digest: Hash
    artifact_sha256: Hash
    package_files: dict[str, Hash]
    input_sha256: Hash
    preprocessed_sha256: Hash
    sample_ids: list[str] = Field(min_length=1, max_length=1000)
    classes: list[str]
    numbers: dict[str, Numbers]
    predictions: list[str]
    threshold_decisions: list[bool] | None
    operating_point: OperatingPoint | None
    boundary: Boundary | None
    normalized_threshold: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)] | None
    normalized_decisions: list[bool] | None
    normalized_boundary: Boundary | None
    authoritative_security_judgment: Literal["INCONCLUSIVE"] = "INCONCLUSIVE"

    @model_validator(mode="after")
    def aligned(self):
        if len(set(self.sample_ids)) != len(self.sample_ids) or len(self.predictions) != len(
            self.sample_ids
        ):
            raise ValueError("Unaligned model decisions")
        if set(self.package_files) != {
            "manifest.json",
            "metadata.json",
            "model/model.json",
            "preprocessing/profile.json",
        }:
            raise ValueError("Missing package inventory")
        if (
            self.package_files["manifest.json"] != self.manifest_sha256
            or self.package_files["model/model.json"] != self.artifact_sha256
        ):
            raise ValueError("Artifact binding differs")
        required = (
            {
                "raw_margin",
                "native_probability",
                "package_probability",
                "reference_probability",
                "confidence",
            }
            if self.kind == "network_classifier"
            else {
                "raw_score",
                "raw_anomaly_measure",
                "normalized_anomaly_score",
                "raw_decision_score",
            }
        )
        if set(self.numbers) != required:
            raise ValueError("Missing model numeric fields")
        for name, values in self.numbers.items():
            array = values.array()
            if len(array) != len(self.sample_ids):
                raise ValueError("Unaligned samples")
            if "probability" in name or name == "confidence":
                if ((array < 0) | (array > 1)).any():
                    raise ValueError("Probability outside [0,1]")
        if self.kind == "network_classifier":
            if any(
                value is not None
                for value in (
                    self.normalized_threshold,
                    self.normalized_decisions,
                    self.normalized_boundary,
                )
            ):
                raise ValueError("Invented classifier normalized threshold")
            if (
                self.operating_point is not None
                or self.boundary is not None
                or self.threshold_decisions is not None
            ):
                raise ValueError("Invented classifier threshold")
            if len(set(self.classes)) != len(self.classes) or len(self.classes) < 2:
                raise ValueError("Invalid class mapping")
            for name in (
                "raw_margin",
                "native_probability",
                "package_probability",
                "reference_probability",
            ):
                array = self.numbers[name].array()
                if array.shape[1] != len(self.classes):
                    raise ValueError("Class mapping shape differs")
                if "probability" in name and not np.allclose(
                    array.sum(axis=1), 1, rtol=0, atol=1e-5
                ):
                    raise ValueError("Invalid probabilities")
            actual = self.numbers["package_probability"].array()
            if self.numbers["confidence"].array().shape[1] != 1:
                raise ValueError("Confidence must be scalar")
            if self.predictions != [self.classes[i] for i in actual.argmax(axis=1)]:
                raise ValueError("Class decision contradicts probabilities")
            if not np.array_equal(self.numbers["confidence"].array()[:, 0], actual.max(axis=1)):
                raise ValueError("Confidence contradicts probabilities")
        else:
            if self.classes or self.operating_point is None or self.boundary is None:
                raise ValueError("Missing anomaly decision contract")
            if (
                self.normalized_threshold is None
                or self.normalized_decisions is None
                or self.normalized_boundary is None
            ):
                raise ValueError("Missing native normalized threshold contract")
            if any(values.array().shape[1] != 1 for values in self.numbers.values()):
                raise ValueError("Anomaly measurements must be scalar")
            norm_values = self.numbers["normalized_anomaly_score"].array()
            if ((norm_values < 0) | (norm_values > 1)).any():
                raise ValueError("Invalid normalized anomaly score")
            raw = tuple(self.numbers["raw_anomaly_measure"].array()[:, 0])
            norm = tuple(self.numbers["normalized_anomaly_score"].array()[:, 0])
            if self.normalized_decisions != [v >= self.normalized_threshold for v in norm]:
                raise ValueError("Normalized threshold decision contradicts scores")
            normal_point = OperatingPoint(space="normalized", threshold=self.normalized_threshold)
            normal_expected = (
                math.nextafter(self.normalized_threshold, -math.inf),
                self.normalized_threshold,
                math.nextafter(self.normalized_threshold, math.inf),
            )
            if (
                self.normalized_boundary.space != "normalized"
                or float.fromhex(self.normalized_boundary.threshold_hex)
                != self.normalized_threshold
                or tuple(map(float.fromhex, self.normalized_boundary.values_hex)) != normal_expected
                or self.normalized_boundary.decisions
                != normal_point.decisions(normal_expected, normal_expected)
            ):
                raise ValueError("Invalid normalized boundary probe")
            decisions = list(self.operating_point.decisions(raw, norm))
            if self.threshold_decisions != decisions or self.predictions != [
                "anomaly" if v else "normal" for v in decisions
            ]:
                raise ValueError("Threshold decision contradicts scores")
            threshold = self.operating_point.threshold
            expected = (
                math.nextafter(threshold, -math.inf),
                threshold,
                math.nextafter(threshold, math.inf),
            )
            if (
                self.boundary.space != self.operating_point.space
                or float.fromhex(self.boundary.threshold_hex) != threshold
                or tuple(map(float.fromhex, self.boundary.values_hex)) != expected
                or self.boundary.decisions != self.operating_point.decisions(expected, expected)
            ):
                raise ValueError("Invalid boundary probe")
        return self


class Export(Record):
    contract: Literal["soc-native-inference:v2"]
    platform: dict[str, str]
    versions: dict[str, str]
    fixture_sha256: Hash
    evaluation: Literal["native; reference is diagnostic only"]
    models: dict[Kind, ModelTrace]

    @model_validator(mode="after")
    def inventory(self):
        if set(self.models) != {"network_classifier", "network_anomaly", "authentication_anomaly"}:
            raise ValueError("Incomplete model inventory")
        if (
            not {"python", "numpy", "sklearn", "xgboost"} <= self.versions.keys()
            or not {"system", "machine"} <= self.platform.keys()
        ):
            raise ValueError("Missing environment provenance")
        if any(k != v.kind for k, v in self.models.items()):
            raise ValueError("Model kind binding differs")
        return self


def numbers(array: np.ndarray) -> Numbers:
    values = np.asarray(array)
    if values.ndim == 1:
        values = values[:, None]
    return Numbers(dtype=str(values.dtype), hex=[[float(v).hex() for v in row] for row in values])


def _ulp_key(value: np.floating, dtype: str) -> int:
    unsigned = np.asarray(value).view(np.uint32 if dtype == "float32" else np.uint64).item()
    sign = 1 << (31 if dtype == "float32" else 63)
    magnitude = unsigned & (sign - 1)
    return sign - magnitude if unsigned & sign else sign + magnitude


def numeric_difference(left: Numbers, right: Numbers) -> dict:
    if left.dtype != right.dtype:
        raise ValueError("Numeric dtype differs; ULP comparison stopped")
    a, b = left.array(), right.array()
    if a.shape != b.shape:
        raise ValueError("Numeric shape differs")
    absolute, relative, ulps = [], [], {}
    changed_rows, changed_values, relative_undefined = set(), 0, 0
    first = None
    for i, (x, y) in enumerate(zip(a.flat, b.flat, strict=True)):
        difference = abs(float(x) - float(y))
        if not math.isfinite(difference):
            raise ValueError("Numeric difference overflow")
        absolute.append(difference)
        if float(y) == 0:
            relative_undefined += int(difference != 0)
        else:
            ratio = difference / abs(float(y))
            if math.isfinite(ratio):
                relative.append(ratio)
            else:
                relative_undefined += 1
        distance = abs(_ulp_key(x, left.dtype) - _ulp_key(y, right.dtype))
        ulps[str(distance)] = ulps.get(str(distance), 0) + 1
        if float(x).hex() != float(y).hex():
            changed_values += 1
            changed_rows.add(i // a.shape[1])
            if first is None:
                first = {
                    "row": i // a.shape[1],
                    "column": i % a.shape[1],
                    "left_hex": float(x).hex(),
                    "right_hex": float(y).hex(),
                }
    return {
        "dtype": left.dtype,
        "samples": len(a),
        "exact_samples": len(a) - len(changed_rows),
        "different_samples": len(changed_rows),
        "different_values": changed_values,
        "maximum_absolute_error": max(absolute),
        "mean_absolute_error": math.fsum(v / a.size for v in absolute),
        "maximum_relative_error_defined": max(relative, default=0),
        "undefined_relative_error_values": relative_undefined,
        "ulp_distribution": ulps,
        "first_difference": first,
        "exact_status": "PASS" if not changed_values else "FAIL",
    }


def compare(left: dict, right: dict) -> dict:
    result = {"contract": "soc-native-comparison:v2", "status": "FAIL", "models": {}}
    try:
        a, b = Export.model_validate(left), Export.model_validate(right)
        result["cross_platform_execution"] = (
            "PASS" if a.platform["system"] != b.platform["system"] else "INCONCLUSIVE"
        )
        result["environment_versions"] = "PASS" if a.versions == b.versions else "FAIL"
        if a.fixture_sha256 != b.fixture_sha256:
            raise ValueError("Input fixture SHA-256 differs")
        failed = a.versions != b.versions
        for kind, x in a.models.items():
            y = b.models[kind]
            if (
                x.sample_ids != y.sample_ids
                or x.input_sha256 != y.input_sha256
                or x.classes != y.classes
            ):
                raise ValueError("Sample/input/class alignment differs")
            artifact_same = (x.package_files, x.manifest_sha256, x.selection_digest) == (
                y.package_files,
                y.manifest_sha256,
                y.selection_digest,
            )
            preprocessing_same = x.preprocessed_sha256 == y.preprocessed_sha256
            identity_same = (x.model_id, x.model_version, x.framework, x.serialization) == (
                y.model_id,
                y.model_version,
                y.framework,
                y.serialization,
            )
            prediction_changes = sum(
                v != w for v, w in zip(x.predictions, y.predictions, strict=True)
            )
            threshold_changes = (
                sum(
                    v != w
                    for v, w in zip(x.threshold_decisions, y.threshold_decisions, strict=True)
                )
                if x.threshold_decisions is not None and y.threshold_decisions is not None
                else None
            )
            policy_same = x.operating_point == y.operating_point and x.boundary == y.boundary
            policy_same &= (
                x.normalized_threshold == y.normalized_threshold
                and x.normalized_boundary == y.normalized_boundary
            )
            normalized_changes = (
                sum(
                    v != w
                    for v, w in zip(x.normalized_decisions, y.normalized_decisions, strict=True)
                )
                if x.normalized_decisions is not None and y.normalized_decisions is not None
                else None
            )
            measurements = {
                name: numeric_difference(values, y.numbers[name])
                for name, values in x.numbers.items()
            }
            nearest = None
            nearest_normalized = None
            if x.operating_point is not None:
                name = (
                    "raw_anomaly_measure"
                    if x.operating_point.space == "raw"
                    else "normalized_anomaly_score"
                )
                values = x.numbers[name].array()[:, 0]
                index = int(np.argmin(np.abs(values - x.operating_point.threshold)))
                nearest = {
                    "row": index,
                    "sample_id": x.sample_ids[index],
                    "space": x.operating_point.space,
                    "threshold_hex": x.operating_point.threshold.hex(),
                    "left_hex": float(values[index]).hex(),
                    "right_hex": float(y.numbers[name].array()[index, 0]).hex(),
                    "left_distance": abs(float(values[index]) - x.operating_point.threshold),
                }
                norm_values = x.numbers["normalized_anomaly_score"].array()[:, 0]
                norm_index = int(np.argmin(np.abs(norm_values - x.normalized_threshold)))
                nearest_normalized = {
                    "row": norm_index,
                    "sample_id": x.sample_ids[norm_index],
                    "threshold_hex": x.normalized_threshold.hex(),
                    "left_hex": float(norm_values[norm_index]).hex(),
                    "right_hex": float(
                        y.numbers["normalized_anomaly_score"].array()[norm_index, 0]
                    ).hex(),
                    "left_distance": abs(float(norm_values[norm_index]) - x.normalized_threshold),
                }
            first = next(
                (
                    {"field": name, **v["first_difference"]}
                    for name, v in measurements.items()
                    if v["first_difference"] is not None
                ),
                None,
            )
            model_failed = (
                not (artifact_same and preprocessing_same and identity_same and policy_same)
                or prediction_changes != 0
                or threshold_changes not in (0, None)
                or normalized_changes not in (0, None)
            )
            failed |= model_failed
            result["models"][kind] = {
                "status": "FAIL" if model_failed else "PASS",
                "scope": "sampled model decisions; not SOC authority",
                "artifact_identity": "PASS" if artifact_same else "FAIL",
                "preprocessing_identity": "PASS" if preprocessing_same else "FAIL",
                "numeric_exact": "PASS"
                if all(v["exact_status"] == "PASS" for v in measurements.values())
                else "FAIL",
                "prediction_changes": prediction_changes,
                "threshold_changes": threshold_changes,
                "normalized_threshold_changes": normalized_changes,
                "boundary": "NOT_APPLICABLE"
                if x.boundary is None
                else "PASS"
                if policy_same
                else "FAIL",
                "numbers": measurements,
                "nearest_threshold_sample": nearest,
                "nearest_normalized_threshold_sample": nearest_normalized,
                "first_difference": first,
                "authoritative_security_judgment": "INCONCLUSIVE",
            }
        result["sampled_model_decision_comparison"] = "FAIL" if failed else "PASS"
        # No offline model comparison proves severity, final agent decisions or Windows execution.
        result["status"] = "FAIL" if failed else "INCONCLUSIVE"
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        result["error_type"] = type(error).__name__
    return result
