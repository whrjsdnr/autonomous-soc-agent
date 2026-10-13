"""Offline pinned-artifact copying/inference; no training, registry, provider or executor."""

import argparse
import hashlib
import json
import math
import os
import platform
import stat
import sys
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

import numpy as np
import sklearn
import xgboost as xgb
from pydantic import Field

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.authentication.anomaly import AuthenticationInferenceProfile
from soc_agent.security_ai.authentication.anomaly import feature_matrix as auth_matrix
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.evaluation.metrics import OperatingPoint
from soc_agent.security_ai.evaluation.reference_probability import reference_softmax
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.network.classifier import NetworkAttackClassifier
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.packaging import load_package
from soc_agent.security_ai.packaging.files import read_package, strict_json
from tests.evaluation_support import auth_rows, network_rows
from tests.native_inference_compare import (
    CONTRACT,
    Boundary,
    Export,
    Hash,
    Kind,
    ModelTrace,
    Record,
    compare,
    numbers,
    numeric_difference,
)
from tests.scenarios.test_security_ai_fusion import PINS

ROOT = Path(__file__).parents[1]
MAX_JSON = 16 * 1024 * 1024


class InputRow(Record):
    row_id: str
    features: FeatureSet


class Inputs(Record):
    contract: Literal["soc-portability-inputs:v1"] = "soc-portability-inputs:v1"
    synthetic: Literal[True] = True
    network: list[InputRow] = Field(min_length=1, max_length=400)
    authentication: list[InputRow] = Field(min_length=1, max_length=100)


class Bundle(Record):
    contract: Literal["soc-portability-bundle:v1"] = "soc-portability-bundle:v1"
    inputs_sha256: Hash
    manifest_pins: dict[Kind, Hash]
    origin: dict[str, str]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encoded(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("utf-8")


def new_directory(path: Path) -> None:
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Diagnostic output reparse/symlink path rejected")
    path.mkdir(mode=0o700, parents=False, exist_ok=False)


def write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)


def read_document(path: Path) -> tuple[dict, bytes]:
    if path.suffix.lower() != ".json":
        raise ValueError("Diagnostic input must be JSON")
    for parent in (path, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Diagnostic input reparse/symlink path rejected")
    if os.name == "nt":
        import ctypes as c

        from soc_agent.security_ai.packaging.windows_files import (
            DWORD,
            PTR,
            NativeWin32,
            _information,
            _read_file,
        )

        api = NativeWin32()
        api.kernel.ReadFile.argtypes = [PTR, PTR, DWORD, c.POINTER(DWORD), PTR]
        api.kernel.ReadFile.restype = c.c_int32
        api.kernel.GetFileType.argtypes = [PTR]
        api.kernel.GetFileType.restype = DWORD
        absolute = Path(os.path.abspath(path))
        with ExitStack() as held:
            for parent in reversed(absolute.parents):
                handle = held.enter_context(api.hold(str(parent)))
                _information(api, handle, directory=True)
            # Reuse public-artifact handle checks, bounded reads and identity checks.
            raw = _read_file(api, str(absolute))
    else:
        absolute = Path(os.path.abspath(path))
        with ExitStack() as held:
            directory = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
            held.callback(os.close, directory)
            for part in absolute.parts[1:-1]:
                directory = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                held.callback(os.close, directory)
            fd = os.open(
                absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
            stream = held.enter_context(os.fdopen(fd, "rb"))
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_JSON:
                raise ValueError("Unsupported diagnostic input")
            raw = stream.read(MAX_JSON + 1)
            after = os.fstat(stream.fileno())
            if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or len(raw) > MAX_JSON:
                raise ValueError("Diagnostic input changed or oversized")
    # Old PowerShell redirects used UTF-16; duplicates/nonfinite values remain rejected.
    original = raw
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        raw = raw.decode("utf-16").encode("utf-8")
    data = strict_json(raw.removeprefix(b"\xef\xbb\xbf"))
    if not isinstance(data, dict):
        raise ValueError("Diagnostic JSON object required")
    return data, original


def read_json(path: Path) -> dict:
    return read_document(path)[0]


def environment() -> tuple[dict[str, str], dict[str, str]]:
    return (
        {"system": platform.system(), "machine": platform.machine()},
        {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "sklearn": sklearn.__version__,
            "xgboost": xgb.__version__,
        },
    )


def create_bundle(
    output: Path, source_root: Path | None = None, inputs_source: Path | None = None
) -> str:
    """Copy only existing trusted public packages, never retrain or alter releases."""
    new_directory(output)
    package_root = output / "packages"
    package_root.mkdir()
    pins = {}
    for kind, pin, _ in PINS:
        source = (source_root or ROOT / "tests/fixtures/security_ai_packages") / kind
        load_package(source, expected_manifest_digest=pin)
        raw_files = read_package(source)
        target = package_root / kind
        target.mkdir()
        (target / "model").mkdir()
        (target / "preprocessing").mkdir()
        for name, raw in raw_files.items():
            write_new(target / name, raw)
        copied = read_package(target)
        if copied != raw_files:
            raise ValueError("Package copy bytes differ")
        load_package(target, expected_manifest_digest=pin)
        pins[kind] = pin
    if inputs_source is not None:
        data, raw = read_document(inputs_source)
        Inputs.model_validate(data)
    else:
        with TemporaryDirectory(prefix="soc-portability-inputs-") as temp:
            network, _ = network_rows(Path(temp) / "development.csv")
        inputs = Inputs(
            network=[InputRow(row_id=r.row_id, features=r.features) for r in network],
            authentication=[InputRow(row_id=r.row_id, features=r.features) for r in auth_rows()],
        )
        raw = encoded(inputs.model_dump(mode="json"))
    write_new(output / "inputs.json", raw)
    host, versions = environment()
    bundle = Bundle(inputs_sha256=sha(raw), manifest_pins=pins, origin=host | versions)
    raw_bundle = encoded(bundle.model_dump(mode="json"))
    write_new(output / "bundle.json", raw_bundle)
    return sha(raw_bundle)


def matrix_digest(matrix: np.ndarray) -> str:
    return sha(matrix.astype("<f4").tobytes())


def infer_bundle(bundle_path: Path, expected_bundle_sha256: str) -> dict:
    metadata, raw = read_document(bundle_path / "bundle.json")
    # Canonical export bytes are pinned out of band, not inferred from the file itself.
    if sha(raw) != expected_bundle_sha256:
        raise ValueError("Bundle differs from trusted digest")
    bundle = Bundle.model_validate(metadata)
    trusted = {kind: pin for kind, pin, _ in PINS}
    if bundle.contract != "soc-portability-bundle:v1" or bundle.manifest_pins != trusted:
        raise ValueError("Unapproved package inventory")
    input_data, input_bytes = read_document(bundle_path / "inputs.json")
    if sha(input_bytes) != bundle.inputs_sha256:
        raise ValueError("Input fixture hash mismatch")
    inputs = Inputs.model_validate(input_data)
    if inputs.contract != "soc-portability-inputs:v1" or not inputs.synthetic:
        raise ValueError("Only versioned synthetic inputs supported")
    traces = {}
    for kind, pin in trusted.items():
        package_path = bundle_path / "packages" / kind
        package = load_package(package_path, expected_manifest_digest=pin)
        files = read_package(package_path)
        if sha(files["manifest.json"]) != pin or any(
            sha(files[f.path]) != f.sha256 for f in package.manifest.file_hashes
        ):
            raise ValueError("Package changed between loading and hash capture")
        rows = inputs.authentication if kind == "authentication_anomaly" else inputs.network
        features = tuple(r.features for r in rows)
        outputs = [package.predict(f) for f in features]
        if isinstance(package.model, NetworkAttackClassifier):
            matrix = feature_matrix(features, package.profile)
            margins, probabilities = [], []
            for row in matrix:
                data = xgb.DMatrix(
                    row.reshape(1, -1),
                    feature_names=package.model._booster.feature_names,
                    nthread=1,
                )
                margins.append(package.model._booster.predict(data, output_margin=True)[0])
                probabilities.append(package.model._booster.predict(data)[0])
            raw_margin, native = np.asarray(margins), np.asarray(probabilities)
            numeric = {
                "raw_margin": numbers(raw_margin),
                "native_probability": numbers(native),
                "package_probability": numbers(
                    np.asarray(
                        [[v.probability for v in p.class_probabilities] for p in outputs],
                        dtype=np.float64,
                    )
                ),
                "reference_probability": numbers(reference_softmax(raw_margin)),
                "confidence": numbers(
                    np.asarray([p.confidence for p in outputs], dtype=np.float64)
                ),
            }
            classes = list(package.profile.classes)
            predictions = [p.predicted_class for p in outputs]
            point, decisions, boundary = None, None, None
            norm_threshold, norm_decisions, norm_boundary = None, None, None
            framework, serialization = "XGBoost native Booster", "XGBoost JSON"
        else:
            matrix = (
                auth_matrix(features)
                if isinstance(package.profile, AuthenticationInferenceProfile)
                else feature_matrix(features, package.profile.contract)
            )
            matrix = package.profile.scaler.transform(matrix).astype(np.float32)
            numeric = {
                name: numbers(np.asarray([getattr(p, attr) for p in outputs], dtype=np.float64))
                for name, attr in (
                    ("raw_score", "raw_score"),
                    ("raw_anomaly_measure", "raw_anomaly_measure"),
                    ("normalized_anomaly_score", "anomaly_score"),
                    ("raw_decision_score", "raw_decision_score"),
                )
            }
            point = package.manifest.operating_point
            decisions = [package.operating_decision(p) for p in outputs]
            predictions = ["anomaly" if v else "normal" for v in decisions]
            probes = (
                math.nextafter(point.threshold, -math.inf),
                point.threshold,
                math.nextafter(point.threshold, math.inf),
            )
            boundary = Boundary(
                space=point.space,
                threshold_hex=point.threshold.hex(),
                values_hex=tuple(v.hex() for v in probes),
                decisions=point.decisions(probes, probes),
            )
            norm_threshold = package.profile.normalization.threshold
            norm_decisions = [p.is_anomaly for p in outputs]
            norm_probes = (
                math.nextafter(norm_threshold, -math.inf),
                norm_threshold,
                math.nextafter(norm_threshold, math.inf),
            )
            norm_point = OperatingPoint(space="normalized", threshold=norm_threshold)
            norm_boundary = Boundary(
                space="normalized",
                threshold_hex=norm_threshold.hex(),
                values_hex=tuple(v.hex() for v in norm_probes),
                decisions=norm_point.decisions(norm_probes, norm_probes),
            )
            classes = []
            framework, serialization = (
                "sklearn IsolationForest export; NumericForest inference",
                "isolation_forest_numeric:v1 JSON; no pickle/joblib",
            )
        traces[kind] = ModelTrace(
            kind=kind,
            model_id=package.manifest.model_id,
            model_version=package.manifest.model_version,
            framework=framework,
            serialization=serialization,
            load_status="PASS",
            manifest_sha256=pin,
            selection_digest=package.manifest.selection_digest,
            artifact_sha256=sha(files["model/model.json"]),
            package_files={name: sha(raw) for name, raw in files.items()},
            input_sha256=sha(
                canonical_json_object({"rows": [r.model_dump(mode="json") for r in rows]}).encode(
                    "utf-8"
                )
            ),
            preprocessed_sha256=matrix_digest(matrix),
            sample_ids=[r.row_id for r in rows],
            classes=classes,
            numbers=numeric,
            predictions=predictions,
            operating_point=point,
            threshold_decisions=decisions,
            boundary=boundary,
            normalized_threshold=norm_threshold,
            normalized_decisions=norm_decisions,
            normalized_boundary=norm_boundary,
        )
    host, versions = environment()
    return Export(
        contract=CONTRACT,
        platform=host,
        versions=versions,
        fixture_sha256=bundle.inputs_sha256,
        evaluation="native; reference is diagnostic only",
        models=traces,
    ).model_dump(mode="json")


def training_impact(left: dict, right: dict) -> dict:
    """Read prior actual-fit diagnostics, without claiming same trained artifacts."""
    for key in ("hash_contract", "synthetic_input_contract", "evaluation_probability_transform"):
        if key not in left or key not in right or left[key] != right[key]:
            raise ValueError("Selection diagnostic comparison contract differs")
    result = {"contract": "soc-platform-training-impact:v1", "status": "INCONCLUSIVE", "models": {}}
    for kind in ("network_classifier", "network_anomaly", "authentication_anomaly"):
        a, b = left["models"][kind], right["models"][kind]
        if any(
            digest(model["selection_report"]) != model["actual_freeze_digest"] for model in (a, b)
        ):
            raise ValueError("Selection report digest mismatch")
        entry = {
            "reference_selection_digest_match": a["actual_freeze_digest"]
            == b["actual_freeze_digest"],
            "candidate_inference": "INCONCLUSIVE",
            "security_judgment": "INCONCLUSIVE",
        }
        if kind == "network_classifier":
            candidates = []
            for x, y in zip(a["classifier_trace"], b["classifier_trace"], strict=True):
                if any(
                    x[k] != y[k]
                    for k in (
                        "candidate_id",
                        "configuration_digest",
                        "training_matrix",
                        "labels_digest",
                        "classes",
                    )
                ):
                    raise ValueError("Unaligned native training diagnostics")
                if x["raw_probability_dtype"] != y["raw_probability_dtype"]:
                    raise ValueError("Raw native probability dtype differs")
                raw_dtype = x["raw_probability_dtype"]
                xp, yp = (
                    numbers(
                        np.asarray(
                            [[float.fromhex(v) for v in r] for r in x["synthetic_probability_hex"]],
                            dtype=raw_dtype,
                        )
                    ),
                    numbers(
                        np.asarray(
                            [[float.fromhex(v) for v in r] for r in y["synthetic_probability_hex"]],
                            dtype=raw_dtype,
                        )
                    ),
                )
                # Verify the declared float32 source, do not silently downcast binary64.
                if any(
                    float(v).hex() != original
                    for array, trace in ((xp.array(), x), (yp.array(), y))
                    for v, original in zip(
                        array.flat,
                        (h for r in trace["synthetic_probability_hex"] for h in r),
                        strict=True,
                    )
                ):
                    raise ValueError("Native probability is not representable in source dtype")
                margin_a = numbers(
                    np.asarray(
                        [[float.fromhex(v) for v in r] for r in x["synthetic_margin_hex"]],
                        dtype=np.float32,
                    )
                )
                margin_b = numbers(
                    np.asarray(
                        [[float.fromhex(v) for v in r] for r in y["synthetic_margin_hex"]],
                        dtype=np.float32,
                    )
                )
                prediction_a = [x["classes"][i] for i in xp.array().argmax(axis=1)]
                prediction_b = [y["classes"][i] for i in yp.array().argmax(axis=1)]
                reference_a = numbers(
                    np.asarray(
                        [[float.fromhex(v) for v in r] for r in x["reference_probability_hex"]],
                        dtype=np.float64,
                    )
                )
                reference_b = numbers(
                    np.asarray(
                        [[float.fromhex(v) for v in r] for r in y["reference_probability_hex"]],
                        dtype=np.float64,
                    )
                )
                probability_difference = numeric_difference(xp, yp)
                first = probability_difference["first_difference"]
                first_record = None
                if first is not None:
                    index = first["row"]
                    source_index = a["development_trace"][0]["source_indices"][index]
                    first_record = {
                        "training_row": index,
                        "source_row": source_index,
                        "input_float32_row_hash": x["training_matrix"]["rows"][index],
                        "left_probabilities_hex": x["synthetic_probability_hex"][index],
                        "right_probabilities_hex": y["synthetic_probability_hex"][index],
                        "left_margin_hex": x["synthetic_margin_hex"][index],
                        "right_margin_hex": y["synthetic_margin_hex"][index],
                        "candidate_model_hash_left": x["model_json_digest"],
                        "candidate_model_hash_right": y["model_json_digest"],
                    }
                if (
                    digest(prediction_a) != x["class_predictions"]
                    or digest(prediction_b) != y["class_predictions"]
                ):
                    raise ValueError("Class prediction binding differs")
                candidates.append(
                    {
                        "candidate_id": x["candidate_id"],
                        "selected": x["candidate_id"]
                        == a["selection_report"]["selected_candidate"],
                        "fresh_model_canonical_hash_match": x["model_json_digest"]
                        == y["model_json_digest"],
                        "raw_margin": numeric_difference(margin_a, margin_b),
                        "native_probability": probability_difference,
                        "reference_probability": numeric_difference(reference_a, reference_b),
                        "first_sample": first_record,
                        "confidence": numeric_difference(
                            numbers(xp.array().max(axis=1).astype(np.float64)),
                            numbers(yp.array().max(axis=1).astype(np.float64)),
                        ),
                        "prediction_changes": sum(
                            p != q for p, q in zip(prediction_a, prediction_b, strict=True)
                        ),
                        "threshold": "NOT_APPLICABLE; classifier uses argmax",
                    }
                )
            entry["candidate_inference"] = candidates
        result["models"][kind] = entry
    return result


def markdown(result: dict) -> str:
    lines = [
        "# Offline Native Inference Validation",
        "",
        f"Status: **{result.get('status', 'INCONCLUSIVE')}**",
        "",
        "Scope: sampled model inference. Severity/final SOC authority are not exercised.",
        "",
    ]
    if "models" in result:
        for name, item in result["models"].items():
            if result.get("contract") == CONTRACT:
                item = {
                    k: v
                    for k, v in item.items()
                    if k not in {"numbers", "sample_ids", "predictions", "threshold_decisions"}
                } | {"samples": len(item["sample_ids"])}
            lines += [
                f"## {name}",
                "",
                "```json",
                json.dumps(item, ensure_ascii=True, allow_nan=False, indent=2),
                "```",
                "",
            ]
    else:
        lines += [
            "```json",
            json.dumps(result, ensure_ascii=True, allow_nan=False, indent=2),
            "```",
        ]
    return "\n".join(lines) + "\n"


def save_reports(output: Path, result: dict) -> None:
    new_directory(output)
    write_new(output / "report.json", encoded(result))
    write_new(output / "report.md", markdown(result).encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bundle = commands.add_parser(
        "bundle", help="Copy existing trusted packages and synthetic inputs"
    )
    bundle.add_argument("--output", type=Path, required=True)
    bundle.add_argument(
        "--source-packages",
        type=Path,
        help="Optional source root; existing trusted pins still mandatory",
    )
    bundle.add_argument("--inputs-from", type=Path, help="Reuse exact frozen synthetic input bytes")
    infer = commands.add_parser("infer", help="Load pinned copies; never retrain")
    infer.add_argument("--bundle", type=Path, required=True)
    infer.add_argument("--expected-bundle-sha256", required=True)
    infer.add_argument("--output", type=Path, required=True)
    for name in ("compare", "training-impact"):
        sub = commands.add_parser(name)
        sub.add_argument("--left", type=Path, required=True)
        sub.add_argument("--right", type=Path, required=True)
        sub.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise FileExistsError("Diagnostic output already exists")
        if args.command == "bundle":
            print(
                json.dumps(
                    {
                        "bundle_sha256": create_bundle(
                            args.output, args.source_packages, args.inputs_from
                        )
                    }
                )
            )
        elif args.command == "infer":
            save_reports(args.output, infer_bundle(args.bundle, args.expected_bundle_sha256))
        else:
            result = (compare if args.command == "compare" else training_impact)(
                read_json(args.left), read_json(args.right)
            )
            save_reports(args.output, result)
            if result["status"] == "FAIL":
                return 1
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
