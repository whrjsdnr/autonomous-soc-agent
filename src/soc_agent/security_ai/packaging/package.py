"""Selection-bound packages with native XGBoost and numerical IsolationForest inference."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

import numpy as np
import xgboost as xgb
from pydantic import Field

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.anomaly_common import AnomalyPrediction
from soc_agent.security_ai.authentication.anomaly import (
    AuthenticationInferenceProfile,
)
from soc_agent.security_ai.authentication.anomaly import (
    feature_matrix as auth_matrix,
)
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.evaluation.experiments import FrozenSelection, SelectionReport
from soc_agent.security_ai.evaluation.metrics import OperatingPoint, temperature_scale
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.anomaly import AnomalyInferenceProfile
from soc_agent.security_ai.network.classifier import (
    ClassificationPrediction,
    ClassProbability,
    ModelContract,
    NetworkAttackClassifier,
)
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.packaging.files import FILES, read_package, sha256, strict_json
from soc_agent.security_ai.packaging.forest import NumericForest

Hash = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Kind = Literal["network_classifier", "network_anomaly", "authentication_anomaly"]
Profile = ModelContract | AnomalyInferenceProfile | AuthenticationInferenceProfile


class FileHash(Snapshot):
    path: Literal["metadata.json", "model/model.json", "preprocessing/profile.json"]
    sha256: Hash


class PackageManifest(Snapshot):
    package_format_version: Literal["1"] = "1"
    model_id: str
    model_version: str
    model_kind: Kind
    feature_schema_name: str
    feature_schema_version: str
    extractor_name: str
    extractor_version: str
    ordered_feature_names: tuple[str, ...]
    training_configuration: str
    operating_point: OperatingPoint | None
    temperature: float = Field(gt=0, allow_inf_nan=False)
    selection_digest: Hash
    file_hashes: tuple[FileHash, ...] = Field(min_length=3, max_length=3)


def make_manifest(
    report: SelectionReport, profile: Profile, kind: Kind, hashes: tuple[FileHash, ...]
) -> PackageManifest:
    selected = [c for c in report.candidates if c.selected]
    if len(selected) != 1 or selected[0].candidate_id != report.selected_candidate:
        raise ValueError("Inconsistent selection")
    contract = profile if isinstance(profile, ModelContract) else profile.contract
    candidate = selected[0]
    if (report.model_name, report.model_version) != (contract.model_name, contract.model_version):
        raise ValueError("Selection identity mismatch")
    temperature = report.calibration.temperature if report.calibration else 1.0
    if isinstance(profile, ModelContract):
        if report.calibration is None or candidate.operating_point is not None:
            raise ValueError("Classifier calibration/operating point mismatch")
        from soc_agent.security_ai.network.training import TrainingConfig

        configuration = TrainingConfig.model_validate_json(candidate.configuration)
        binding = canonical_json_object(
            {
                "contract": contract.model_dump(mode="json"),
                "configuration": configuration.model_dump(),
                "temperature": temperature,
                "calibration_digest": report.audits[2].digest if len(report.audits) == 3 else None,
            }
        )
    else:
        if report.calibration is not None or candidate.operating_point is None:
            raise ValueError("Anomaly operating point required; calibration forbidden")
        if candidate.configuration != profile.config.model_dump_json():
            raise ValueError("Forest training configuration differs")
        binding = canonical_json_object(
            {
                "profile": profile.model_dump(mode="json"),
                "operating_point": candidate.operating_point.model_dump(),
            }
        )
    if binding != report.selected_binding:
        raise ValueError("Selection binding differs from preprocessing/contract")
    return PackageManifest(
        model_id=contract.model_name,
        model_version=contract.model_version,
        model_kind=kind,
        feature_schema_name=contract.feature_schema.schema_name,
        feature_schema_version=contract.feature_schema.schema_version,
        extractor_name=contract.extractor_name,
        extractor_version=contract.extractor_version,
        ordered_feature_names=tuple(f.name for f in contract.feature_schema.features),
        training_configuration=candidate.configuration,
        operating_point=candidate.operating_point,
        temperature=temperature,
        selection_digest=digest(report.model_dump(mode="json")),
        file_hashes=hashes,
    )


@dataclass(frozen=True)
class ModelPackage:
    manifest: PackageManifest
    manifest_digest: str
    selection: SelectionReport
    profile: Profile
    model: NetworkAttackClassifier | NumericForest

    def predict(self, features: FeatureSet) -> ClassificationPrediction | AnomalyPrediction:
        features = FeatureSet.model_validate(features.model_dump())
        if isinstance(self.model, NetworkAttackClassifier):
            prediction = self.model.predict(features)
            p = temperature_scale(
                np.asarray([[c.probability for c in prediction.class_probabilities]]),
                self.manifest.temperature,
            )[0]
            probabilities = tuple(
                ClassProbability(label=c.label, probability=float(v))
                for c, v in zip(prediction.class_probabilities, p, strict=True)
            )
            winner = max(probabilities, key=lambda c: c.probability)
            return ClassificationPrediction(
                predicted_class=winner.label,
                confidence=winner.probability,
                class_probabilities=probabilities,
            )
        profile = self.profile
        matrix = (
            auth_matrix((features,))
            if isinstance(profile, AuthenticationInferenceProfile)
            else feature_matrix((features,), profile.contract)
        )
        raw = float(self.model.score_samples(profile.scaler.transform(matrix))[0])
        reference = profile.normalization
        norm = reference.normalize(-raw)
        return AnomalyPrediction(
            raw_score=raw,
            raw_anomaly_measure=-raw,
            raw_decision_score=raw - reference.sklearn_offset,
            anomaly_score=norm,
            threshold=reference.threshold,
            is_anomaly=norm >= reference.threshold,
        )

    def operating_decision(self, prediction: AnomalyPrediction) -> bool:
        point = self.manifest.operating_point
        if point is None:
            raise ValueError("Classifier has no anomaly operating point")
        return point.decisions((prediction.raw_anomaly_measure,), (prediction.anomaly_score,))[0]


def save_package(selection: FrozenSelection, path: Path) -> str:
    """Write a new package; return the manifest digest for trusted out-of-band pinning."""
    selection.__post_init__()
    model = selection.selected_model
    if isinstance(model, NetworkAttackClassifier):
        kind = "network_classifier"
        profile = model.contract
        # Reuse the native JSON mechanism of network.artifacts, without the old
        # TrainingResult envelope (which cannot represent a selected/calibrated bundle).
        model_bytes = bytes(model._booster.save_raw(raw_format="json"))
    else:
        profile = model.profile
        kind = (
            "authentication_anomaly"
            if isinstance(profile, AuthenticationInferenceProfile)
            else "network_anomaly"
        )
        model_bytes = NumericForest.from_fitted(model._model).model_dump_json().encode()
    values = {
        "metadata.json": selection.report.model_dump_json().encode(),
        "preprocessing/profile.json": profile.model_dump_json().encode(),
        "model/model.json": model_bytes,
    }
    hashes = tuple(
        FileHash(path=name, sha256=sha256(value)) for name, value in sorted(values.items())
    )
    manifest = make_manifest(selection.report, profile, kind, hashes)
    values["manifest.json"] = manifest.model_dump_json().encode()
    from soc_agent.security_ai.packaging.files import MAX_FILE_BYTES, MAX_PACKAGE_BYTES

    if (
        any(len(v) > MAX_FILE_BYTES for v in values.values())
        or sum(map(len, values.values())) > MAX_PACKAGE_BYTES
    ):
        raise ValueError("Package exceeds size budget")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Package output must not traverse symbolic links")
    path.mkdir(parents=False, exist_ok=False)
    (path / "model").mkdir()
    (path / "preprocessing").mkdir()
    for name, value in values.items():  # Manifest last; failed writes remain unloadable.
        (path / name).write_bytes(value)
    expected = sha256(values["manifest.json"])
    load_package(path, expected_manifest_digest=expected)
    return expected


def load_package(path: Path, *, expected_manifest_digest: str) -> ModelPackage:
    """No registry access. Caller must supply a trusted manifest SHA-256."""
    values = read_package(path)
    if sha256(values["manifest.json"]) != expected_manifest_digest:
        raise ValueError("Manifest differs from trusted digest")
    manifest = PackageManifest.model_validate(strict_json(values["manifest.json"]))
    entries = {f.path: f.sha256 for f in manifest.file_hashes}
    if len(entries) != len(manifest.file_hashes) or set(entries) != FILES - {"manifest.json"}:
        raise ValueError("Invalid manifest inventory")
    for name, expected in entries.items():
        if sha256(values[name]) != expected:
            raise ValueError("Package file digest mismatch")
    report = SelectionReport.model_validate(strict_json(values["metadata.json"]))
    profile_type = {
        "network_classifier": ModelContract,
        "network_anomaly": AnomalyInferenceProfile,
        "authentication_anomaly": AuthenticationInferenceProfile,
    }[manifest.model_kind]
    profile = profile_type.model_validate(strict_json(values["preprocessing/profile.json"]))
    if make_manifest(report, profile, manifest.model_kind, manifest.file_hashes) != manifest:
        raise ValueError("Manifest and selected model bindings differ")
    model_data = strict_json(values["model/model.json"])
    if isinstance(profile, ModelContract):
        # Inspect native model dimensions before invoking the native parser.
        try:
            learner = model_data["learner"]
            dimensions = learner["learner_model_param"]
            if (
                int(dimensions["num_feature"]) != len(profile.feature_schema.features)
                or int(dimensions["num_class"]) != len(profile.classes)
                or learner["objective"]["name"] != "multi:softprob"
            ):
                raise ValueError("Native model dimensions/objective differ")
            booster = xgb.Booster(params={"nthread": 1, "device": "cpu"})
            booster.load_model(bytearray(values["model/model.json"]))
            config = json.loads(manifest.training_configuration)
            if booster.num_boosted_rounds() != config["n_estimators"]:
                raise ValueError("Native model rounds differ")
            model = NetworkAttackClassifier(booster=booster, contract=profile)
        except (KeyError, TypeError, xgb.core.XGBoostError) as error:
            raise ValueError("Invalid native XGBoost model") from error
    else:
        model = NumericForest.model_validate(model_data)
        if (
            model.n_features != len(profile.scaler.mean)
            or model.max_samples != profile.fitted_max_samples
            or len(model.trees) != profile.config.n_estimators
        ):
            raise ValueError("Forest and preprocessing configuration differ")
    return ModelPackage(manifest, expected_manifest_digest, report, profile, model)
