"""Native JSON artifacts with contract and integrity binding; never pickle."""

import hashlib
from pathlib import Path

import xgboost as xgb

from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.classifier import NetworkAttackClassifier
from soc_agent.security_ai.network.training import TrainingMetadata, TrainingResult


class ArtifactManifest(Snapshot):
    format_version: str = "1"
    model_sha256: str
    metadata_sha256: str


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def save_artifact(result: TrainingResult, output_dir: Path) -> Path:
    """Create a new version directory; existing artifacts are never overwritten."""
    metadata = TrainingMetadata.model_validate(result.metadata.model_dump())
    if result.classifier.contract != metadata.contract:
        raise ValueError("Classifier and training metadata contracts differ")
    data = metadata.model_dump_json().encode()
    booster = result.classifier._booster
    if booster.attr("training_metadata_digest") != _sha(data):
        raise ValueError("Training metadata differs from fitted model")
    model = bytes(booster.save_raw(raw_format="json"))
    manifest = ArtifactManifest(model_sha256=_sha(model), metadata_sha256=_sha(data))
    target = output_dir / metadata.contract.model_name / metadata.contract.model_version
    target.mkdir(parents=True, exist_ok=False)
    (target / "model.json").write_bytes(model)
    (target / "metadata.json").write_bytes(data)
    # Manifest last: incomplete writes are not loadable artifacts.
    (target / "manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")
    return target


def load_artifact(path: Path, *, expected_manifest_digest: str | None = None) -> TrainingResult:
    try:
        manifest_bytes = (path / "manifest.json").read_bytes()
        if (
            expected_manifest_digest is not None
            and _sha(manifest_bytes) != expected_manifest_digest
        ):
            raise ValueError("Manifest differs from trusted digest")
        manifest = ArtifactManifest.model_validate_json(manifest_bytes)
        if manifest.format_version != "1":
            raise ValueError("Unsupported artifact format")
        data = (path / "metadata.json").read_bytes()
        model = (path / "model.json").read_bytes()
        if _sha(data) != manifest.metadata_sha256 or _sha(model) != manifest.model_sha256:
            raise ValueError("Artifact digest mismatch")
        metadata = TrainingMetadata.model_validate_json(data)
        booster = xgb.Booster(params={"nthread": 1, "device": "cpu"})
        booster.load_model(bytearray(model))
        if booster.attr("training_metadata_digest") != _sha(metadata.model_dump_json().encode()):
            raise ValueError("Model training metadata binding differs")
        classifier = NetworkAttackClassifier(booster=booster, contract=metadata.contract)
        return TrainingResult(classifier=classifier, metadata=metadata)
    except (OSError, ValueError, TypeError, xgb.core.XGBoostError):
        raise ValueError("Invalid, incompatible, or incomplete network model artifact") from None
