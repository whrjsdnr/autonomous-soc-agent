"""Typed synthetic adapter payloads for isolated fusion contract tests."""

import json
from pathlib import Path

from soc_agent.security_ai.authentication.anomaly import AuthenticationInferenceProfile
from soc_agent.security_ai.enums import SecurityAITaskType
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.security_ai.evaluation.experiments import SelectionReport
from soc_agent.security_ai.fusion import FusionInput, FusionModelBinding
from soc_agent.security_ai.models import SecurityAIResult
from soc_agent.security_ai.network.anomaly import AnomalyInferenceProfile
from soc_agent.security_ai.network.classifier import ModelContract
from soc_agent.security_ai.packaging.package import FileHash, make_manifest
from soc_agent.security_ai.signals import create_ai_signal


def model_bindings():
    report = json.loads(
        (Path(__file__).parents[1] / "docs/evaluation/synthetic-phase3-5.json").read_text()
    )
    bindings = {}
    for kind, data in report["experiments"].items():
        selection = SelectionReport.model_validate(data["selection"])
        bound = json.loads(selection.selected_binding)
        profile_type = {
            "network_classifier": ModelContract,
            "network_anomaly": AnomalyInferenceProfile,
            "authentication_anomaly": AuthenticationInferenceProfile,
        }[kind]
        profile = profile_type.model_validate(
            bound["contract"] if kind == "network_classifier" else bound["profile"]
        )
        hashes = tuple(
            FileHash(path=name, sha256="a" * 64)
            for name in ("metadata.json", "model/model.json", "preprocessing/profile.json")
        )
        manifest = make_manifest(selection, profile, kind, hashes)
        bindings[kind] = FusionModelBinding(
            manifest=manifest,
            manifest_digest=digest(manifest.model_dump(mode="json")),
            profile=profile,
        )
    return bindings


def fusion_input(binding, features, state, *, positive=True, label="BruteForce"):
    manifest = binding.manifest
    explanation = {
        "feature_fingerprint": features.input_fingerprint,
        "feature_provenance": features.provenance.model_dump(mode="json"),
        "package_manifest_digest": binding.manifest_digest,
        "selection_digest": manifest.selection_digest,
        "synthetic_selection_not_operational_approval": True,
    }
    if manifest.model_kind == "network_classifier":
        prediction = label if positive else "BENIGN"
        scores = {
            "class_probabilities": {
                name: 0.85 if name == prediction else 0.05 for name in binding.profile.classes
            }
        }
        confidence = 0.85
        task = SecurityAITaskType.CLASSIFICATION
        explanation |= {"operating_point": "argmax", "temperature": manifest.temperature}
    else:
        raw = 0.9 if positive else 0.1
        reference = binding.profile.normalization
        norm = reference.normalize(raw)
        point = manifest.operating_point
        decision = point.decisions((raw,), (norm,))[0]
        prediction = "anomaly" if decision else "normal"
        scores = {
            "raw_anomaly_measure": raw,
            "normalized_anomaly_score": norm,
            "normalized_threshold": reference.threshold,
            "normalized_decision": norm >= reference.threshold,
            "selected_decision": decision,
        }
        confidence = None
        task = SecurityAITaskType.ANOMALY_DETECTION
        explanation |= {
            "operating_point": point.model_dump(mode="json"),
            "operating_point_identity": digest(
                {
                    "model": manifest.model_id,
                    "version": manifest.model_version,
                    "selection": manifest.selection_digest,
                    "operating_point": point.model_dump(mode="json"),
                }
            ),
            "score_semantics": "anomaly ranking; not attack probability",
        }
    result = SecurityAIResult(
        incident_id=state.incident_id,
        model_name=manifest.model_id,
        model_version=manifest.model_version,
        task_type=task,
        prediction=prediction,
        confidence=confidence,
        scores=scores,
        explanation=explanation,
    )
    return FusionInput(signal=create_ai_signal(result, state=state), features=features)
