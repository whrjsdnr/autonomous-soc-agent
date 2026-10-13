"""Explicit offline native inference; no runtime, persistence or action capability."""

import importlib.metadata
import platform
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from soc_agent.review.models import StoredIncident
from soc_agent.security_ai.external.adapters import ExternalEvidenceAdapter
from soc_agent.security_ai.external.models import (
    ExternalModelResult,
    InferenceProvenance,
    Snapshot,
    SourceFeatureObservation,
    Text,
    TrustedExternalModelBinding,
    content_digest_payload,
)
from soc_agent.security_ai.external.validation import (
    ValidationFailure,
    feature_input_digest,
    strict_json,
    validate_setup,
)


class InferenceUnavailable(ValueError):
    """Sanitized failure, never a fallback prediction."""


class ModelRun(Snapshot):
    binding: TrustedExternalModelBinding
    required: bool
    status: Literal["AVAILABLE", "UNAVAILABLE"]
    code: Text
    result: ExternalModelResult | None = None


def _inventory(root: Path, binding: TrustedExternalModelBinding) -> tuple[tuple[int, ...], ...]:
    """Reject links/reparse points; detect replacement around loading/inference.

    The caller must control this read-only artifact root. This is not an ACL
    provisioning API, nor proof against a malicious writer racing path-based loaders.
    """
    paths = {root, *root.parents}
    for item in binding.artifact_identity.files:
        path = root / item.path
        paths.add(path)
        paths.update(p for p in path.parents if p.is_relative_to(root))
    entries = []
    for path in sorted(paths):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InferenceUnavailable("UNSAFE_ARTIFACT_PATH")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise InferenceUnavailable("UNSAFE_ARTIFACT_PATH")
        entries.append(
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            if stat.S_ISREG(info.st_mode)
            else (info.st_dev, info.st_ino)
        )
    return tuple(entries)


def _environment(binding: TrustedExternalModelBinding) -> str:
    backend = {
        "detection_quality": ("lightgbm",),
        "edge": ("torch", "scikit-learn", "joblib"),
        "litert": ("ai-edge-litert", "scikit-learn", "joblib", "pandas"),
    }[binding.profile]
    return content_digest_payload(
        {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "versions": {
                name: importlib.metadata.version(name) for name in ("numpy", "pydantic", *backend)
            },
        }
    )


def infer(
    root: Path,
    binding: TrustedExternalModelBinding,
    observation: SourceFeatureObservation,
    *,
    required: bool = True,
    incident: StoredIncident | None = None,
    history: tuple[ExternalModelResult, ...] = (),
) -> ModelRun:
    """Verify installed bundle before official lazy loading; validate again after inference.

    Required failures raise a sanitized exception; optional failures return unavailable
    data only. No prediction is manufactured. Native/Reference logic is not replaced.
    """
    from dns_security_ai.errors import DNSSecurityAIError
    from network_security_ai.errors import SecurityAIError
    from security_ai import to_envelope
    from security_ai.artifacts import ArtifactDistributionError, verify_install

    try:
        binding = validate_setup(binding)
        observation = SourceFeatureObservation.model_validate(observation)
        feature_digest = feature_input_digest(observation, binding)
        environment = _environment(binding)
        root = Path(root).absolute()
        before = _inventory(root, binding)
        verify_install(root, model=binding.binding_id)
        features = strict_json(observation.feature_payload)
        if binding.profile == "litert":
            from dns_security_ai import DNSConfig, DNSPredictor
            from dns_security_ai.evidence import prediction_to_evidence

            predictor = DNSPredictor(DNSConfig(artifact_root=root / "dns", runtime="litert"))
            prediction = predictor.predict(features)
            receipt = prediction_to_evidence(
                prediction, observation_ref=observation.source_observation_id
            )
        else:
            from network_security_ai import NetworkSecurityAIConfig, create_network_security_ai
            from network_security_ai.evidence import prediction_to_evidence

            predictor = create_network_security_ai(
                NetworkSecurityAIConfig(enabled=True, profile=binding.profile, artifact_root=root)
            )
            if predictor is None:
                raise InferenceUnavailable("MODEL_NOT_CONFIGURED")
            prediction = predictor.predict(features)
            receipt = prediction_to_evidence(
                prediction, flow_reference=observation.source_observation_id
            )
        envelope = to_envelope(receipt)
        verify_install(root, model=binding.binding_id)
        if before != _inventory(root, binding):
            raise InferenceUnavailable("ARTIFACT_PATH_CHANGED")
        from soc_agent.review.identity import content_digest

        provenance = InferenceProvenance(
            inference_origin="LOCAL_MANAGED_INFERENCE",
            binding_digest=binding.binding_digest,
            observation_digest=content_digest(observation),
            feature_input_digest=feature_digest,
            artifact_identity=binding.artifact_identity,
            execution_environment_digest=environment,
        )
        outcome = ExternalEvidenceAdapter().adapt(
            envelope,
            binding=binding,
            observation=observation,
            provenance=provenance,
            received_at=datetime.now(UTC),
            incident=incident,
            history=history,
        )
        if outcome.result is None:
            raise InferenceUnavailable(outcome.validation.code)
        return ModelRun(
            binding=binding, required=required, status="AVAILABLE", code="OK", result=outcome.result
        )
    except ValidationFailure as error:
        code = str(error)
    except InferenceUnavailable as error:
        code = str(error)
    except importlib.metadata.PackageNotFoundError:
        code = "RUNTIME_BACKEND_UNAVAILABLE"
    except (ImportError, OSError, ArtifactDistributionError, DNSSecurityAIError, SecurityAIError):
        code = "ARTIFACT_OR_BACKEND_UNAVAILABLE"
    except (ValidationError, ValueError, TypeError):
        code = "INVALID_INFERENCE_CONTRACT"
    if required:
        raise InferenceUnavailable(code) from None
    return ModelRun(binding=binding, required=False, status="UNAVAILABLE", code=code)
