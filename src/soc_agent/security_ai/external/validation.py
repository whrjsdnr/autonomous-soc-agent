"""Fail-closed contract validation; no predictor, store, executor or provider calls."""

import hashlib
import json
import math
import struct
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from pydantic import BaseModel, JsonValue, TypeAdapter

from soc_agent._json import canonical_json_object
from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import StoredIncident
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import (
    ExternalModelResult,
    ExternalModelResultContent,
    InferenceProvenance,
    SourceFeatureObservation,
    TrustedExternalModelBinding,
    content_digest_payload,
)
from soc_agent.state.evidence import UTCTimestamp

MAX_ENVELOPE_BYTES = 32 * 1024
MAX_SOURCE_BYTES = 64 * 1024
MAX_HISTORY = 128


class ValidationFailure(ValueError):
    """Fixed codes only: never format raw data or external exception messages."""


def fail(code: str) -> NoReturn:
    raise ValidationFailure(code)


def strict_json(raw: bytes | str) -> dict[str, JsonValue]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("INVALID_SERIALIZATION")
            result[key] = value
        return result

    def nonfinite(value):
        fail("NONFINITE_VALUE")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    return TypeAdapter(dict[str, JsonValue]).validate_python(value, strict=True)


def _extras(value: object) -> None:
    if isinstance(value, BaseModel):
        if value.model_extra or set(value.__dict__) - set(type(value).model_fields):
            fail("INVALID_ENVELOPE")
        for child in value.__dict__.values():
            _extras(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            _extras(child)


def envelope_snapshot(value: object) -> tuple[BaseModel, str, str]:
    from dns_security_ai import DNSThreatPrediction
    from dns_security_ai.evidence import DNSSecurityEvidence
    from network_security_ai import NetworkThreatPrediction
    from network_security_ai.evidence import NetworkSecurityEvidence
    from security_ai import EvidenceEnvelope

    if type(value) is EvidenceEnvelope:
        _extras(value)
        raw = canonical_json_object(value.model_dump(mode="json", warnings="error")).encode("utf-8")
    elif type(value) in (str, bytes):
        raw = value.encode("utf-8") if isinstance(value, str) else value
    else:
        fail("INVALID_ENVELOPE_TYPE")
    if len(raw) > MAX_ENVELOPE_BYTES:
        fail("ENVELOPE_TOO_LARGE")
    data = strict_json(raw.decode("utf-8"))
    if set(data) != set(EvidenceEnvelope.model_fields):
        fail("MISSING_OR_EXTRA_ENVELOPE_FIELDS")
    # bool/numeric strings must not exploit the external float coercion boundary.
    payload = data.get("payload")
    prediction = payload.get("prediction") if isinstance(payload, dict) else None
    if not isinstance(prediction, dict):
        fail("INVALID_ENVELOPE")
    network = data["evidence_type"] == "network_threat_prediction"
    receipt_type = NetworkSecurityEvidence if network else DNSSecurityEvidence
    prediction_type = NetworkThreatPrediction if network else DNSThreatPrediction
    if set(payload) != set(receipt_type.model_fields) or set(prediction) != set(
        prediction_type.model_fields
    ):
        fail("MISSING_OR_EXTRA_PAYLOAD_FIELDS")
    if type(prediction.get("class_id")) is not int or any(
        type(payload[name]) is not bool
        for name in ("model_derived", "confidence_calibrated", "attack_confirmed")
    ):
        fail("INVALID_PREDICTION_SEMANTICS")
    scalars = [
        prediction.get(name)
        for name in ("confidence", "threat_score", "probability")
        if name in prediction
    ]
    probabilities = prediction.get("class_probabilities", [])
    if not isinstance(probabilities, list):
        fail("INVALID_SCORE")
    for item in probabilities:
        if not isinstance(item, dict):
            fail("INVALID_SCORE")
        scalars.append(item.get("probability"))
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in scalars):
        fail("INVALID_SCORE")
    envelope = EvidenceEnvelope.model_validate(data)
    text = canonical_json_object(envelope.model_dump(mode="json"))
    return envelope, hashlib.sha256(raw).hexdigest(), text


def validate_setup(binding: TrustedExternalModelBinding) -> TrustedExternalModelBinding:
    if type(binding) is not TrustedExternalModelBinding:
        fail("INVALID_BINDING_TYPE")
    binding = TrustedExternalModelBinding.model_validate(binding.model_dump())
    expected = reviewed_binding(
        binding.profile,
        expected_code_identity=binding.package_code_identity,
        runtime_contract_digest=binding.runtime_contract_digest,
    )
    if binding != expected:
        fail("BINDING_MISMATCH")
    return binding


def feature_input_digest(
    observation: SourceFeatureObservation, binding: TrustedExternalModelBinding
) -> str:
    """External input matrix conversion only; no scaling or prediction execution."""
    from dns_security_ai import DNSFeatureContract
    from dns_security_ai.errors import DNSInputError
    from network_security_ai import NetworkSecurityAIConfig, Top40Contract
    from network_security_ai.errors import SecurityAIInputValidationError

    if len(observation.feature_payload.encode("utf-8")) > MAX_SOURCE_BYTES:
        fail("SOURCE_TOO_LARGE")
    if observation.feature_identity != binding.feature_identity:
        fail("FEATURE_CONTRACT_MISMATCH")
    expected_domain = (
        "dns_stateless_feature_record" if binding.profile == "litert" else "network_flow_top40"
    )
    if observation.observation_type != expected_domain:
        fail("OBSERVATION_TYPE_MISMATCH")
    values = strict_json(observation.feature_payload)
    if any(type(v) not in (float, int) and v is not None for v in values.values()):
        fail("INVALID_FEATURE_VALUE")
    contract = (
        DNSFeatureContract()
        if binding.profile == "litert"
        else Top40Contract(NetworkSecurityAIConfig(artifact_root=Path(".")))
    )
    try:
        matrix = contract.matrix(values)
    except (DNSInputError, SecurityAIInputValidationError):
        fail("INVALID_FEATURE_VALUE")
    bits = [None if math.isnan(float(v)) else struct.pack(">f", float(v)).hex() for v in matrix[0]]
    return content_digest_payload(
        {
            "version": "soc-external-feature-input:v2",
            "dtype": "float32",
            "shape": [1, len(bits)],
            "names": list(binding.feature_identity.ordered_names),
            "schema": binding.feature_identity.schema_version,
            "missing_mask": [v is None for v in bits],
            "bits_be": bits,
        }
    )


def validate_source(observation: SourceFeatureObservation, incident: StoredIncident | None) -> bool:
    """Validate supplied current snapshot; never loads or changes persistent state."""
    association = observation.association
    if association is None or incident is None:
        return False
    if type(incident) is not StoredIncident:
        fail("INVALID_INCIDENT_TYPE")
    incident = StoredIncident.model_validate(incident.model_dump())
    if (
        association.snapshot != incident.anchor
        or association.incident_id != incident.state.incident_id
        or state_fingerprint(incident.state) != incident.anchor.fingerprint
    ):
        fail("INCIDENT_BINDING_MISMATCH")
    if observation.event_time_start is None or observation.entity_reference is None:
        return False
    if len(canonical_json_object(observation.source_payload()).encode("utf-8")) > MAX_SOURCE_BYTES:
        fail("SOURCE_TOO_LARGE")
    by_id = {e.evidence_id: e for e in incident.state.evidence}
    for ref in association.source_evidence_references:
        evidence = by_id.get(ref.evidence_id)
        if evidence is None or content_digest(evidence) != ref.content_digest:
            fail("SOURCE_EVIDENCE_MISMATCH")
        if len(evidence.raw_data.encode("utf-8")) > MAX_SOURCE_BYTES:
            fail("SOURCE_TOO_LARGE")
        source = strict_json(evidence.raw_data)
        if (
            canonical_json_object(source) != canonical_json_object(observation.source_payload())
            or evidence.observed_at != observation.event_time_end
            or evidence.source != observation.source_namespace
        ):
            fail("SOURCE_CONTENT_MISMATCH")
    return True


def validate_prediction(envelope: BaseModel, binding: TrustedExternalModelBinding) -> None:
    data = envelope.model_dump(mode="json")
    p = data["payload"]["prediction"]
    if (data["model_id"], data["model_version"]) != (binding.model_id, binding.model_version):
        fail("MODEL_IDENTITY_MISMATCH")
    if binding.profile == "litert":
        if (
            data["source"] != "dns_security_ai"
            or p["runtime"] != binding.profile
            or p["feature_schema_version"] != binding.feature_identity.schema_version
            or p["artifacts"]["feature_contract_digest"]
            != binding.feature_identity.ordered_names_digest
        ):
            fail("FEATURE_CONTRACT_MISMATCH")
        artifacts = {f.path: f.sha256 for f in binding.artifact_identity.files}
        if (
            p["artifacts"]["model_sha256"] != artifacts["dns/model/dnn_int8.tflite"]
            or p["artifacts"]["scaler_sha256"] != artifacts["dns/preprocessor/scaler.joblib"]
        ):
            fail("ARTIFACT_MISMATCH")
    elif (
        data["source"] != "network_security_ai"
        or p["deployment_profile"] != binding.profile
        or p["feature_set_version"] != binding.feature_identity.schema_version
        or p["feature_contract_digest"] != binding.feature_identity.ordered_names_digest
        or p["label_mapping_digest"] != binding.feature_identity.label_mapping_digest
        or tuple(item["label"] for item in p["class_probabilities"])
        != binding.feature_identity.ordered_labels
    ):
        fail("FEATURE_OR_LABEL_CONTRACT_MISMATCH")


def check_history(result: ExternalModelResult, history: tuple[ExternalModelResult, ...]) -> None:
    if type(history) is not tuple or len(history) > MAX_HISTORY:
        fail("INVALID_DUPLICATE_HISTORY")
    new_id = strict_json(result.original_envelope)["evidence_id"]
    for old in history:
        if type(old) is not ExternalModelResult:
            fail("INVALID_DUPLICATE_HISTORY")
        old = ExternalModelResult.model_validate(old.model_dump())
        old_id = strict_json(old.original_envelope)["evidence_id"]
        if old_id == new_id or old.semantic_key == result.semantic_key:
            if (
                old.semantic_key != result.semantic_key
                or old.semantic_output_digest != result.semantic_output_digest
            ):
                fail("EVIDENCE_OUTPUT_CONFLICT")
            fail("DUPLICATE_EVIDENCE")


def normalized_result(
    envelope: BaseModel,
    original_digest: str,
    normalized: str,
    binding: TrustedExternalModelBinding,
    observation: SourceFeatureObservation,
    provenance: InferenceProvenance,
    received_at: datetime,
    incident: StoredIncident | None,
) -> ExternalModelResult:
    from soc_agent.security_ai.external.models import ValidationReport

    if (
        type(observation) is not SourceFeatureObservation
        or type(provenance) is not InferenceProvenance
    ):
        fail("MISSING_TYPED_PROVENANCE")
    observation = SourceFeatureObservation.model_validate(observation.model_dump())
    provenance = InferenceProvenance.model_validate(provenance.model_dump())
    validate_prediction(envelope, binding)
    fingerprint = feature_input_digest(observation, binding)
    if provenance.artifact_identity != binding.artifact_identity:
        fail("ARTIFACT_MISMATCH")
    if (
        provenance.binding_digest != binding.binding_digest
        or provenance.observation_digest != content_digest(observation)
        or provenance.feature_input_digest != fingerprint
    ):
        fail("INFERENCE_PROVENANCE_MISMATCH")
    data = envelope.model_dump(mode="json")
    if data["observation_ref"] != observation.source_observation_id:
        fail("OBSERVATION_ID_MISMATCH")
    received_at = TypeAdapter(UTCTimestamp).validate_python(received_at)
    inference_time = TypeAdapter(UTCTimestamp).validate_python(data["timestamp"])
    if inference_time > received_at or (
        observation.event_time_end is not None and observation.event_time_end > inference_time
    ):
        fail("TIMESTAMP_MISMATCH")
    linked = validate_source(observation, incident)
    prediction = data["payload"]["prediction"]
    semantic_output = {
        key: value
        for key, value in prediction.items()
        if key not in ("inferred_at", "inference_latency_ms")
    }
    report = ValidationReport(
        status="VALIDATED_FOR_ADVISORY" if linked else "UNLINKED",
        code="CONTRACT_VALIDATED" if linked else "SOURCE_ASSOCIATION_UNVERIFIED",
    )
    payload = {
        "original_envelope_digest": original_digest,
        "normalized_envelope_digest": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "original_envelope": normalized,
        "binding": binding.model_dump(mode="json"),
        "observation": observation.model_dump(mode="json"),
        "provenance": provenance.model_dump(mode="json"),
        "inference_time": inference_time.isoformat(),
        "received_at": received_at.isoformat(),
        "feature_input_digest": fingerprint,
        "semantic_key": content_digest_payload(
            {
                "observation": observation.observation_key,
                "binding": binding.binding_digest,
                "feature": fingerprint,
                "runtime": binding.runtime_contract_digest,
            }
        ),
        "semantic_output_digest": content_digest_payload(semantic_output),
        "score_semantics": "dns_uncalibrated_malicious_probability"
        if binding.profile == "litert"
        else "network_uncalibrated_class_probabilities",
        "validation": report.model_dump(mode="json"),
        "contract_version": "soc-external-model-result:v2",
    }
    # Validate all content first; hash the final canonical timestamp/nested representation.
    content = ExternalModelResultContent.model_validate(payload)
    return ExternalModelResult.model_validate(
        content.model_dump() | {"result_digest": content_digest(content)}
    )
