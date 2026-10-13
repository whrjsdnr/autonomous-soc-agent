"""Real external schemas; synthetic test values are not actual inference results."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from dns_security_ai import DNSThreatPrediction
from dns_security_ai.contracts import DNSArtifactReference
from dns_security_ai.evidence import prediction_to_evidence as dns_receipt
from network_security_ai import NetworkThreatPrediction
from network_security_ai.evidence import prediction_to_evidence as network_receipt
from network_security_ai.schema import ClassProbability
from security_ai import to_envelope

from soc_agent._json import canonical_json_object
from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import StateAnchor, StoredIncident
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import (
    DerivationProvenance,
    IncidentAssociation,
    InferenceProvenance,
    SourceEvidenceReference,
    SourceFeatureObservation,
)
from soc_agent.security_ai.external.validation import feature_input_digest
from soc_agent.state import Evidence, IncidentState

TIME = datetime(2026, 10, 12, 1, tzinfo=UTC)
CODE_PIN = "56293972d069dffaf564a390ab7a4c4554c2a2a5b2ab6be6f6f758b5ea3cce44"


@pytest.fixture(autouse=True)
def no_model_inference(monkeypatch):
    from dns_security_ai import DNSPredictor
    from network_security_ai.predictors import (
        DNNNetworkThreatPredictor,
        LightGBMNetworkThreatPredictor,
    )

    def forbidden(*args, **kwargs):
        pytest.fail("B-3.1 must not run inference")

    for cls in (DNSPredictor, DNNNetworkThreatPredictor, LightGBMNetworkThreatPredictor):
        monkeypatch.setattr(cls, "predict", forbidden)


@pytest.fixture
def case():
    def make(profile="detection_quality"):
        binding = reviewed_binding(
            profile, expected_code_identity=CODE_PIN, runtime_contract_digest="1" * 64
        )
        observation = SourceFeatureObservation(
            source_namespace="synthetic-feature-source",
            source_event_id="synthetic-event-1",
            source_observation_id="synthetic-flow-1" if profile != "litert" else "synthetic-dns-1",
            observation_type="network_flow_top40"
            if profile != "litert"
            else "dns_stateless_feature_record",
            event_time_start=TIME,
            event_time_end=TIME,
            entity_reference="synthetic-device-1",
            feature_identity=binding.feature_identity,
            feature_payload=canonical_json_object(
                dict.fromkeys(binding.feature_identity.ordered_names, 1.0)
            ),
            derivation_provenance=DerivationProvenance(
                origin_assurance="synthetic_contract_only",
                fixture_digest="2" * 64,
                extractor_id="synthetic-precomputed-fixture",
                extractor_version="v1",
            ),
            synthetic=True,
        )
        incident_id = UUID(int=1)
        source = Evidence(
            evidence_id=UUID(int=2),
            incident_id=incident_id,
            source=observation.source_namespace,
            summary="Synthetic feature source; not model evidence",
            raw_data=canonical_json_object(observation.source_payload()),
            observed_at=TIME,
            collected_at=TIME,
        )
        state = IncidentState(
            incident_id=incident_id, evidence=(source,), created_at=TIME, updated_at=TIME
        )
        incident = StoredIncident(
            state=state,
            anchor=StateAnchor(
                repository_id=UUID(int=3),
                incident_id=incident_id,
                revision=0,
                fingerprint=state_fingerprint(state),
            ),
        )
        observation = observation.model_copy(
            update={
                "association": IncidentAssociation(
                    incident_id=incident_id,
                    snapshot=incident.anchor,
                    source_evidence_references=(
                        SourceEvidenceReference(
                            evidence_id=source.evidence_id, content_digest=content_digest(source)
                        ),
                    ),
                )
            }
        )
        provenance = InferenceProvenance(
            inference_origin="LOCAL_MANAGED_INFERENCE",
            binding_digest=binding.binding_digest,
            observation_digest=content_digest(observation),
            feature_input_digest=feature_input_digest(observation, binding),
            artifact_identity=binding.artifact_identity,
            execution_environment_digest="3" * 64,
        )
        # Trusted synthetic caller assertion; deliberately no predictor is executed.
        inferred = TIME + timedelta(seconds=1)
        if profile == "litert":
            artifacts = {f.path: f.sha256 for f in binding.artifact_identity.files}
            prediction = DNSThreatPrediction(
                class_id=0,
                label="NORMAL",
                probability=0.0,
                runtime="litert",
                artifacts=DNSArtifactReference(
                    model_sha256=artifacts["dns/model/dnn_int8.tflite"],
                    scaler_sha256=artifacts["dns/preprocessor/scaler.joblib"],
                ),
                inferred_at=inferred,
                inference_latency_ms=0.0,
            )
            envelope = to_envelope(
                dns_receipt(prediction, observation_ref=observation.source_observation_id)
            )
        else:
            prediction = NetworkThreatPrediction(
                predicted_class="Benign",
                class_id=0,
                confidence=1.0,
                threat_score=0.0,
                class_probabilities=tuple(
                    ClassProbability(label=n, probability=float(i == 0))
                    for i, n in enumerate(binding.feature_identity.ordered_labels)
                ),
                model_name=binding.model_id,
                model_version=binding.model_version,
                deployment_profile=profile,
                feature_set_version=binding.feature_identity.schema_version,
                feature_contract_digest=binding.feature_identity.ordered_names_digest,
                label_mapping_digest=binding.feature_identity.label_mapping_digest,
                inferred_at=inferred,
                inference_latency_ms=0.0,
            )
            envelope = to_envelope(
                network_receipt(prediction, flow_reference=observation.source_observation_id)
            )
        return envelope, dict(
            binding=binding,
            observation=observation,
            provenance=provenance,
            received_at=TIME + timedelta(seconds=2),
            incident=incident,
        )

    return make
