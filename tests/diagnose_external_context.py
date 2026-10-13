"""Offline B-3.2 actual native inference and read-only assembly; exclusive output creation."""

import argparse
import hashlib
import importlib.metadata
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from soc_agent._json import canonical_json_object
from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import StateAnchor, StoredIncident
from soc_agent.security_ai.external.assembly import assemble
from soc_agent.security_ai.external.inference import infer
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import (
    DerivationProvenance,
    IncidentAssociation,
    SourceEvidenceReference,
    SourceFeatureObservation,
)
from soc_agent.state import Evidence, IncidentState

CODE_PIN = "56293972d069dffaf564a390ab7a4c4554c2a2a5b2ab6be6f6f758b5ea3cce44"


def smoke(root: Path) -> dict:
    profiles = ("detection_quality", "edge", "litert")
    bindings = [
        reviewed_binding(
            profile,
            expected_code_identity=CODE_PIN,
            runtime_contract_digest=hashlib.sha256(b"native-offline-b32-v1").hexdigest(),
        )
        for profile in profiles
    ]
    when = datetime(2026, 10, 12, tzinfo=UTC)
    sources = []
    for binding in (bindings[0], bindings[2]):
        dns = binding.profile == "litert"
        payload = canonical_json_object(dict.fromkeys(binding.feature_identity.ordered_names, 1.0))
        sources.append(
            SourceFeatureObservation(
                source_namespace="b32-synthetic-precomputed",
                source_event_id="synthetic-event-dns" if dns else "synthetic-event-network",
                source_observation_id="synthetic-dns-1" if dns else "synthetic-flow-1",
                observation_type="dns_stateless_feature_record" if dns else "network_flow_top40",
                event_time_start=when,
                event_time_end=when,
                entity_reference="synthetic-device-1",
                feature_identity=binding.feature_identity,
                feature_payload=payload,
                derivation_provenance=DerivationProvenance(
                    origin_assurance="synthetic_contract_only",
                    fixture_digest=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    extractor_id="precomputed-synthetic-feature-record",
                    extractor_version="v1",
                ),
                synthetic=True,
            )
        )
    incident_id = UUID(int=1)
    evidence = tuple(
        Evidence(
            evidence_id=UUID(int=index + 2),
            incident_id=incident_id,
            source=source.source_namespace,
            summary="Synthetic source feature record, not model inference",
            raw_data=canonical_json_object(source.source_payload()),
            observed_at=when,
            collected_at=when,
        )
        for index, source in enumerate(sources)
    )
    state = IncidentState(
        incident_id=incident_id, evidence=evidence, created_at=when, updated_at=when
    )
    stored = StoredIncident(
        state=state,
        anchor=StateAnchor(
            repository_id=UUID(int=10),
            incident_id=incident_id,
            revision=0,
            fingerprint=state_fingerprint(state),
        ),
    )
    sources = [
        source.model_copy(
            update={
                "association": IncidentAssociation(
                    incident_id=incident_id,
                    snapshot=stored.anchor,
                    source_evidence_references=(
                        SourceEvidenceReference(
                            evidence_id=item.evidence_id,
                            content_digest=content_digest(item),
                        ),
                    ),
                )
            }
        )
        for source, item in zip(sources, evidence, strict=True)
    ]
    runs = []
    for binding in bindings:
        source = sources[1] if binding.profile == "litert" else sources[0]
        runs.append(
            infer(root, binding, source, incident=stored, history=tuple(r.result for r in runs))
        )
    context = assemble(tuple(runs), incident=stored)
    assert len(context.results) == 3 and not context.unlinked_results
    assert len(context.correlation_groups) == 2
    assert content_digest(stored.state) == content_digest(state)
    return {
        "contract_version": "gate-b32-native-context-smoke:v1",
        "status": "PASS",
        "native_inference_calls": 3,
        "provider_calls": 0,
        "database_writes": 0,
        "action_calls": 0,
        "versions": {
            name: importlib.metadata.version(name)
            for name in (
                "network-security-ai",
                "dns-security-ai",
                "security-ai",
                "numpy",
                "pydantic",
                "lightgbm",
                "torch",
                "ai-edge-litert",
                "scikit-learn",
                "joblib",
                "pandas",
            )
        },
        "context": context.model_dump(mode="json"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Refuse collision before inference, then use exclusive creation as well.
    if args.output.exists():
        parser.error("Output already exists; refusing overwrite")
    result = smoke(args.artifact_root)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
