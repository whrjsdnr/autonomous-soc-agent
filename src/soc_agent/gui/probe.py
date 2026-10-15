"""Explicit synthetic fixture through existing native service and guarded SOC runtime."""

import asyncio
from uuid import uuid4

from soc_agent._json import canonical_json_object
from soc_agent.demo.scenarios import scenario_event
from soc_agent.external_runtime import CODE_PIN, CONTRACT, FeatureRow, bind_features
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import DerivationProvenance, SourceFeatureObservation
from soc_agent.security_ai.external.projection import project, projection_digest


async def probe(service) -> dict:
    event = scenario_event("b").model_copy(update={"event_id": uuid4()})
    receipt = service.ingest(event)
    rows = []
    for profiles, kind in (
        (("detection_quality", "edge"), "network_flow_top40"),
        (("litert",), "dns_stateless_feature_record"),
    ):
        binding = reviewed_binding(
            profiles[0], expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
        )
        observation = SourceFeatureObservation(
            source_namespace="gui-explicit-synthetic-precomputed",
            source_event_id=str(event.event_id),
            source_observation_id="fixture-" + kind,
            observation_type=kind,
            event_time_start=event.occurred_at,
            event_time_end=event.occurred_at,
            entity_reference="fixture-device",
            feature_identity=binding.feature_identity,
            feature_payload=canonical_json_object(
                dict.fromkeys(binding.feature_identity.ordered_names, 1.0)
            ),
            derivation_provenance=DerivationProvenance(
                origin_assurance="synthetic_contract_only",
                fixture_digest=binding.feature_identity.ordered_names_digest,
                extractor_id="gui-synthetic-precomputed",
                extractor_version="1",
            ),
            synthetic=True,
        )
        rows.append(FeatureRow(event_id=event.event_id, profiles=profiles, observation=observation))
    context = await asyncio.to_thread(
        service.analyze_external,
        receipt.incident_id,
        bind_features(service.store, receipt.incident_id, rows),
    )
    runtime = service.runtime_factory()
    runtime.start(receipt.incident_id)
    for _ in range(12):
        result = await runtime.advance(receipt.incident_id)
        if result.waiting_for_human or result.terminal:
            break
    else:
        raise ValueError("PROBE_RUNTIME_LIMIT")
    restored = service.runtime_factory()
    if restored.restore(receipt.incident_id) != runtime.checkpoint(receipt.incident_id).result:
        raise ValueError("PROBE_RESUME_MISMATCH")
    return {
        "status": "VERIFIED",
        "input_origin": "SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE",
        "assessment_mode": "SCRIPTED",
        "incident_id": str(receipt.incident_id),
        "model_results": len(context.results),
        "correlation_groups": len(context.correlation_groups),
        "context_digest": context.context_digest,
        "projection_digest": projection_digest(project(context)),
        "native_models": [r.binding.binding_id for r in context.results],
        "operational_input": "NOT_INFERABLE",
        "action_policy": "WRITE_DENIED",
        "llm_provider_calls": 0,
        "os_security_changes": 0,
    }
