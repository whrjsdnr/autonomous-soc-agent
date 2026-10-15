"""Explicit native interpreter only; actual probe, synthetic features, no LLM/provider."""

import os
from pathlib import Path

from soc_agent.security_ai.external.package_status import verify_fixture_demo
from soc_agent.security_ai.external.service import ModelInput
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace


def test_actual_native_fixture_probe_never_authorizes_operational_inference(bundle):
    _, context, *_ = bundle
    root = Path(os.environ["SOC_EXTERNAL_ARTIFACT_ROOT"])
    from soc_agent.review.persistence.session import GovernanceSession

    store = bundle[0]
    with store.database.transaction(write=False) as connection:
        incident = GovernanceSession(connection, store.database.store_id).load(
            context.input_snapshot.incident_id
        )
    status = verify_fixture_demo(
        artifact_root=root,
        inputs=tuple(
            ModelInput(binding=r.binding, observation=r.observation) for r in context.results
        ),
        incident=incident,
    )
    selected = {r.binding.binding_id for r in context.results}
    assert status.context_digest and status.projection_digest
    assert status.input_origin == "SYNTHETIC_PRECOMPUTED_FEATURE_FIXTURE"
    for row in status.packages:
        assert row.demo_inference == ("VERIFIED" if row.binding_id in selected else "UNKNOWN")
        assert row.operational_input == "NOT_INFERABLE"
    assert status.write_disposition == "WRITE_DENIED"
    assert not status.execution_authority
