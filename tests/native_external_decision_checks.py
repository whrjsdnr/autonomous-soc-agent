"""Explicit native inference, existing core analysis and SQLite receipt checks."""

import asyncio
import os
from pathlib import Path
from uuid import UUID

from soc_agent.llm import MockLLMClient
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.security_ai.external.assembly import assemble
from soc_agent.security_ai.external.diagnostic import ExternalAdvisoryDiagnostic
from soc_agent.security_ai.external.inference import infer
from soc_agent.tools import MockTool, ToolMetadata, ToolRegistry
from tests.bounded_support import Query, Reputation
from tests.external_advisory_support import responses
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace


def test_actual_native_results_used_by_core_diagnostic(bundle):
    store, synthetic, _, _, _ = bundle
    with store.database.transaction(write=False) as connection:
        stored = GovernanceSession(connection, store.database.store_id).load(
            synthetic.input_snapshot.incident_id
        )
    root = Path(os.environ["SOC_EXTERNAL_ARTIFACT_ROOT"])
    # Synthetic source schemas are reused; fixture prediction outputs are discarded.
    runs = []
    for old in synthetic.results:
        runs.append(
            infer(
                root,
                old.binding,
                old.observation,
                incident=stored,
                history=tuple(r.result for r in runs),
            )
        )
    native = assemble(tuple(runs), incident=stored)
    store.save_context(native)
    tool = MockTool(
        metadata=ToolMetadata(
            name="source_lookup",
            description="Non-executed synthetic catalog",
            permission="network_read",
            risk_level="read_only",
        ),
        input_model=Query,
        output_model=Reputation,
        responses=[],
    )
    registry = ToolRegistry()
    registry.register(tool.tool)
    client = MockLLMClient(responses(native))
    trial = ExternalAdvisoryDiagnostic(
        store=store,
        context_digest=native.context_digest,
        required_models=tuple(r.binding.binding_id for r in native.results),
        llm_client=client,
        registry=registry,
    )
    result = asyncio.run(trial.evaluate(run_id=UUID(int=301)))
    restored = trial.restore_receipts(result.resume_requirement)
    assert restored[0] == native
    assert restored[1].core_result == result.assessment
    assert restored[3].core_decision == result.decision
    assert client.call_count == 2 and tool.call_count == 0
    assert result.assessment.incident_state == stored.state
    assert all(r.provenance.inference_origin == "LOCAL_MANAGED_INFERENCE" for r in native.results)
