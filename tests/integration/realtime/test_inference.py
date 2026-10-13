"""Same queue/worker path with explicit synthetic features and real official predictors."""

import asyncio
import os
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from tests.integration.external_runtime.test_gate_c_entrypoints import inputs

from soc_agent.external_runtime import read_features
from soc_agent.local_events import LocalJSONLSource
from soc_agent.realtime.models import CommonEvent, SourceIdentity, SourceMetadata
from soc_agent.realtime.queue import EventQueue
from soc_agent.realtime.worker import composition, drain, incident_id, process
from soc_agent.review.identity import content_digest
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.security_ai.external.storage import ExternalContextStore


def test_real_three_predictors_queue_runtime_resume(tmp_path):
    artifacts = Path(
        os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT", "/tmp/soc-gate-b-artifacts-20261012")
    )
    interpreter = Path(
        os.environ.get(
            "SOC_EXTERNAL_INFERENCE_PYTHON", "/tmp/security-ai-artifact-validation/bin/python"
        )
    )
    events_path, features_path = inputs(tmp_path)
    original = next(LocalJSONLSource(events_path).events())
    features = read_features(features_path)[original.event_id]
    source = SourceIdentity(
        namespace="explicit-fixture", generation="v1", record=str(original.event_id)
    )
    event = CommonEvent(
        event_id=uuid5(NAMESPACE_URL, content_digest(source)),
        platform="validated_fixture",
        collector_id="explicit-fixture:v1",
        event_type="validated_model_input",
        event_timestamp=original.occurred_at,
        ingestion_timestamp=original.occurred_at,
        source=source,
        metadata=SourceMetadata(channel="fixture", provider="precomputed"),
        provenance="explicit_precomputed_fixture",
        soc_event=original,
        feature_payload=tuple(features),
    )
    root = tmp_path / "private"
    q = EventQueue.create(root / "queue.sqlite")
    store = RuntimeGovernanceStore.create_isolated(root / "runtime")
    app = composition(store, artifacts=artifacts, native_python=interpreter)
    q.enqueue(event)
    asyncio.run(drain(q, app))
    assert q.counts() == {"DONE": 1}
    with q.database.transaction(write=False) as c:
        assert (
            "VALIDATED_FOR_ADVISORY"
            in c.execute("SELECT outcome FROM realtime_events").fetchone()[0]
        )
    with store.database.transaction(write=False) as c:
        assert c.execute("SELECT count(*) FROM external_runtime_requirements").fetchone()[0] == 1
    binding = store.boundary.binding(incident_id(event))
    context = ExternalContextStore(store.database.path, database=store.database).load_context(
        binding.context_digest
    )
    assert len(context.results) == 3
    assert len({r.observation.observation_key for r in context.results}) == 2
    assert all(r.provenance.execution_environment_digest for r in context.results)
    assert not q.enqueue(event)
    reopened = RuntimeGovernanceStore(store.database.path)
    app = composition(reopened, artifacts=artifacts, native_python=interpreter)
    # Explicitly replay after Runtime commit / queue acknowledgement loss: no reinference.
    resumed = asyncio.run(process(app, event))
    assert resumed["inference"] == "VALIDATED_FOR_ADVISORY"
    assert resumed["human_boundary"]
    assert reopened.boundary.binding(incident_id(event)).context_digest == binding.context_digest
    with reopened.database.transaction(write=False) as c:
        assert c.execute("SELECT count(*) FROM execution_records").fetchone()[0] == 0
    asyncio.run(drain(EventQueue(q.database.path), app))
    assert q.counts() == {"DONE": 1}


def test_missing_features_rejected_before_predictor(tmp_path):
    import pytest

    from soc_agent.realtime.worker import validate_features

    events_path, features_path = inputs(tmp_path)
    original = next(LocalJSONLSource(events_path).events())
    rows = read_features(features_path)[original.event_id]
    source = SourceIdentity(
        namespace="explicit-fixture", generation="v1", record=str(original.event_id)
    )
    first = rows[0]
    damaged = first.model_copy(
        update={"observation": first.observation.model_copy(update={"feature_payload": "{}"})}
    )
    event = CommonEvent(
        event_id=uuid5(NAMESPACE_URL, content_digest(source)),
        platform="validated_fixture",
        collector_id="explicit-fixture:v1",
        event_type="validated_model_input",
        event_timestamp=original.occurred_at,
        ingestion_timestamp=original.occurred_at,
        source=source,
        metadata=SourceMetadata(channel="fixture", provider="precomputed"),
        provenance="explicit_precomputed_fixture",
        soc_event=original,
        feature_payload=(damaged,),
    )
    with pytest.raises(ValueError, match="no filling"):
        validate_features(event)
