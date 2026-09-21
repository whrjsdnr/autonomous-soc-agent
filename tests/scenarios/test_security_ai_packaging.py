"""Actual records -> extractors -> persisted models -> explicit registry -> results."""

from datetime import UTC, datetime

import pytest
from tests.authentication_support import fixture_examples
from tests.packaging_support import selected_models

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import SecurityAIRegistry
from soc_agent.security_ai.features import (
    DatasetRecordReference,
    DatasetSchema,
    SecurityRecord,
    SourceReference,
)
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor
from soc_agent.security_ai.packaging import (
    AuthenticationAnomalyAdapter,
    NetworkAnomalyAdapter,
    NetworkClassifierAdapter,
    load_package,
    save_package,
)
from soc_agent.state import IncidentState
from soc_agent.tools import Tool


def network_feature(kind):
    dataset = DatasetSchema(
        dataset_name="scenario", dataset_version="1", record_schema_version="1.0.0"
    )
    record = SecurityRecord(
        record_type="network_flow",
        record_schema_version="1.0.0",
        source="scenario",
        source_reference=SourceReference(
            source_type=kind, source_name="scenario", source_version="1", record_id="flow-1"
        ),
        dataset_reference=DatasetRecordReference(dataset=dataset, record_id="flow-1")
        if kind == "dataset"
        else None,
        fields={
            "duration_us": 200000.0,
            "fwd_packets": 100,
            "bwd_packets": 5,
            "fwd_bytes": 10000,
            "bwd_bytes": 200,
        },
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return NetworkFeatureExtractor().extract(record)


@pytest.mark.asyncio
async def test_three_model_packaged_end_to_end(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Packaging crossed agent execution boundary")

    for cls, name in (
        (Tool, "execute"),
        (MockLLMClient, "generate_structured"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (GovernedExecutor, "execute"),
    ):
        monkeypatch.setattr(cls, name, forbidden)
    models = selected_models(tmp_path)
    registry = SecurityAIRegistry()
    state = IncidentState()
    before = state.model_dump_json()
    offline_auth = fixture_examples("dataset")[0].features
    stream_auth = fixture_examples("stream")[0].features
    adapters = {
        "network_classifier": NetworkClassifierAdapter,
        "network_anomaly": NetworkAnomalyAdapter,
        "authentication_anomaly": AuthenticationAnomalyAdapter,
    }
    for name, adapter in adapters.items():
        selection, _ = models[name]
        path = tmp_path / name
        pin = save_package(selection, path)
        previous = registry.list()
        package = load_package(path, expected_manifest_digest=pin)
        assert registry.list() == previous
        wrapper = adapter(package).as_security_ai()
        registry.register(wrapper)
        offline, stream = (
            (offline_auth, stream_auth)
            if name == "authentication_anomaly"
            else (network_feature("dataset"), network_feature("stream"))
        )
        assert offline.input_fingerprint == stream.input_fingerprint
        first, second = [
            await registry.get(wrapper.metadata.name).predict(
                SecurityAIRequest(incident_id=state.incident_id, input=f)
            )
            for f in (offline, stream)
        ]
        assert first.prediction == second.prediction
        assert first.scores == second.scores
        assert first.confidence == second.confidence
        assert (
            first.explanation_payload()["feature_provenance"]
            != second.explanation_payload()["feature_provenance"]
        )
        assert state.model_dump_json() == before
    assert len(registry.list()) == 3
