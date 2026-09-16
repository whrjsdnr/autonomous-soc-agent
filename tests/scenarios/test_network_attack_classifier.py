"""Synthetic-only offline training → native artifact → streaming inference bridge."""

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc_agent.adaptive import AdaptiveInvestigationPlanner
from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import SecurityAI, SecurityAIRegistry
from soc_agent.security_ai.features import SecurityRecord, SourceReference
from soc_agent.security_ai.network.dataset import CICIDS2017Adapter
from soc_agent.security_ai.network.schema import COLUMNS, NetworkFeatureExtractor
from soc_agent.state import IncidentState
from soc_agent.tools import Tool


def test_fixture_training_to_streaming(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from soc_agent.security_ai.network.artifacts import load_artifact, save_artifact
    from soc_agent.security_ai.network.training import TrainingConfig, train

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("ML pipeline crossed a governance or agent execution boundary")

    for cls, method in (
        (MockLLMClient, "generate_structured"),
        (Tool, "execute"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (AdaptiveInvestigationPlanner, "replan"),
        (SecurityAI, "predict"),
        (GovernedExecutor, "execute"),
        (SecurityAIRegistry, "register"),
    ):
        monkeypatch.setattr(cls, method, forbidden)
    state = IncidentState()
    before = state.model_dump_json()
    path = tmp_path / "synthetic-network.csv"
    with path.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([column for column, _ in COLUMNS] + ["Label", "Flow ID"])
        for index, label in enumerate(("BENIGN", "DoS", "PortScan", "BruteForce")):
            for sample in range(30):
                n = (index + 1) * 1000 + sample
                writer.writerow([n, n + 10, n + 20, n * 10, n * 20, label, f"{index}-{sample}"])
    dataset = CICIDS2017Adapter(dataset_name="synthetic-network-fixture").load(
        (path,), observed_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    result = train(dataset, config=TrainingConfig(n_estimators=5, max_depth=2))
    artifact = save_artifact(result, tmp_path / "artifacts")
    loaded = load_artifact(artifact)
    offline = dataset.examples[0].features
    stream_record = SecurityRecord(
        source="userspace fixture",
        record_type="network_flow",
        record_schema_version="1.0.0",
        fields=offline.input_payload(),
        observed_at=datetime.now(UTC),
        source_reference=SourceReference(
            source_type="stream",
            source_name="network_flow_events",
            source_version="1",
            record_id="event-42",
        ),
    )
    online = NetworkFeatureExtractor().extract(stream_record)
    assert offline.input_fingerprint == online.input_fingerprint
    assert offline.provenance != online.provenance
    assert loaded.classifier.predict(offline) == loaded.classifier.predict(online)
    assert state.model_dump_json() == before
    assert len(loaded.metadata.test.per_class) == 4
    assert loaded.metadata == result.metadata
    # Human-readable fixture metrics only; no metric is treated as real IDS accuracy.
    print(
        json.dumps({"dataset": "SYNTHETIC FIXTURE ONLY", "test": result.metadata.test.model_dump()})
    )
