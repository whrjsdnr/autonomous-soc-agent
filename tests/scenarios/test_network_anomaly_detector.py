"""One shared contract feeds two independent models; synthetic evidence only."""

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
from soc_agent.security_ai.network import AnomalyTrainingConfig, NetworkAnomalyDetector
from soc_agent.security_ai.network.anomaly_training import train_anomaly
from soc_agent.security_ai.network.dataset import CICIDS2017Adapter
from soc_agent.security_ai.network.schema import COLUMNS, NetworkFeatureExtractor
from soc_agent.security_ai.network.training import TrainingConfig, train
from soc_agent.state import IncidentState
from soc_agent.tools import Tool


def test_offline_stream_and_independent_models(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Anomaly detection crossed an agent/governance boundary")

    for cls, method in (
        (MockLLMClient, "generate_structured"),
        (Tool, "execute"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (GovernedExecutor, "execute"),
        (AdaptiveInvestigationPlanner, "replan"),
        (SecurityAI, "predict"),
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
    dataset = CICIDS2017Adapter(dataset_name="synthetic-anomaly-fixture").load(
        (path,), observed_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    result = train_anomaly(dataset, config=AnomalyTrainingConfig(n_estimators=16))
    detector: NetworkAnomalyDetector = result.detector  # In-memory strategy: no loader exists.
    classifier = train(dataset, config=TrainingConfig(n_estimators=3, max_depth=2)).classifier
    profile_before = detector.profile.model_dump_json()
    # Both a benign and an attack fixture measurement travel through the same extractor.
    for index in (0, 60):
        offline = dataset.examples[index].features
        record = SecurityRecord(
            record_type="network_flow",
            record_schema_version="1.0.0",
            source="userspace fixture",
            observed_at=datetime(2026, 1, 1, tzinfo=UTC),
            fields=offline.input_payload(),
            source_reference=SourceReference(
                source_type="stream",
                source_name="network_flow_events",
                source_version="1",
                record_id=f"event-{index}",
            ),
        )
        online = NetworkFeatureExtractor().extract(record)
        assert online.input_fingerprint == offline.input_fingerprint
        assert online.provenance != offline.provenance
        assert detector.predict(online) == detector.predict(offline)
        assert classifier.predict(online) == classifier.predict(offline)
        # These are separate outputs. No fusion, attack attribution by anomaly, or winner.
        assert not hasattr(detector.predict(online), "predicted_class")
    assert detector.profile.model_dump_json() == profile_before
    assert state.model_dump_json() == before
    assert all(dataset.examples[i].label == "BENIGN" for i in result.metadata.baseline_indices)
    assert len(result.metadata.baseline_indices) == 18
    assert result.metadata.test.normal_support == 6 and result.metadata.test.anomaly_support == 18
    assert result.metadata.persistence == "in_memory_only"
    print(
        json.dumps(
            {
                "dataset": "SYNTHETIC PIPELINE TEST ONLY",
                "rows": len(dataset.examples),
                "baseline_rows": len(result.metadata.baseline_indices),
                "test": result.metadata.test.model_dump(),
            }
        )
    )
