"""Evidence, offline rows, and stream events share a local feature contract."""

import ast
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import SecurityAI
from soc_agent.security_ai.features import (
    AuthenticationSummaryExtractor,
    DatasetRecordReference,
    DatasetSchema,
    FeatureDefinition,
    FeatureExtractor,
    FeatureSchema,
    FeatureSet,
    SecurityRecord,
    SourceReference,
    SourceType,
    create_feature_set,
    record_from_evidence,
)
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool


@pytest.fixture(autouse=True)
def no_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Feature extraction crossed an execution boundary")

    for cls, method in (
        (MockLLMClient, "generate_structured"),
        (Tool, "execute"),
        (SecurityAI, "predict"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (GovernedExecutor, "execute"),
    ):
        monkeypatch.setattr(cls, method, forbidden)


def test_incident_evidence_to_feature_set() -> None:
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="auth.log",
        summary="Authentication window",
        raw_data='{"failed_login_count":40,"successful_login_count":2,'
        '"unique_accounts":8,"window_seconds":60}',
        observed_at=utc_now(),
    )
    state = state.add_evidence(evidence)
    before = state.model_dump_json()
    record = record_from_evidence(
        state=state,
        evidence_id=evidence.evidence_id,
        record_type="authentication_summary",
        record_schema_version="1.0.0",
    )
    extractor: FeatureExtractor = AuthenticationSummaryExtractor()
    first, second = extractor.extract(record, state=state), extractor.extract(record, state=state)
    assert first.provenance.source_evidence_ids == (evidence.evidence_id,)
    assert first.provenance.sources[0].source_reference.source_type == SourceType.EVIDENCE
    assert first.feature_set_id != second.feature_set_id
    assert first.input_fingerprint == second.input_fingerprint
    assert first.feature_values == (40, 8, 40 / 42, 0.7)
    assert state.model_dump_json() == before


class FlowInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    duration: float = Field(gt=0)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)


class FixtureFlowExtractor:
    """Test-only transformation: no reader, consumer, transport, or inference."""

    def extract(self, record: SecurityRecord, *, state: IncidentState | None = None) -> FeatureSet:
        payload = record.payload()
        if record.dataset_reference is not None:
            label = record.dataset_reference.dataset.label_field
            if label is not None:
                payload.pop(label)
        validated = FlowInput.model_validate(payload)
        return create_feature_set(
            feature_schema=FeatureSchema(
                schema_name="fixture_flow",
                schema_version="1",
                features=(
                    FeatureDefinition(name="duration", data_type="float", description="Seconds"),
                    FeatureDefinition(name="packet_count", data_type="int", description="Packets"),
                    FeatureDefinition(name="byte_count", data_type="int", description="Bytes"),
                ),
            ),
            values=validated.model_dump(),
            records=(record,),
            extractor_name="fixture_flow",
            extractor_version="1",
            state=state,
        )


@pytest.mark.parametrize("kind", [SourceType.DATASET, SourceType.STREAM])
def test_offline_and_streaming_source_contract(kind: SourceType) -> None:
    state = IncidentState()
    before = state.model_dump_json()
    dataset = DatasetSchema(
        dataset_name="fixture_network",
        dataset_version="1",
        record_schema_version="1",
        label_field="label",
    )
    ref = SourceReference(
        source_type=kind,
        source_name="fixture_network" if kind == SourceType.DATASET else "network_flow_events",
        source_version="1",
        record_id="row-42" if kind == SourceType.DATASET else "event-42",
    )
    payload = {"byte_count": 14291, "duration": 2.4, "packet_count": 183}
    record = SecurityRecord(
        source="fixture",
        source_reference=ref,
        record_type="network_flow",
        record_schema_version="1",
        observed_at=utc_now(),
        fields=payload | ({"label": "attack"} if kind == SourceType.DATASET else {}),
        dataset_reference=DatasetRecordReference(dataset=dataset, record_id="row-42")
        if kind == SourceType.DATASET
        else None,
    )
    extractor: FeatureExtractor = FixtureFlowExtractor()
    first, second = extractor.extract(record), extractor.extract(record)
    assert first.provenance.sources[0].source_reference == ref
    assert first.provenance.source_evidence_ids == ()
    assert first.provenance.incident_id is None
    assert first.feature_names == ("duration", "packet_count", "byte_count")
    assert first.feature_values == (2.4, 183, 14291)
    assert first.input_fingerprint == second.input_fingerprint
    assert first.feature_set_id != second.feature_set_id
    assert "label" not in first.input_payload()
    assert state.model_dump_json() == before


def test_feature_modules_have_no_execution_dependencies() -> None:
    import soc_agent.security_ai.features as features

    allowed = {"soc_agent._json", "soc_agent.state", "soc_agent.state.evidence"}
    for path in Path(features.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("soc_agent")
            ):
                assert node.module in allowed or node.module.startswith(
                    "soc_agent.security_ai.features"
                )
