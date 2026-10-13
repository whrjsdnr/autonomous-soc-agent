"""Actual preserved package inference through runtime, persistence and read surfaces."""

import asyncio
from pathlib import Path

import pytest
from pydantic import TypeAdapter, ValidationError

from soc_agent.demo.command_center import manifest, observation_app
from soc_agent.demo.local_server import read_response
from soc_agent.demo.model_analysis import PackagedAnalysis
from soc_agent.ingestion.authentication import authentication_records
from soc_agent.ingestion.models import Event, IngestionReceipt, NetworkEvent, SOCEvent
from soc_agent.ingestion.network import network_record
from soc_agent.live import initialize, main, process_event
from soc_agent.llm.openai_compatible import OpenAICompatibleClient
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.security_ai.packaging import ModelPackage, load_package
from tests.scenarios.test_security_ai_fusion import PINS

ROOT = Path(__file__).parents[3]


@pytest.fixture(scope="module")
def packages():
    return tuple(
        load_package(
            ROOT / "tests/fixtures/security_ai_packages" / kind, expected_manifest_digest=pin
        )
        for kind, pin, _ in PINS
    )


def events():
    return tuple(
        TypeAdapter(Event).validate_json(line)
        for line in (ROOT / "examples/live_security_ai_events.jsonl").read_text().splitlines()
    )


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Provider requests forbidden")

    monkeypatch.setattr(OpenAICompatibleClient, "_post", forbidden)


def test_actual_models_runtime_provenance_governance_dashboard(
    live_runtime_directory, packages, monkeypatch
):
    calls = []
    original = ModelPackage.predict

    def predict(package, features):
        calls.append(package.manifest.model_kind)
        return original(package, features)

    monkeypatch.setattr(ModelPackage, "predict", predict)
    service = initialize(live_runtime_directory, packages=packages)
    app, observer = observation_app(live_runtime_directory)
    for event in events():
        identity = service.ingest(event).incident_id
        initial = service.incident(identity).state
        result = asyncio.run(
            process_event(service, live_runtime_directory, event, notify=lambda _: None)
        )
        saved = service.checkpoint(identity)
        state = service.incident(identity).state
        assert (state.severity, state.status) == (initial.severity, initial.status)
        assert result.waiting_for_human
        assert saved.artifacts.execution_intent_id is None
        assert saved.artifacts.decision is not None
        assert len(state.evidence) == 1  # actual read-only tool report, not a model output
        assert not state.observations and not state.hypotheses
        assessment = saved.artifacts.assessment
        assert assessment.incident_state == state
        fusion = assessment.model_derived_context
        expected = (
            ("network_classifier", "network_anomaly")
            if event.event_type == "network"
            else ("authentication_anomaly",)
        )
        assert {c.model_kind for c in fusion.contributions} == set(expected)
        assert len(fusion.signals) == len(expected)
        assert fusion.confidence_state == "unknown"
        for signal in fusion.signals:
            assert not signal.source_evidence_ids
        for contribution in fusion.contributions:
            package = next(p for p in packages if p.manifest.model_kind == contribution.model_kind)
            binding = next(
                b
                for b in fusion.model_references
                if b.manifest.model_kind == contribution.model_kind
            )
            assert binding.manifest_digest == package.manifest_digest
            assert binding.manifest.file_hashes == package.manifest.file_hashes
            assert contribution.provenance.incident_id == identity
            assert all(s.source_evidence_id is None for s in contribution.provenance.sources)
        status, _, body = asyncio.run(
            read_response(app, observer, f"/dashboard/incidents/{identity}")
        )
        assert status == 200 and b"LIVE LOCAL RUNTIME" in body
        before = tuple(calls)
        replay = asyncio.run(
            process_event(
                initialize(live_runtime_directory, packages=packages),
                live_runtime_directory,
                event,
                notify=lambda _: None,
            )
        )
        assert replay.checkpoint_revision == result.checkpoint_revision
        assert tuple(calls) == before
    assert calls == ["network_classifier", "network_anomaly", "authentication_anomaly"]
    view = service.dashboard_security_ai(lambda _: True)
    assert view.retained_signal_count == 3
    assert {s.kind for s in view.latest_retained_signals} == set(calls)
    for path in ("/dashboard", "/dashboard/security-ai"):
        assert asyncio.run(read_response(app, observer, path))[0] == 200
    body = asyncio.run(read_response(app, observer, "/dashboard/security-ai"))[2]
    for package in packages:
        assert package.manifest_digest.encode() in body
        assert package.manifest.model_id.encode() in body
    assert observer._credential.encode() not in body
    assert len(manifest(live_runtime_directory).incidents) == 2
    assert service.dashboard_self_improvement(lambda _: True).candidate_count == 0


def test_partial_availability_and_domain_routing(live_runtime_directory, packages):
    service = initialize(live_runtime_directory, packages=(packages[0],))
    for event in events():
        result = asyncio.run(
            process_event(service, live_runtime_directory, event, notify=lambda _: None)
        )
        fusion = service.checkpoint(result.incident_id).artifacts.assessment.model_derived_context
        expected = 1 if event.event_type == "network" else 0
        assert len(fusion.signals) == expected
        assert fusion.confidence_state == "unknown"
        coverage = {c.model_kind: c.status for c in fusion.coverage}
        assert coverage["authentication_anomaly"] == (
            "not_run" if event.event_type == "authentication" else "insufficient_input"
        )
        assert coverage["network_anomaly"] == (
            "not_run" if event.event_type == "network" else "insufficient_input"
        )


def test_network_schema_and_replay_integrity(live_runtime_directory):
    network, auth = events()
    assert isinstance(network, NetworkEvent) and isinstance(auth, SOCEvent)
    with pytest.raises(ValidationError):
        SOCEvent.model_validate(network.model_dump())
    bad = network.model_dump()
    bad["attributes"]["fwd_packets"] = -1
    with pytest.raises(ValidationError):
        TypeAdapter(Event).validate_python(bad)
    service = initialize(live_runtime_directory)
    result = service.ingest(network)
    receipt = service.ingestion.load(result.incident_id)
    assert receipt.ingestion_version == "network-ingestion:v1"
    assert service.ingest(network).duplicate
    assert network_record(receipt).record_type == "network_flow"
    with pytest.raises(ValueError):
        authentication_records(receipt)
    bad_receipt = receipt.model_dump()
    bad_receipt["ingestion_version"] = "authentication-ingestion:v1"
    with pytest.raises(ValidationError):
        IngestionReceipt.model_validate(bad_receipt)


def test_activation_rejects_bad_or_missing_pins_before_start(live_runtime_directory, monkeypatch):
    for arguments in (
        [
            "--auth-package",
            str(ROOT / "tests/fixtures/security_ai_packages/authentication_anomaly"),
        ],
        ["--auth-package", str(live_runtime_directory / "missing"), "--manifest-digest", "0" * 64],
        [
            "--auth-package",
            str(ROOT / "tests/fixtures/security_ai_packages/network_classifier"),
            "--manifest-digest",
            PINS[0][1],
        ],
    ):
        directory = live_runtime_directory / "not-created"
        monkeypatch.setattr(
            "sys.argv", ["soc_agent.live", "--directory", str(directory), *arguments]
        )
        assert main() == 1
        assert not directory.exists()


def test_duplicate_or_conflicting_composition_rejected(live_runtime_directory, packages):
    service = initialize(live_runtime_directory)
    with pytest.raises(ValueError, match="Duplicate"):
        PackagedAnalysis(service.ingestion, (packages[0], packages[0]))
    with pytest.raises(ValueError, match="one explicit"):
        initialize(live_runtime_directory, packages=packages, model_analysis=lambda _: None)


def test_retained_package_pin_must_match_signal_lineage(live_runtime_directory, packages):
    import hashlib
    import json

    from soc_agent._json import canonical_json_object

    service = initialize(live_runtime_directory, packages=packages)
    asyncio.run(process_event(service, live_runtime_directory, events()[0], notify=lambda _: None))
    with service.store.database.transaction() as connection:
        row = connection.execute("SELECT * FROM workflow_checkpoints").fetchone()
        payload = json.loads(row["payload"])
        fusion = payload["artifacts"]["assessment"]["model_derived_context"]
        binding = next(
            b
            for b in fusion["model_references"]
            if b["manifest"]["model_kind"] == "network_classifier"
        )
        original = binding["manifest_digest"]
        binding["manifest_digest"] = "0" * 64
        for contribution in fusion["contributions"]:
            if contribution["model_reference"] == original:
                contribution["model_reference"] = "0" * 64
        encoded = canonical_json_object(payload)
        connection.execute(
            "UPDATE workflow_checkpoints SET payload=?, digest=?",
            (encoded, hashlib.sha256(encoded.encode()).hexdigest()),
        )
    with pytest.raises(StoredDataError):
        service.dashboard_security_ai(lambda _: True)
