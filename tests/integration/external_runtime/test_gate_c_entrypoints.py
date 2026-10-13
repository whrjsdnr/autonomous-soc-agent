"""Real CLI/native predictors, process restart and authenticated production ASGI routes.

Synthetic feature inputs and the existing offline scripted client are deliberate;
this is not a production collection or remote-service deployment test.
"""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from tests.integration.api.conftest import TestAccess as FixtureAccess
from tests.integration.api.conftest import call
from tests.unit.identity.conftest import Boundary

from soc_agent._json import canonical_json_object
from soc_agent.api import SOCApplication
from soc_agent.application import compose_application
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, source_report_tool
from soc_agent.external_runtime import CODE_PIN, CONTRACT, FeatureRow
from soc_agent.ingestion import EventIngestor
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.persistence import ledger
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import DerivationProvenance, SourceFeatureObservation
from soc_agent.security_ai.external.runtime_store import RuntimeBinding, RuntimeGovernanceStore
from soc_agent.security_ai.external.storage import ExternalContextStore
from soc_agent.tools import ToolRegistry


def inputs(directory: Path) -> tuple[Path, Path]:
    event_id = UUID("c919fa0f-8c0a-5829-9ab3-99ef2cc45e41")
    when = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
    event = {
        "event_id": str(event_id),
        "event_type": "network",
        "source": "synthetic-demo",
        "occurred_at": when.isoformat(),
        "subject": "demo-network-host",
        "resource": "demo-flow",
        "synthetic": True,
        "attributes": {
            "duration_us": 500000.0,
            "fwd_packets": 100,
            "bwd_packets": 10,
            "fwd_bytes": 5000,
            "bwd_bytes": 500,
        },
    }
    events, features = directory / "events.jsonl", directory / "features.jsonl"
    events.write_text(json.dumps(event) + "\n", encoding="utf-8")
    rows = []
    for profiles, observation_id, kind in (
        (("detection_quality", "edge"), "synthetic-flow-1", "network_flow_top40"),
        (("litert",), "synthetic-dns-1", "dns_stateless_feature_record"),
    ):
        binding = reviewed_binding(
            profiles[0], expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
        )
        observation = SourceFeatureObservation(
            source_namespace="synthetic-local-feature-file",
            source_event_id=str(event_id),
            source_observation_id=observation_id,
            observation_type=kind,
            event_time_start=when,
            event_time_end=when,
            entity_reference="synthetic-device-1",
            feature_identity=binding.feature_identity,
            feature_payload=canonical_json_object(
                dict.fromkeys(binding.feature_identity.ordered_names, 1.0)
            ),
            derivation_provenance=DerivationProvenance(
                origin_assurance="synthetic_contract_only",
                fixture_digest="2" * 64,
                extractor_id="synthetic-file-fixture",
                extractor_version="v1",
            ),
            synthetic=True,
        )
        rows.append(
            FeatureRow(
                event_id=event_id, profiles=profiles, observation=observation
            ).model_dump_json()
        )
    features.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return events, features


@pytest.mark.parametrize("profile", ("DESKTOP",) if os.name == "nt" else ("DESKTOP", "SERVER"))
def test_native_cli_restart_and_asgi_boundaries(tmp_path, profile):
    artifacts = Path(
        os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT", "/tmp/soc-gate-b-artifacts-20261012")
    )
    native = Path(
        os.environ.get(
            "SOC_EXTERNAL_INFERENCE_PYTHON", "/tmp/security-ai-artifact-validation/bin/python"
        )
    )
    assert artifacts.is_dir() and native.is_file(), "Explicit native environment required"
    events, features = inputs(tmp_path)
    data = tmp_path / "private runtime 한글"
    command = [
        sys.executable,
        "-m",
        "soc_agent.external_runtime",
        "--directory",
        str(data),
        "--input",
        str(events),
        "--external-features",
        str(features),
        "--artifacts",
        str(artifacts),
        "--native-python",
        str(native),
        "--profile",
        profile,
    ]
    env = dict(os.environ, RUN_LIVE_LLM_TESTS="0")
    env["PYTHONPATH"] = str(Path(__file__).parents[3] / "src")
    path = data / ("external-runtime" if profile == "DESKTOP" else "")
    path /= "external-validation.sqlite"
    digests = []
    for _ in range(2):
        process = subprocess.run(command, env=env, capture_output=True, timeout=180)
        assert process.returncode == 0, "Offline CLI failed; inspect isolated test diagnostics"
        output = json.loads(process.stdout.decode("utf-8").strip())
        assert output["human_boundary"] and output["context_available"]
        incident_id = UUID(output["incident_id"])
        store = RuntimeGovernanceStore(path)
        with store.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM external_runtime_incidents WHERE incident_id=?",
                (str(incident_id),),
            ).fetchone()
            assert row is not None
            binding = ledger.decode(RuntimeBinding, row)
        digests.append(binding.context_digest)
    assert digests[0] == digests[1]
    context = ExternalContextStore(path, database=store.database).load_context(digests[0])
    assert len(context.results) == 3 and len(context.correlation_groups) == 2
    assert len({r.observation.observation_key for r in context.results}) == 2
    assert {r.binding.model_id for r in context.results} == {
        "network_cse2018_lightgbm_v4b2",
        "network_cse2018_dnn_fp32",
        "dns_cicbell_dnn_int8",
    }
    for result in context.results:
        assert result.validation.status == "VALIDATED_FOR_ADVISORY"
        assert result.provenance.execution_environment_digest
        for artifact in result.binding.artifact_identity.files:
            with (artifacts / artifact.path).open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == artifact.sha256
    ingestion = EventIngestor(store)
    registry = ToolRegistry()
    registry.register(source_report_tool(ingestion))
    composition = compose_application(
        store,
        deployment=DeploymentDescriptor(profile=profile),
        ingestion=ingestion,
        registry=registry,
        llm_client=OfflineDesktopClient(),
    )
    asyncio.run(api_boundaries(composition.service, incident_id))
    with store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT COUNT(*) FROM execution_records").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM external_security_audit").fetchone()[0] > 0
        assert (
            connection.execute("SELECT COUNT(*) FROM external_decision_receipts").fetchone()[0] > 0
        )


async def api_boundaries(service, incident_id):
    identity, access = Boundary(), FixtureAccess()
    token = identity.issue(
        HumanActionContext(
            incident_id=incident_id,
            action=HumanAction.RECORD_REVIEW,
            binding_digest="a" * 64,
            decision_id="b" * 64,
        ),
        (HumanRole.ADMIN,),
    )
    app = SOCApplication(
        lambda: service, provider=identity.provider, provider_id="test-identity", access=access
    )
    messages = iter(({"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}))
    lifecycle = []

    async def receive():
        return next(messages)

    async def send(message):
        lifecycle.append(message["type"])

    await app({"type": "lifespan"}, receive, send)
    assert lifecycle == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    base = f"/incidents/{incident_id}"
    assert (await call(app, "GET", base + "/workflow"))[0] == 401
    assert (await call(app, "GET", base + "/workflow", token=token))[0] == 200
    access.denied = True
    assert (await call(app, "GET", base + "/workflow", token=token))[0] == 403
    access.denied = False
    assert (await call(app, "POST", base + "/approval-requests", {"execute": True}, token))[
        0
    ] == 422
    saved = service.checkpoint(incident_id)
    request = {"run_id": str(saved.run_id), "expected_revision": saved.revision}
    assert (await call(app, "POST", base + "/workflow/resume", request, token))[0] == 200
    assert (await call(app, "POST", base + "/workflow/resume", request, token))[0] == 409
