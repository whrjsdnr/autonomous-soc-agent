"""Real CLI, image and private Ledger; no Root, DNS, reservation or approvals consumed."""

import json
import threading
import time
from pathlib import Path

import pytest
from tests.unit.ebpf_tc.test_controller_admission_path import (  # noqa: F401
    admission as admission_fixture,
)
from tests.unit.ebpf_tc.test_controller_admission_path import built as built  # noqa: F401
from tests.unit.ebpf_tc.test_controller_admission_path import fixture as fixture  # noqa: F401
from tests.unit.ebpf_tc.test_controller_admission_path import package as package  # noqa: F401
from tests.unit.ebpf_tc.test_controller_admission_path import stable as stable  # noqa: F401
from tests.unit.ebpf_tc.test_r1r2_operational import h

from soc_agent.security_ai.ebpf_tc import namespace_controller, operational_recovery
from soc_agent.security_ai.ebpf_tc import request_handoff as handoff
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.native_campaign import NativeCampaign

admission = admission_fixture


def publish(admission):
    config, request, _, _, _ = admission
    target = Path(config["request_file"])
    target.unlink()  # Fixture setup only: publication requires a new absent path.
    ready = handoff.publish_request(target, request)
    return target, ready


@pytest.mark.parametrize(
    "fault", [None, "sha", "missing", "partial", "stale", "session", "release", "replay"]
)
def test_real_cli_handoff_and_controller(admission, monkeypatch, fault):
    config, request, ledger, path, claim = admission
    before = path.read_bytes()
    target, ready = publish(admission)
    assert ready["session"] == ledger.amendment.binding.next_session
    assert (
        ready["preparation_started_ns"]
        <= ready["preparation_completed_ns"]
        <= ready["ready_published_ns"]
    )
    assert not ready["authorizes_execution"]
    if fault in {"sha", "partial"}:
        target.write_bytes(
            b"{"
            if fault == "partial"
            else canonical(request.model_dump() | dict(manifest="0" * 64))
        )
    elif fault == "missing":
        target.unlink()
    elif fault == "stale":
        NativeCampaign._locked(ledger, lambda _: dict(event="SYNTHETIC_UNRELATED_APPEND"))
    elif fault in {"session", "release"}:
        marker = handoff.ready_path(target)
        value = json.loads(marker.read_bytes())
        value[fault] = "WRONG_IDENTITY"
        marker.write_bytes(canonical(value))
    elif fault == "replay":
        claim.write_text("SYNTHETIC_CONSUMED_TRAFFIC")
    if fault:
        with pytest.raises((ValueError, FileNotFoundError)):
            handoff.verify_ready(target)
    else:
        observed = handoff.wait_for_request(target, timeout=0)
        results = []
        args = namespace_controller.check_request(
            config, observed["request_sha"], {"request_ready": observed}, results.append
        )
        assert args[0] == request.directory
        assert results[-1]["status"] == "EXECUTION_READY"
        with pytest.raises(ValueError, match="PUBLICATION_REPLAY"):
            handoff.publish_request(target, request)
    if fault != "stale":
        assert path.read_bytes() == before
    assert claim.exists() is (fault == "replay")


def test_delayed_atomic_publication_does_not_read_pending_request(admission, monkeypatch):
    config, request, _, ledger_path, _ = admission
    path = Path(config["request_file"])
    path.unlink()
    pending = path.parent / ".request-pending-unpublished"
    pending.write_text('{"partial":')
    before = ledger_path.read_bytes()
    failures = []

    def publisher():
        try:
            time.sleep(0.05)
            handoff.publish_request(path, request)
        except Exception as exc:
            failures.append(exc)

    thread = threading.Thread(target=publisher)
    thread.start()
    ready = handoff.wait_for_request(path, timeout=3)
    thread.join()
    assert failures == [] and ready["request_sha"] == h(path.read_bytes())
    assert pending.read_text() == '{"partial":'
    assert ledger_path.read_bytes() == before


def test_ready_required_before_controller_reads_request(admission):
    config, _, _, ledger, _ = admission
    path = Path(config["request_file"])
    before = ledger.read_bytes()
    with pytest.raises(TimeoutError, match="READY_TIMEOUT"):
        handoff.wait_for_request(path, timeout=0)
    with pytest.raises(ValueError, match="NOT_READY"):
        namespace_controller.check_request(
            config, h(path.read_bytes()), {"request_ready": {}}, None
        )
    path.unlink()
    with pytest.raises(TimeoutError, match="READY_TIMEOUT"):
        handoff.wait_for_request(path, timeout=0)
    assert ledger.read_bytes() == before


def test_publication_cli_and_failure_never_publish_ready(admission, capsys, tmp_path):
    config, request, _, ledger, _ = admission
    target = Path(config["request_file"])
    target.unlink()
    packet = tmp_path / "publication.json"
    packet.write_bytes(
        canonical(
            dict(
                kind="EXECUTION_REQUEST_PUBLICATION",
                request_file=str(target),
                request=request.model_dump(),
            )
        )
    )
    before = ledger.read_bytes()
    code = operational_recovery.main(
        [
            "prepare",
            request.directory,
            "--request-preparation-file",
            str(packet),
            "--request-preparation-sha",
            h(packet.read_bytes()),
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["contract"] == "SOC_EXECUTION_REQUEST_READY_V1"
    assert handoff.verify_ready(target)["ledger"]["sha256"] == h(before)
    assert (
        operational_recovery.main(
            [
                "execute",
                request.directory,
                "--request-preparation-file",
                str(packet),
                "--request-preparation-sha",
                h(packet.read_bytes()),
            ]
        )
        == 2
    )
    assert ledger.read_bytes() == before


def test_invalid_receipt_prevents_ready(admission):
    config, request, _, ledger, _ = admission
    target = Path(config["request_file"])
    target.unlink()
    before = ledger.read_bytes()
    broken = request.model_copy(update=dict(approval_sha="0" * 64))
    with pytest.raises(ValueError):
        handoff.publish_request(target, broken)
    assert target.exists()  # Complete failed bytes preserved; never treated as ready.
    assert not handoff.ready_path(target).exists()
    assert ledger.read_bytes() == before


@pytest.fixture
def r1_input(stable, built, tmp_path):
    from tests.unit.ebpf_tc.test_r1r2_operational import review

    from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
    from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign

    history = review.__wrapped__(stable)
    campaign = stable[0]
    directory, image, _ = built
    ledger = StabilizationCampaign(campaign, "BATCH2")
    NativeCampaign._locked(
        ledger,
        lambda _: dict(
            event="ROOT_OPERATION_FINISHED_V1", state="SUCCEEDED", attempt_id="SYNTHETIC_ROOT_ENTRY"
        ),
    )
    snapshot = handoff.ledger_snapshot(campaign)
    plan = ApplicationPlan(
        controller=local_controller(),
        mode="PHASE_A_NATIVE_BLOCKED",
        scope=Scope(
            net_namespace="net:[4026532999]",
            ifindex=1,
            hook="INGRESS",
            program_sha256="a" * 64,
            loader_sha256="b" * 64,
            bundle_digest="c" * 64,
        ),
    )
    # Read the exact synthetic Namespace from the actual built Phase D image.
    ns = json.loads((directory / "phase-d.json").read_bytes())["scope"]["namespace"]
    plan = plan.model_copy(update=dict(scope=plan.scope.model_copy(update=dict(net_namespace=ns))))
    plan_file = tmp_path / "official-plan.json"
    plan_file.write_bytes(canonical(plan.model_dump(mode="json")))
    prior = tmp_path / "historical-evidence.json"
    prior.write_bytes(
        canonical(
            dict(
                binding=history["expected_binding"].model_dump(mode="json"),
                evidence=history["evidence"].model_dump(mode="json"),
                source_paths={k: str(v) for k, v in history["source_paths"].items()},
            )
        )
    )
    ack = tmp_path / "controller-ready.json"
    ack.write_bytes(
        canonical(
            dict(
                stage="REQUEST_INPUT",
                root_entry=dict(state="SUCCEEDED", record_sha256=snapshot["head"]),
                ledger_at_ack=snapshot,
                namespace=ns,
                artifact=dict(
                    directory=str(directory),
                    campaign=str(campaign),
                    manifest=image["manifest"],
                    image_sha=image["image"],
                ),
            )
        )
    )
    packet = dict(
        kind="R1_REVIEW_PREPARATION",
        campaign=str(campaign),
        manifest=image["manifest"],
        image_sha=image["image"],
        controller_ready_file=str(ack),
        controller_ready_sha=h(ack.read_bytes()),
        historical_evidence_file=str(prior),
        historical_evidence_sha=h(prior.read_bytes()),
        plan_file=str(plan_file),
        plan_sha=h(plan_file.read_bytes()),
        output_file=str(tmp_path / "pending-r1.json"),
    )
    return directory, packet, history, ledger, plan


def test_r1_cli_derives_current_binding_without_approval(r1_input, capsys):
    directory, packet, history, ledger, plan = r1_input
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    path = Path(packet["output_file"]).with_name("prepare-r1.json")
    path.write_bytes(canonical(packet))
    assert (
        operational_recovery.main(
            [
                "prepare",
                str(directory),
                "--request-preparation-file",
                str(path),
                "--request-preparation-sha",
                h(path.read_bytes()),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "PENDING_EXPLICIT_HUMAN_RISK_ACCEPTANCE"
    assert result["binding"]["next_session"] == str(plan.application_session)
    assert result["binding"]["next_session"] != history["expected_binding"].next_session
    assert result["binding"]["next_artifact"]["manifest"] == packet["manifest"]
    assert result["binding"]["previous_attempt"] == history["expected_binding"].previous_attempt
    assert result["preparation_ledger"]["sha256"] == h(before)
    assert not result["authorizes_execution"]
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize("fault", ["stale", "artifact", "namespace", "session_replay"])
def test_r1_preparation_rejects_old_or_foreign_context(r1_input, fault):
    directory, packet, _, ledger, plan = r1_input
    if fault == "stale":
        NativeCampaign._locked(ledger, lambda _: dict(event="SYNTHETIC_UNRELATED_APPEND"))
    elif fault == "artifact":
        packet["manifest"] = "0" * 64
    else:
        marker = Path(packet["controller_ready_file"])
        ready = json.loads(marker.read_bytes())
        if fault == "namespace":
            ready["namespace"] = "net:[4026531833]"
        else:
            NativeCampaign._locked(
                ledger,
                lambda _: dict(
                    event="SAFETY_REASSESSMENT_RECORDED_V1",
                    binding=dict(next_session=str(plan.application_session)),
                ),
            )
            last = NativeCampaign._locked(
                ledger,
                lambda _: dict(
                    event="ROOT_OPERATION_FINISHED_V1",
                    state="SUCCEEDED",
                    attempt_id="SYNTHETIC_LATEST_ENTRY",
                ),
            )
            ready["ledger_at_ack"] = handoff.ledger_snapshot(ledger.directory)
            ready["root_entry"]["record_sha256"] = last["record_sha256"]
        marker.write_bytes(canonical(ready))
        packet["controller_ready_sha"] = h(marker.read_bytes())
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError):
        handoff.prepare_r1(directory, packet)
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_malformed_ready_fails_explicitly(admission):
    config, _, _, ledger, _ = admission
    target = Path(config["request_file"])
    before = ledger.read_bytes()
    handoff.ready_path(target).write_bytes(b"{")
    with pytest.raises(ValueError, match="EXECUTION_REQUEST_READY_JSON"):
        handoff.wait_for_request(target, timeout=0)
    assert ledger.read_bytes() == before


def test_official_plan_pin_rejects_different_session(r1_input):
    directory, packet, _, ledger, _ = r1_input
    path = Path(packet["plan_file"])
    value = json.loads(path.read_bytes())
    value["application_session"] = "00000000-0000-4000-8000-000000000099"
    path.write_bytes(canonical(value))
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="RECEIPT_SHA_MISMATCH"):
        handoff.prepare_r1(directory, packet)
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_pending_r1_ledger_snapshot_is_rechecked_by_reassess_cli(r1_input, capsys):
    directory, packet, history, ledger, _ = r1_input
    pending = handoff.prepare_r1(directory, packet)
    output = Path(packet["output_file"])
    output.write_bytes(canonical(pending))
    NativeCampaign._locked(ledger, lambda _: dict(event="SYNTHETIC_NEW_LEDGER_EVENT"))
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    args = [
        "reassess",
        str(directory),
        "--campaign",
        str(ledger.directory),
        "--procedure-file",
        str(history["procedure_file"]),
        "--procedure-sha",
        history["procedure_sha"],
        "--review-file",
        str(history["receipt_file"]),
        "--review-sha",
        history["receipt_sha"],
        "--evidence-file",
        str(output),
        "--evidence-sha",
        h(output.read_bytes()),
    ]
    assert operational_recovery.main(args) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "R1_PREPARATION_STALE_LEDGER"
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before
