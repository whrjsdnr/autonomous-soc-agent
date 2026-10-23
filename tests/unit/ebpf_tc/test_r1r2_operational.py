"""Real locked temporary ledgers and synthetic clocks/sockets; no real approvals or traffic."""

import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_stabilization_campaign import approved
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import r2_diagnostic as r2
from soc_agent.security_ai.ebpf_tc import reassessment as r1
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.native_campaign import NativeCampaign
from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign


def h(body):
    return hashlib.sha256(body).hexdigest()


def artifact():
    return r1.Artifact(
        git_commit="1" * 40,
        git_tree="2" * 40,
        release="FIXTURE_NOT_NATIVE",
        manifest="a" * 64,
        bundle="b" * 64,
        image="c" * 64,
        root_manifest="d" * 64,
    )


@pytest.fixture
def review(stable):
    root, receipt, scope, dns = stable
    ledger = StabilizationCampaign(root, "BATCH2")
    a = artifact()
    old = ledger.reserve(
        dict(manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest),
        scope,
        dns,
        receipt,
        approved(stable, "BATCH2"),
        root_cost=1,
        git_commit=a.git_commit,
    )
    ledger.finish(old["attempt_id"], outcome="FAILED", evidence={"application_session": "previous"})
    negative = ledger._locked(
        lambda rows: dict(
            event="DIAGNOSTIC_E2E_EVIDENCE_REVIEW_COMPLETED",
            attempt_id=old["attempt_id"],
            safe_for_next_attempt=False,
        )
    )
    source = root / "owned-evidence.json"
    source.write_bytes(b'{"source":"SYNTHETIC_NO_NATIVE"}\n')
    evidence = r1.CleanupEvidence(
        sources={"native_result": h(source.read_bytes())},
        owned_fd_closed=True,
        owned_maps_remaining=0,
        owned_links_remaining=0,
        owned_filters_remaining=0,
        container_absent=True,
        drain_verified=True,
        new_unknown_programs=0,
        external_owner="wsl-pro.service",
    )
    binding = r1.Binding(
        previous_attempt=old["attempt_id"],
        previous_session="previous",
        previous_artifact=a,
        next_session="next",
        next_artifact=a,
        negative_review_sha=negative["record_sha256"],
        scope_sha=r1.digest(scope),
        evidence_sha=r1.digest(evidence.model_dump()),
    )
    now = int(time.time())
    procedure = r1.ProcedureApproval(
        decision="APPROVED",
        approver="FIXTURE_HUMAN",
        human_reference_sha="7" * 64,
        implementation_sha=h(Path(r1.__file__).read_bytes()),
        budget_sha=h(ledger.budget_body),
        baseline_sha=h(ledger.baseline_body),
        binding_sha=r1.digest(binding.model_dump()),
        issued_at=now - 5,
        expires_at=now + 100,
    )
    p = root / "procedure.json"
    p.write_bytes(canonical(procedure.model_dump()))
    review = r1.ReviewReceipt(
        receipt_id="FIXTURE_REVIEW_1",
        reviewer="FIXTURE_REVIEWER",
        human_reference_sha="8" * 64,
        procedure_sha=h(p.read_bytes()),
        binding=binding,
        ledger_tip_sha=negative["record_sha256"],
        decision="ALLOW_NEXT_ADMISSION_ONLY",
        accept_unknown_external_removal_cause=True,
        issued_at=now - 5,
        expires_at=now + 100,
    )
    receipt.write_bytes(canonical(review.model_dump()))
    return dict(
        campaign=ledger,
        procedure_file=p,
        procedure_sha=h(p.read_bytes()),
        receipt_file=receipt,
        receipt_sha=h(receipt.read_bytes()),
        evidence=evidence,
        source_paths={"native_result": source},
        expected_binding=binding,
    )


def rewrite_receipt(review, **changes):
    p = review["receipt_file"]
    data = json.loads(p.read_bytes()) | changes
    p.write_bytes(canonical(data))
    review["receipt_sha"] = h(p.read_bytes())


def test_r1_append_preserves_prefix_and_legacy_block(review):
    ledger = review["campaign"]
    path = ledger.directory / "execution-ledger.jsonl"
    before = path.read_bytes()
    event = r1.reassess(**review)
    assert event["event"] == "SAFETY_REASSESSMENT_RECORDED_V1"
    assert "safe_for_next_attempt" not in event
    assert path.read_bytes().startswith(before)
    assert event["evidence"]["global_cleanup"] == "UNVERIFIED"
    with pytest.raises(ValueError, match="PREVIOUS_ATTEMPT_UNREVIEWED"):
        ledger._locked(lambda rows: dict(event="NATIVE_ATTEMPT_RESERVED", root_cost=0))


@pytest.mark.parametrize(
    "field,value",
    [
        ("ledger_tip_sha", "0" * 64),
        ("procedure_sha", "0" * 64),
        ("issued_at", 2**40),
        ("expires_at", 1),
        ("authorize_native", True),
        ("max_next_attempts", True),
        ("accept_unknown_external_removal_cause", False),
    ],
)
def test_r1_reject_without_write(review, field, value):
    rewrite_receipt(review, **{field: value})
    path = review["campaign"].directory / "execution-ledger.jsonl"
    before = path.read_bytes()
    with pytest.raises((ValueError, ValidationError)):
        r1.reassess(**review)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("previous_session", "wrong"),
        ("next_session", "wrong"),
        ("scope_sha", "0" * 64),
        ("next_artifact", artifact().model_dump() | {"image": "0" * 64}),
    ],
)
def test_r1_binding_mismatch(review, field, value):
    data = json.loads(review["receipt_file"].read_bytes())
    rewrite_receipt(review, binding=data["binding"] | {field: value})
    with pytest.raises(ValueError, match="BINDING"):
        r1.reassess(**review)


def test_r1_mutated_evidence_and_receipt(review):
    review["source_paths"]["native_result"].write_bytes(b"changed")
    with pytest.raises(ValueError, match="EVIDENCE_SHA"):
        r1.reassess(**review)
    review["receipt_sha"] = "0" * 64
    with pytest.raises(ValueError, match="RECEIPT_SHA"):
        r1.reassess(**review)


def test_r1_stale_and_replay(review):
    event = r1.reassess(**review)
    rewrite_receipt(review, ledger_tip_sha=event["record_sha256"])
    with pytest.raises(ValueError, match="REPLAY"):
        r1.reassess(**review)


def test_r1_concurrent_append(review):
    NativeCampaign._locked(review["campaign"], lambda rows: {"event": "FIXTURE_CONCURRENT_CHANGE"})
    with pytest.raises(ValueError, match="STALE"):
        r1.reassess(**review)


@pytest.fixture
def launcher(tmp_path, monkeypatch):
    monkeypatch.setattr(r2, "_udp_witness", lambda: {"synthetic": True})
    receipt = r2.TrafficReceipt(
        decision="APPROVED",
        approver="FIXTURE",
        human_reference_sha="a" * 64,
        session="00000000-0000-0000-0000-000000000001",
        artifact=artifact(),
        claim_path=str(tmp_path / "claim"),
        scenario=r2.Scenario(),
        implementation_sha=h(Path(r2.__file__).read_bytes()),
        issued_at=int(time.time()) - 5,
        expires_at=int(time.time()) + 100,
    )
    path = tmp_path / "traffic.json"
    path.write_bytes(canonical(receipt.model_dump()))
    return r2.LaunchApproval(
        path, h(path.read_bytes()), receipt.session, artifact(), tmp_path / "claim"
    )


def step(launch, seconds, **changes):
    return launch.advance(
        seconds * r2.SECOND,
        **dict(tcp_closed_ns=2 * r2.SECOND, sidecar_closed=True, received=12, capture_closed=False)
        | changes,
    )


def test_r2_single_late_witness_and_stop(launcher):
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    assert not step(launch, 36)
    assert not launch.attempted
    assert not step(launch, 37)
    assert launch.witness == {"synthetic": True}
    assert not step(launch, 38)
    assert step(launch, 47)
    assert launch.stop_reason == "PLANNED_STOP"
    assert launch.snapshot()["eligibility"] == "NOT_ASSESSED_BY_LAUNCHER"


@pytest.mark.parametrize("changes", [{"received": 4096}, {"capture_closed": True}])
def test_r2_early_end_no_witness(launcher, changes):
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    assert step(launch, 13, **changes)
    assert launch.witness is None
    assert launch.stop_reason.startswith("INCOMPLETE")


def test_r2_sidecar_and_clock_boundaries(launcher):
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    with pytest.raises(ValueError, match="SIDECAR"):
        step(launch, 37, sidecar_closed=False)
    with pytest.raises(ValueError, match="CLOCK"):
        step(launch, 36)


def test_r2_skip_witness_on_late_tick(launcher):
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    assert step(launch, 47)
    assert launch.stop_reason == "INCOMPLETE_NO_WITNESS"


def test_r2_no_retry_after_failed_send(launcher, monkeypatch):
    def fail():
        raise TimeoutError("FIXTURE")

    monkeypatch.setattr(r2, "_udp_witness", fail)
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    with pytest.raises(TimeoutError):
        step(launch, 37)
    assert launch.attempted
    assert not step(launch, 38)
    assert launch.witness is None


def test_r2_claim_replay_and_path_binding(launcher):
    r2.R2Launcher(launcher).start(0)
    with pytest.raises(FileExistsError):
        r2.R2Launcher(launcher).start(0)
    with pytest.raises(ValueError, match="BINDING"):
        r2.R2Launcher(replace(launcher, claim_file=launcher.claim_file.with_name("other")))


@pytest.mark.parametrize(
    "change",
    [
        {"session": "wrong"},
        {"receipt_sha": "0" * 64},
        {"artifact": artifact().model_copy(update={"image": "0" * 64})},
    ],
)
def test_r2_approval_failure_before_claim(launcher, change):
    with pytest.raises(ValueError):
        r2.R2Launcher(replace(launcher, **change))
    assert not launcher.claim_file.exists()


def test_r2_scope_and_literal_guards():
    for change in (
        {"udp_queries": 3},
        {"sidecar_seconds": 45},
        {"tcp_queries": True},
        {"max_events": 8192},
        {"queue": 64},
    ):
        with pytest.raises(ValidationError):
            r2.Scenario(**change)


def activate_fixture(review, stable, *, decision="APPROVED"):
    from soc_agent.security_ai.ebpf_tc import reassessment_admission as admission

    event = r1.reassess(**review)
    ledger = review["campaign"]
    data = dict(
        decision=decision,
        approver="FIXTURE_POLICY_REVIEWER",
        human_reference_sha="9" * 64,
        implementation_sha=h(Path(admission.__file__).read_bytes()),
        base_controller_sha=ledger.controller_sha,
        budget_sha=h(ledger.budget_body),
        baseline_sha=h(ledger.baseline_body),
        binding=review["expected_binding"].model_dump(),
        reassessment_record_sha=event["record_sha256"],
        review_receipt_sha=review["receipt_sha"],
        expires_at=int(time.time()) + 100,
        activate_versioned_admission=True,
    )
    path = ledger.directory / "FIXTURE_amendment.json"
    path.write_bytes(canonical(data))
    adapter = admission.ReassessedCampaign(
        ledger.directory, amendment_file=path, amendment_sha=h(path.read_bytes())
    )
    root, execution_path, scope, dns = stable
    approved(stable, "BATCH2", 2)
    execution = json.loads(execution_path.read_bytes()) | dict(
        admission_amendment_sha=adapter.amendment_sha,
        next_session="next",
        reassessment_record_sha=event["record_sha256"],
        r2_receipt_sha="f" * 64,
    )
    execution_path.write_bytes(canonical(execution))
    return adapter, execution_path, scope, dns


def test_versioned_admission_needs_separate_grant_and_uses_same_budget(review, stable):
    from soc_agent.security_ai.ebpf_tc import reassessment_admission as admission

    adapter, path, scope, dns = activate_fixture(review, stable)
    a = artifact()
    identity = dict(
        manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest
    )
    event = adapter.reserve(identity, scope, dns, path, h(path.read_bytes()), root_cost=1)
    assert event["native_used"] == event["root_installations_used"] == 2
    assert event["next_session"] == "next"
    before = (adapter.directory / "execution-ledger.jsonl").read_bytes()
    admission.require_r2_reservation(
        adapter.directory, session="next", receipt_sha="f" * 64, identity=identity
    )
    assert (adapter.directory / "execution-ledger.jsonl").read_bytes() == before
    with pytest.raises(ValueError, match="RESERVATION_REQUIRED"):
        admission.require_r2_reservation(
            adapter.directory, session="wrong", receipt_sha="f" * 64, identity=identity
        )
    with pytest.raises(ValueError):
        adapter.reserve(identity, scope, dns, path, h(path.read_bytes()), root_cost=1)
    adapter.finish(event["attempt_id"], outcome="FAILED", evidence={})
    with pytest.raises(ValueError, match="RESERVATION_REQUIRED"):
        admission.require_r2_reservation(
            adapter.directory, session="next", receipt_sha="f" * 64, identity=identity
        )


def test_versioned_admission_stale_ledger(review, stable):
    adapter, path, scope, dns = activate_fixture(review, stable)
    NativeCampaign._locked(adapter, lambda rows: {"event": "FIXTURE_CHANGED"})
    a = artifact()
    with pytest.raises(ValueError, match="STALE"):
        adapter.reserve(
            dict(manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest),
            scope,
            dns,
            path,
            h(path.read_bytes()),
            root_cost=1,
        )


def test_versioned_admission_unapproved(review, stable):
    with pytest.raises(ValidationError):
        activate_fixture(review, stable, decision="REQUESTED_NOT_APPROVED")


@pytest.mark.parametrize(
    "change",
    [
        {"owned_fd_closed": False},
        {"owned_maps_remaining": 1},
        {"drain_verified": False},
        {"new_unknown_programs": 1},
        {"external_owner": "UNKNOWN"},
    ],
)
def test_r1_owned_evidence_fail_closed(review, change):
    evidence = r1.CleanupEvidence.model_validate(review["evidence"].model_dump() | change)
    binding = r1.Binding.model_validate(
        review["expected_binding"].model_dump()
        | dict(evidence_sha=r1.digest(evidence.model_dump()))
    )
    review["evidence"], review["expected_binding"] = evidence, binding
    p = review["procedure_file"]
    procedure = json.loads(p.read_bytes()) | dict(binding_sha=r1.digest(binding.model_dump()))
    p.write_bytes(canonical(procedure))
    review["procedure_sha"] = h(p.read_bytes())
    rewrite_receipt(review, binding=binding.model_dump(), procedure_sha=review["procedure_sha"])
    with pytest.raises(ValueError, match="CLEANUP"):
        r1.reassess(**review)


def test_r2_udp_wire_contract_without_network(monkeypatch):
    import struct

    calls = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            calls.append("CLOSED")

        def settimeout(self, value):
            assert value == 1

        def bind(self, value):
            assert value == ("127.0.0.1", 0)

        def connect(self, value):
            assert value == ("127.0.0.53", 53)

        def send(self, message):
            calls.append(message)
            return len(message)

        def recv(self, bound):
            assert bound == 513
            return struct.pack("!6H", 0xC203, 0x8180, 1, 0, 0, 0) + r2.QUESTION

        def getsockname(self):
            return ("127.0.0.1", 12345)

    monkeypatch.setattr(r2, "local_controller", lambda: None)
    monkeypatch.setattr(r2.os, "readlink", lambda *_: "net:[4026531833]")
    monkeypatch.setattr(r2.socket, "socket", lambda *args: FakeSocket())
    result = r2._udp_witness()
    assert len(calls) == 2 and calls[-1] == "CLOSED"
    assert result["transaction_id"] == 0xC203 and result["rcode"] == 0


@pytest.mark.parametrize("fails", [False, True])
def test_r1_r2_dispatch_existing_supervisor_once(review, stable, tmp_path, monkeypatch, fails):
    from types import SimpleNamespace

    from soc_agent.security_ai.ebpf_tc import phase_d, reassessment_admission, unified_image

    adapter, approval, scope, dns = activate_fixture(review, stable)
    root = adapter.directory
    traffic = r2.TrafficReceipt(
        decision="APPROVED",
        approver="FIXTURE",
        human_reference_sha="b" * 64,
        session="next",
        claim_path=str(tmp_path / "claim"),
        artifact=artifact(),
        scenario=r2.Scenario(),
        implementation_sha=h(Path(r2.__file__).read_bytes()),
        issued_at=int(time.time()) - 5,
        expires_at=int(time.time()) + 100,
    )
    path = tmp_path / "traffic.json"
    path.write_bytes(canonical(traffic.model_dump()))
    data = json.loads(approval.read_bytes()) | {"r2_receipt_sha": h(path.read_bytes())}
    approval.write_bytes(canonical(data))
    directory = tmp_path / "stage"
    (directory / "dns-sidecar").mkdir(parents=True)
    (directory / "dns-sidecar/release.json").write_bytes(canonical({"scope": dns}))
    monkeypatch.setattr(
        phase_d,
        "validate",
        lambda *a: dict(
            bundle=artifact().bundle, tcx_manifest=artifact().root_manifest, scope=scope
        ),
    )
    monkeypatch.setattr(unified_image, "installed_release", lambda: SimpleNamespace(identity="old"))
    calls = []

    def existing_supervisor(stage, manifest, image, *, gui, r2_approval):
        calls.append((stage, r2_approval.session))
        assert gui is False and not r2_approval.claim_file.exists()
        if fails:
            raise OSError(5, "FIXTURE_NO_NATIVE")
        result = {"cleanup_status": "PROCESS_AND_AUDIT_VERIFIED", "broker_session": "next"}
        (stage / "supervised-result.json").write_bytes(canonical(result))
        return result

    monkeypatch.setattr(phase_d, "execute", existing_supervisor)
    kwargs = dict(
        campaign=root,
        amendment_file=root / "FIXTURE_amendment.json",
        amendment_sha=adapter.amendment_sha,
        approval_file=approval,
        approval_sha=h(approval.read_bytes()),
        traffic_file=path,
        traffic_sha=h(path.read_bytes()),
        claim_file=tmp_path / "claim",
    )
    if fails:
        with pytest.raises(OSError) as error:
            reassessment_admission.execute(
                directory, artifact().manifest, artifact().image, **kwargs
            )
        assert error.value.errno == 5
    else:
        reassessment_admission.execute(directory, artifact().manifest, artifact().image, **kwargs)
    assert calls == [(directory, "next")]
    rows = [
        json.loads(line) for line in (root / "execution-ledger.jsonl").read_bytes().splitlines()
    ]
    assert rows[-1]["event"] == "NATIVE_ATTEMPT_FINISHED"
    assert rows[-1]["outcome"] == ("FAILED" if fails else "RETURNED_PENDING_EVIDENCE_REVIEW")
    assert rows[-1]["native_verified"] is False
