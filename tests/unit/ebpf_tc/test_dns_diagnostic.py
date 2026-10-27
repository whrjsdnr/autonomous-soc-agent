"""Temporary receipts/ledgers, memory DNS sockets and compile-only images. No Root."""

import json
import os
from types import SimpleNamespace

import pytest
from tests.unit.ebpf_tc.test_isolated_dns_launcher import lease
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_root_governance import allocate, rows
from tests.unit.ebpf_tc.test_root_governance import governance as governance
from tests.unit.ebpf_tc.test_root_operations import package as package
from tests.unit.ebpf_tc.test_root_operations import setup as setup
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_tc import dns_diagnostic as dns
from soc_agent.security_ai.ebpf_tc import dns_diagnostic_engine as engine
from soc_agent.security_ai.ebpf_tc import isolated_dns_launcher
from soc_agent.security_ai.ebpf_tc import root_governance as gov
from soc_agent.security_ai.ebpf_tc import root_operations as root
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.operational_recovery import main
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, digest
from soc_agent.security_ai.native_campaign import sha
from soc_agent.security_ai.operation_budget import (
    DNS_ALLOCATION_EVENT,
    ROOT_FINISHED,
    ROOT_RESERVED,
    batch_root_limit,
    guard_reservation,
    totals,
)


def amendment(governance):
    s, kw = allocate(governance)
    parent = gov.allocate_root(s.ledger, **kw)
    policy = root.RootPolicy.model_validate_json(s.policy_file.read_bytes())
    review = json.loads(kw["review_file"].read_bytes())
    review["budget"]["DNS"] = dict(
        proposed_batch3_total_root_cap=4,
        human_reference_sha="9" * 64,
        approver=policy.approver,
    )
    path = s.ledger.directory / "dns-review.json"
    path.write_bytes(canonical(review))
    grant = gov.RootDNSAllocation(
        decision="APPROVED",
        approver=policy.approver,
        human_reference_sha="9" * 64,
        approved_binding=s.binding,
        review_package_sha=sha(path.read_bytes()),
        budget_sha=sha(s.ledger.budget_body),
        baseline_sha=sha(s.ledger.baseline_body),
        ledger_tip_sha=parent["record_sha256"],
        policy_record_sha=policy_record(s),
        previous_allocation_record_sha=parent["record_sha256"],
        issued_at=policy.issued_at,
        expires_at=policy.expires_at,
    )
    file = s.ledger.directory / "dns-allocation.json"
    file.write_bytes(canonical(grant.model_dump()))
    return s, dict(
        review_file=path,
        review_sha=sha(path.read_bytes()),
        allocation_file=file,
        allocation_sha=sha(file.read_bytes()),
    )


def policy_record(s):
    return next(r["record_sha256"] for r in rows(s) if r.get("event") == "ROOT_POLICY_ACTIVATED_V1")


def test_dns_amendment_is_append_only_and_does_not_consume(governance):
    s, kw = amendment(governance)
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    budget = (s.ledger.directory / "budget.json").read_bytes()
    event = gov.allocate_dns_root(s.ledger, **kw)
    assert event["event"] == DNS_ALLOCATION_EVENT and event["authorizes_execution"] is False
    assert batch_root_limit(rows(s), s.ledger.budget, "BATCH3") == 4
    assert totals(rows(s)) == (0, 0)
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes().startswith(before)
    assert (s.ledger.directory / "budget.json").read_bytes() == budget
    with pytest.raises(ValueError, match="REPLAY"):
        gov.allocate_dns_root(s.ledger, **kw)


@pytest.mark.parametrize("change", ["stale", "parent", "review", "native", "cap", "expired"])
def test_invalid_dns_allocation_never_appends(governance, change):
    s, kw = amendment(governance)
    grant = json.loads(kw["allocation_file"].read_bytes())
    if change == "stale":
        grant["ledger_tip_sha"] = "a" * 64
    if change == "parent":
        grant["previous_allocation_record_sha"] = "a" * 64
    if change == "review":
        grant["review_package_sha"] = "a" * 64
    if change == "native":
        grant["native_max"] = 3
    if change == "cap":
        grant["campaign_root_max"] = 11
    if change == "expired":
        grant["expires_at"] = 1
    kw["allocation_file"].write_bytes(canonical(grant))
    kw["allocation_sha"] = sha(kw["allocation_file"].read_bytes())
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError):
        gov.allocate_dns_root(s.ledger, **kw)
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def reserve_fake(rs, operation, attempt):
    event = dict(
        event=ROOT_RESERVED,
        operation=operation,
        batch="BATCH3",
        attempt_id=attempt,
        native_cost=0,
        root_cost=1,
    )
    return event, dict(event=ROOT_FINISHED, attempt_id=attempt, outcome="SUCCEEDED")


def test_four_slots_preserve_native_installation_and_campaign_limit(governance):
    s, kw = amendment(governance)
    gov.allocate_dns_root(s.ledger, **kw)
    data = rows(s)
    for n, operation in enumerate(
        ["ROOT_SETUP", "ROOT_DNS_DIAGNOSTIC", "ROOT_INSTALL", "ROOT_INSTALL"]
    ):
        event, finish = reserve_fake(data, operation, str(n))
        guard_reservation(data, event, s.ledger.budget, "BATCH3")
        data += [event, finish]
    assert totals(data) == (0, 4)
    event, _ = reserve_fake(data, "ROOT_INSTALL", "overflow")
    with pytest.raises(ValueError):
        guard_reservation(data, event, s.ledger.budget, "BATCH3")
    event, _ = reserve_fake(data, "ROOT_DNS_DIAGNOSTIC", "duplicate")
    with pytest.raises(ValueError):
        guard_reservation(data, event, s.ledger.budget, "BATCH3")
    event, _ = reserve_fake(data, "ROOT_INSTALL", "campaign")
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        guard_reservation(data, event, s.ledger.budget | dict(root_installations_used=10), "BATCH3")


def test_existing_three_slot_grant_cannot_admit_dns(governance):
    s, kw = allocate(governance)
    gov.allocate_root(s.ledger, **kw)
    event, _ = reserve_fake(rows(s), "ROOT_DNS_DIAGNOSTIC", "attempt")
    with pytest.raises(ValueError, match="ROOT_DNS_ALLOCATION_REQUIRED"):
        guard_reservation(rows(s), event, s.ledger.budget, "BATCH3")


def test_cli_records_only_budget_amendment_and_blocks_replay(governance, capsys):
    s, kw = amendment(governance)
    packet = dict(kind="ROOT_DNS_ALLOCATION", **{k: str(v) for k, v in kw.items()})
    path = s.ledger.directory / "packet.json"
    path.write_bytes(canonical(packet))
    args = [
        "reassess",
        str(s.ledger.directory),
        "--campaign",
        str(s.ledger.directory),
        "--root-governance-file",
        str(path),
        "--root-governance-sha",
        sha(path.read_bytes()),
    ]
    assert main(args) == 0
    assert DNS_ALLOCATION_EVENT in capsys.readouterr().out
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    assert main(args) == 2
    assert "REPLAY" in capsys.readouterr().out
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before
    assert totals(rows(s)) == (0, 0)


@pytest.fixture
def diagnostic(setup, tmp_path, monkeypatch):
    origin = setup.binding
    fake = lease(origin)
    monkeypatch.setattr(dns, "inspect_lease", lambda *_: fake)
    monkeypatch.setattr(isolated_dns_launcher, "inspect_lease", lambda *_: fake)
    plan = ApplicationPlan(
        controller=local_controller(),
        mode="PHASE_A_NATIVE_BLOCKED",
        scope=Scope(
            net_namespace=fake["namespace"],
            ifindex=1,
            hook="INGRESS",
            program_sha256="a" * 64,
            loader_sha256="b" * 64,
            bundle_digest="c" * 64,
        ),
    )
    output = tmp_path / "diagnostic"
    result = dns.prepare(
        output,
        package=setup.manifest.parent,
        root_manifest=origin.artifact.root_manifest,
        origin=origin,
        lease_file=tmp_path / "lease.json",
        lease_sha="d" * 64,
        source_snapshot="e" * 64,
        plan=plan,
    )
    binding = root.RootBinding(
        session=str(plan.application_session),
        artifact=Artifact(
            git_commit="1" * 40,
            git_tree="2" * 40,
            release=origin.artifact.release,
            manifest=result["manifest"],
            image=result["image"],
            bundle=result["bundle"],
            root_manifest=result["root_manifest"],
        ),
        source_snapshot="e" * 64,
        scope_sha=digest(result["scope"]),
        installed_manifest=origin.installed_manifest,
        rollback_manifest=origin.rollback_manifest,
    )
    setup.binding = binding
    return setup, output, result


def test_real_builder_creates_validating_entry_without_root(diagnostic):
    s, output, result = diagnostic
    metadata = dns.verify(output, s.binding)
    assert metadata["config"]["scope"] == result["scope"]
    body = (output / "dns-diagnostic.py").read_text()
    assert "from soc_agent" not in body
    ns = {"__name__": "fixture"}
    exec(compile(body, "<fixture>", "exec"), ns)
    assert callable(ns["dns_root_main"]) and callable(ns["diagnostic_worker"])
    assert callable(ns["_candidate_policy"])
    assert (
        ns["DNS_POLICY_IMAGE"]["files"]["bootstrap"]["sha256"]
        == metadata["config"]["password_policy_bootstrap_sha"]
    )
    with pytest.raises(SystemExit) as blocked:
        exec(compile(body, "<fixture>", "exec"), {"__name__": "__main__"})
    assert blocked.value.code == 1
    command = dns.command(output, s.binding, {"fixture": "not-executed"})
    assert command[:9] == (
        "/usr/bin/sudo",
        "-k",
        "-u",
        "root",
        "--",
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
    )


@pytest.mark.parametrize("change", ["session", "scope", "image", "source"])
def test_artifact_binding_fail_closed(diagnostic, change):
    s, output, _ = diagnostic
    data = s.binding.model_dump()
    if change == "session":
        data["session"] = "11111111-1111-4111-8111-111111111111"
    if change == "scope":
        data["scope_sha"] = "a" * 64
    if change == "image":
        data["artifact"]["image"] = "a" * 64
    if change == "source":
        data["source_snapshot"] = "a" * 64
    with pytest.raises(ValueError):
        dns.verify(output, root.RootBinding.model_validate(data))


def test_missing_policy_cannot_reach_authentication(diagnostic, monkeypatch):
    s, out, _ = diagnostic
    from soc_agent.security_ai.ebpf_tc import operational_recovery

    monkeypatch.setattr(
        operational_recovery,
        "source_git_identity",
        lambda: (s.binding.artifact.git_commit, s.binding.artifact.git_tree),
    )
    monkeypatch.setattr(dns.subprocess, "run", lambda *_a, **_k: pytest.fail("No authentication"))
    packet = dict(
        kind="ROOT_DNS_EXECUTION_V1",
        binding=s.binding.model_dump(),
        campaign=str(s.ledger.directory),
        policy_file=str(out / "missing"),
        policy_sha="a" * 64,
        approval_file=str(out / "missing2"),
        approval_sha="b" * 64,
        root_manifest_file=str(s.manifest),
        lease_file=str(out / "lease"),
    )
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(OSError):
        dns.run_packet("execute", out, packet)
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_budget_context_does_not_activate_new_execution_policy(diagnostic):
    s, output, result = diagnostic
    args = s.issue(operation="ROOT_DNS_DIAGNOSTIC", scope=result["scope"])
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="POLICY_ACTIVATION_REQUIRED"):
        s.ledger.check_root(
            s.binding, **args, dns_directory=output, dns_lease_file=output / "lease"
        )
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_os_entry_rejects_ordinary_uid_before_files_or_claim(monkeypatch):
    monkeypatch.setattr(engine, "dns_held_json", lambda *_: pytest.fail("No grant IO"))
    with pytest.raises(ValueError, match="AUTHENTICATION_REQUIRED"):
        engine.dns_validate_grant(dict(uid=os.getuid(), gid=os.getgid()), {})


@pytest.mark.parametrize("mutation", ["source", "dependency"])
def test_build_observation_window_rejects_mutation(tmp_path, monkeypatch, mutation):
    from soc_agent.security_ai.ebpf_tc.source_guard import SourceGuard

    frozen = tmp_path / "frozen"
    frozen.mkdir()
    file = frozen / "input.py"
    file.write_text("original")
    monkeypatch.setattr(dns, "SourceGuard", lambda _: SourceGuard(frozen))
    host = iter([dict(zlib="old"), dict(zlib="new" if mutation == "dependency" else "old")])
    monkeypatch.setattr(dns, "host_identity", lambda: next(host))

    def build(*_, **__):
        if mutation == "source":
            file.write_text("changed")
            file.write_text("original")
        return {}

    monkeypatch.setattr(dns, "_prepare", build)
    with pytest.raises(
        ValueError,
        match="SOURCE_CHANGED_DURING_BUILD"
        if mutation == "source"
        else "DEPENDENCIES_CHANGED_DURING_BUILD",
    ):
        dns.prepare(
            tmp_path / "out",
            package=None,
            root_manifest="a" * 64,
            origin=None,
            lease_file=None,
            lease_sha="b" * 64,
            source_snapshot="c" * 64,
            plan=None,
        )


def test_dns_real_reservation_requires_activation_and_fourth_slot(diagnostic, governance):
    s, output, result = diagnostic
    s, kw = amendment(governance)
    gov.allocate_dns_root(s.ledger, **kw)
    policy = root.RootPolicy.model_validate_json(s.policy_file.read_bytes())
    grant = root.RootApproval(
        decision="APPROVED",
        approver=policy.approver,
        human_reference_sha="b" * 64,
        policy_sha=sha(s.policy_file.read_bytes()),
        binding=s.binding,
        operation="ROOT_DNS_DIAGNOSTIC",
        scope=result["scope"],
        ledger_tip_sha=gov._tip(rows(s)),
        issued_at=policy.issued_at,
        expires_at=policy.expires_at,
    )
    s.approval_file.write_bytes(canonical(grant.model_dump()))
    fields = dict(
        policy_file=s.policy_file,
        policy_sha=sha(s.policy_file.read_bytes()),
        approval_file=s.approval_file,
        approval_sha=sha(s.approval_file.read_bytes()),
        root_manifest_file=s.manifest,
        dns_directory=output,
        dns_lease_file=output / "lease",
    )
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    assert s.ledger.check_root(s.binding, **fields)["status"] == "CHECKED_NOT_RESERVED"
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before
    event = s.ledger.reserve_root(s.binding, **fields)
    assert (event["native_used"], event["root_installations_used"]) == (0, 1)
    assert totals(rows(s)) == (0, 1)
    with pytest.raises(ValueError, match="REPLAY"):
        s.ledger.reserve_root(s.binding, **fields)
    s.ledger.record_root(
        event["attempt_id"], state="CANCELLED_BEFORE_EXECUTION", evidence_sha="c" * 64
    )
    assert totals(rows(s)) == (0, 1)


def test_existing_cli_refuses_missing_dns_packet_pin(tmp_path, capsys):
    assert main(["execute", str(tmp_path), "--dns-operation-file", str(tmp_path / "absent")]) == 2
    assert "DNS_OPERATION_PACKET_PIN_REQUIRED" in capsys.readouterr().out


def test_scope_decline_never_reserves_or_authenticates(setup, monkeypatch, tmp_path):
    """UX-only synthetic backend; real admission validators are tested above."""
    import sys

    from soc_agent.security_ai.ebpf_tc import operational_recovery

    monkeypatch.setattr(
        operational_recovery,
        "source_git_identity",
        lambda: (setup.binding.artifact.git_commit, setup.binding.artifact.git_tree),
    )

    class Backend:
        def __init__(self, *_):
            pass

        def check_root(self, *_, **__):
            return dict(proposal=dict(operation="ROOT_DNS_DIAGNOSTIC", scope={}))

        def reserve_root(self, *_, **__):
            pytest.fail("Declined Scope must not reserve")

    monkeypatch.setattr(dns, "RootOperations", Backend)
    monkeypatch.setattr(dns, "held_json", lambda *_: dict(approver="operator"))
    monkeypatch.setattr(dns.subprocess, "run", lambda *_a, **_k: pytest.fail("No authentication"))
    monkeypatch.setattr("builtins.input", lambda _: "no")
    original_stdout = sys.stdout

    class Console:
        def isatty(self):
            return True

        def fileno(self):
            return 20001

        def write(self, text):
            return original_stdout.write(text)

        def flush(self):
            return original_stdout.flush()

    monkeypatch.setattr(sys, "stdout", Console())
    monkeypatch.setattr(sys, "stdin", Console())
    original_open, original_close, original_stat = os.open, os.close, os.fstat
    monkeypatch.setattr(
        os,
        "open",
        lambda path, *a, **k: 20002 if path == "/dev/tty" else original_open(path, *a, **k),
    )
    monkeypatch.setattr(os, "close", lambda fd: None if fd == 20002 else original_close(fd))
    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: SimpleNamespace(st_uid=os.getuid()) if fd == 20001 else original_stat(fd),
    )
    monkeypatch.setattr(os, "ttyname", lambda _: "/dev/pts/fixture")
    monkeypatch.setattr(os, "tcgetpgrp", lambda _: os.getpgrp())
    packet = dict(
        kind="ROOT_DNS_EXECUTION_V1",
        binding=setup.binding.model_dump(),
        campaign=str(setup.ledger.directory),
        policy_file=str(tmp_path / "p"),
        policy_sha="a" * 64,
        approval_file=str(tmp_path / "a"),
        approval_sha="b" * 64,
        root_manifest_file=str(setup.manifest),
        lease_file=str(tmp_path / "lease"),
    )
    before = (setup.ledger.directory / "execution-ledger.jsonl").read_bytes()
    result = dns.run_packet("execute", tmp_path, packet)
    assert result == dict(status="CANCELLED_BEFORE_RESERVATION", reserved=False, executed=False)
    assert (setup.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize("fault", [None, "cookie", "response"])
def test_fixed_local_client_coordinator_without_packets(monkeypatch, fault):
    """Memory sockets + actual coordinator; server transport tested separately."""
    from soc_agent.security_ai.ebpf_tc.namespace_isolation import local_dns_response

    clock = [0]
    channels = []
    snapshots = []

    class Listener:
        closed = False

        def close(self):
            self.closed = True

        def fileno(self):
            return -1 if self.closed else 77

    udp, tcp = Listener(), Listener()
    cookie = b"cookie00"

    def snapshot():
        sockets = (
            {"tcp": ["listener"], "udp": ["listener"], "tcp6": [], "udp6": []}
            if not snapshots
            else {n: [] for n in ("tcp", "tcp6", "udp", "udp6")}
        )
        snapshots.append(True)
        return dict(socket_cookie=cookie.hex(), sockets=sockets)

    def serve(scope, u, t, *, ready, tcp_closed):
        ready(dict(state="LOCAL_DNS_READY"))
        clock[0] = 2_000_000_000
        tcp_closed(clock[0])
        u.close()
        t.close()
        return dict(queries=3)

    class Client:
        def __init__(self, af, kind):
            self.kind = kind
            self.body = b""
            self.reply = bytearray()
            channels.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, _):
            pass

        def bind(self, endpoint):
            assert endpoint == ("127.0.0.1", 0)

        def getsockopt(self, *_):
            return b"different" if fault == "cookie" else cookie

        def connect(self, endpoint):
            assert endpoint == ("127.0.0.53", 53)

        def sendto(self, body, endpoint):
            assert endpoint == ("127.0.0.53", 53)
            self.body = body
            return len(body)

        def recvfrom(self, _):
            return (b"wrong" if fault == "response" else local_dns_response(self.body)), (
                "127.0.0.53",
                53,
            )

        def sendall(self, body):
            self.reply = bytearray(local_dns_response(body, tcp=True))

        def recv(self, size):
            value = bytes(self.reply[:size])
            del self.reply[:size]
            return value

    monkeypatch.setattr(engine, "local_controller", lambda: None)
    monkeypatch.setattr(engine, "dns_snapshot", snapshot)
    monkeypatch.setattr(engine, "serve_prebound", serve)
    monkeypatch.setattr(engine.socket, "socket", Client)
    monkeypatch.setattr(engine.time, "monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(engine.time, "monotonic", lambda: clock[0] / 1e9)
    monkeypatch.setattr(
        engine.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + int(seconds * 1e9))
    )
    if fault:
        with pytest.raises(
            ValueError, match="COOKIE_MISMATCH" if fault == "cookie" else "RESPONSE_MISMATCH"
        ):
            engine.diagnostic_worker(SimpleNamespace(), udp, tcp, ready=lambda _: None)
        assert udp.closed and tcp.closed
    else:
        value = engine.diagnostic_worker(SimpleNamespace(), udp, tcp, ready=lambda _: None)
        assert value["state"] == "DNS_DIAGNOSTIC_COMPLETED"
        assert [r["transport"] for r in value["exchanges"]] == ["UDP", "TCP", "UDP"]
        assert value["exchanges"][-1]["sent_ns"] >= 37_000_000_000
        assert clock[0] == 45_000_000_000 and len(channels) == 3
        assert value["listener_fds_closed"] and value["capture_integrity"] == "NOT_ASSESSED"
