"""Compile and mocked syscall/terminal boundaries only. No Root/traffic/container/API."""

import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.unit.ebpf_tc.test_isolated_dns_launcher import lease
from tests.unit.ebpf_tc.test_root_operations import fixture as fixture
from tests.unit.ebpf_tc.test_root_operations import package as package
from tests.unit.ebpf_tc.test_root_operations import setup as setup
from tests.unit.ebpf_tc.test_root_operations import stable as stable

from soc_agent.security_ai.ebpf_tc import namespace_controller as controller
from soc_agent.security_ai.ebpf_tc import namespace_runtime as runtime
from soc_agent.security_ai.ebpf_tc import operational_recovery, phase_d, supervisor_engine
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import (
    IsolatedScenario,
    Scenario,
    scenario_for_namespace,
)
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisorImage

NS = "net:[4999999999]"


def test_phase_d_does_not_contact_or_require_a_host_docker_daemon(monkeypatch):
    def forbidden(*_):
        pytest.fail("Phase D privileged path must not contact Docker")

    monkeypatch.setattr(supervisor_engine, "DockerAPI", forbidden)
    monkeypatch.setattr(supervisor_engine, "start_dns_worker", object(), raising=False)
    monkeypatch.setattr(supervisor_engine, "SUPERVISOR_CONFIG", {}, raising=False)
    seen = []
    monkeypatch.setattr(supervisor_engine, "_supervisor_fork", lambda *args: seen.append(args))
    supervisor_engine._supervisor_prepare({}, b"", b"", {})
    assert len(seen) == 1
    ops = supervisor_engine.RootOperations(
        {}, NS, "test", None, SimpleNamespace(close=lambda: None)
    )
    assert ops.api is None
    with pytest.raises(ValueError, match="LIVE_CONTAINER_FORBIDDEN"):
        ops.start({})


def test_legacy_docker_unavailable_is_not_silently_skipped(monkeypatch):
    monkeypatch.delattr(supervisor_engine, "start_dns_worker", raising=False)
    monkeypatch.setattr(supervisor_engine, "SUPERVISOR_CONFIG", {}, raising=False)

    def absent(*_):
        raise OSError("Docker unavailable")

    monkeypatch.setattr(supervisor_engine, "DockerAPI", absent)
    monkeypatch.setattr(supervisor_engine, "_supervisor_fork", lambda *_: pytest.fail("fork"))
    with pytest.raises(OSError, match="unavailable"):
        supervisor_engine._supervisor_prepare({}, b"", b"", {})


def test_legacy_live_docker_still_rejects_cross_namespace_peer(monkeypatch):
    api = SimpleNamespace(
        peer=(123, 0, 0), request=lambda *_: {"MinAPIVersion": "1.50", "ApiVersion": "1.52"}
    )
    monkeypatch.setattr(supervisor_engine, "DockerAPI", lambda: api)
    monkeypatch.setattr(
        supervisor_engine.os,
        "readlink",
        lambda p: NS if p == "/proc/self/ns/net" else "net:[4026531833]",
    )
    with pytest.raises(ValueError, match="DOCKER_NAMESPACE"):
        supervisor_engine.sup_docker_preflight({})


@pytest.mark.parametrize("which", ["dns", "responder"])
def test_stop_attempts_both_owned_dns_lifecycles_on_failure(which):
    calls = []

    def close(name):
        def run():
            calls.append(name)
            if name == which:
                raise OSError(name)

        return run

    ops = supervisor_engine.RootOperations(
        {},
        NS,
        "test",
        None,
        SimpleNamespace(close=close("dns")),
        SimpleNamespace(close=close("responder")),
    )
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        ops.stop()
    assert calls == ["dns", "responder"]
    assert ops.stopped


def test_isolated_r2_requires_an_explicit_policy_binding():
    with pytest.raises(ValueError):
        Scenario(namespace=NS)
    with pytest.raises(ValueError):
        IsolatedScenario(namespace=NS)
    isolated = scenario_for_namespace(NS, "a" * 64)
    assert isolated.namespace_policy_sha == "a" * 64
    assert isolated.sidecar_seconds == 10 and isolated.max_events == 4096
    assert Scenario().namespace == "net:[4026531833]"


@pytest.fixture
def namespace_build(setup, monkeypatch):
    fake = lease(setup.binding)
    from soc_agent.security_ai.ebpf_tc import isolated_dns_launcher

    monkeypatch.setattr(isolated_dns_launcher, "inspect_lease", lambda *_: fake)
    return runtime.NamespaceBuild(
        lease_file=Path("/synthetic-lease"), lease_sha="a" * 64, origin=setup.binding
    )


def test_namespace_policy_requires_exact_source_release_and_fresh_human_binding(
    namespace_build, package, tmp_path
):
    _, release = package
    expected, _ = runtime.binding(namespace_build, release)
    data = dict(
        contract="SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1",
        decision="APPROVED",
        approver="UNIT TEST REVIEWER",
        human_reference_sha="b" * 64,
        binding=expected,
        issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 60,
        activate_namespace_supervisor=True,
        authorize_root=False,
        authorize_native=False,
        authorize_traffic=False,
    )
    assert runtime.check_policy(data, expected).authorize_root is False
    for patch in [
        dict(approver="MOCK"),
        dict(expires_at=0),
        dict(authorize_root=True),
        dict(binding=expected | dict(namespace="net:[123]")),
    ]:
        with pytest.raises(ValueError):
            runtime.check_policy(data | patch, expected)


def test_real_build_with_missing_namespace_policy_is_guarded_and_nonconsuming(
    namespace_build, tmp_path
):
    directory = tmp_path / "pending"
    identity = phase_d.prepare(directory, namespace_build=namespace_build)
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    assert image.namespace_preview and image.namespace_runtime["policy"] is None
    value = phase_d.validate_preparation(directory, identity["manifest"], identity["image"])
    assert value["scope"]["namespace"] == NS
    source = image.path.read_bytes()
    assert b"ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED" in source[:150]
    result = operational_recovery.readiness(directory, identity["manifest"], identity["image"])
    assert result["status"] == "BLOCKED" and not result["reserved"] and not result["executed"]
    assert result["error"] == "ISOLATED_NAMESPACE_POLICY_NOT_ACTIVATED"


def test_reviewed_namespace_image_compiles_but_cannot_execute_from_host(namespace_build, tmp_path):
    pending = tmp_path / "pending"
    identity = phase_d.prepare(pending, namespace_build=namespace_build)
    image = SupervisorImage.model_validate_json((pending / "supervisor-image.json").read_bytes())
    policy = runtime.NamespacePolicy(
        decision="APPROVED",
        approver="UNIT TEST REVIEWER",
        human_reference_sha="b" * 64,
        binding=image.namespace_runtime["binding"],
        issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 120,
        activate_namespace_supervisor=True,
    )
    path = tmp_path / "test-only-policy.json"
    path.write_bytes(canonical(policy.model_dump()))
    build = namespace_build.model_copy(
        update={"policy_file": path, "policy_sha": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    directory = tmp_path / "test-approved"
    identity = phase_d.prepare(directory, namespace_build=build)
    descriptor = SupervisorImage.model_validate_json(
        (directory / "supervisor-image.json").read_bytes()
    )
    assert not descriptor.namespace_preview
    runtime.verify_descriptor(descriptor)
    source = descriptor.path.read_text()
    assert "namespace_runtime_root_check(NAMESPACE_RUNTIME)" in source
    assert "spawn_dns_child" in source and "DNS_CAPTURE_COOKIE" in source
    assert (
        phase_d.validate_preparation(directory, identity["manifest"], identity["image"])["contract"]
        == "SOC_PHASE_D_NAMESPACE_V1"
    )
    with pytest.raises(ValueError, match="COLLECTOR_SCOPE_MISMATCH"):
        phase_d.validate(directory, identity["manifest"], identity["image"])


def config(tmp_path):
    project = tmp_path / "source"
    project.mkdir()
    (project / "x.py").write_text("# source\n")
    pins = tmp_path / "source-pins.json"
    pins.write_text(
        json.dumps({"x.py": hashlib.sha256((project / "x.py").read_bytes()).hexdigest()})
    )
    interpreter = Path(os.sys.executable).resolve()
    return dict(
        project=str(project),
        interpreter=str(interpreter),
        interpreter_sha=hashlib.sha256(interpreter.read_bytes()).hexdigest(),
        source_pins=str(pins),
        source_pins_sha=hashlib.sha256(pins.read_bytes()).hexdigest(),
        target=dict(
            directory=str(tmp_path / "candidate"),
            manifest="a" * 64,
            image_sha="b" * 64,
            campaign=str(tmp_path / "ledger"),
        ),
        request_file=str(tmp_path / "fresh-approval-request.json"),
        docker_group=None,
    )


@pytest.mark.parametrize("change", ["command", "relative", "sha", "group", "target"])
def test_controller_is_not_an_arbitrary_root_or_command_launcher(tmp_path, change):
    data = config(tmp_path)
    if change == "command":
        data["argv"] = ["sh"]
    if change == "relative":
        data["project"] = "relative"
    if change == "sha":
        data["interpreter_sha"] = "bad"
    if change == "group":
        data["docker_group"] = 0
    if change == "target":
        data["target"]["command"] = "sh"
    with pytest.raises(ValueError):
        controller.validate_controller(data)


def test_controller_source_mutation_stops_before_any_root_call(tmp_path):
    data = config(tmp_path)
    controller.verify_sources(data)
    (Path(data["project"]) / "x.py").write_text("# changed\n")
    with pytest.raises(ValueError, match="SOURCE_MUTATION"):
        controller.verify_sources(data)


@pytest.mark.parametrize("mode", ["prepare", "check", "execute"])
def test_controller_cli_requires_pinned_packet_before_any_root_call(
    tmp_path, capsys, monkeypatch, mode
):
    monkeypatch.setattr(controller, "_execute", lambda *_: pytest.fail("Root launch"))
    result = operational_recovery.main(
        [mode, str(tmp_path), "--namespace-controller-file", str(tmp_path / "missing")]
    )
    assert result == 2
    assert json.loads(capsys.readouterr().out)["executed"] is False


def test_probe_plan_binds_the_actual_namespace_without_sending():
    from soc_agent.security_ai.collectors.offload_session import PROBE_APPROVAL, probe_approval

    body = Path("tests/native_dns_live_probe.py").read_bytes()
    assert probe_approval(body, "net:[4026531833]") == PROBE_APPROVAL
    assert probe_approval(body, NS) != PROBE_APPROVAL


def test_empty_source_files_are_verified_without_relaxing_executable_validation(tmp_path):
    from soc_agent.security_ai.ebpf_tc.dependencies import read_held

    data = config(tmp_path)
    empty = Path(data["project"]) / "__init__.py"
    empty.touch()
    pins = json.loads(Path(data["source_pins"]).read_bytes())
    pins["__init__.py"] = hashlib.sha256(b"").hexdigest()
    Path(data["source_pins"]).write_text(json.dumps(pins))
    data["source_pins_sha"] = hashlib.sha256(Path(data["source_pins"]).read_bytes()).hexdigest()
    controller.verify_sources(data)
    with pytest.raises(ValueError, match="TRUST_FILE_INVALID"):
        read_held(empty, owner=os.getuid())


def test_controller_capsule_uses_existing_root_dns_validator_and_cannot_run_unprivileged(
    setup, monkeypatch, tmp_path
):
    from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
    from soc_agent.security_ai.ebpf_tc import dns_diagnostic, isolated_dns_launcher
    from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, digest
    from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding

    origin = setup.binding
    fake = lease(origin)
    monkeypatch.setattr(isolated_dns_launcher, "inspect_lease", lambda *_: fake)
    monkeypatch.setattr(dns_diagnostic, "inspect_lease", lambda *_: fake)
    plan = ApplicationPlan(
        mode="PHASE_A_FIXTURE",
        controller=local_controller(),
        scope=Scope(
            ifindex=1,
            net_namespace=NS,
            hook="INGRESS",
            program_sha256="a" * 64,
            loader_sha256="b" * 64,
            bundle_digest="c" * 64,
        ),
    )
    output = tmp_path / "capsule"
    data = config(tmp_path)
    result = controller.run_packet(
        "prepare",
        output,
        dict(
            kind="NAMESPACE_CONTROLLER_PREPARATION_V1",
            controller=data,
            package=str(setup.manifest.parent),
            root_manifest=origin.artifact.root_manifest,
            origin=origin.model_dump(),
            lease_file=str(tmp_path / "lease"),
            lease_sha="d" * 64,
            source_snapshot="e" * 64,
            plan=plan.model_dump(mode="json"),
        ),
    )
    artifact = Artifact(
        git_commit="1" * 40,
        git_tree="2" * 40,
        release=origin.artifact.release,
        manifest=result["manifest"],
        bundle=result["bundle"],
        image=result["image"],
        root_manifest=result["root_manifest"],
    )
    bound = RootBinding(
        session=str(plan.application_session),
        artifact=artifact,
        source_snapshot="e" * 64,
        scope_sha=digest(result["scope"]),
        installed_manifest=origin.installed_manifest,
        rollback_manifest=origin.rollback_manifest,
    )
    metadata = dns_diagnostic.verify(output, bound)
    assert metadata["config"]["admitted_operation"] == "ROOT_DNS_DIAGNOSTIC"
    assert result["scope"]["native_cost"] == 0 and result["scope"]["root_cost"] == 1
    assert result["scope"]["udp_queries"] == 2 and result["scope"]["tcp_queries"] == 1
    assert result["scope"]["native"] is False
    body = (output / "dns-diagnostic.py").read_text()
    import ast

    assert not any(
        isinstance(n, ast.ImportFrom) and (n.module or "").startswith("soc_agent")
        for n in ast.walk(ast.parse(body))
    )
    assert "controller_root_main(DNS_CONFIG)" in body
    namespace = {"__name__": "unit_test_import"}
    exec(compile(body, "<unit-test-compile-only>", "exec"), namespace)
    assert callable(namespace["controller_root_main"])
    # The fixed Root main rejects before reading receipts, changing credentials
    # or entering the synthetic namespace. No Root primitive is mocked as success.
    with pytest.raises(SystemExit) as stopped:
        exec(compile(body, "<unit-test-reject>", "exec"), {"__name__": "__main__"})
    assert stopped.value.code == 1


@pytest.mark.parametrize("settled", [False, True])
def test_ordinary_controller_requires_settlement_and_fresh_request_before_existing_cli(
    tmp_path, monkeypatch, settled
):
    from soc_agent.security_ai.ebpf_tc import dns_diagnostic_engine, operational_recovery

    data = config(tmp_path)
    ack = tmp_path / "ack.json"
    ack.write_text(json.dumps(dict(ledger_sha="a" * 64)))
    request = Path(data["request_file"])
    request.write_text(json.dumps(data["target"]))
    pin = hashlib.sha256(request.read_bytes()).hexdigest()
    data.update(
        namespace=NS,
        cookie="0011223344556677",
        attempt="test-attempt",
        ack=str(ack),
        ledger=str(tmp_path / "ledger"),
    )
    monkeypatch.setattr(controller, "verify_sources", lambda *_: None)
    monkeypatch.setattr(controller.os, "readlink", lambda *_: NS)

    class Cookie:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def getsockopt(self, *_):
            return bytes.fromhex(data["cookie"])

    monkeypatch.setattr(controller.socket, "socket", lambda *_: Cookie())
    monkeypatch.setattr(
        dns_diagnostic_engine,
        "dns_held_json_ledger",
        lambda *_: [
            dict(
                attempt_id="test-attempt",
                event="ROOT_OPERATION_FINISHED_V1",
                state="SUCCEEDED" if settled else "UNKNOWN",
            )
        ],
    )
    calls = []
    monkeypatch.setattr(operational_recovery, "main", lambda args: calls.append(args[0]) or 0)
    monkeypatch.setattr(
        "builtins.input", lambda *_: pin if settled else pytest.fail("No prompt before settlement")
    )
    if not settled:
        with pytest.raises(ValueError, match="ENTRY_NOT_SETTLED"):
            controller.child_main(data)
        assert not calls
    else:
        with pytest.raises(SystemExit) as done:
            controller.child_main(data)
        assert done.value.code == 0 and calls == ["check", "execute"]
        # These calls are mocked existing CLI dispatch only, not Native execution.


def test_scope_rejection_never_reserves_or_requests_os_authentication(monkeypatch, tmp_path):
    from soc_agent.security_ai.ebpf_tc import auth_session
    from soc_agent.security_ai.ebpf_tc.namespace_controller import _execute

    monkeypatch.setattr(
        auth_session, "open_authentication_tty", lambda *_: os.open(os.devnull, os.O_RDONLY)
    )
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    ledger = SimpleNamespace(reserve_root=lambda *_a, **_kw: pytest.fail("reservation"))
    result = _execute(tmp_path, {}, None, {"scope": {}}, ledger, {})
    assert result == dict(status="CANCELLED_BEFORE_RESERVATION", reserved=False, executed=False)


def test_existing_cli_prepares_pinned_namespace_json_without_root(
    namespace_build, tmp_path, capsys
):
    packet = tmp_path / "namespace-config.json"
    packet.write_text(namespace_build.model_dump_json())
    pin = hashlib.sha256(packet.read_bytes()).hexdigest()
    directory = tmp_path / "cli-prepared"
    assert (
        operational_recovery.main(
            [
                "prepare",
                str(directory),
                "--namespace-config",
                str(packet),
                "--namespace-config-sha",
                pin,
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "POLICY_APPROVAL_REQUIRED" and result["executed"] is False
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    assert image.namespace_preview and image.scope_namespace == NS


@pytest.mark.parametrize("failure", ["timeout", "wrong_namespace", "cookie"])
def test_responder_ready_failure_closes_owned_child_without_waiting_60_seconds(
    monkeypatch, failure
):
    child = SimpleNamespace(deadline=time.monotonic() + 66, closed=False)

    def receive():
        assert child.deadline - time.monotonic() <= 2
        if failure == "timeout":
            raise TimeoutError("ready")
        return dict(
            state="LOCAL_DNS_READY",
            namespace="net:[123]" if failure == "wrong_namespace" else NS,
            cookie="invalid" if failure == "cookie" else "0011223344556677",
        )

    child.receive = receive
    child.close = lambda: setattr(child, "closed", True)
    monkeypatch.setattr(supervisor_engine, "spawn_dns_child", lambda *_: child, raising=False)
    monkeypatch.setattr(supervisor_engine, "serve_prebound", object(), raising=False)
    with pytest.raises((ValueError, TimeoutError)):
        supervisor_engine.sup_start_responder({}, NS)
    assert child.closed
    assert child.deadline - time.monotonic() > 60


def test_namespace_root_policy_checks_sudo_actor_before_any_namespace_fd(monkeypatch):
    from soc_agent.security_ai.ebpf_tc import namespace_runtime_engine

    monkeypatch.setenv("SUDO_UID", "2000")
    monkeypatch.setenv("SUDO_GID", "2000")
    for name in ("getuid", "geteuid", "getgid", "getegid"):
        monkeypatch.setattr(namespace_runtime_engine.os, name, lambda: 0)
    monkeypatch.setattr(
        namespace_runtime_engine.os,
        "open",
        lambda *_: pytest.fail("No namespace FD before actor validation"),
    )
    with pytest.raises(ValueError, match="NAMESPACE_RUNTIME_POLICY_REQUIRED"):
        namespace_runtime_engine.namespace_runtime_root_check(
            dict(binding=dict(uid=1000, gid=1000), policy=None)
        )


def test_git_drift_during_scope_confirmation_never_reserves(monkeypatch, tmp_path):
    from soc_agent.security_ai.ebpf_tc import auth_session, operational_recovery

    data = config(tmp_path)
    monkeypatch.setattr(
        auth_session, "open_authentication_tty", lambda *_: os.open(os.devnull, os.O_RDONLY)
    )
    monkeypatch.setattr("builtins.input", lambda *_: "yes")
    monkeypatch.setattr(operational_recovery, "source_git_identity", lambda: ("3" * 40, "4" * 40))
    bound = SimpleNamespace(artifact=SimpleNamespace(git_commit="1" * 40, git_tree="2" * 40))
    ledger = SimpleNamespace(
        reserve_root=lambda *_a, **_kw: pytest.fail("No reservation after Git drift")
    )
    with pytest.raises(ValueError, match="GIT_CHANGED_AFTER_CONFIRMATION"):
        controller._execute(tmp_path, {}, bound, dict(scope={}, controller=data), ledger, {})
