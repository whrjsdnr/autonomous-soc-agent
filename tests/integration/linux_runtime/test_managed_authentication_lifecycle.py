"""Owned auth child: only journal availability/command replaced with saved fixtures."""

import asyncio
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.continuous.authentication_lifecycle import (
    METADATA,
    AuthenticationLifecycle,
    action,
    preflight,
)
from soc_agent.continuous.cli import code_identity
from soc_agent.continuous.models import ContinuousConfig, ManagedAuthentication
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import initialize
from soc_agent.state.evidence import utc_now


def prepare(tmp_path, *, packages=(), scope_sha256=None):
    directory = tmp_path / "continuous"
    source = tmp_path / "empty.jsonl"
    source.write_bytes(b"")
    Store.create(
        directory,
        ContinuousConfig(
            source="JSONL_REPLAY",
            authentication_packages=packages,
            native_model_approvals=tmp_path / "model-approvals" if packages else None,
            input_file=source,
            input_sha256=scope_sha256 or hashlib.sha256(b"").hexdigest(),
            authentication_runtime=directory / "authentication",
            managed_authentication=ManagedAuthentication(
                approval_file=tmp_path / "approval.json",
                duration_seconds=30,
            ),
        ),
    )
    store = Store(directory)
    initialize(
        directory / "authentication",
        RuntimeConfig(
            incident_id=store.database.store_id,
            repeated_failures=3,
            multiple_accounts=3,
            poll_seconds=0.2,
            assessment_mode="READ_ONLY",
        ),
    )
    (directory / "code-identity").write_text(code_identity())
    return store


def approve_fixture(store, *, reject=False):
    proposed = action(store)
    manager = ApprovalManager()
    pending = manager.create(
        incident_id=proposed.incident_id,
        metadata=METADATA,
        reason="Fixture-only Host command replacement",
        action_id=proposed.action_id,
        action_input_json=proposed.tool_input,
        expires_at=utc_now() + timedelta(minutes=1),
    )
    decision = (manager.reject if reject else manager.approve)(pending.approval_id, actor="fixture")
    store.config.managed_authentication.approval_file.write_text(decision.model_dump_json())


def journal_fixture_rows(seconds=(1, 2, 3), messages=None):
    from tests.unit.operational_features.test_native_authentication import row

    message = "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2"
    return [
        row(i + 1, second, messages[i] if messages else message) for i, second in enumerate(seconds)
    ]


def mock_journal_child(
    monkeypatch, *, denied=False, seconds=(1, 2, 3), messages=None, held_until_stop=False
):
    rows = journal_fixture_rows(seconds, messages)
    original = asyncio.create_subprocess_exec
    # Keep the real CLI, monitor, parser, queue, stores, signal handlers and audit.
    # The child patches only the unavailable Host Journal command boundary.
    bootstrap = (
        """
import json, runpy, sys, os, time, threading
from pathlib import Path
trace = (Path(sys.argv[sys.argv.index("--directory")+1]).parent
         / "authentication-fixture-startup.jsonl")
def mark(stage):
    value = dict(stage=stage,monotonic=time.monotonic(),cpu_seconds=time.process_time(),
                 pid=os.getpid(),thread=threading.get_ident())
    fd = os.open(trace,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try: os.write(fd,(json.dumps(value)+"\\n").encode())
    finally: os.close(fd)
mark("SCRIPT_READY")
from soc_agent.realtime.collectors import (
    LinuxJournalCollector, CollectorUnavailable, CommandObservation,
)
from soc_agent.security_ai.operational import native_authentication
rows = json.loads(ROWS_JSON)
mark("JOURNAL_BOUNDARY_IMPORTED")
def available(self): self.command = "/fixture/journalctl"
source_release = threading.Event()
def command(arguments):
    if HELD_UNTIL_STOP:
        began = time.monotonic()
        mark("JOURNAL_COMMAND_BEGIN")
        assert source_release.wait(12), "FIXTURE_STOP_NOT_RECEIVED"
        mark("JOURNAL_COMMAND_TERMINATED_AFTER_STOP")
        raise CollectorUnavailable("fixture command stopped", failure_code="COMMAND_EXIT_NONZERO",
            command_observation=CommandObservation(started_monotonic=began,
                finished_monotonic=time.monotonic(),returncode=-15))
    if DENIED: raise CollectorUnavailable("PERMISSION_DENIED:fixture")
    assert arguments[0] == "/fixture/journalctl"
    assert arguments[-4:] == ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+", "_COMM=sshd"]
    cursor = next((a.split("=",1)[1] for a in arguments if a.startswith("--cursor=")),None)
    if cursor: return json.dumps(next(r for r in rows if r["__CURSOR"] == cursor)) + "\\n"
    if any(a.startswith("--after-cursor=") for a in arguments): return ""
    return "\\n".join(json.dumps(r) for r in rows) + ("\\n" if rows else "")
LinuxJournalCollector.__init__ = available
native_authentication.bounded_command = command
from soc_agent.linux_runtime.service import LinuxMonitor
mark("SERVICE_IMPORTED")
assert "pytest" not in sys.modules, "TEST_FRAMEWORK_IN_CHILD_STARTUP_BUDGET"
original_init = LinuxMonitor.__init__
def initialize(self,*args,**kwargs):
    mark("INITIALIZE_BEGIN")
    try: return original_init(self,*args,**kwargs)
    finally: mark("INITIALIZE_END")
LinuxMonitor.__init__ = initialize
original_run = LinuxMonitor.run
async def run(self,*args,**kwargs):
    mark("RUN_BEGIN")
    try: return await original_run(self,*args,**kwargs)
    finally: mark("RUN_END")
LinuxMonitor.run = run
original_stop = LinuxMonitor.request_stop
def stop(self):
    mark("STOP_RECEIVED")
    source_release.set()
    return original_stop(self)
LinuxMonitor.request_stop = stop
sys.argv = ["soc_agent.linux_runtime"] + sys.argv[1:]
runpy.run_module("soc_agent.linux_runtime", run_name="__main__")
""".replace("if DENIED:", f"if {denied}:")
        .replace("if HELD_UNTIL_STOP:", f"if {held_until_stop}:")
        .replace("ROWS_JSON", repr(json.dumps(rows)))
    )

    async def spawn(*args, **kwargs):
        assert args[1:4] == ("-B", "-m", "soc_agent.linux_runtime")
        return await original(args[0], "-B", "-c", bootstrap, *args[4:], **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)


def test_no_implicit_host_authority_or_replay(tmp_path):
    store = prepare(tmp_path)
    with pytest.raises(ValueError, match="EXACT_HUMAN_APPROVAL_REQUIRED"):
        preflight(store)
    assert not (store.directory / "authentication-start-intent.json").exists()
    approve_fixture(store)
    preflight(store)
    (store.directory / "authentication-start-intent.json").write_text("{}")
    with pytest.raises(ValueError, match="NO_REPLAY"):
        preflight(store)


def test_rejection_and_code_change_fail_closed(tmp_path):
    store = prepare(tmp_path)
    approve_fixture(store, reject=True)
    with pytest.raises(Exception, match="rejected"):
        preflight(store)
    (store.directory / "code-identity").write_text("0" * 64)
    with pytest.raises(ValueError, match="EXECUTABLE_CHANGED"):
        preflight(store)


@pytest.mark.asyncio
async def test_owned_child_ready_ingestion_gui_cache_stop_ack_and_durable_cleanup(
    tmp_path, monkeypatch
):
    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch)
    runtime = ContinuousRuntime(store.directory)
    child = runtime.auth_lifecycle
    try:
        await child.start()
        value = await runtime.observed_snapshot()
        auth = value["authentication"]
        assert auth["runtime_state"] == "RUNNING"
        assert auth["host_events"] == 3
        assert auth["if_admission"]["state"] == "BLOCKED_NO_APPROVED_PACKAGE"
        assert auth["if_admission"]["predictions"] == 0
        assert "fixture-user" not in json.dumps(auth)
        assert "192.0.2.5" not in json.dumps(auth)
        watcher = asyncio.create_task(child.watch(asyncio.Event()))
        await asyncio.sleep(0.4)
        assert not watcher.done()
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)
        # GUI projection reads the same backend snapshot and preserves session.
        from soc_agent.gui.continuous_projection import availability

        assert availability(value, [])["authentication"] == "RUNNING"
    finally:
        await child.close()
    proof = json.loads((store.directory / "authentication-cleanup.json").read_text())
    assert proof["cleanup"] == "VERIFIED" and proof["stop_ack"]
    assert proof["child_reaped"] and not proof["forced"]
    assert proof["queue_counts"] == {"DONE": 3} and proof["queue_drained"]
    assert proof["pending_jobs_preserved"]
    assert proof["observed_monotonic"] >= proof["stop_requested_monotonic"]
    assert (await runtime.observed_snapshot())["authentication"]["runtime_state"] == "STOPPED"
    await child.close()  # Idempotent stop; no receipt reuse or re-execution.
    with pytest.raises(ValueError, match="NO_REPLAY"):
        preflight(store)


@pytest.mark.asyncio
async def test_permission_denial_does_not_claim_cleanup_or_restart(tmp_path, monkeypatch):
    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch, denied=True)
    child = AuthenticationLifecycle(store)
    with pytest.raises(ValueError, match="COLLECTION_FAILED_BEFORE_READY|CHILD_EXIT_BEFORE_READY"):
        await child.start()
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        await child.close()
    proof = json.loads((store.directory / "authentication-cleanup.json").read_text())
    assert proof["cleanup"] == "UNVERIFIED" and not proof["stop_ack"]
    assert child.process.returncode != 0
    assert child._read()["collector"] == "PERMISSION_DENIED"
    with pytest.raises(ValueError, match="NO_REPLAY"):
        preflight(store)


@pytest.mark.asyncio
async def test_main_continuous_entry_owns_auth_start_and_stop(tmp_path, monkeypatch):
    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch)
    runtime = ContinuousRuntime(store.directory)

    class IdleFixtureSource:
        async def events(self):
            await runtime.stop.wait()
            if False:
                yield {}  # Only the TCX/Replay I/O boundary; no Native execution.

        async def close(self):
            return None

    runtime.source = IdleFixtureSource()
    task = asyncio.create_task(runtime.run())
    try:
        for _ in range(150):
            if runtime.auth_lifecycle.state == "RUNNING" or task.done():
                break
            await asyncio.sleep(0.05)
        assert not task.done(), task.exception() if task.done() else None
        assert runtime.auth_lifecycle.state == "RUNNING"
        assert (await runtime.observed_snapshot())["authentication"]["host_events"] == 3
    finally:
        runtime.stop.set()
        await asyncio.wait_for(task, 15)
    assert runtime.auth_lifecycle.evidence["cleanup"] == "VERIFIED"
    assert runtime.auth_lifecycle.evidence["stop_ack"]


@pytest.mark.parametrize("fault", ["stale", "identity", "crash"])
@pytest.mark.asyncio
async def test_lifecycle_watch_failures_are_visible_and_do_not_restart(
    tmp_path, monkeypatch, fault
):
    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch)
    child = AuthenticationLifecycle(store)
    try:
        await child.start()
        if fault == "crash":
            child.process.kill()
            await child.process.wait()
            expected = "CHILD_EXITED"
        else:
            observed = child._read()
            if fault == "stale":
                observed["heartbeat_monotonic"] = 0
                expected = "HEARTBEAT_STALE"
            else:
                observed["runtime_identity"] = {}
                expected = "IDENTITY_CHANGED"
            monkeypatch.setattr(child, "_read", lambda: observed)
        with pytest.raises(ValueError, match=expected):
            await child.watch(asyncio.Event())
    finally:
        if fault == "crash":
            with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
                await child.close()
        else:
            await child.close()
    assert (store.directory / "authentication-start-intent.json").exists()
    with pytest.raises(ValueError, match="NO_REPLAY"):
        preflight(store)


def test_package_schema_integrity_without_any_if_execution(tmp_path):
    from soc_agent.continuous.authentication_admission import observation
    from soc_agent.security_ai.workflow_models import PackageInput

    store = prepare(tmp_path)
    directory = Path(__file__).parents[2] / "fixtures/security_ai_packages/authentication_anomaly"
    package = PackageInput(
        directory=str(directory),
        manifest_sha256=hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest(),
    )
    result = observation(store.config.authentication_runtime, (package,))
    admission = result["if_admission"]
    assert admission["state"] == "INSUFFICIENT_COMPLETE_WINDOW"
    assert admission["native_training_parity"] == "UNVERIFIED"
    assert admission["predictions"] == 0
    assert len(admission["model"]["feature_names"]) == 5
    assert admission["model"]["threshold"] == 0.95


def test_gui_preserves_lifecycle_admission_and_reconnect_projection():
    from soc_agent.gui.continuous_projection import project

    snapshot = dict(
        state="RUNNING",
        authentication=dict(
            runtime_state="FAILED",
            host_events=3,
            if_admission=dict(state="BLOCKED_NO_APPROVED_PACKAGE", predictions=0),
            managed_lifecycle=dict(state="FAILED", cleanup="UNVERIFIED"),
        ),
    )
    # The independent attached GUI store can still have an old RUNNING snapshot.
    value = dict(authentication=dict(runtime_state="RUNNING"), continuous=snapshot)
    first = project(value)
    again = project(value)
    assert first == again
    assert first["authentication"]["runtime_state"] == "FAILED"
    assert first["authentication"]["host_events"] == 3
    assert first["authentication"]["if_admission"]["predictions"] == 0


@pytest.mark.asyncio
async def test_cleanup_evidence_write_failure_does_not_publish_verified(tmp_path, monkeypatch):
    import soc_agent.continuous.authentication_lifecycle as lifecycle

    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch)
    child = AuthenticationLifecycle(store)
    await child.start()
    original = lifecycle.write_new

    def disk_full(path, value):
        if path.name == "authentication-cleanup.json":
            raise OSError("FIXTURE_DISK_FULL")
        return original(path, value)

    monkeypatch.setattr(lifecycle, "write_new", disk_full)
    with pytest.raises(OSError, match="FIXTURE_DISK_FULL"):
        await child.close()
    value = child.snapshot()["managed_lifecycle"]
    assert child.process.returncode == 0 and value["stop_ack"]
    assert value["cleanup"] == "UNVERIFIED" and not value["durable_cleanup"]
    assert value["state"] == "FAILED"
    assert not (store.directory / "authentication-cleanup.json").exists()


@pytest.mark.asyncio
async def test_stop_during_status_read_is_not_a_new_stale_failure(tmp_path, monkeypatch):
    import threading
    from types import SimpleNamespace

    child = AuthenticationLifecycle(prepare(tmp_path))
    child.process = SimpleNamespace(returncode=None)
    child.state = "RUNNING"
    entered, release = threading.Event(), threading.Event()
    stopped = asyncio.Event()

    def read():
        entered.set()
        assert release.wait(2)
        return dict(heartbeat_monotonic=0, runtime_identity={}, state="STOPPED")

    monkeypatch.setattr(child, "_read", read)
    watching = asyncio.create_task(child.watch(stopped))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        stopped.set()
        release.set()
        await asyncio.wait_for(watching, 1)
    finally:
        release.set()
        await asyncio.gather(watching, return_exceptions=True)
    assert child.state != "FAILED"
    assert child.evidence.get("cleanup") != "VERIFIED"  # STOP is not cleanup proof.
