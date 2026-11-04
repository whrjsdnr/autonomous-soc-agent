"""Own the existing LinuxMonitor child under the parent's resource/STOP scope.

No collector, policy issuer, inference implementation or permission escalation.
"""

import asyncio
import hashlib
import json
import os
import sys
import time
from uuid import NAMESPACE_URL, UUID, uuid5

from soc_agent.approval import ApprovalManager, ApprovalRequest
from soc_agent.continuous.process_identity import runtime_identity, same_runtime
from soc_agent.continuous.store import Store
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry
from soc_agent.tools.errors import ToolExecutionError

METADATA = ToolMetadata(
    name="collect_host_authentication_journal",
    description="Bounded existing auth/authpriv or sshd journal read; no settings changes",
    permission="system_read",
    risk_level="medium",
)
SELECTION = ("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+", "_COMM=sshd")


def action(store: Store) -> ActionProposal:
    if os.getuid() == 0:
        raise ValueError("AUTHENTICATION_REQUIRES_UNPRIVILEGED_USER")
    cfg = store.config
    if cfg.managed_authentication is None or cfg.authentication_runtime is None:
        raise ValueError("AUTHENTICATION_MANAGED_SCOPE_REQUIRED")
    path = cfg.authentication_runtime
    if path != store.directory / "authentication" or path.is_symlink():
        raise ValueError("AUTHENTICATION_RUNTIME_MUST_BE_SESSION_OWNED")
    authentication = RuntimeStore(path)
    if (
        authentication.config.incident_id != store.database.store_id
        or authentication.config.assessment_mode != "READ_ONLY"
        or authentication.config.env_file is not None
        or (path / "network/config.json").exists()
    ):
        raise ValueError("AUTHENTICATION_RUNTIME_SCOPE_MISMATCH")
    from soc_agent.continuous.cli import code_identity

    pin = read_local(store.directory / "code-identity", 128).decode()
    if pin != code_identity():
        raise ValueError("AUTHENTICATION_EXECUTABLE_CHANGED")
    body = dict(
        session=str(store.database.store_id),
        namespace=cfg.namespace,
        continuous_config_sha256=digest(cfg.model_dump(mode="json")),
        runtime=str(path),
        authentication_config_sha256=authentication.config.digest,
        code_identity=pin,
        uid=os.getuid(),
        selection=list(SELECTION),
        duration_seconds=cfg.managed_authentication.duration_seconds,
        permissions="READ_ONLY_NO_IF_API_ROOT_OR_RESPONSE_AUTHORITY",
    )
    return ActionProposal(
        action_id=uuid5(NAMESPACE_URL, "soc-authentication:" + digest(body)),
        incident_id=store.database.store_id,
        tool_name=METADATA.name,
        tool_input=body,
    )


class _Input(Frozen):
    session: UUID
    namespace: str
    continuous_config_sha256: str
    runtime: str
    authentication_config_sha256: str
    code_identity: str
    uid: int
    selection: tuple[str, ...]
    duration_seconds: int
    permissions: str


class _Output(Frozen):
    state: str
    pid: int


async def _no_dispatch(_):
    raise ValueError("AUTHENTICATION_PREFLIGHT_ONLY_TOOL")


def _authorized(store, handler=_no_dispatch):
    proposed = action(store)
    try:
        receipt = ApprovalRequest.model_validate_json(
            read_local(store.config.managed_authentication.approval_file, 32768)
        )
    except FileNotFoundError as error:
        raise ValueError("AUTHENTICATION_EXACT_HUMAN_APPROVAL_REQUIRED") from error
    if (
        receipt.expires_at is None
        or receipt.decision is None
        or receipt.decision.decided_at > utc_now()
        or (receipt.expires_at - utc_now()).total_seconds()
        < store.config.managed_authentication.duration_seconds + 5
    ):
        raise ValueError("AUTHENTICATION_EXACT_HUMAN_APPROVAL_REQUIRED")
    approvals = ApprovalManager()
    approvals.restore(receipt)
    registry = ToolRegistry()
    registry.register(Tool(METADATA, _Input, _Output, handler))
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
    executor.preflight(proposed, approval_id=receipt.approval_id)
    if (store.directory / "authentication-start-intent.json").exists():
        raise ValueError("AUTHENTICATION_SESSION_ALREADY_ATTEMPTED_NO_REPLAY")
    return proposed, receipt, executor


def preflight(store):
    proposed, receipt, _ = _authorized(store)
    return proposed, receipt


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


class AuthenticationLifecycle:
    def __init__(self, store: Store):
        self.store = store
        self.directory = store.config.authentication_runtime
        self.process = None
        self.identity = None
        self.log = None
        self.state = "NOT_STARTED"
        self.cleanup_written = False
        self.startup_diagnostic = {}
        self._reader = None
        self.evidence = dict(cleanup="NOT_STARTED", stop_ack=False)

    def snapshot(self):
        if self.state == "RUNNING" and (
            self.process.returncode is not None or not same_runtime(self.identity)
        ):
            self.state = "FAILED"
        return dict(
            runtime_state=self.state,
            managed_lifecycle=dict(
                state=self.state,
                identity=self.identity,
                startup_diagnostic=dict(self.startup_diagnostic),
                durable_cleanup=self.cleanup_written,
                **self.evidence,
                input_assurance="DECLARED_HOST_READER_NOT_KERNEL_ATTESTATION",
                inference="NO_IF_ACTION_GRANTED_BY_COLLECTION_APPROVAL",
            ),
        )

    def _read(self):
        return RuntimeStore.observation(self.directory)

    async def _observe(self, timeout):
        if self._reader is not None and not self._reader.done():
            raise ValueError("AUTHENTICATION_STATE_READER_STILL_PENDING")
        self._reader = asyncio.create_task(asyncio.to_thread(self._read))
        return await asyncio.wait_for(asyncio.shield(self._reader), timeout)

    async def _join_reader(self, timeout):
        if self._reader is not None:
            await asyncio.wait_for(asyncio.shield(self._reader), max(0.001, timeout))

    async def start(self) -> None:
        async def launch(value):
            if value.model_dump(mode="json") != action(self.store).input_payload():
                raise ValueError("AUTHENTICATION_SCOPE_CHANGED_BEFORE_EXECUTION")
            await self._start_owned(proposed, receipt)
            return _Output(state=self.state, pid=self.process.pid)

        proposed, receipt, executor = await asyncio.to_thread(_authorized, self.store, launch)
        try:
            await executor.execute(proposed, approval_id=receipt.approval_id)
        except BaseException as error:
            self.state = "FAILED"
            if isinstance(error, ToolExecutionError) and isinstance(
                error.__cause__, (ValueError, OSError)
            ):
                raise error.__cause__ from error
            raise

    async def _start_owned(self, proposed, receipt):
        saved = await self._observe(5)
        if saved["state"] != "STOPPED":
            raise ValueError("AUTHENTICATION_RUNTIME_NOT_STOPPED")
        await asyncio.to_thread(
            write_new,
            self.store.directory / "authentication-start-intent.json",
            dict(
                action=proposed.model_dump(mode="json"),
                approval_sha256=hashlib.sha256(receipt.model_dump_json().encode()).hexdigest(),
                automatic_retry=False,
            ),
        )
        self.state = "STARTING"
        fd = os.open(
            self.store.directory / "authentication-child.log",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        self.log = os.fdopen(fd, "wb")
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-B",
            "-m",
            "soc_agent.linux_runtime",
            "--directory",
            str(self.directory),
            "start",
            "--duration-seconds",
            str(self.store.config.managed_authentication.duration_seconds),
            env=dict(
                os.environ,
                PYTHONDONTWRITEBYTECODE="1",
                OPENBLAS_NUM_THREADS="1",
                OMP_NUM_THREADS="1",
                MKL_NUM_THREADS="1",
            ),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=self.log,
            stderr=self.log,
        )
        self.identity = runtime_identity(self.process.pid)
        spawned = time.monotonic()
        deadline = spawned + 5
        self.startup_diagnostic = dict(spawned_monotonic=spawned, deadline_monotonic=deadline)
        while time.monotonic() < deadline:
            if self.process.returncode is not None:
                raise ValueError("AUTHENTICATION_CHILD_EXIT_BEFORE_READY")
            observed = await self._observe(max(0.001, deadline - time.monotonic()))
            self.startup_diagnostic.update(
                observed_monotonic=time.monotonic(),
                identity_matches=observed.get("runtime_identity") == self.identity,
                state=observed["state"],
                collector=observed.get("collector"),
                collection_diagnostic=observed.get("collection_diagnostic"),
            )
            if (
                observed.get("runtime_identity") == self.identity
                and observed.get("collector")
                in ("INITIAL_READ", "RESUMED_EXACT", "RESUMED_WITH_REPLAY")
                and observed["state"] == "RUNNING"
            ):
                self.state = "RUNNING"
                return
            if observed["state"] == "FAILED":
                raise ValueError("AUTHENTICATION_COLLECTION_FAILED_BEFORE_READY")
            await asyncio.sleep(0.05)
        raise ValueError("AUTHENTICATION_READY_TIMEOUT")

    async def watch(self, stopped: asyncio.Event) -> None:
        try:
            while not stopped.is_set():
                if self.process.returncode is not None:
                    raise ValueError("AUTHENTICATION_CHILD_EXITED_DURING_COLLECTION")
                try:
                    state = await self._observe(5)
                except TimeoutError as error:
                    raise ValueError("AUTHENTICATION_STATE_OBSERVATION_TIMEOUT") from error
                # STOP can arrive while the read is in flight. Liveness applies
                # to active collection, not a snapshot read before requested STOP.
                # close() still independently requires exit/ACK/durable evidence.
                if stopped.is_set():
                    return
                if state.get("runtime_identity") != self.identity or not same_runtime(
                    self.identity
                ):
                    raise ValueError("AUTHENTICATION_PROCESS_IDENTITY_CHANGED")
                age = time.monotonic() - state.get("heartbeat_monotonic", float("-inf"))
                if not 0 <= age < 5:
                    raise ValueError("AUTHENTICATION_HEARTBEAT_STALE")
                if state["state"] != "RUNNING" or state.get("last_error"):
                    raise ValueError("AUTHENTICATION_RUNTIME_FAILED")
                await asyncio.sleep(0.2)
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError):
                self.state = "FAILED"
            raise

    async def close(self) -> None:
        if self.evidence.get("cleanup") == "VERIFIED":
            return
        if self.process is None:
            await self._join_reader(5)
            if self.log is not None:
                self.log.close()
            return
        requested = time.monotonic()
        self.state = "STOPPING"
        forced = False
        try:
            if self.process.returncode is None:
                if not same_runtime(self.identity):
                    raise ValueError("AUTHENTICATION_STOP_IDENTITY_CHANGED")
                self.process.terminate()  # Only this owned child; existing CLI handles SIGTERM.
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except TimeoutError:
                forced = True
                if same_runtime(self.identity):
                    self.process.kill()
                await asyncio.wait_for(self.process.wait(), 5)
            # A timed-out/cancelled observation still owns its SQLite reader.
            # It must finish before any resource Cleanup claim, within the
            # existing STOP budget, without issuing another observation.
            await self._join_reader(requested + 5 - time.monotonic())
            auth = await asyncio.to_thread(RuntimeStore, self.directory)
            state = await asyncio.to_thread(auth.state)
            await asyncio.to_thread(auth.verify_audit)
            with auth.database.transaction(write=False) as connection:
                events = [
                    json.loads(row[0])["kind"]
                    for row in connection.execute(
                        "SELECT payload FROM monitor_audit ORDER BY sequence"
                    )
                ]
            # Only the latest child run's ordered stop records can acknowledge it.
            latest_start = max(
                (i for i, kind in enumerate(events) if kind == "RUNTIME_STARTED"),
                default=-1,
            )
            latest_events = events[latest_start + 1 :]
            from soc_agent.linux_runtime.service import open_pipeline

            pipeline = await asyncio.to_thread(open_pipeline, self.directory, auth.config)
            queue_counts = await asyncio.to_thread(pipeline.queue.counts)
            jobs = await asyncio.to_thread(auth.jobs)
            ack = bool(
                not forced
                and self.process.returncode == 0
                and state["state"] == "STOPPED"
                and state.get("last_error") is None
                and state.get("runtime_identity") == self.identity
                and latest_start >= 0
                and "RUNTIME_STOPPING" in latest_events
                and "RUNTIME_STOPPED" in latest_events
                and latest_events.index("RUNTIME_STOPPING") < latest_events.index("RUNTIME_STOPPED")
            )
            self.evidence = dict(
                cleanup="VERIFIED" if ack else "UNVERIFIED",
                stop_ack=ack,
                stop_requested_monotonic=requested,
                observed_monotonic=time.monotonic(),
                returncode=self.process.returncode,
                forced=forced,
                child_reaped=True,
                state_reader_joined=self._reader is None or self._reader.done(),
                queue_counts=queue_counts,
                queue_drained=not any(queue_counts.get(k, 0) for k in ("PENDING", "CLAIMED")),
                investigation_jobs=jobs,
                pending_jobs_preserved=True,
                scope="OWNED_AUTHENTICATION_CHILD_AND_AUDITED_STORE_NOT_GLOBAL_KERNEL",
            )
            await asyncio.to_thread(
                write_new, self.store.directory / "authentication-cleanup.json", self.evidence
            )
            self.cleanup_written = True
            if not ack:
                raise ValueError("AUTHENTICATION_CLEANUP_UNVERIFIED")
            self.state = "STOPPED"
        except BaseException as error:
            self.state = "FAILED"
            if self.evidence.get("cleanup") == "VERIFIED":
                # An ACK cannot replace failed durable evidence storage.
                self.evidence.update(
                    cleanup="UNVERIFIED",
                    first_cleanup_error=type(error).__name__ + ":" + str(error)[:300],
                )
            if self.evidence.get("cleanup") == "NOT_STARTED":
                self.evidence = dict(
                    cleanup="UNVERIFIED",
                    stop_ack=False,
                    stop_requested_monotonic=requested,
                    observed_monotonic=time.monotonic(),
                    returncode=self.process.returncode,
                    forced=forced,
                    first_cleanup_error=type(error).__name__ + ":" + str(error)[:300],
                )
                await asyncio.to_thread(
                    write_new, self.store.directory / "authentication-cleanup.json", self.evidence
                )
            raise
        finally:
            if self.log is not None:
                self.log.close()
