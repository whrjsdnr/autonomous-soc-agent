"""Fixed fixture child bootstrap and PID/start-tick supervision, no elevation path."""

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Command
from soc_agent.security_ai.ebpf_broker.identity import sealed_object, verify_bundle
from soc_agent.security_ai.ebpf_broker.ipc import receive, send
from soc_agent.security_ai.ebpf_broker.journal import recover
from soc_agent.security_ai.ebpf_native.contracts import ProcessIdentity, alive, process_identity


class BrokerProcess:
    def __init__(self, plan: BrokerPlan, program: Path, directory: Path):
        self.plan, self.directory = plan, directory
        self.sequence, self.closed = 0, False
        self.identity: ProcessIdentity | None = None
        self.last: dict = {}
        self.lock = threading.Lock()
        verify_bundle(plan.bundle_digest)
        object_fd = sealed_object(program, plan.application.scope.program_sha256)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        for channel in (parent, child):
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        self.channel = parent
        parent.settimeout(5)
        try:
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "soc_agent.security_ai.ebpf_broker.server",
                    str(child.fileno()),
                    str(object_fd),
                ],
                cwd=directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(child.fileno(), object_fd),
                close_fds=True,
                start_new_session=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C",
                    "OPENBLAS_NUM_THREADS": "1",
                    "OMP_NUM_THREADS": "1",
                    "MKL_NUM_THREADS": "1",
                    "PYTHONPATH": str(Path(__file__).resolve().parents[3]),
                },
            )
            child.close()
            send(parent, plan.model_dump(mode="json"))
            response = receive(parent)
            self.identity = ProcessIdentity.model_validate(response["identity"])
            if (
                not response.get("ready")
                or response.get("plan_digest") != plan.identity
                or self.identity.pid != self.process.pid
                or process_identity(self.process.pid) != self.identity
                or self.identity.uid != plan.uid
            ):
                raise ValueError("BROKER_PROCESS_IDENTITY_FAILED")
        except BaseException:
            parent.close()
            child.close()
            if hasattr(self, "process"):
                # Closing the inherited peer signals cleanup; wait/reap only our child.
                try:
                    self.process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            raise
        finally:
            os.close(object_fd)

    def request(self, operation: str, **arguments) -> dict:
        with self.lock:
            if self.closed or self.process.poll() is not None or not alive(self.identity):
                raise ValueError("BROKER_PROCESS_NOT_RUNNING")
            verify_bundle(self.plan.bundle_digest)
            command = Command(
                command=operation,
                plan_digest=self.plan.identity,
                sequence=self.sequence + 1,
                **arguments,
            )
            send(self.channel, command.model_dump(mode="json"))
            self.sequence += 1
            response = receive(self.channel)
            if (
                response.get("plan_digest") != self.plan.identity
                or response.get("sequence") != command.sequence
                or response.get("identity") != self.identity.model_dump()
            ):
                raise ValueError("BROKER_RESPONSE_INTEGRITY_FAILED")
            self.last = response
            return response["snapshot"]

    def close(self) -> dict:
        if self.closed:
            return recover(self.directory / "broker-audit.jsonl", self.plan.identity)
        self.closed = True
        self.channel.close()  # EOF requests exact-owned cleanup even if the controller fails.
        try:
            code = self.process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            # Identity was established at bootstrap, Popen owns this unreaped child only.
            self.process.kill()
            self.process.wait(timeout=2)
            raise ValueError("BROKER_EXIT_CLEANUP_UNVERIFIED") from None
        result = recover(self.directory / "broker-audit.jsonl", self.plan.identity)
        if code != 0 or result["cleanup_status"] != "FIXTURE_VERIFIED":
            raise ValueError("BROKER_EXIT_CLEANUP_UNVERIFIED")
        return dict(**result, process_exit=code)

    def metrics(self) -> dict:
        rss = None
        if self.identity and alive(self.identity):
            rows = Path(f"/proc/{self.identity.pid}/status").read_text().splitlines()
            rss = int(next(v.split()[1] for v in rows if v.startswith("VmRSS:"))) * 1024
        return dict(
            process_identity=self.identity.model_dump() if self.identity else None,
            rss_bytes=rss,
            process_exit=self.process.poll(),
            ipc_in_flight_limit=1,
            kernel_event_queue_depth=None,
            observed_at_monotonic=time.monotonic(),
        )
