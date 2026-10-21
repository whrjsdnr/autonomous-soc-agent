"""Ordinary-user client/image preparation for a single OS-authenticated supervisor."""

import array
import base64
import fcntl
import hashlib
import json
import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path
from typing import Literal

from soc_agent.review.models import Hash
from soc_agent.security_ai.collectors.live_contract import LivePlan, docker_argv
from soc_agent.security_ai.collectors.live_contract import bundle as zeek_bundle
from soc_agent.security_ai.ebpf_native.contracts import process_identity
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.supervisor_engine import SUP_LIMIT, sup_json
from soc_agent.security_ai.ebpf_tc.unified import UnifiedSession
from soc_agent.security_ai.ebpf_tc.unified_image import UnifiedImage, prepare_unified_image
from soc_agent.security_ai.research.models import digest


class SupervisorImage(UnifiedImage):
    supervisor_contract: Literal["SOC_SINGLE_AUTH_SUPERVISOR_V1"] = "SOC_SINGLE_AUTH_SUPERVISOR_V1"
    zeek_bundle: Hash
    scope_namespace: Literal["net:[4026531833]"]


def prepare_supervisor_image(package: Path, manifest: str, output: Path) -> SupervisorImage:
    """Build bytes only. No auth, install, inventory syscall, Docker run or capability changes."""
    if os.readlink("/proc/self/ns/net") != "net:[4026531833]":
        raise ValueError("SUPERVISOR_REVIEWED_NAMESPACE_CHANGED")
    base = prepare_unified_image(package, manifest, output.with_suffix(".tcx-only.py"))
    plan = LivePlan(net_namespace="net:[4026531833]", bundle_digest=digest(zeek_bundle()))
    argv = docker_argv(plan, Path("@POLICY@"))
    for index, arg in enumerate(argv):
        argv[index] = (
            arg.replace("soc-zeek-" + plan.session_id.hex, "@NAME@")
            .replace(plan.identity, "@PLAN@")
            .replace(str(plan.controller_generation), "@GENERATION@")
            .replace(plan.net_namespace, "@NAMESPACE@")
        )
    argv[0] = "/usr/bin/docker"
    root = Path(__file__).parents[1] / "collectors"
    config = dict(
        bpftool="/usr/lib/linux-tools-6.8.0-147/bpftool",
        tc="/usr/sbin/tc",
        zeek_argv=argv,
        zeek_scope={
            k: v
            for k, v in plan.model_dump(mode="json").items()
            if k not in {"session_id", "controller_generation", "net_namespace"}
        },
        scripts={
            n: dict(
                body=base64.b64encode((root / n).read_bytes()).decode(),
                sha256=hashlib.sha256((root / n).read_bytes()).hexdigest(),
            )
            for n in ("live.zeek", "network14.zeek", "visibility.zeek")
        },
        tools={},
    )
    for name in (config["bpftool"], config["tc"]):
        path = Path(name)
        body = read_held(path, owner=0, limit=64 * 1024**2)
        config["tools"][name] = dict(
            sha256=hashlib.sha256(body).hexdigest(), mode=stat.S_IMODE(path.stat().st_mode)
        )
    source = base.path.read_bytes()
    trailer = (
        b"if __name__ == '__main__':\n    import sys\n"
        b"    unified_root_main(IMAGE, PREVIOUS, sys.argv, globals())\n"
    )
    if not source.endswith(trailer):
        raise ValueError("SUPERVISOR_IMAGE_TEMPLATE_CHANGED")
    source = source[: -len(trailer)] + Path(__file__).with_name("supervisor_engine.py").read_bytes()
    source += (
        b"\nSUPERVISOR_CONFIG = json.loads("
        + repr(json.dumps(config, sort_keys=True)).encode()
        + b")\n"
    )
    source += trailer
    compile(source, "<supervisor-image>", "exec")
    if len(source) > 1048576:
        raise ValueError("SUPERVISOR_IMAGE_BOUND")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(source)
        stream.flush()
        os.fsync(stream.fileno())
    return SupervisorImage(
        **(
            base.model_dump()
            | dict(
                path=output.absolute(),
                sha256=hashlib.sha256(source).hexdigest(),
                zeek_bundle=plan.bundle_digest,
                scope_namespace=plan.net_namespace,
            )
        )
    )


class SupervisorClient:
    def __init__(self, channel, identity, binding, record=None):
        self.channel, self.identity, self.binding = channel, identity, binding
        self.record = record
        self.lock = threading.Lock()
        self.sequence = 0
        self.chain = "0" * 64
        self.final = None
        self.stopping = False
        self.last_status = None

    def receive(self, *, fd_allowed=False):
        body, ancillary, flags, _ = self.channel.recvmsg(
            SUP_LIMIT, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC
        )
        descriptors = []
        try:
            credentials = []
            bad = False
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received = array.array("i")
                    received.frombytes(data[: len(data) - len(data) % received.itemsize])
                    descriptors.extend(received)
                elif (
                    level == socket.SOL_SOCKET
                    and kind == socket.SCM_CREDENTIALS
                    and len(data) == 12
                ):
                    credentials.append(struct.unpack("3i", data))
                else:
                    bad = True
            value = json.loads(body) if body else {}
            try:
                identity = process_identity(self.identity.pid)
            except (OSError, ValueError):
                if "final" not in value:
                    raise
                identity = self.identity  # Final queued Kernel-credentialed frame after exit.
            if (
                not body
                or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or bad
                or credentials != [(self.identity.pid, 0, 0)]
                or identity.start_ticks != self.identity.start_ticks
                or identity.uid != 0
                or len(descriptors) > 1
                or descriptors
                and not fd_allowed
            ):
                raise ValueError("SUPERVISOR_RESPONSE_IDENTITY")
            if not isinstance(value, dict) or value.get("binding") != self.binding:
                raise ValueError("SUPERVISOR_RESPONSE_BINDING")
            if descriptors:
                fd = descriptors[0]
                if (
                    not stat.S_ISFIFO(os.fstat(fd).st_mode)
                    or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                ):
                    raise ValueError("SUPERVISOR_DATA_FD_NOT_READ_ONLY_PIPE")
            result = descriptors.pop() if descriptors else None
            return value, result
        finally:
            for fd in descriptors:
                os.close(fd)

    def request(self, command, data=None):
        with self.lock:
            if self.stopping:
                raise ValueError("SUPERVISOR_CLIENT_CLOSED")
            self.sequence += 1
            request = dict(
                command=command, sequence=self.sequence, binding=self.binding, data=data or {}
            )
            body = sup_json(request)
            if len(body) > SUP_LIMIT or self.channel.send(body) != len(body):
                raise ValueError("SUPERVISOR_REQUEST_BOUND")
            response, fd = self.receive(fd_allowed=command == "START_ZEEK")
            if "final" in response:
                self.final = response
                raise ValueError("SUPERVISOR_SESSION_TERMINATED")
            if (
                not isinstance(response, dict)
                or set(response)
                != {"sequence", "binding", "state", "status", "error", "previous", "digest"}
                or response["sequence"] != self.sequence
                or response["previous"] != self.chain
                or not isinstance(response["digest"], str)
            ):
                if fd is not None:
                    os.close(fd)
                raise ValueError("SUPERVISOR_RESPONSE_SCHEMA")
            claimed = response.pop("digest")
            if hashlib.sha256(sup_json(response)).hexdigest() != claimed:
                if fd is not None:
                    os.close(fd)
                raise ValueError("SUPERVISOR_AUDIT_CHAIN")
            self.chain = claimed
            self.last_status = response["status"]
            if self.record and (command != "STATUS" or response["error"]):
                self.record(response | {"digest": claimed, "command": command})
            if response["error"]:
                if fd is not None:
                    os.close(fd)
                raise ValueError(response["error"])
            if command == "STOP":
                self.stopping = True
            return response, fd

    def status(self):
        if self.stopping:
            return self.last_status
        response, _ = self.request("STATUS")
        return response["status"]

    def authorize(self, plan):
        if plan.bundle_digest != digest(zeek_bundle()):
            raise ValueError("SUPERVISOR_ZEEK_BUNDLE_CHANGED")
        self.status()  # Peer/session checked, not a cached sudo assertion.

    def start(self, plan):
        response, fd = self.request("START_ZEEK", plan.model_dump(mode="json"))
        if fd is None:
            raise ValueError("SUPERVISOR_DATA_FD_MISSING")
        return ZeekProcess(self, fd)

    def stop_zeek(self):
        if self.stopping:
            return self.last_status["zeek_stopped"]
        return self.request("STOP_ZEEK")[0]["status"]["zeek_stopped"]


class ZeekProcess:
    """Read-only data pipe plus fixed status/stop operations; no privileged FD."""

    def __init__(self, client, fd):
        self.client = client
        self.stdout = os.fdopen(fd, "rb", buffering=0)
        self.returncode = None

    def poll(self):
        if self.returncode is None:
            self.returncode = self.client.status()["zeek_exit"]
        return self.returncode

    def wait(self, timeout):
        import subprocess

        deadline = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("SUPERVISED_ZEEK", timeout)
            time.sleep(0.1)
        return self.returncode

    def kill(self):
        # This means identity-checked container stop, never arbitrary PID signal.
        self.client.stop_zeek()


class SupervisedSession(UnifiedSession):
    def __init__(self, *args, image: SupervisorImage, **kwargs):
        if not isinstance(image, SupervisorImage):
            raise ValueError("SUPERVISOR_IMAGE_REQUIRED")
        self.supervisor_listener = self.supervisor = None
        self.supervisor_hello = self.supervisor_final = None
        self.zeek_snapshot = None
        super().__init__(*args, image=image, **kwargs)

    def prepare(self):
        result = super().prepare()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.settimeout(5)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(
            f"\0soc-supervisor.{self.plan.broker.uid}.{self.plan.broker.application.application_session.hex}"
        )
        listener.listen(1)
        self.supervisor_listener = listener
        return result

    def _authentication_verified(self):
        super()._authentication_verified()
        channel, _ = self.supervisor_listener.accept()
        channel.settimeout(12)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.supervisor_listener.close()
        self.supervisor_listener = None
        pid, uid, gid = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        try:
            if (uid, gid) != (0, 0):
                raise ValueError("SUPERVISOR_ROOT_PEER_REQUIRED")
            identity = process_identity(pid)
            parent = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1]
            if int(parent) != self.identity.pid:
                raise ValueError("SUPERVISOR_PARENT_BROKER_MISMATCH")
            binding = hashlib.sha256(
                b"SOC_SUPERVISOR_V1\0" + bytes.fromhex(self.approval) + self.envelope
            ).hexdigest()
            self.supervisor = SupervisorClient(
                channel,
                identity,
                binding,
                record=lambda evidence: self._event("SUPERVISOR_COMMAND", evidence=evidence),
            )
            self.supervisor_hello, _ = self.supervisor.receive()
            if self.supervisor_hello["state"] != "RESOURCE_VERIFIED":
                raise ValueError("SUPERVISOR_RESOURCE_VERIFICATION_REQUIRED")
            status = Path(f"/proc/{pid}/status").read_text()
            observed = {
                k: int(v.strip(), 16)
                for row in status.splitlines()
                if ":" in row
                for k, v in [row.split(":", 1)]
                if k in {"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"}
            }
            mask = (1 << 39) | (1 << 12)
            if observed != dict(CapEff=0, CapPrm=mask, CapInh=0, CapAmb=0, CapBnd=mask):
                raise ValueError("SUPERVISOR_CAPABILITY_SCOPE_MISMATCH")
            self._event(
                "SUPERVISOR_SESSION_BOUND", evidence=self.supervisor_hello, capability_sets=observed
            )
        except BaseException:
            channel.close()
            raise

    def command(self, value):
        if value.command in {"ATTACH", "PREPARE"}:
            if self.supervisor is None or self.supervisor.stopping:
                raise ValueError("SUPERVISOR_SESSION_REQUIRED_FOR_NEW_WORK")
            self.supervisor.status()
        # STOP/DETACH/CLEANUP retain the original owned-FD safety path even if
        # the companion Supervisor or release verification has failed.
        return super().command(value)

    def observe(self):
        result = super().observe()
        if self.supervisor and not self.ended and not self.supervisor.stopping:
            try:
                self.supervisor.status()
            except (OSError, ValueError, EOFError) as exc:
                self.error = self.error or str(exc)
                self.close()
        return result

    def close(self):
        if self.ended:
            return self.snapshot()
        failure = None
        try:
            if self.supervisor:
                self.supervisor.request(
                    "STOP"
                )  # Stop Zeek first, then existing FD-owning TCX cleanup.
        except (OSError, ValueError) as exc:
            failure = str(exc)
        try:
            super().close()
        finally:
            if self.supervisor:
                try:
                    if self.supervisor.final is not None:
                        self.supervisor_final = self.supervisor.final
                    else:
                        self.supervisor_final, _ = self.supervisor.receive()
                    self._event("SUPERVISOR_CLEANUP", evidence=self.supervisor_final)
                    if self.supervisor_final["final"]["cleanup"] != "VERIFIED":
                        failure = failure or "SUPERVISOR_CLEANUP_UNVERIFIED"
                except (OSError, ValueError, EOFError) as exc:
                    failure = failure or str(exc)
                self.supervisor.channel.close()
            if self.supervisor_listener:
                self.supervisor_listener.close()
                self.supervisor_listener = None
        if failure:
            self.error = self.error or failure
            self.cleanup = "CLEANUP_UNVERIFIED"
            self.state = "ERROR"
        return self.snapshot()

    def approval_scope(self):
        return super().approval_scope() | dict(
            supervisor="READ_ONLY_INSPECTION_TCX_BROKER_BOUNDED_ZEEK_NO_SUDO_CACHE",
            zeek_bundle=self.image.zeek_bundle,
            zeek_scope=(
                "lo same namespace; 300s/4096 packets/8192 events/8MiB output; CPU1/RAM512MiB"
            ),
            supervisor_scope="E0 idle; permitted/bounding CAP_BPF+CAP_NET_ADMIN; 256MiB/CPU20s",
        )

    def snapshot(self):
        lifecycle = "PREPARE"
        if self.ended:
            lifecycle = (
                "CLOSED"
                if not self.error and self.cleanup == "PROCESS_AND_AUDIT_VERIFIED"
                else "ERROR"
            )
        elif self.supervisor_hello:
            lifecycle = "TCX_READY"
            if self.zeek_snapshot and self.zeek_snapshot.get("collection_live"):
                lifecycle = "ZEEK_READY"
                if self.link_evidence and self.link_evidence.get("state") == "TCX_LINK_VERIFIED":
                    lifecycle = "ACTIVE"
        elif self.authentication == "OS_AUTHENTICATED":
            lifecycle = "AUTHENTICATED"
        return super().snapshot() | dict(
            supervisor_lifecycle=lifecycle,
            supervisor_hello=self.supervisor_hello,
            supervisor_final=self.supervisor_final,
            zeek=self.zeek_snapshot,
            zeek_summary=(
                {
                    "state": self.zeek_snapshot.get("state"),
                    "origin": self.zeek_snapshot.get("input_origin"),
                    "network": self.zeek_snapshot.get("network"),
                    "dns_visibility": self.zeek_snapshot.get("capture_attestation", {}).get(
                        "dns_visibility"
                    ),
                    "native_ai": "BLOCKED",
                    "dns9": "BLOCKED",
                }
                if self.zeek_snapshot
                else None
            ),
        )
