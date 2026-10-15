"""User-executed capture, unprivileged READY observer, and saved-data verification.

Never invokes sudo, setpriv, a shell, or another process. This is a new probe
revision requiring separate approval; the original approved probe is unchanged.
"""

import argparse
import asyncio
import hashlib
import json
import os
import shlex
import signal
import socket
import sqlite3
import sys
import time
from pathlib import Path
from uuid import uuid4

from pydantic import Field

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configuration, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.queue import EventQueue
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_directory,
    validate_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    FlowSummary,
    PacketObservation,
    model_gates,
)
from soc_agent.security_ai.operational.network_capture.native_probe import (
    ProbeCapture,
    validate_probe_privileges,
)
from soc_agent.security_ai.operational.network_capture.permissions import NET_RAW, privileges
from soc_agent.security_ai.operational.network_capture.pipeline import NetworkPipeline
from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt
from soc_agent.security_ai.operational.source_store import OperationalSourceStore

ORIGINAL_SHA = "59b67d8a7654eebbb7f05e3810b3d3e2da0aea5029872a09ca01ed1e9a12a50d"
MODULE = "soc_agent.security_ai.operational.network_capture.manual_capture"
CODE_FILES = (
    "security_ai/operational/network_capture/manual_capture.py",
    "security_ai/operational/network_capture/native_probe.py",
    "security_ai/operational/network_capture/capture.py",
    "security_ai/operational/network_capture/permissions.py",
    "security_ai/operational/network_capture/pipeline.py",
    "security_ai/operational/network_capture/parsing.py",
    "security_ai/operational/network_capture/flows.py",
    "security_ai/operational/network_capture/models.py",
    "security_ai/operational/source_store.py",
    "security_ai/operational/provenance.py",
    "linux_runtime/network_monitor.py",
    "linux_runtime/store.py",
    "linux_runtime/service.py",
    "realtime/queue.py",
)


class Session(Snapshot):
    run_id: str
    uid: int
    gid: int
    interface_id: Hash
    python_sha256: Hash
    code_digests: tuple[tuple[str, Hash], ...]

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class Ready(Snapshot):
    session_digest: Hash
    pid: int = Field(strict=True, gt=1)
    process_start: str
    socket_fd: int = Field(strict=True, ge=3)
    socket_inode: int = Field(strict=True, gt=0)
    uid: int
    gid: int
    interface_id: Hash
    effective: int
    permitted: int
    inheritable: int
    ambient: int
    bounding: int
    no_new_privs: int


def code_digests() -> tuple[tuple[str, str], ...]:
    package = Path(__file__).parents[3]
    result = tuple(
        (name, hashlib.sha256((package / name).read_bytes()).hexdigest()) for name in CODE_FILES
    )
    if dict(result)[CODE_FILES[1]] != ORIGINAL_SHA:
        raise ValueError("ORIGINAL_PROBE_DIGEST_MISMATCH")
    return result


def path_checked(path: Path) -> Path:
    path = path.expanduser().absolute()
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("SESSION_PATH_REDIRECTION")
    return path


def write_record(path: Path, payload: dict) -> None:
    """Atomic exclusive publication; readers never see a half-written READY."""
    validate_directory(path.parent)
    temporary = path.with_name(".publish-" + uuid4().hex)
    create_private_file(temporary)
    try:
        with temporary.open("w") as stream:
            json.dump({"payload": payload, "digest": content_digest_payload(payload)}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # refuses an existing result, including a symlink
    finally:
        temporary.unlink()


def read_record(path: Path) -> dict:
    validate_directory(path.parent)
    validate_file(path)
    if path.stat().st_size > 262144:
        raise ValueError("SESSION_RECORD_TOO_LARGE")
    value = json.loads(path.read_text())
    if set(value) != {"payload", "digest"} or (
        content_digest_payload(value["payload"]) != value["digest"]
    ):
        raise ValueError("SESSION_RECORD_DIGEST_MISMATCH")
    return value["payload"]


def unprivileged() -> None:
    p = privileges()
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid() or os.geteuid() == 0:
        raise ValueError("ORDINARY_USER_REQUIRED")
    if any(p[n] != 0 for n in ("CapEff", "CapPrm", "CapInh", "CapAmb")):
        raise ValueError("UNPRIVILEGED_CONTROLLER_REQUIRED")


def load_session(root: Path) -> Session:
    session = Session.model_validate(read_record(root / "session.json"))
    if (session.uid, session.gid) != (os.getuid(), os.getgid()):
        raise ValueError("SESSION_OS_IDENTITY_MISMATCH")
    if session.code_digests != code_digests():
        raise ValueError("SESSION_CODE_CHANGED")
    if (
        session.python_sha256
        != hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()
    ):
        raise ValueError("SESSION_INTERPRETER_CHANGED")
    return session


def process_start(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def initialize_session(root: Path) -> Session:
    if root.exists():
        raise ValueError("SESSION_ALREADY_EXISTS_NO_REPLAY")
    create_private_directory(root, exist_ok=False)
    session = Session(
        run_id=uuid4().hex,
        uid=os.getuid(),
        gid=os.getgid(),
        interface_id=interface_identity("lo"),
        python_sha256=hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
        code_digests=code_digests(),
    )
    initialize(
        root / "runtime",
        RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3),
    )
    configure(root / "runtime", CaptureConfig(interface="lo", packet_batch=8, max_flows=16))
    for name in ("capture.lock", "traffic.lock"):
        create_private_file(root / name)
    write_record(root / "session.json", session.model_dump(mode="json"))
    return session


class ManualCapture(ProbeCapture):
    def __init__(self, config: CaptureConfig, root: Path, session: Session):
        super().__init__(config)
        self.root, self.session = root, session
        self.opened = None

    def open(self):
        if self.config.interface != "lo" or self.identity != self.session.interface_id:
            raise ValueError("MANUAL_CAPTURE_INTERFACE_MISMATCH")
        if (os.getuid(), os.getgid()) != (self.session.uid, self.session.gid):
            raise ValueError("MANUAL_CAPTURE_OS_IDENTITY_MISMATCH")
        if signal.getsignal(signal.SIGALRM) != signal.SIG_DFL:
            raise ValueError("WATCHDOG_DEFAULT_SIGNAL_REQUIRED")
        # Kernel default SIGALRM terminates only this process even if SQLite stalls.
        # The socket window is bounded below the approved five seconds.
        signal.setitimer(signal.ITIMER_REAL, 4)
        self.opened = time.monotonic()
        try:
            super().open()  # original capability validation, bound socket, capset, recheck
            p = privileges()
            ready = Ready(
                session_digest=self.session.digest,
                pid=os.getpid(),
                process_start=process_start(os.getpid()),
                socket_fd=self.socket.fileno(),
                socket_inode=os.fstat(self.socket.fileno()).st_ino,
                uid=os.getuid(),
                gid=os.getgid(),
                interface_id=self.identity,
                effective=p["CapEff"],
                permitted=p["CapPrm"],
                inheritable=p["CapInh"],
                ambient=p["CapAmb"],
                bounding=p["CapBnd"],
                no_new_privs=p["NoNewPrivs"],
            )
            if any((ready.effective, ready.permitted, ready.inheritable, ready.ambient)):
                raise ValueError("READY_BEFORE_CAPABILITY_DROP_FORBIDDEN")
            write_record(self.root / "ready.json", ready.model_dump(mode="json"))
            print(json.dumps({"stage": "READY", "session_digest": self.session.digest}), flush=True)
        except (OSError, ValueError):
            self.close()
            raise

    def close(self):
        was_open = self.socket is not None
        terminal = self.statistics() if was_open else None
        super().close()
        if self.opened is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if was_open:
                write_record(
                    self.root / "closed.json",
                    {
                        "session_digest": self.session.digest,
                        "capture_elapsed_seconds": time.monotonic() - self.opened,
                        "remaining_capabilities": privileges(),
                        "terminal_kernel_packets": terminal[0] if terminal is not None else None,
                        "terminal_capture_drops": terminal[1] if terminal is not None else None,
                    },
                )
            self.opened = None


async def capture(root: Path) -> dict:
    validate_probe_privileges()
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise ValueError("CAPTURE_REAL_EFFECTIVE_IDENTITY_MISMATCH")
    session = initialize_session(root)
    store = RuntimeStore(root / "runtime")
    config, identity = configuration(root / "runtime", store)
    if identity != session.interface_id:
        raise ValueError("CAPTURE_CONFIGURATION_IDENTITY_MISMATCH")
    receiver = ManualCapture(config, root, session)
    with exclusive_runtime_lock(root / "capture.lock"):
        monitor = NetworkMonitor(root / "runtime", store, capture=receiver)
        receiver.stop = monitor.stopped

        async def stop():
            await asyncio.sleep(2)
            monitor.stopped.set()

        timer = asyncio.create_task(stop())
        try:
            await monitor.run()
        finally:
            timer.cancel()
            await asyncio.gather(timer, return_exceptions=True)
            receiver.close()
        result = {
            "session_digest": session.digest,
            "metrics": monitor.metrics,
            "audit_digest": store.verify_audit(),
            "operational_models": model_gates(),
        }
        write_record(root / "capture-result.json", result)
        return result


def validate_ready_peer(root: Path, session: Session) -> Ready:
    ready = Ready.model_validate(read_record(root / "ready.json"))
    if (
        ready.session_digest != session.digest
        or ready.interface_id != session.interface_id
        or (ready.uid, ready.gid) != (session.uid, session.gid)
        or interface_identity("lo") != session.interface_id
        or any((ready.effective, ready.permitted, ready.inheritable, ready.ambient))
        or ready.bounding != NET_RAW
        or ready.no_new_privs != 1
    ):
        raise ValueError("READY_SESSION_BINDING_MISMATCH")
    if root.joinpath("closed.json").exists() or process_start(ready.pid) != ready.process_start:
        raise ValueError("CAPTURE_NOT_LIVE")
    executable = Path(f"/proc/{ready.pid}/exe")
    if hashlib.sha256(executable.read_bytes()).hexdigest() != session.python_sha256:
        raise ValueError("READY_INTERPRETER_MISMATCH")
    arguments = Path(f"/proc/{ready.pid}/cmdline").read_bytes().split(b"\0")
    expected = [b"-I", b"-m", MODULE.encode(), b"capture", b"--directory", os.fsencode(root)]
    if arguments[1:-1] != expected:
        raise ValueError("READY_PROCESS_COMMAND_MISMATCH")
    fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{ready.pid}/status").read_text().splitlines()
        if ":" in line
    )
    required = {
        "Uid",
        "Gid",
        "Groups",
        "CapEff",
        "CapPrm",
        "CapInh",
        "CapAmb",
        "CapBnd",
        "NoNewPrivs",
    }
    if not required <= fields.keys():
        raise ValueError("READY_PEER_STATUS_INCOMPLETE")
    for field, value in (("Uid", session.uid), ("Gid", session.gid)):
        if tuple(map(int, fields[field].split())) != (value,) * 4:
            raise ValueError("READY_PEER_OS_IDENTITY_MISMATCH")
    if "Groups" not in fields or fields["Groups"].strip():
        raise ValueError("READY_PEER_SUPPLEMENTARY_GROUPS_NOT_CLEARED")
    if any(int(fields[k], 16) != 0 for k in ("CapEff", "CapPrm", "CapInh", "CapAmb")):
        raise ValueError("READY_PEER_CAPABILITIES_NOT_DROPPED")
    if int(fields["CapBnd"], 16) != NET_RAW or int(fields["NoNewPrivs"]) != 1:
        raise ValueError("READY_PEER_PRIVILEGE_PROFILE_MISMATCH")
    if os.readlink(f"/proc/{ready.pid}/fd/{ready.socket_fd}") != f"socket:[{ready.socket_inode}]":
        raise ValueError("READY_SOCKET_IDENTITY_MISMATCH")
    matches = [
        line.split()
        for line in Path("/proc/net/packet").read_text().splitlines()[1:]
        if line.split()[-1] == str(ready.socket_inode)
    ]
    if len(matches) != 1 or (
        int(matches[0][2]),
        int(matches[0][3], 16),
        int(matches[0][4]),
        int(matches[0][7]),
    ) != (socket.SOCK_RAW, 3, socket.if_nametoindex("lo"), session.uid):
        raise ValueError("READY_SOCKET_NOT_BOUND_LOOPBACK")
    return ready


def loopback_traffic() -> dict:
    """Two owned endpoints per protocol. No raw socket, DNS resolver or remote address."""
    payload = b"soc-owned-loopback-check"
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client,
    ):
        for stream in (server, client):
            stream.bind(("127.0.0.1", 0))
            stream.settimeout(0.2)
        udp = sorted([server.getsockname()[1], client.getsockname()[1]])
        client.sendto(payload, server.getsockname())
        received, address = server.recvfrom(128)
        if received != payload or address != client.getsockname():
            raise ValueError("OWNED_UDP_BINDING_MISMATCH")
        server.sendto(payload, address)
        reply, address = client.recvfrom(128)
        if reply != payload or address != server.getsockname():
            raise ValueError("OWNED_UDP_REPLY_MISMATCH")
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server,
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
    ):
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client.bind(("127.0.0.1", 0))
        server.settimeout(0.2)
        client.settimeout(0.2)
        client.connect(server.getsockname())
        tcp = sorted([server.getsockname()[1], client.getsockname()[1]])
        accepted, address = server.accept()
        with accepted:
            if address != client.getsockname():
                raise ValueError("OWNED_TCP_PEER_MISMATCH")
            accepted.settimeout(0.2)
            client.sendall(payload)
            if read_exact(accepted, len(payload)) != payload:
                raise ValueError("OWNED_TCP_REQUEST_MISMATCH")
            accepted.sendall(payload)
            if read_exact(client, len(payload)) != payload:
                raise ValueError("OWNED_TCP_REPLY_MISMATCH")
    return {
        "udp_ports": udp,
        "tcp_ports": tcp,
        "udp_datagrams_sent": 2,
        "tcp_connections": 1,
        "tcp_payload_messages": 2,
        "external_test_traffic": False,
        "dns_resolver_query": False,
    }


def read_exact(stream: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise ValueError("OWNED_TCP_INCOMPLETE_MESSAGE")
        data.extend(part)
    return bytes(data)


def watch(root: Path) -> dict:
    unprivileged()
    print(
        json.dumps(
            {"stage": "WAITING_FOR_VERIFIED_READY", "timeout_seconds": 120, "traffic_sent": 0}
        ),
        flush=True,
    )
    deadline = time.monotonic() + 120
    while not (root / "ready.json").exists():
        if (root / "capture-result.json").exists() or time.monotonic() >= deadline:
            raise ValueError("CAPTURE_READY_NOT_OBSERVED_NO_TRAFFIC_SENT")
        time.sleep(0.01)  # waiting for a verifiable receipt, never assumed readiness
    session = load_session(root)
    validate_file(root / "traffic.lock")
    with exclusive_runtime_lock(root / "traffic.lock"):
        if (root / "traffic-result.json").exists() or (root / "traffic-claimed.json").exists():
            raise ValueError("TRAFFIC_REPLAY_FORBIDDEN")
        ready = validate_ready_peer(root, session)
        write_record(root / "traffic-claimed.json", {"session_digest": session.digest})
        result = {
            "session_digest": session.digest,
            "ready_digest": content_digest_payload(ready.model_dump(mode="json")),
            "peer_verified": True,
            "status": "COMPLETED",
            **loopback_traffic(),
        }
        write_record(root / "traffic-result.json", result)
        return result


def stored_summary(root: Path, session: Session, pipeline: NetworkPipeline) -> dict:
    packets, flows, dns, owned, links = 0, 0, 0, set(), []
    timestamps = []
    traffic = (
        read_record(root / "traffic-result.json") if (root / "traffic-result.json").exists() else {}
    )
    with pipeline.queue.database.transaction(write=False) as c:
        rows = c.execute("SELECT * FROM realtime_events ORDER BY rowid").fetchall()
    for row in rows:
        event = pipeline.queue._decode(row)
        record = pipeline.decode(event)
        source = pipeline._source(event, record)
        receipt = build_receipt(pipeline.sources, incident_id=pipeline.incident, sources=(source,))
        verify_receipt(receipt, pipeline.sources, incident_id=pipeline.incident, sources=(source,))
        if pipeline.committed.get(str(event.event_id)) != receipt.model_dump(mode="json"):
            raise ValueError("SAVED_PROVENANCE_AUDIT_MISMATCH")
        links.append(
            {
                "event_id": str(event.event_id),
                "source_digest": source.content_digest,
                "provenance_digest": receipt.receipt_digest,
            }
        )
        if isinstance(record, PacketObservation):
            packets += 1
            if record.timestamp_origin != "KERNEL_SO_TIMESTAMPNS":
                raise ValueError("NON_NATIVE_PACKET_IN_MANUAL_SESSION")
            timestamps.append(record.capture_timestamp_ns)
            dns += int(record.dns is not None)
            if str(record.source_address) == str(record.destination_address) == "127.0.0.1":
                if sorted([record.source_port, record.destination_port]) == traffic.get(
                    record.transport + "_ports"
                ):
                    owned.add(record.transport)
        elif isinstance(record, FlowSummary):
            flows += 1
    return {
        "packets": packets,
        "flows": flows,
        "dns_events": dns,
        "owned_transports_observed": sorted(owned),
        "links": links,
        "queue_counts": pipeline.queue.counts(),
        "audit_digest": pipeline.audit.verify_audit(),
        "session_digest": session.digest,
        "kernel_timestamp_ns_min": min(timestamps) if timestamps else None,
        "kernel_timestamp_ns_max": max(timestamps) if timestamps else None,
    }


def verify(root: Path) -> dict:
    unprivileged()
    session = load_session(root)
    validate_file(root / "capture.lock")
    with exclusive_runtime_lock(root / "capture.lock"):
        store = RuntimeStore(root / "runtime")
        config, identity = configuration(root / "runtime", store)
        if identity != session.interface_id or config.interface != "lo":
            raise ValueError("SAVED_CAPTURE_CONFIGURATION_MISMATCH")
        pipeline = NetworkPipeline(
            EventQueue(root / "runtime/network/queue.sqlite"),
            OperationalSourceStore(
                root / "runtime/network/sources.sqlite",
                allowed_lateness_seconds=60,
                max_future_skew_seconds=5,
                capacity=10000,
            ),
            store.config.incident_id,
            config,
            identity,
            store,
        )
        pipeline.recover()
        for _ in range(512):
            if pipeline.step() == "IDLE":
                break
        else:
            raise ValueError("RECOVERY_WORK_BUDGET_EXCEEDED")
        summary = stored_summary(root, session, pipeline)
        with pipeline.queue.database.transaction(write=False) as c:
            events = [pipeline.queue._decode(r) for r in c.execute("SELECT * FROM realtime_events")]
        if any(pipeline.queue.enqueue(event) for event in events):
            raise ValueError("DUPLICATE_EVENT_ACCEPTED")
        stable = stored_summary(root, session, pipeline) == summary
        integrity = []
        for name in ("monitor.sqlite", "network/queue.sqlite", "network/sources.sqlite"):
            path = root / "runtime" / name
            validate_file(path)
            with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as c:
                integrity.append(c.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
        complete = (
            read_record(root / "capture-result.json")
            if (root / "capture-result.json").exists()
            else None
        )
        closed = read_record(root / "closed.json") if (root / "closed.json").exists() else None
        traffic = (
            read_record(root / "traffic-result.json")
            if (root / "traffic-result.json").exists()
            else None
        )
        ready = (
            Ready.model_validate(read_record(root / "ready.json"))
            if (root / "ready.json").exists()
            else None
        )
        if ready is not None and (
            ready.session_digest != session.digest
            or ready.interface_id != session.interface_id
            or (ready.uid, ready.gid) != (session.uid, session.gid)
            or any((ready.effective, ready.permitted, ready.inheritable, ready.ambient))
            or ready.bounding != NET_RAW
            or ready.no_new_privs != 1
        ):
            raise ValueError("SAVED_READY_PROFILE_MISMATCH")
        for record in (complete, closed, traffic):
            if record is not None and record.get("session_digest") != session.digest:
                raise ValueError("SAVED_RESULT_SESSION_MISMATCH")
        if traffic is not None and (
            ready is None
            or traffic.get("ready_digest") != content_digest_payload(ready.model_dump(mode="json"))
            or traffic.get("peer_verified") is not True
        ):
            raise ValueError("SAVED_TRAFFIC_READY_BINDING_MISMATCH")
        with store.database.transaction(write=False) as c:
            gaps = sum(
                json.loads(row[0])["kind"] == "NETWORK_CAPTURE_GAP"
                for row in c.execute("SELECT payload FROM monitor_audit")
            )
        state = store.state()
        reduced = closed is not None and all(
            closed["remaining_capabilities"].get(k) == 0
            for k in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
        if closed is not None:
            p = closed["remaining_capabilities"]
            if (p.get("euid"), p.get("egid"), p.get("CapBnd"), p.get("NoNewPrivs")) != (
                session.uid,
                session.gid,
                NET_RAW,
                1,
            ):
                raise ValueError("SAVED_CLOSED_IDENTITY_MISMATCH")
        passed = (
            bool(complete and closed and traffic and ready)
            and stable
            and all(integrity)
            and reduced
            and traffic["status"] == "COMPLETED"
            and state.get("network", {}).get("state") == "STOPPED"
            and summary["owned_transports_observed"] == ["tcp", "udp"]
            and complete["metrics"]["capture_drops"] == 0
            and closed["terminal_capture_drops"] == 0
            and complete["metrics"]["last_error"] is None
            and 0 <= closed["capture_elapsed_seconds"] <= 5
            and complete["metrics"]["inference_count"] == 0
            and complete["metrics"]["finding_count"] == 0
            and summary["queue_counts"] == {"DONE": len(events)}
        )
        return {
            "status": "VERIFIED" if passed else "PARTIAL" if summary["packets"] else "BLOCKED",
            "summary": summary,
            "capture_result": complete,
            "closed": closed,
            "traffic": traffic,
            "duplicate_effect_prevented": stable,
            "sqlite_integrity": all(integrity),
            "capture_gap_count": gaps,
            "runtime_network_state": state.get("network", {}).get("state", "UNKNOWN"),
            "operational_models": model_gates(),
            "write_disposition": "WRITE_DENIED",
        }


def commands(root: Path) -> dict:
    unprivileged()
    if root.exists():
        raise ValueError("CHOOSE_A_NEW_SESSION_DIRECTORY")
    python = str(Path(sys.executable).absolute())
    command = [python, "-I", "-m", MODULE]
    return {
        "approval_required": True,
        "original_probe_unchanged_sha256": ORIGINAL_SHA,
        "new_manual_probe_sha256": dict(code_digests())[CODE_FILES[0]],
        "terminal_A_unprivileged_observer": shlex.join(
            command + ["watch", "--directory", str(root)]
        ),
        "terminal_B_user_only_capture": shlex.join(
            [
                "sudo",
                "-n",
                "/usr/bin/setpriv",
                f"--reuid={os.getuid()}",
                f"--regid={os.getgid()}",
                "--clear-groups",
                "--bounding-set=-all,+net_raw",
                "--inh-caps=-all,+net_raw",
                "--ambient-caps=-all,+net_raw",
                "--no-new-privs",
                *command,
                "capture",
                "--directory",
                str(root),
            ]
        ),
        "after_capture_verify": shlex.join(command + ["verify", "--directory", str(root)]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("commands", "watch", "capture", "verify"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        root = path_checked(args.directory)
        if args.command == "capture":
            result = asyncio.run(capture(root))
        else:
            result = {"commands": commands, "watch": watch, "verify": verify}[args.command](root)
        print(json.dumps(result, indent=2))
        if args.command == "verify":
            return 0 if result["status"] == "VERIFIED" else 1
        if args.command == "capture":
            return (
                0
                if result["metrics"]["packets_collected"] > 0
                and not result["metrics"]["last_error"]
                else 1
            )
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        # Never print arbitrary exception payloads, paths, raw packets or secrets.
        code = str(error)
        if not code.replace("_", "").isalnum() or code.upper() != code:
            code = type(error).__name__
        print(json.dumps({"status": "BLOCKED", "reason": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
