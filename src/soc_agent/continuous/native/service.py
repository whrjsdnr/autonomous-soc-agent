"""Fixed privileged TCX service. No sudo, setns, shell, policy issuance or installation.

Installed by an administrator, started in the pre-approved Namespace by the service
manager. Default checkout execution is rejected before any BPF operation.
"""

import ctypes as C
import hashlib
import json
import os
import signal
import socket
import struct
import time
from collections import deque
from pathlib import Path
from sys import exception as sys_exception

INSTALL = Path("/usr/lib/soc-agent/continuous")
POLICY = Path("/etc/soc-agent/continuous-installation.json")


def audit_tail(lines):
    previous = "0" * 64
    for line in lines:
        if len(line) > 1024**2 or not line.endswith(b"\n"):
            raise ValueError("CONTINUOUS_ROOT_AUDIT_PARTIAL_OR_BOUND")
        record = json.loads(line)
        pin = record.pop("sha256")
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        if record["previous"] != previous or hashlib.sha256(encoded).hexdigest() != pin:
            raise ValueError("CONTINUOUS_ROOT_AUDIT_INTEGRITY")
        previous = pin
    return previous


def resource_scope(proc=Path("/proc/self"), cgroups=Path("/sys/fs/cgroup")):
    status = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in (proc / "status").read_text().splitlines()
        if ":" in line
    }
    allowed = (1 << 39) | (1 << 12) | 1  # CAP_BPF, CAP_NET_ADMIN, socket CAP_CHOWN.
    if status.get("NoNewPrivs") != "1" or int(status.get("CapEff", "0"), 16) != allowed:
        raise ValueError("CONTINUOUS_SERVICE_CAPABILITY_SCOPE")
    rows = (proc / "cgroup").read_text().splitlines()
    row = next((line[3:] for line in rows if line.startswith("0::")), None)
    if row is None or Path(row).name != "soc-continuous-collector.service":
        raise ValueError("CONTINUOUS_SERVICE_CGROUP_SCOPE")
    root = (cgroups / row.lstrip("/")).resolve()
    if not root.is_relative_to(cgroups.resolve()):
        raise ValueError("CONTINUOUS_CGROUP_PATH")
    memory = (root / "memory.max").read_text().strip()
    tasks = (root / "pids.max").read_text().strip()
    cpu = (root / "cpu.max").read_text().split()
    if (
        memory == "max"
        or not 0 < int(memory) <= 128 * 1024**2
        or tasks == "max"
        or not 0 < int(tasks) <= 4
        or len(cpu) != 2
        or cpu[0] == "max"
        or not 0 < int(cpu[0]) <= int(cpu[1]) // 4
    ):
        raise ValueError("CONTINUOUS_SERVICE_RESOURCE_SCOPE")


def cleanup_failed(error):
    """Preserve the primary failure without losing chained owned-resource uncertainty."""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if "CLEANUP_UNVERIFIED" in str(error):
            return True
        error = error.__cause__ or error.__context__
    return False


def clock_samples(phase, generation):
    result = []
    for _ in range(3):
        before = time.monotonic_ns()
        wall = time.time_ns()
        after = time.monotonic_ns()
        result.append(
            dict(phase=phase, generation=generation, before_ns=before, wall_ns=wall, after_ns=after)
        )
    return result


def seal_record(policy, policy_pin, generation, rows, samples, callbacks, dropped):
    import uuid

    seal = dict(
        contract="soc-continuous-seal:v1",
        namespace=policy["namespace"],
        session=str(uuid.uuid5(uuid.NAMESPACE_URL, str(generation))),
        generation=generation,
        program_sha256=policy["files"]["continuous.bpf.o"],
        policy_sha256=policy_pin,
        release_manifest=hashlib.sha256(
            json.dumps(policy["files"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        cpu_windows=rows,
        clock_samples=samples,
        callbacks=callbacks,
        transport_dropped=dropped,
        cleanup="VERIFIED",
        drain_result=0,
    )
    encoded = json.dumps(seal, sort_keys=True, separators=(",", ":")).encode()
    seal["seal_sha256"] = hashlib.sha256(encoded).hexdigest()
    return seal


class Provider:
    def __init__(self, policy, receive, rates=None):
        self.lib = C.CDLL(str(INSTALL / "provider.so"), use_errno=True)
        self.callback = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)(
            lambda _, body, size: receive(C.string_at(body, size))
        )
        self.lib.continuous_open.argtypes = [
            C.c_char_p,
            C.c_uint,
            C.c_uint64,
            type(self.callback),
            C.c_void_p,
            C.c_size_t,
        ]
        self.lib.continuous_open.restype = C.c_void_p
        for name in ("continuous_close", "continuous_poll", "continuous_cpus"):
            getattr(self.lib, name).argtypes = [C.c_void_p]
        self.lib.continuous_renew.argtypes = [C.c_void_p, C.c_uint64, C.c_uint64, C.c_uint]
        self.lib.continuous_counters.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
        for name in ("continuous_initial", "continuous_finish"):
            getattr(self.lib, name).argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
        self.index = socket.if_nametoindex("lo")
        self.generation = time.monotonic_ns()
        self.samples = clock_samples(1, self.generation)
        rate_array = (C.c_uint64 * len(rates))(*rates) if rates else None
        self.handle = self.lib.continuous_open(
            os.fsencode(INSTALL / "continuous.bpf.o"),
            self.index,
            int(policy["namespace"][5:-1]),
            self.callback,
            rate_array,
            len(rates) // 2 if rates else 0,
        )
        if not self.handle:
            import errno

            if C.get_errno() == errno.EUCLEAN:
                raise ValueError("CONTINUOUS_TCX_ATTACH_CLEANUP_UNVERIFIED")
            raise OSError(C.get_errno() or errno.EIO, "CONTINUOUS_TCX_ATTACH_FAILED_NO_RETRY")
        try:
            self.initial = self.boundary("continuous_initial", "PRE_ATTACH")
        except BaseException as first:
            try:
                self.close()
            except (ValueError, OSError) as cleanup:
                raise first from cleanup
            raise

    def boundary(self, function, phase):
        n = self.lib.continuous_cpus(self.handle)
        if not 1 <= n <= 128:
            raise ValueError("CONTINUOUS_ATTESTED_CPU_BOUND")
        values = (C.c_uint64 * (n * 9 + 2))()
        result = getattr(self.lib, function)(self.handle, values, C.sizeof(values))
        if result:
            import errno

            if result == -errno.EUCLEAN:
                raise ValueError("CONTINUOUS_TCX_CLEANUP_UNVERIFIED")
            raise ValueError("CONTINUOUS_BOUNDARY_OR_DRAIN_FAILED")
        names = (
            "observed",
            "emitted",
            "ring_reservation_failures",
            "unsupported",
            "malformed",
            "disabled",
            "budget",
        )
        if phase == "POST_DETACH":
            self.rates = [v for cpu in range(n) for v in values[2 + cpu * 9 + 7 : 2 + cpu * 9 + 9]]
        return [
            dict(
                cpu=cpu,
                possible_cpus=n,
                phase=phase,
                before_ns=values[0],
                after_ns=values[1],
                counters=dict(zip(names, values[2 + cpu * 9 : 2 + cpu * 9 + 7], strict=True)),
            )
            for cpu in range(n)
        ]

    def finish(self):
        try:
            rows = self.boundary("continuous_finish", "POST_DETACH")
        except BaseException as first:
            try:
                self.close()
            except (ValueError, OSError) as cleanup:
                raise first from cleanup
            raise
        self.close()
        samples = self.samples + clock_samples(2, self.generation)
        return self.initial + rows, samples

    def renew(self):
        if self.lib.continuous_renew(self.handle, self.generation, time.monotonic_ns(), self.index):
            raise ValueError("CONTINUOUS_TCX_ENABLE_FAILED")

    def poll(self):
        result = self.lib.continuous_poll(self.handle)
        if result < 0 and result != -4:
            raise ValueError("CONTINUOUS_TCX_POLL_FAILED")

    def counters(self):
        n = self.lib.continuous_cpus(self.handle)
        values = (C.c_uint64 * (n * 9))()
        if self.lib.continuous_counters(self.handle, values, C.sizeof(values)):
            raise ValueError("CONTINUOUS_TCX_COUNTER_READ_FAILED")
        return {
            str(cpu): list(values[cpu * 9 : cpu * 9 + 7]) for cpu in range(n) if values[cpu * 9]
        }

    def close(self):
        held, self.handle = self.handle, None
        if held and self.lib.continuous_close(held):
            raise ValueError("CONTINUOUS_TCX_CLEANUP_UNVERIFIED")


def run():
    if os.geteuid() != 0 or Path(__file__).resolve() != INSTALL / "service.py":
        raise ValueError("CONTINUOUS_PRIVILEGED_INSTALLATION_REQUIRED")
    # Standalone stdlib-only installed entry, invoked with Python -I. Import only
    # the pinned Root-owned sibling; never resolve the checkout through PYTHONPATH.
    import importlib.util
    import stat

    sibling = INSTALL / "policy.py"
    for path in (Path(__file__), sibling, *sibling.parents):
        info = path.lstat()
        if info.st_uid or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("CONTINUOUS_UNTRUSTED_ENTRY")
    spec = importlib.util.spec_from_file_location("installed_continuous_policy", sibling)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    installed, root_file, validate = module.installed, module.root_file, module.validate
    import sys

    if not sys.flags.isolated or any(
        key in os.environ for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME")
    ):
        raise ValueError("CONTINUOUS_ISOLATED_INSTALLED_ENTRY_REQUIRED")
    policy = installed()
    resource_scope()
    if os.readlink("/proc/self/ns/net") != policy["namespace"] or (
        {name for _, name in socket.if_nameindex()} != {"lo"}
    ):
        raise ValueError("CONTINUOUS_NAMESPACE_SCOPE")
    for file in ("route", "ipv6_route"):
        lines = Path("/proc/self/net", file).read_text().splitlines()
        if any(
            line.split()[-1 if file == "ipv6_route" else 0] != "lo"
            for line in (lines[1:] if file == "route" else lines)
            if line.strip()
        ):
            raise ValueError("CONTINUOUS_EXTERNAL_ROUTE")
    frames = deque(maxlen=32)
    policy_pin = hashlib.sha256(root_file(POLICY)).hexdigest()
    state = dict(
        state="STARTING",
        received=0,
        transport_dropped=0,
        cleanup="PENDING",
        namespace=policy["namespace"],
        policy_sha256=policy_pin,
        program_sha256=policy["files"]["continuous.bpf.o"],
    )

    def receive(body):
        nonlocal window_callbacks
        window_callbacks += 1
        if len(body) != 80:
            state["state"] = "DEGRADED"
            return -1
        state["received"] += 1
        if len(frames) == frames.maxlen:
            state["transport_dropped"] += 1
        else:
            frames.append(body.hex())
        return 0

    window_callbacks = 0
    stop = False

    def request_stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    # Socket ownership is exclusive. Never unlink an unknown or previous socket.
    path = Path("/run/soc-agent-continuous") / f"{policy['uid']}.sock"
    log_path = Path("/var/lib/soc-agent/continuous") / f"{policy['uid']}.jsonl"
    for parent in (*log_path.parents, *path.parents):
        info = parent.lstat()
        if info.st_uid or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError("CONTINUOUS_ROOT_STORAGE_SCOPE")
    fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    if os.fstat(fd).st_uid != 0 or os.fstat(fd).st_mode & 0o077:
        os.close(fd)
        raise ValueError("CONTINUOUS_ROOT_AUDIT_OWNERSHIP")
    previous = "0" * 64
    if os.fstat(fd).st_size:
        if os.fstat(fd).st_size > 64 * 1024**2:
            os.close(fd)
            raise ValueError("CONTINUOUS_ROOT_AUDIT_QUOTA")
        reader = os.open(log_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if (os.fstat(reader).st_dev, os.fstat(reader).st_ino) != (
                os.fstat(fd).st_dev,
                os.fstat(fd).st_ino,
            ):
                raise ValueError("CONTINUOUS_ROOT_AUDIT_REPLACED")
            with os.fdopen(reader, "rb", closefd=False) as stream:
                previous = audit_tail(iter(lambda: stream.readline(1024**2 + 1), b""))
        finally:
            os.close(reader)

    def audit(code):
        nonlocal previous
        if os.fstat(fd).st_size >= 64 * 1024**2:
            raise ValueError("CONTINUOUS_ROOT_AUDIT_QUOTA")
        row = dict(code=code, state=dict(state), previous=previous, at=time.time_ns())
        encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        previous = hashlib.sha256(encoded).hexdigest()
        body = json.dumps(row | dict(sha256=previous)).encode() + b"\n"
        if os.write(fd, body) != len(body):
            raise ValueError("CONTINUOUS_ROOT_AUDIT_PARTIAL")
        os.fsync(fd)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    provider = peer = None
    pending_seal = None
    carried_rates = None
    owned = False

    def finish_window():
        nonlocal provider, pending_seal, carried_rates
        generation = provider.generation
        rows, samples = provider.finish()
        carried_rates = provider.rates
        provider = None
        pending_seal = seal_record(
            policy,
            policy_pin,
            generation,
            rows,
            samples,
            window_callbacks,
            state["transport_dropped"],
        )
        audit("CAPTURE_WINDOW_SEALED")

    try:
        audit("ATTACH_REQUESTED")
        provider = Provider(policy, receive)
        # A pathname must never advertise readiness before Kernel load/owned attach.
        server.bind(str(path))
        owned = True
        os.chmod(path, 0o600)
        os.chown(path, policy["uid"], -1)
        server.listen(1)
        server.setblocking(False)
        state["state"] = "RUNNING"
        audit("ATTACH_OWNED")
        window_started = time.monotonic()
        last = 0.0
        last_audit = 0.0
        sequence = 0
        while not stop:
            validate(root_file(POLICY))  # Expiry/revocation fails closed on every poll.
            if installed() != policy:
                raise ValueError("CONTINUOUS_POLICY_CHANGED")
            if provider is None:
                time.sleep(0.01)
            if provider is not None:
                provider.renew()
                provider.poll()
            # A bounded window is detached and drained before any seal is emitted.
            # New owned maps start only after the previous seal was delivered.
            if provider is not None and (
                time.monotonic() - window_started >= 180 or window_callbacks >= 4000
            ):
                finish_window()
            if time.monotonic() - last_audit >= 1:
                if provider is not None:
                    state["counters"] = provider.counters()
                audit("HEARTBEAT")
                last_audit = time.monotonic()
            if peer is None:
                try:
                    peer, _ = server.accept()
                    credentials = struct.unpack(
                        "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    )
                    if credentials[1] != policy["uid"]:
                        peer.close()
                        peer = None
                        continue
                    peer.setblocking(False)
                except BlockingIOError:
                    continue
            try:
                control = peer.recv(256)
            except BlockingIOError:
                control = None
            if control == b"":
                peer.close()
                peer = None
                continue
            if control:
                command = json.loads(control)
                if command != dict(
                    operation="STOP_CAPTURE",
                    generation=provider.generation if provider else pending_seal["generation"],
                    policy_sha256=policy_pin,
                ):
                    peer.close()
                    peer = None
                    continue
                stop = True
                continue
            if time.monotonic() - last >= 1:
                # Bracketed monotonic/wall sample remains evidence, never a UTC relabel.
                before = time.monotonic_ns()
                wall = time.time_ns()
                after = time.monotonic_ns()
                packet = dict(
                    contract="soc-continuous-tcx:v1",
                    namespace=policy["namespace"],
                    ifindex=provider.index if provider else 1,
                    generation=provider.generation if provider else pending_seal["generation"],
                    program_sha256=policy["files"]["continuous.bpf.o"],
                    clock=[before, wall, after],
                    state=dict(state),
                    frames=list(frames),
                    sequence=sequence + 1,
                    seal=pending_seal,
                )
                try:
                    body = json.dumps(packet).encode()
                    if len(body) > 262144 or peer.send(body) != len(body):
                        raise ValueError("CONTINUOUS_TRANSPORT_BOUND")
                    sequence += 1
                    frames.clear()
                    if pending_seal is not None:
                        pending_seal = None
                        window_callbacks = 0
                        state["transport_dropped"] = 0
                        state["received"] = 0
                        provider = Provider(policy, receive, carried_rates)
                        window_started = time.monotonic()
                    last = time.monotonic()
                except (BrokenPipeError, ConnectionResetError):
                    peer.close()
                    peer = None
                except BlockingIOError:
                    state["state"] = "DEGRADED"
        state["state"] = "STOPPING"
    finally:
        try:
            if provider and sys_exception() is None:
                finish_window()
            if pending_seal is not None and peer:
                try:
                    before = time.monotonic_ns()
                    wall = time.time_ns()
                    after = time.monotonic_ns()
                    body = json.dumps(
                        dict(
                            contract="soc-continuous-tcx:v1",
                            namespace=policy["namespace"],
                            ifindex=1,
                            generation=pending_seal["generation"],
                            program_sha256=policy["files"]["continuous.bpf.o"],
                            clock=[before, wall, after],
                            state=dict(state, state="SEALED"),
                            frames=list(frames),
                            sequence=sequence + 1,
                            seal=pending_seal,
                        )
                    ).encode()
                    if len(body) > 262144 or peer.send(body) != len(body):
                        raise ValueError("CONTINUOUS_FINAL_SEAL_SEND_FAILED")
                except (OSError, ValueError):
                    state["transport_dropped"] += len(frames)
                    audit("CAPTURE_FINAL_SEAL_NOT_DELIVERED")
            if provider:
                try:
                    provider.close()
                except (ValueError, OSError):
                    state["cleanup"] = "UNVERIFIED"
                    state["state"] = "DEGRADED"
                    audit("CLEANUP_FAILED_NO_RETRY")
                    raise
            import sys

            pending = sys.exception()
            if pending and cleanup_failed(pending):
                state["cleanup"] = "UNVERIFIED"
                audit("ATTACH_CLEANUP_UNVERIFIED")
                raise pending
            state["cleanup"] = "VERIFIED"
            state["state"] = "STOPPED"
            audit("SERVICE_STOPPED")
            if peer:
                try:
                    peer.send(
                        json.dumps(
                            dict(
                                contract="soc-continuous-tcx-stop:v1",
                                generation=provider.generation
                                if provider
                                else (pending_seal or {}).get("generation"),
                                namespace=policy["namespace"],
                                policy_sha256=policy_pin,
                                cleanup=state["cleanup"],
                            )
                        ).encode()
                    )
                except (OSError, ValueError):
                    # No receipt is fabricated when the consumer disconnects.
                    pass
        finally:
            if peer:
                peer.close()
            server.close()
            if owned:
                path.unlink()
            os.close(fd)


if __name__ == "__main__":
    import sys

    # Preserve the first traceback; distribution crash reporters cannot write this sandbox.
    sys.excepthook = sys.__excepthook__
    run()
