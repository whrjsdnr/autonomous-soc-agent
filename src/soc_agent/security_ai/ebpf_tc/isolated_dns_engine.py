"""Fixed child lifecycle, embedded as stdlib-only bytes into a reviewed image.

Not a CLI or authorization validator. Only a future admitted Root Supervisor may
call this service with its immutable DNS_CONFIG. Development builds cannot run
as programs. No command runner, namespace creation/deletion, or traffic generator.
"""

import ctypes
import json
import os
import resource
import select
import signal
import socket
import struct
import time
from pathlib import Path
from types import SimpleNamespace


def local_controller():
    """Embedded ordinary worker invariant, checked before receiving packets."""
    rows = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if os.getuid() <= 0 or os.getresuid() != (os.getuid(),) * 3:
        raise ValueError("DNS_WORKER_ORDINARY_UID_REQUIRED")
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if int(rows[name].strip(), 16):
            raise ValueError("DNS_WORKER_CAPABILITIES_REMAIN")
    if (
        rows["NoNewPrivs"].strip() != "1"
        or os.getgroups()
        or os.getresgid() != (os.getgid(),) * 3
        or os.getgid() <= 0
    ):
        raise ValueError("DNS_WORKER_PRIVILEGE_DROP_INCOMPLETE")


def _prctl(option, value=0):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, value, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "DNS_PRCTL_FAILED")


def _drop_credentials(uid, gid, parent):
    if uid <= 0 or gid <= 0:
        raise ValueError("DNS_WORKER_ROOT_IDENTITY_FORBIDDEN")
    _prctl(47, 4)  # PR_CAP_AMBIENT / CLEAR_ALL
    for cap in range(int(Path("/proc/sys/kernel/cap_last_cap").read_text()) + 1):
        _prctl(24, cap)  # PR_CAPBSET_DROP, while CAP_SETPCAP is still available
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    # UID change resets PDEATHSIG, so install it afterwards and close the race.
    _prctl(1, signal.SIGKILL)
    if os.getppid() != parent:
        raise ValueError("DNS_SUPERVISOR_DISAPPEARED")
    local_controller()


def _enter_and_bind(config):
    """Only called in the Root child. Hold nsfs FD across setns and check again."""
    fd = os.open("/run/netns/soc-native-b3", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    udp = tcp = None
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino, st.st_uid) != (
            config["namespace_device"],
            config["namespace_inode"],
            0,
        ) or Path("/proc/sys/kernel/random/boot_id").read_text().strip() != config["boot_id"]:
            raise ValueError("DNS_NAMESPACE_LEASE_CHANGED")
        os.setns(fd, 0x40000000)  # CLONE_NEWNET; parent stays in the host namespace
        if os.readlink("/proc/self/ns/net") != config["namespace"]:
            raise ValueError("DNS_NAMESPACE_ENTRY_MISMATCH")
        if socket.if_nameindex() != [(1, "lo")]:
            raise ValueError("DNS_EXTERNAL_INTERFACE_OR_MISSING_LO")
        # Read interface flags through ioctl: sysfs still belongs to the mount
        # namespace and must not be substituted for network-namespace evidence.
        import fcntl

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            flags = fcntl.ioctl(probe, 0x8913, struct.pack("256s", b"lo"))
            if not struct.unpack_from("H", flags, 16)[0] & 1:
                raise ValueError("DNS_LOOPBACK_NOT_UP")
            cookie = probe.getsockopt(socket.SOL_SOCKET, 71, 8)
        # /proc/net follows this child network namespace. Reject non-lo routes.
        for row in Path("/proc/net/route").read_text().splitlines()[1:]:
            if row.split()[0] != "lo":
                raise ValueError("DNS_EXTERNAL_ROUTE")
        for row in Path("/proc/net/ipv6_route").read_text().splitlines():
            if row.split()[-1] != "lo":
                raise ValueError("DNS_EXTERNAL_ROUTE")
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for channel in (udp, tcp):
            channel.set_inheritable(False)
            channel.bind(("127.0.0.53", 53))
            if channel.getsockopt(socket.SOL_SOCKET, 71, 8) != cookie:
                raise ValueError("DNS_SOCKET_NAMESPACE_COOKIE")
        tcp.listen(1)
        return udp, tcp
    except BaseException:
        for channel in (udp, tcp):
            if channel is not None:
                channel.close()
        raise
    finally:
        os.close(fd)


def dns_child(config, ready, worker):
    """Root child body used by an admitted Supervisor, never the host controller.

    Binding, image SHA, policy, traffic grant, ledger/replay and budget admission
    belong to the existing Supervisor before fork. This function creates no such
    grants. A result is application evidence only, never Network14 eligibility.
    """
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError("DNS_CHILD_REQUIRES_AUTHENTICATED_ROOT_SUPERVISOR")
    parent = os.getppid()
    _prctl(1, signal.SIGKILL)
    if os.getppid() != parent:
        raise ValueError("DNS_SUPERVISOR_DISAPPEARED")
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.alarm(65)  # Includes setup/credential drop; worker has its own 60s limit.
    udp = tcp = None
    try:
        udp, tcp = _enter_and_bind(config)
        _drop_credentials(config["uid"], config["gid"], parent)
        return worker(SimpleNamespace(namespace=config["namespace"]), udp, tcp, ready=ready)
    finally:
        for channel in (udp, tcp):
            if channel is not None:
                channel.close()
        signal.alarm(0)


class DNSChild:
    """Root Supervisor owns one unreaped PID and bounded evidence channel."""

    def __init__(self, pid, channel):
        self.pid = pid
        self.channel = channel
        self.status = None
        self.deadline = time.monotonic() + 66

    def receive(self):
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.channel], [], [], remaining)[0]:
                raise TimeoutError("DNS_CHILD_EVIDENCE_DEADLINE")
            body, _, flags, _ = self.channel.recvmsg(16384)
            if not body or flags & socket.MSG_TRUNC:
                raise ValueError("DNS_CHILD_EVIDENCE_TRUNCATED")
            value = json.loads(body)
            if not isinstance(value, dict) or value.get("state") not in {
                "LOCAL_DNS_READY",
                "DNS_CHILD_FAILED",
                "DNS_RESPONDER_COMPLETED",
                "DNS_DIAGNOSTIC_COMPLETED",
            }:
                raise ValueError("DNS_CHILD_EVIDENCE_SCHEMA")
            return value
        except (OSError, ValueError, UnicodeError):
            # Malformed evidence and transport failures must not leave the
            # owned child alive until its wall deadline. Preserve the original
            # exception; closing the unreaped child never signals another PID.
            self.close()
            raise

    def close(self):
        try:
            if self.status is None:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
                if not pid:
                    # Our child is still unreaped, so its PID cannot be reused.
                    # SIGKILL bounds cancellation even if the worker is wedged.
                    os.kill(self.pid, signal.SIGKILL)
                    _, status = os.waitpid(self.pid, 0)
                self.status = os.waitstatus_to_exitcode(status)
        finally:
            self.channel.close()
        return self.status

    def finish(self):
        """Reap normal completion; distinguish a final packet from process exit."""
        end = min(self.deadline, time.monotonic() + 2)
        while self.status is None and time.monotonic() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                break
            time.sleep(0.01)
        return self.close()


def spawn_dns_child(config, worker):
    """Internal authenticated-Supervisor service, not a public Root launcher.

    Future admission must authorize these exact image/config bytes first. The
    current CLI has no call to this function and the review image refuses main.
    """
    if os.getuid() != 0 or os.geteuid() != 0:
        raise ValueError("DNS_CHILD_REQUIRES_AUTHENTICATED_ROOT_SUPERVISOR")
    host = os.readlink("/proc/self/ns/net")
    if host == config["namespace"]:
        raise ValueError("DNS_SUPERVISOR_MUST_REMAIN_OUTSIDE_NAMESPACE")
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        pid = os.fork()
    except BaseException:
        parent.close()
        child.close()
        raise
    if pid:
        child.close()
        return DNSChild(pid, parent)
    parent.close()
    # The privileged child retains only the dedicated evidence channel. No
    # inherited TCX, controller, terminal or other service FD crosses UID drop.
    keep = child.fileno()
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd != keep:
            try:
                os.close(fd)
            except OSError as exc:
                if exc.errno != 9:  # listdir's directory FD has already closed
                    os._exit(125)

    def emit(value):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(body) > 16384 or child.send(body) != len(body):
            raise ValueError("DNS_CHILD_EVIDENCE_BOUND")

    code = 1
    try:
        emit(dns_child(config, emit, worker))
        code = 0
    except Exception as exc:
        try:
            emit(dict(state="DNS_CHILD_FAILED", error_class=type(exc).__name__, error=str(exc)))
        except (OSError, ValueError):
            code = 125
    finally:
        child.close()
    os._exit(code)
