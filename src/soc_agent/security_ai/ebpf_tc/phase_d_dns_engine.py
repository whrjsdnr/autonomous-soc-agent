"""Embedded single-use DNS worker. Called only after the existing OS auth gate.

Forked before TCX/stream threads or authority FDs exist. No install, sudo or BPF.
"""

import ctypes
import os
import resource
import socket
import struct
import time

DNS_MASK = (1 << 13) | (1 << 6) | (1 << 7)  # NET_RAW, SETGID, SETUID until capture drop.


class DNSWorker:
    def __init__(self, channel, fd, pid):
        self.channel, self.fd, self.pid = channel, fd, pid
        self.started = self.closed = False
        self.exit_code = None

    def status(self):
        if self.exit_code is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.exit_code = os.waitstatus_to_exitcode(status)
        return dict(
            pid=self.pid,
            started=self.started,
            exited=self.exit_code is not None,
            exit_code=self.exit_code,
            closed=self.closed,
        )

    def start(self):
        if self.started or self.closed or self.status()["exited"]:
            raise ValueError("DNS_SUPERVISOR_NO_RESTART")
        self.started = True
        if self.channel.send(b"RUN_ONCE") != 8:
            raise ValueError("DNS_SUPERVISOR_START_WRITE")
        fd, self.fd = self.fd, -1
        return fd

    def close(self):
        if self.closed:
            return
        self.channel.close()  # EOF cancels a worker that never began capture.
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        until = time.monotonic() + 12
        while not self.status()["exited"] and time.monotonic() < until:
            time.sleep(0.02)
        if not self.status()["exited"]:
            raise ValueError("DNS_SUPERVISOR_EXIT_UNVERIFIED")
        self.closed = True


def start_dns_worker(image, envelope, approval):
    """Authenticated Supervisor-only fork; never called by a preparation/test import."""
    import sys

    if any((os.getuid(), os.geteuid(), os.getgid(), os.getegid())):
        raise ValueError("DNS_SUPERVISOR_ROOT_REQUIRED")
    uid, gid, controller = struct.unpack_from("<III", envelope, 4)
    context = dict(
        controller_pid=controller,
        binding=globals()["start_binding"](
            envelope,
            sys.argv[5],
            image["manifest_sha256"],
            approval.hex(),
            globals()["DNS_SCOPE_DIGEST"],
        ),
    )
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    parent = os.getpid()
    try:
        child = os.fork()
    except BaseException:
        a.close()
        b.close()
        os.close(read_fd)
        os.close(write_fd)
        raise
    if child == 0:
        a.close()
        os.close(read_fd)
        # Own only control fd3 and metadata stdout; no Inspector/Broker/Link FD.
        duplicate = os.dup(b.fileno())
        os.dup2(write_fd, 1)
        os.dup2(duplicate, 3)
        os.closerange(4, 1048576)
        control = socket.socket(fileno=3)
        code = 2
        try:
            globals()["sup_parent_death"](parent)
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2,) * 2)
            resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            globals()["sup_caps"](DNS_MASK, initial=True)
            control.settimeout(300)
            if control.recv(9) != b"RUN_ONCE":
                os._exit(0)  # No request / parent closure never authorizes a capture.
            control.close()
            # Enable only already permitted worker caps, inheritable/ambient stay zero.
            header = (ctypes.c_uint32 * 2)(0x20080522, 0)
            caps = (ctypes.c_uint32 * 6)(DNS_MASK, DNS_MASK, 0, 0, 0, 0)
            if ctypes.CDLL(None, use_errno=True).capset(header, caps):
                raise OSError(ctypes.get_errno(), "DNS_SUPERVISOR_CAPSET")
            result = globals()["capture_analysis"](
                uid,
                gid,
                globals()["attach_filter"],
                globals()["restrict_process"],
                globals()["analysis_copy"],
                globals()["chain_receipt"],
                globals()["DNS_SCOPE_DIGEST"],
                start_gate=True,
                session_started=time.monotonic(),
                start_context=context,
            )
            result.update(
                image_sha256=sys.argv[5],
                manifest=image["manifest_sha256"],
                scope_digest=globals()["DNS_SCOPE_DIGEST"],
            )
            globals()["emit_result"](result)
            code = 0
        except Exception as exc:
            try:
                globals()["emit_result"](
                    globals()["root_error"](exc, "SUPERVISED_DNS", "capture_analysis")
                )
            except OSError:
                pass  # Original failure still determines nonzero exit, no success receipt.
        finally:
            os._exit(code)
    b.close()
    os.close(write_fd)
    return DNSWorker(a, read_fd, child)
