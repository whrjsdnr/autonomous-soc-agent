"""Separate ordinary-UID fixture Broker. Native/root execution is refused at entry."""

import os
import resource
import signal
import socket
import struct
import sys
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Command
from soc_agent.security_ai.ebpf_broker.engine import Engine
from soc_agent.security_ai.ebpf_broker.identity import broker_sha, verify_bundle, verify_object
from soc_agent.security_ai.ebpf_broker.ipc import receive, send
from soc_agent.security_ai.ebpf_broker.journal import Journal
from soc_agent.security_ai.ebpf_native.contracts import (
    alive,
    controller_unprivileged,
    local_controller,
)


def run(channel: socket.socket, object_fd: int) -> int:
    if not controller_unprivileged():
        raise ValueError("BROKER_PHASE_B1_ROOT_OR_PRIVILEGE_DENIED")
    channel.settimeout(5)
    plan = BrokerPlan.model_validate(receive(channel))
    peer_pid, peer_uid, peer_gid = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    )
    if (peer_pid, peer_uid, peer_gid) != (
        plan.application.controller.pid,
        plan.uid,
        plan.gid,
    ) or os.getppid() != peer_pid:
        raise ValueError("BROKER_BOOTSTRAP_PEER_MISMATCH")
    if plan.broker_sha256 != broker_sha():
        raise ValueError("BROKER_EXECUTABLE_SHA_MISMATCH")

    def validate():
        scope = plan.application.scope
        if not alive(plan.application.controller):
            raise ValueError("BROKER_CONTROLLER_IDENTITY_FAILED")
        if os.getuid() != plan.uid or os.getgid() != plan.gid or not controller_unprivileged():
            raise ValueError("BROKER_UID_GID_MISMATCH")
        if os.readlink("/proc/self/ns/net") != scope.net_namespace:
            raise ValueError("BROKER_NAMESPACE_MISMATCH")
        if int(Path("/sys/class/net/lo/ifindex").read_text()) != scope.ifindex:
            raise ValueError("BROKER_INTERFACE_MISMATCH")
        verify_object(object_fd, scope.program_sha256)
        verify_bundle(plan.bundle_digest)
        rss = (
            int(
                next(
                    v.split()[1]
                    for v in Path("/proc/self/status").read_text().splitlines()
                    if v.startswith("VmRSS:")
                )
            )
            * 1024
        )
        if rss > plan.broker_rss_mib * 1024**2:
            raise ValueError("BROKER_MEMORY_BUDGET")

    validate()
    # Fixed fixture bounds; no capabilities are granted or inherited.
    resource.setrlimit(resource.RLIMIT_CPU, (plan.broker_cpu_seconds, plan.broker_cpu_seconds))
    resource.setrlimit(
        resource.RLIMIT_AS, (plan.broker_address_mib * 1024**2, plan.broker_address_mib * 1024**2)
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    journal = Journal(Path("broker-audit.jsonl"), plan.identity, plan.journal_bytes)
    engine = Engine(plan, journal.record, validate)
    identity = local_controller()
    interrupted: list[str] = []

    def on_signal(number, frame):
        if not interrupted:
            interrupted.append("SIGINT" if number == signal.SIGINT else "SIGTERM")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    journal.record("BROKER_BOOTSTRAPPED", identity=identity.model_dump(), privilege="NONE")
    channel.settimeout(0.5)
    try:
        send(channel, dict(plan_digest=plan.identity, identity=identity.model_dump(), ready=True))
        while not engine.exited:
            if interrupted:
                engine.cleanup_owned(interrupted[0])
                journal.record("BROKER_EXITED", reason=interrupted[0], cleanup=engine.cleanup)
                return 0
            engine.tick()
            try:
                payload = receive(channel)
            except TimeoutError:
                continue
            command = Command.model_validate(payload)
            result = engine.execute(command)
            send(
                channel,
                dict(
                    plan_digest=plan.identity,
                    sequence=command.sequence,
                    snapshot=result,
                    audit_digest=journal.previous,
                    identity=identity.model_dump(),
                    process_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                ),
            )
        return 0
    except EOFError:
        engine.cleanup_owned("CONTROLLER_EXIT")
        journal.record("BROKER_EXITED", reason="CONTROLLER_EXIT", cleanup=engine.cleanup)
        return 0
    except (ValueError, OSError, MemoryError) as exc:
        # Reviewed codes only, no arbitrary exception text, paths or payloads.
        try:
            journal.record(
                "BROKER_FAILURE_CLASSIFIED",
                error_class=type(exc).__name__,
                code=(
                    str(exc)
                    if str(exc)
                    in {
                        "BROKER_BUNDLE_MISMATCH",
                        "BROKER_MEMORY_BUDGET",
                        "BROKER_CONTROLLER_IDENTITY_FAILED",
                        "BROKER_NAMESPACE_MISMATCH",
                        "BROKER_MONOTONIC_INVALID",
                        "BROKER_HEARTBEAT_TIMEOUT",
                        "BROKER_APPLICATION_DEADLINE",
                        "BROKER_IPC_OUTPUT_BOUND",
                    }
                    else "BROKER_PROTOCOL_OR_SUPERVISION_FAILED"
                ),
            )
            engine.fail("BROKER_PROTOCOL_OR_SUPERVISION_FAILED")
            engine.cleanup_owned("CONTROLLER_EXIT")
            journal.record("BROKER_EXITED", reason="FAILURE", cleanup=engine.cleanup)
            send(channel, dict(error="BROKER_PROTOCOL_OR_SUPERVISION_FAILED"))
        except (ValueError, OSError, MemoryError):
            # No unverifiable detach or automatic restart fallback.
            return 2
        return 1
    finally:
        journal.close()
        os.close(object_fd)
        channel.close()


def fixture_guard(event, args):
    if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        raise PermissionError("BROKER_FIXTURE_PROCESS_EXECUTION_DENIED")
    if event == "socket.__new__" and args[1] in {
        socket.AF_PACKET,
        socket.AF_INET,
        socket.AF_INET6,
        socket.AF_NETLINK,
    }:
        raise PermissionError("BROKER_FIXTURE_NATIVE_SOCKET_DENIED")


def main() -> int:
    sys.addaudithook(fixture_guard)
    # No native mode, arbitrary command, path argument, or privileged startup flag exists.
    if len(sys.argv) != 3 or not all(v.isdecimal() for v in sys.argv[1:]):
        raise ValueError("BROKER_INTERNAL_INHERITED_FDS_REQUIRED")
    started = time.monotonic()
    channel = socket.socket(fileno=int(sys.argv[1]))
    if time.monotonic() - started > 5:
        raise ValueError("BROKER_BOOTSTRAP_TIMEOUT")
    return run(channel, int(sys.argv[2]))


if __name__ == "__main__":
    raise SystemExit(main())
