"""Embedded fixed DNS diagnostic, no project imports or caller-selected commands.

Only dns_root_main invokes the service, after exact grant, reservation and OS
authentication validation. Importing/compiling this file never invokes it.
"""

import hashlib
import json
import os
import resource
import signal
import socket
import stat
import struct
import sys
import threading
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.isolated_dns_engine import local_controller, spawn_dns_child
from soc_agent.security_ai.ebpf_tc.isolated_dns_worker import _exact, serve_prebound
from soc_agent.security_ai.ebpf_tc.namespace_isolation import local_dns_response
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import QUESTION
from soc_agent.security_ai.ebpf_tc.unified_image_engine import (
    _candidate_policy,
    _safe_environment,
    _sudo_parent,
)

DNS_POLICY_IMAGE: dict | None = None


def dns_snapshot():
    import fcntl

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        flags = fcntl.ioctl(probe, 0x8913, struct.pack("256s", b"lo"))
        cookie = probe.getsockopt(socket.SOL_SOCKET, 71, 8).hex()
    tables = {}
    for name in ("tcp", "tcp6", "udp", "udp6"):
        with open("/proc/net/" + name, "rb") as stream:
            body = stream.read(16385)
        if len(body) > 16384:
            raise ValueError("DNS_SOCKET_SNAPSHOT_BOUND")
        tables[name] = body.decode("ascii").splitlines()[1:]
    return dict(
        namespace=os.readlink("/proc/self/ns/net"),
        interfaces=[list(row) for row in socket.if_nameindex()],
        lo_up=bool(struct.unpack_from("H", flags, 16)[0] & 1),
        ipv4_routes=Path("/proc/net/route").read_text().splitlines(),
        ipv6_routes=Path("/proc/net/ipv6_route").read_text().splitlines(),
        socket_cookie=cookie,
        sockets=tables,
        application_monotonic_ns=time.monotonic_ns(),
    )


def diagnostic_worker(scope, udp, tcp, *, ready):
    """Ordinary credentials only; reuse the exact server and wire protocol."""
    local_controller()
    baseline = dns_snapshot()
    # The only permitted pre-existing sockets are our two prebound listeners.
    if any(baseline["sockets"][n] for n in ("tcp6", "udp6")) or any(
        len(baseline["sockets"][n]) != 1 for n in ("tcp", "udp")
    ):
        raise ValueError("DNS_NAMESPACE_HAS_UNOWNED_SOCKETS")
    opened = time.monotonic_ns()
    active, closed = threading.Event(), threading.Event()
    server_result, server_failure, tcp_close = [], [], []

    def on_ready(value):
        ready(value)
        active.set()

    def on_close(value):
        tcp_close.append(value)
        closed.set()

    def server():
        try:
            server_result.append(
                serve_prebound(scope, udp, tcp, ready=on_ready, tcp_closed=on_close)
            )
        except Exception as exc:
            server_failure.append(exc)
        finally:
            active.set()
            closed.set()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    try:
        if not active.wait(2) or server_failure:
            raise ValueError("DNS_WORKER_NOT_READY")
        exchanges = []
        for transaction, transport in ((0xC201, "UDP"), (0xC202, "TCP"), (0xC203, "UDP")):
            if transaction == 0xC203:
                if not closed.wait(2) or not tcp_close or server_failure:
                    raise ValueError("DNS_TCP_CLOSE_MISSING")
                remaining = (tcp_close[0] + 35_000_000_000 - time.monotonic_ns()) / 1e9
                if remaining > 0:
                    time.sleep(remaining)
                if time.monotonic_ns() < tcp_close[0] + 35_000_000_000:
                    raise ValueError("DNS_OBSERVATION_CLOCK_REVERSED")
            query = struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + QUESTION
            tcp_mode = transport == "TCP"
            wire = struct.pack("!H", len(query)) + query if tcp_mode else query
            kind = socket.SOCK_STREAM if tcp_mode else socket.SOCK_DGRAM
            with socket.socket(socket.AF_INET, kind) as client:
                client.settimeout(2)
                client.bind(("127.0.0.1", 0))
                if client.getsockopt(socket.SOL_SOCKET, 71, 8).hex() != baseline["socket_cookie"]:
                    raise ValueError("DNS_CLIENT_COOKIE_MISMATCH")
                sent = time.monotonic_ns()
                if tcp_mode:
                    client.connect(("127.0.0.53", 53))
                    client.sendall(wire)
                    header = _exact(client, 2, time.monotonic() + 2)
                    size = int.from_bytes(header, "big")
                    if size > 512:
                        raise ValueError("DNS_RESPONSE_BOUND")
                    response = header + _exact(client, size, time.monotonic() + 2)
                    if client.recv(1) != b"":
                        raise ValueError("DNS_TCP_CLOSE_EXPECTED")
                else:
                    if client.sendto(wire, ("127.0.0.53", 53)) != len(wire):
                        raise ValueError("DNS_QUERY_PARTIAL")
                    response, peer = client.recvfrom(513)
                    if peer != ("127.0.0.53", 53):
                        raise ValueError("DNS_RESPONSE_PEER")
                if response != local_dns_response(wire, tcp=tcp_mode):
                    raise ValueError("DNS_RESPONSE_MISMATCH")
                exchanges.append(
                    dict(transport=transport, sent_ns=sent, response_ns=time.monotonic_ns())
                )
        thread.join(2)
        if thread.is_alive() or server_failure or len(server_result) != 1:
            raise ValueError("DNS_WORKER_DID_NOT_COMPLETE")
        remaining = (opened + 45_000_000_000 - time.monotonic_ns()) / 1e9
        if remaining > 0:
            time.sleep(remaining)
        after = dns_snapshot()
        if udp.fileno() != -1 or tcp.fileno() != -1:
            raise ValueError("DNS_LISTENER_FD_REMAIN")
        return dict(
            state="DNS_DIAGNOSTIC_COMPLETED",
            baseline=baseline,
            after=after,
            exchanges=exchanges,
            worker=server_result[0],
            listener_fds_closed=True,
            kernel_time_wait_is_not_fd_leak=True,
            sidecar_analysis="NOT_STARTED_10S_LIMIT_UNCHANGED",
            capture_integrity="NOT_ASSESSED",
            native=False,
        )
    finally:
        udp.close()
        tcp.close()
        thread.join(2)
        if thread.is_alive():
            raise ValueError("DNS_WORKER_CLEANUP_UNVERIFIED")


def dns_held_json(path, pin, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != uid
            or st.st_nlink != 1
            or st.st_size > 65536
        ):
            raise ValueError("DNS_GRANT_FILE_TRUST")
        body = os.pread(fd, 65537, 0)
        if hashlib.sha256(body).hexdigest() != pin:
            raise ValueError("DNS_GRANT_SHA")
        return json.loads(body)
    finally:
        os.close(fd)


def dns_validate_grant(config, envelope):
    """Root repeats exact immutable Scope/identity checks; no Root project import."""
    uid, gid = config["uid"], config["gid"]
    if (
        os.getuid() != 0
        or os.geteuid() != 0
        or os.environ.get("SUDO_UID") != str(uid)
        or os.environ.get("SUDO_GID") != str(gid)
    ):
        raise ValueError("DNS_OS_AUTHENTICATION_REQUIRED")
    _sudo_parent()
    policy = dns_held_json(envelope["policy_file"], envelope["policy_sha"], uid)
    approval = dns_held_json(envelope["approval_file"], envelope["approval_sha"], uid)
    metadata = dns_held_json(envelope["manifest_file"], envelope["manifest_sha"], uid)
    binding = approval["binding"]
    if (
        policy.get("contract") != "SOC_ROOT_ONLY_ACCOUNTING_POLICY_V1"
        or approval.get("contract") != "SOC_ROOT_OPERATION_APPROVAL_V1"
        or policy["implementation_sha"] != config["implementation_sha"]
        or policy["approver"] != approval["approver"]
        or any(s in policy["approver"].upper() for s in ("MOCK", "FIXTURE"))
        or type(approval["native_cost"]) is not int
        or type(approval["root_cost"]) is not int
        or policy["binding"] != binding
        or policy["decision"] != "APPROVED"
        or approval["decision"] != "APPROVED"
        or approval["operation"] != "ROOT_DNS_DIAGNOSTIC"
        or approval["native_cost"] != 0
        or approval["root_cost"] != 1
        or approval["policy_sha"] != envelope["policy_sha"]
        or approval["scope"] != config["scope"]
        or metadata["config"] != config
        or binding["session"] != config["session"]
        or binding["source_snapshot"] != config["source_snapshot"]
        or binding["scope_sha"] != hashlib.sha256(dns_canonical(config["scope"])).hexdigest()
        or binding["artifact"]["image"] != envelope["image_sha"]
        or binding["artifact"]["manifest"] != envelope["manifest_sha"]
        or binding["artifact"]["root_manifest"] != config["root_manifest"]
        or binding["artifact"]["release"] != config["release"]
        or binding["artifact"]["bundle"] != metadata["bundle"]
        or not policy["issued_at"] <= time.time() < approval["expires_at"] <= policy["expires_at"]
        or not approval["issued_at"] <= time.time()
    ):
        raise ValueError("DNS_ROOT_GRANT_BINDING")
    # The ordinary controller has validated the full chain under lock. Root also
    # requires that exact after-START_INTENT snapshot, not a floating file path.
    ledger = dns_held_json_ledger(envelope["ledger_file"], envelope["ledger_sha"], uid)
    attempts = [r for r in ledger if r.get("attempt_id") == envelope["approval_sha"]]
    if (
        not attempts
        or attempts[0].get("operation") != "ROOT_DNS_DIAGNOSTIC"
        or attempts[0].get("binding") != binding
        or attempts[-1].get("state") != "START_INTENT"
        or attempts[0].get("policy_sha256") != envelope["policy_sha"]
        or ledger[0].get("budget_sha256") != policy["budget_sha"]
        or ledger[0].get("baseline_sha256") != policy["baseline_sha"]
        or not any(
            row.get("event") == "ROOT_POLICY_ACTIVATED_V1"
            and row.get("policy_sha256") == envelope["policy_sha"]
            and row.get("binding") == binding
            for row in ledger
        )
        or not any(
            row.get("event") == "ROOT_BATCH_DNS_ALLOCATION_RECORDED_V1"
            and row.get("allocation", {}).get("root_max") == 4
            for row in ledger
        )
    ):
        raise ValueError("DNS_ROOT_RESERVATION_REQUIRED")


def dns_canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def dns_held_json_ledger(path, pin, uid):
    # Ledger framing differs from receipt JSON; keep the same bounded held read.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (
            st.st_uid != uid
            or st.st_nlink != 1
            or not stat.S_ISREG(st.st_mode)
            or st.st_size > 1048576
        ):
            raise ValueError("DNS_LEDGER_TRUST")
        body = os.pread(fd, 1048577, 0)
        if hashlib.sha256(body).hexdigest() != pin or not body.endswith(b"\n"):
            raise ValueError("DNS_LEDGER_SHA")
        lines = body.splitlines(keepends=True)
        rows = [json.loads(line) for line in lines]
        for n, row in enumerate(rows[1:], 1):
            unsigned = {k: v for k, v in row.items() if k != "record_sha256"}
            if (
                row["sequence"] != n
                or row["previous_record_sha256"] != hashlib.sha256(lines[n - 1]).hexdigest()
                or row["record_sha256"] != hashlib.sha256(dns_canonical(unsigned)).hexdigest()
            ):
                raise ValueError("DNS_LEDGER_CHAIN")
        return rows
    finally:
        os.close(fd)


def dns_root_main(config):
    if os.getuid() != 0 or os.geteuid() != 0 or len(sys.argv) != 2:
        raise ValueError("DNS_OS_AUTHENTICATION_REQUIRED")
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.alarm(75)
    envelope = json.loads(sys.argv[1])
    dns_validate_grant(config, envelope)
    print(json.dumps(dict(state="DNS_ROOT_AUTHENTICATED", session=config["session"])), flush=True)
    # Fixed root-owned per-receipt fuse survives controller crashes. It is
    # explicitly part of the reviewed DNS Scope, never removed automatically.
    approval = envelope["approval_sha"]
    if len(approval) != 64 or bytes.fromhex(approval).hex() != approval:
        raise ValueError("DNS_APPROVAL_IDENTITY")
    claim = "/run/soc-agent-dns-" + approval + ".claimed"
    fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        os.write(fd, dns_canonical(dict(session=config["session"], approval_sha=approval)))
        os.fsync(fd)
    finally:
        os.close(fd)
    for dependency in config["dependencies"]:
        fd = os.open(dependency["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            body = os.pread(fd, 64 * 1024**2, 0)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid
                or st.st_mode & 0o022
                or hashlib.sha256(body).hexdigest() != dependency["sha256"]
            ):
                raise ValueError("DNS_RUNTIME_DEPENDENCY_CHANGED")
        finally:
            os.close(fd)
    if (
        DNS_POLICY_IMAGE is None
        or DNS_POLICY_IMAGE["files"]["bootstrap"]["sha256"]
        != config["password_policy_bootstrap_sha"]
    ):
        raise ValueError("DNS_PASSWORD_POLICY_BOOTSTRAP_REQUIRED")
    _candidate_policy(
        DNS_POLICY_IMAGE,
        config["uid"],
        config["gid"],
        _safe_environment(config["uid"], config["gid"]),
    )
    signal.alarm(75)
    child = spawn_dns_child(config, diagnostic_worker)
    try:
        while True:
            value = child.receive()
            print(json.dumps(value, separators=(",", ":")), flush=True)
            if value["state"] == "DNS_CHILD_FAILED":
                raise ValueError("DNS_CHILD_FAILED")
            if value["state"] == "DNS_DIAGNOSTIC_COMPLETED":
                if child.finish() != 0:
                    raise ValueError("DNS_CHILD_EXIT_FAILURE")
                break
    finally:
        child.close()
        signal.alarm(0)
