"""Isolated-network preparation. No setns/unshare, Root, bind/connect or traffic.

A Namespace name is not ownership, and an inode is not an approval. New Scope
needs separate infrastructure/policy and exact Artifact execution approvals.
"""

import fcntl
import hashlib
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from soc_agent.security_ai.ebpf_tc.r2_diagnostic import QUESTION
from soc_agent.security_ai.ebpf_tc.reassessment import Contract

HOST_NAMESPACE = "net:[4026531833]"


class IsolatedScope(Contract):
    namespace: str = Field(pattern=r"^net:\[[1-9][0-9]*\]$")
    name: Literal["soc-native-b3"] = "soc-native-b3"
    interface: Literal["lo"] = "lo"
    ifindex: Literal[1] = 1
    hook: Literal["INGRESS"] = "INGRESS"
    endpoint: Literal["127.0.0.53:53"] = "127.0.0.53:53"
    activation: Literal["POLICY_APPROVAL_REQUIRED"] = "POLICY_APPROVAL_REQUIRED"

    @model_validator(mode="after")
    def distinct_from_host(self):
        if self.namespace == HOST_NAMESPACE:
            raise ValueError("ISOLATION_HOST_NAMESPACE_FORBIDDEN")
        return self


def dns_scope_digest(namespace: str) -> str:
    if namespace != HOST_NAMESPACE:
        IsolatedScope(namespace=namespace)
    inode = namespace[5:-1]
    return hashlib.sha256(
        f"DNS_LOCAL_PARTIAL_COPY_V4:net{inode}:lo:7s:32:512:prewarm:shared10s:tty:seqpacket".encode()
    ).hexdigest()


def assess_isolation(scope: IsolatedScope, evidence: dict) -> dict:
    """Assess namespace/interface/route observations, never packet integrity."""
    reasons = []
    if evidence.get("namespace") != scope.namespace:
        reasons.append("NAMESPACE_IDENTITY_MISMATCH")
    if evidence.get("interfaces") != [[1, "lo"]]:
        reasons.append("NON_LOOPBACK_INTERFACE_OR_MISSING_LO")
    if evidence.get("loopback_up") is not True:
        reasons.append("LOOPBACK_NOT_UP")
    if evidence.get("routes_outside_lo") != []:
        reasons.append("EXTERNAL_ROUTE_OR_ROUTE_EVIDENCE_MISSING")
    if evidence.get("resolver_ready") is not True:
        reasons.append("LOCAL_DNS_RESPONDER_NOT_OBSERVED")
    return dict(
        status="INCOMPLETE" if reasons else "OBSERVED_NETWORK_CONFIGURATION_ONLY",
        reasons=reasons,
        namespace=scope.namespace,
        ownership="NOT_PROVEN_BY_NAME_OR_INODE",
        execution_ready=False,
        capture_integrity="NOT_OBSERVED",
        flow_completeness="NOT_OBSERVED",
        native_ai="BLOCKED",
    )


def inspect_current_isolation(scope: IsolatedScope) -> dict:
    """Only inspect an already-entered namespace; never enter or create one."""
    actual = os.readlink("/proc/self/ns/net")
    if actual != scope.namespace:
        return assess_isolation(scope, dict(namespace=actual))
    started_ns = time.monotonic_ns()
    routes = []
    route_tables = {}
    for family in ("-4", "-6"):
        data = subprocess.check_output(
            ["/usr/sbin/ip", "-j", family, "route", "show", "table", "all"], timeout=5
        )
        rows = json.loads(data)
        if not isinstance(rows, list):
            raise ValueError("ISOLATION_ROUTE_SCHEMA")
        route_tables[family] = rows
        routes.extend(row for row in rows if row.get("dev") != "lo")
    # A network-only setns does not remount sysfs. /sys/class/net/lo/flags
    # can therefore describe the host lo. ioctl follows this socket's netns.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        flags = fcntl.ioctl(probe, 0x8913, struct.pack("256s", b"lo"))
        loopback_up = bool(struct.unpack_from("H", flags, 16)[0] & 1)
        cookie = probe.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_NETNS_COOKIE", 71), 8)
    sockets = {}
    for table in ("tcp", "tcp6", "udp", "udp6"):
        with (Path("/proc/net") / table).open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("ISOLATION_SOCKET_SNAPSHOT_BOUND")
        sockets[table] = data.decode("ascii").splitlines()
    interfaces = [list(row) for row in socket.if_nameindex()]
    if os.readlink("/proc/self/ns/net") != actual:
        raise ValueError("ISOLATION_NAMESPACE_CHANGED_DURING_SNAPSHOT")
    evidence = dict(
        namespace=actual,
        interfaces=interfaces,
        loopback_up=loopback_up,
        loopback_flags_source="SIOCGIFFLAGS_CURRENT_NAMESPACE_SOCKET",
        routes=route_tables,
        routes_outside_lo=routes,
        socket_tables=sockets,
        socket_cookie=cookie.hex(),
        cookie_evidence="UNBOUND_PROBE_ONLY_NOT_DNS_WORKER",
        observation_started_monotonic_ns=started_ns,
        observation_ended_monotonic_ns=time.monotonic_ns(),
        evidence_scope="NETWORK_CONFIGURATION_ONLY_NOT_CAPTURE_WINDOW_OR_FLOW",
        # No bind/connect/query: a listener and its lease must be verified later.
        resolver_ready=False,
    )
    return assess_isolation(scope, evidence) | dict(observation=evidence)


def setup_proposal() -> dict:
    """Fixed argv for human review only. No runner and no cleanup-by-name API."""
    return dict(
        contract="SOC_ISOLATED_NETWORK_SETUP_PROPOSAL_V1",
        namespace_name="soc-native-b3",
        namespace_identity="PENDING_PRIVILEGED_CREATION_AND_READ_ONLY_DISCOVERY",
        proposed_root_argv=[
            ["/usr/sbin/ip", "netns", "add", "soc-native-b3"],
            ["/usr/sbin/ip", "-n", "soc-native-b3", "link", "set", "dev", "lo", "up"],
        ],
        collision_policy="FAIL_IF_NAME_EXISTS_DO_NOT_REUSE_OR_DELETE",
        external_interfaces=[],
        external_routes=[],
        veth=False,
        nat=False,
        firewall_changes=False,
        docker_analysis_network="none",
        local_dns="NEW_IN_NAMESPACE_RESPONDER_REQUIRED_127.0.0.53:53",
        controller="START_INSIDE_NAMESPACE_AS_ORDINARY_UID_WITH_EXISTING_CAPABILITY_CHECKS",
        cleanup="REQUIRES_EXACT_NAMESPACE_LEASE_AND_NO_OWNED_PROCESS_OR_TCX_RESIDUAL",
        namespace_cleanup_by_name_authorized=False,
        activation="POLICY_APPROVAL_REQUIRED",
        root_budget_assignment="PENDING_HUMAN_DECISION_NOT_AN_INSTALLATION_REFUND",
        root_native_executions=0,
    )


def local_dns_response(query: bytes, *, tcp: bool = False) -> bytes:
    """Deterministic wire engine for a future approved responder; no IO.

    Exact diagnostic A question only, no forwarding, recursion, arbitrary name,
    extra queries or persistent server. The transport/privilege lease stays gated.
    """
    if tcp:
        if len(query) < 2 or struct.unpack("!H", query[:2])[0] != len(query) - 2:
            raise ValueError("ISOLATED_DNS_TCP_FRAME")
        query = query[2:]
    if len(query) != 12 + len(QUESTION):
        raise ValueError("ISOLATED_DNS_QUERY_SIZE")
    transaction, flags, qd, an, ns, ar = struct.unpack("!6H", query[:12])
    if (
        transaction not in {0xC201, 0xC202, 0xC203}
        or flags != 0x0100
        or (qd, an, ns, ar) != (1, 0, 0, 0)
        or query[12:] != QUESTION
        or tcp != (transaction == 0xC202)
    ):
        raise ValueError("ISOLATED_DNS_QUERY_SCOPE")
    response = (
        struct.pack("!6H", transaction, 0x8500, 1, 1, 0, 0)
        + QUESTION
        + struct.pack("!HHHIH4s", 0xC00C, 1, 1, 0, 4, b"\x7f\0\0\1")
    )
    return struct.pack("!H", len(response)) + response if tcp else response


class IsolatedDNSProtocol:
    """Single-scenario protocol state, not a listening socket or traffic grant."""

    def __init__(self, scope: IsolatedScope):
        self.scope = scope
        self.completed: set[int] = set()

    def respond(self, query: bytes, *, tcp: bool = False) -> bytes:
        response = local_dns_response(query, tcp=tcp)
        transaction = struct.unpack("!H", query[2:4] if tcp else query[:2])[0]
        if transaction in self.completed:
            raise ValueError("ISOLATED_DNS_REPLAY_OR_QUERY_LIMIT")
        if transaction != (0xC201, 0xC202, 0xC203)[len(self.completed)]:
            raise ValueError("ISOLATED_DNS_QUERY_ORDER")
        self.completed.add(transaction)
        return response
