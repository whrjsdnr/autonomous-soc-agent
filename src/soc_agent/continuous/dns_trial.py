"""Reuse installed dnsmasq; build only its fixed service and bounded test client.

No DNS responder is implemented here. Neither candidate() nor source() starts a
service. The existing reviewed Root coordinator owns activation and cleanup.
"""

import ast
import hashlib
import os
import re
import socket
import struct
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_tc import isolated_dns_engine, isolated_dns_worker
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import QUESTION

BINARY = Path("/usr/sbin/dnsmasq")
UNIT = "soc-continuous-dnsmasq.service"


def arguments(*, local_test=False):
    endpoint, port = ("127.0.0.1", 1053) if local_test else ("127.0.0.53", 53)
    return [
        str(BINARY),
        "--keep-in-foreground",
        "--conf-file=/dev/null",
        "--no-resolv",
        "--no-hosts",
        "--no-poll",
        "--bind-interfaces",
        "--listen-address=" + endpoint,
        "--port=" + str(port),
        "--host-record=native-0516.localhost,127.0.0.1,0",
        "--local=/localhost/",
        "--cache-size=0",
        "--pid-file=",
        "--log-facility=-",
        "--user=geonug",
        "--group=geonug",
    ]


def candidate():
    binary = BINARY.resolve(strict=True)
    info = binary.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("CONTINUOUS_DNSMASQ_UNTRUSTED_BINARY")
    body = (
        """[Unit]
Description=SOC bounded local-only dnsmasq DNS test source
[Service]
Type=exec
User=1000
Group=1000
NetworkNamespacePath=/run/netns/soc-native-b3
ExecStart="""
        + " ".join(arguments())
        + """
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX
MemoryMax=67108864
CPUQuota=10%
TasksMax=8
LimitNOFILE=64
LimitCORE=0
RuntimeMaxSec=90s
TimeoutStartSec=5s
TimeoutStopSec=5s
KillMode=control-group
Restart=no
UMask=0077
"""
    )
    return dict(
        contract="soc-dnsmasq-local-test-source:v1",
        unit=UNIT,
        target="/etc/systemd/system/" + UNIT,
        body=body,
        unit_sha256=hashlib.sha256(body.encode()).hexdigest(),
        binary=str(binary),
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        endpoint="127.0.0.53:53",
        upstream_servers=[],
        host_configuration=False,
        uid=1000,
        gid=1000,
        capability="CAP_NET_BIND_SERVICE_ONLY",
        server_implemented_by="dnsmasq",
        activation="EXACT_ROOT_R1_R2_REVIEW_REQUIRED",
    )


def validate_response(query, response):
    """Fixed A record validation, allowing the upstream server's legitimate flags."""
    if len(response) != len(query) + 16:
        raise ValueError("CONTINUOUS_DNSMASQ_RESPONSE_LENGTH")
    transaction, flags, qd, an, ns, ar = struct.unpack("!6H", response[:12])
    if (
        response[:2] != query[:2]
        or flags not in (0x8580, 0x8500)
        or (qd, an, ns, ar) != (1, 1, 0, 0)
        or response[12 : len(query)] != QUESTION
        or response[len(query) :] != struct.pack("!HHHIH4s", 0xC00C, 1, 1, 0, 4, b"\x7f\0\0\1")
    ):
        raise ValueError("CONTINUOUS_DNSMASQ_RESPONSE_BINDING")
    return transaction


def dnsmasq_client(scope, *, ready, local_test=False):
    """Exactly UDP2/TCP1; no resolver, retry, alternative endpoint or raw capture."""
    from soc_agent.security_ai.ebpf_tc.isolated_dns_worker import _exact

    expected_namespace = scope.namespace
    if os.geteuid() != 1000 or os.readlink("/proc/self/ns/net") != expected_namespace:
        raise ValueError("CONTINUOUS_DNSMASQ_CLIENT_IDENTITY")
    if not local_test and expected_namespace != "net:[4026532232]":
        raise ValueError("CONTINUOUS_DNSMASQ_TARGET_REQUIRED")
    if local_test and expected_namespace != "net:[4026531833]":
        raise ValueError("CONTINUOUS_DNSMASQ_TEST_HOST_REQUIRED")
    endpoint = ("127.0.0.1", 1053) if local_test else ("127.0.0.53", 53)
    opened = time.monotonic_ns()
    deadline = time.monotonic() + 60
    exchanges = []
    tcp_closed = None
    option = getattr(socket, "SO_NETNS_COOKIE", 71)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        cookie = probe.getsockopt(socket.SOL_SOCKET, option, 8)
    ready(dict(state="LOCAL_DNS_READY", namespace=expected_namespace, cookie=cookie.hex()))
    for transaction, transport in ((0xC201, "UDP"), (0xC202, "TCP"), (0xC203, "UDP")):
        if transaction == 0xC203:
            remaining = (tcp_closed + 35_000_000_000 - time.monotonic_ns()) / 1e9
            if remaining > 0:
                time.sleep(remaining)
            if time.monotonic_ns() < tcp_closed + 35_000_000_000:
                raise ValueError("CONTINUOUS_DNSMASQ_OBSERVATION_CLOCK")
        query = struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + QUESTION
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM if transport == "TCP" else socket.SOCK_DGRAM
        ) as channel:
            channel.settimeout(min(2, max(0.001, deadline - time.monotonic())))
            channel.bind(("127.0.0.1", 0))
            if channel.getsockopt(socket.SOL_SOCKET, option, 8) != cookie:
                raise ValueError("CONTINUOUS_DNSMASQ_CLIENT_COOKIE")
            sent = time.monotonic_ns()
            if transport == "TCP":
                channel.connect(endpoint)
                channel.sendall(struct.pack("!H", len(query)) + query)
                header = _exact(channel, 2, deadline)
                size = int.from_bytes(header, "big")
                if not 12 <= size <= 512:
                    raise ValueError("CONTINUOUS_DNSMASQ_TCP_BOUND")
                response = _exact(channel, size, deadline)
            else:
                if channel.sendto(query, endpoint) != len(query):
                    raise ValueError("CONTINUOUS_DNSMASQ_PARTIAL_QUERY")
                response, peer = channel.recvfrom(513)
                if peer != endpoint:
                    raise ValueError("CONTINUOUS_DNSMASQ_RESPONSE_PEER")
            validate_response(query, response)
            received = time.monotonic_ns()
        if transport == "TCP":
            tcp_closed = time.monotonic_ns()
        exchanges.append(
            dict(
                transport=transport,
                transaction_id=transaction,
                sent_ns=sent,
                response_ns=received,
                query_sha256=hashlib.sha256(query).hexdigest(),
                response_sha256=hashlib.sha256(response).hexdigest(),
                response_code=0,
            )
        )
    remaining = (opened + 45_000_000_000 - time.monotonic_ns()) / 1e9
    if remaining > 0:
        time.sleep(remaining)
    return dict(
        state="DNS_DIAGNOSTIC_COMPLETED",
        exchanges=exchanges,
        client_fds_closed=True,
        client_tcp_closed_ns=tcp_closed,
        application_elapsed_ns=time.monotonic_ns() - opened,
        namespace=expected_namespace,
        socket_cookie=cookie.hex(),
        server="dnsmasq",
        evidence_scope="APPLICATION_PROTOCOL_ONLY_NOT_KERNEL_CAPTURE",
        native_capture=False,
    )


def _definitions(module, names):
    return "\n\n".join(
        ast.unparse(n)
        for n in ast.parse(Path(module.__file__).read_text()).body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names
    )


def source(config: dict) -> bytes:
    if (
        set(config) != {"uid", "gid", "namespace", "namespace_device", "namespace_inode", "boot_id"}
        or config["uid"] != 1000
        or config["gid"] != 1000
        or config["namespace"] != "net:[4026532232]"
        or config["namespace_inode"] != 4026532232
        or type(config["namespace_device"]) is not int
        or config["namespace_device"] < 1
        or not re.fullmatch(r"[a-f0-9-]{36}", config["boot_id"])
    ):
        raise ValueError("CONTINUOUS_DNS_TRIAL_FIXED_SCOPE_REQUIRED")
    body = (
        "import os,socket,struct,time,hashlib,ctypes,json,resource,select,signal\n"
        "from pathlib import Path\nfrom types import SimpleNamespace\n"
    )
    body += "QUESTION=" + repr(QUESTION) + "\nDNS_CONFIG=" + repr(config) + "\n"
    body += (
        _definitions(
            isolated_dns_engine,
            {
                "local_controller",
                "_prctl",
                "_drop_credentials",
                "enter_namespace",
                "DNSChild",
                "spawn_dns_child",
            },
        )
        + "\n"
    )
    body += _definitions(isolated_dns_worker, {"_exact"}) + "\n"
    tree = ast.parse(Path(__file__).read_text())
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name in {"validate_response", "dnsmasq_client"}:
            n.body = [s for s in n.body if not isinstance(s, ast.ImportFrom)]
            body += ast.unparse(n) + "\n"
    body += _CHILD + _COORDINATOR
    compile(body, "<reviewed-dnsmasq-client>", "exec")
    return body.encode()


_CHILD = """
def dns_child(config, ready, worker):
    if os.geteuid()!=0: raise ValueError("DNS_CHILD_REQUIRES_AUTHENTICATED_ROOT_SUPERVISOR")
    parent=os.getppid()
    _prctl(1,signal.SIGKILL)
    if os.getppid()!=parent: raise ValueError("DNS_SUPERVISOR_DISAPPEARED")
    resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
    resource.setrlimit(resource.RLIMIT_CPU,(20,20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.alarm(65)
    try:
        enter_namespace(config) # No port bind: dnsmasq owns the reviewed listeners.
        _drop_credentials(config["uid"],config["gid"],parent)
        return worker(SimpleNamespace(namespace=config["namespace"]),ready=ready)
    finally: signal.alarm(0)
"""

_COORDINATOR = """
class BoundedDNSProbe:
    def __init__(self):
        self.child=None
        self.started=self.ready=self.completed=False
        self.events=[]
    def start(self):
        if self.started: raise ValueError("CONTINUOUS_DNS_TRIAL_REPLAY")
        self.started=True
        self.child=spawn_dns_child(DNS_CONFIG,dnsmasq_client)
    def poll(self):
        if self.child is None or self.completed: return
        if time.monotonic()>=self.child.deadline:
            raise TimeoutError("CONTINUOUS_DNS_TRIAL_DEADLINE")
        if not select.select([self.child.channel],[],[],0)[0]: return
        value=self.child.receive()
        self.events.append(value)
        if value["state"]=="LOCAL_DNS_READY":
            if self.ready or value["namespace"]!=DNS_CONFIG["namespace"]:
                raise ValueError("CONTINUOUS_DNS_TRIAL_READY_BINDING")
            self.ready=True
        elif value["state"]=="DNS_DIAGNOSTIC_COMPLETED":
            if (not self.ready
                or [x["transport"] for x in value.get("exchanges",[])]!=["UDP","TCP","UDP"]
                or value.get("client_fds_closed") is not True):
                raise ValueError("CONTINUOUS_DNS_TRIAL_RESULT_BINDING")
            code=self.child.finish()
            if code!=0: raise ValueError("CONTINUOUS_DNS_TRIAL_CHILD_EXIT:"+str(code))
            self.completed=True
        else: raise ValueError("CONTINUOUS_DNS_TRIAL_CHILD_FAILED:"+str(value))
    def close(self):
        return dict(started=self.started,completed=self.completed,
                    child_exit=self.child.close() if self.child else None,events=self.events)
if __name__=="__main__":
    raise SystemExit("EXACT_ROOT_R1_R2_AND_NATIVE_APPROVAL_REQUIRED")
"""
