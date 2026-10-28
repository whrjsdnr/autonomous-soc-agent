"""Build a fixed DNS child service for a future exact-SHA approved Supervisor.

No subprocess, sudo or traffic entry point. Setup approval cannot activate this
service. The generated review image is unconditionally blocked as a program;
the existing authenticated Supervisor must own future admission and accounting.
"""

import ast
import hashlib
import os
from pathlib import Path

from soc_agent.security_ai.ebpf_native.contracts import local_controller
from soc_agent.security_ai.ebpf_tc import isolated_dns_worker, namespace_isolation
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.reassessment import digest, held_json
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding


def inspect_lease(path: Path, pin: str, binding: RootBinding) -> dict:
    """Read only: hold the named nsfs mount while checking its creation lease."""
    local_controller()
    lease = held_json(path, pin)
    scope = namespace_isolation.IsolatedScope(namespace=lease["namespace"])
    if (
        lease.get("contract") != "SOC_NAMESPACE_CREATION_LEASE_V1"
        or lease.get("name") != scope.name
        or lease.get("session") != binding.session
        or lease.get("release") != binding.artifact.release
        or lease.get("deletion_authorized") is not False
        or lease.get("owner_uid") != 0
        or lease.get("lo_up_command_succeeded") is not True
        or lease.get("host_namespace") != namespace_isolation.HOST_NAMESPACE
        # Creation provenance is immutable. A caller can inspect the same held
        # lease before entry on its creator Host or after entry on its Target.
        # This read-only check never authorizes setns; admission checks Scope.
        or os.readlink("/proc/self/ns/net") not in (lease.get("host_namespace"), scope.namespace)
        or lease.get("boot_id") != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    ):
        raise ValueError("DNS_LAUNCHER_LEASE_BINDING")
    for name in ("creation_receipt_sha", "reservation"):
        if not isinstance(lease.get(name), str) or len(lease[name]) != 64:
            raise ValueError("DNS_LAUNCHER_CREATION_IDENTITY")
        bytes.fromhex(lease[name])
    if lease["reservation"] != lease["creation_receipt_sha"]:
        raise ValueError("DNS_LAUNCHER_CREATION_IDENTITY")
    fd = os.open("/run/netns/soc-native-b3", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino, st.st_uid) != (
            lease["dev"],
            lease["inode"],
            0,
        ) or scope.namespace != f"net:[{st.st_ino}]":
            raise ValueError("DNS_LAUNCHER_NAMESPACE_REPLACED")
    finally:
        os.close(fd)
    return lease


def launcher_scope(binding: RootBinding, lease: dict, lease_sha: str) -> dict:
    return dict(
        contract="SOC_ISOLATED_DNS_CHILD_SERVICE_V1",
        setup_binding=binding.model_dump(),
        lease_sha256=lease_sha,
        namespace=lease["namespace"],
        namespace_device=lease["dev"],
        namespace_inode=lease["inode"],
        boot_id=lease["boot_id"],
        namespace_path="/run/netns/soc-native-b3",
        endpoint=["127.0.0.53", 53],
        udp_queries=2,
        tcp_queries=1,
        minimum_late_udp_seconds=35,
        worker_deadline_seconds=60,
        sidecar_analysis_seconds=10,
        address_space_mib=256,
        cpu_seconds=20,
        no_external_interfaces=True,
        parent_namespace_unchanged=True,
        worker_uid="AUTHENTICATED_ORDINARY_CONTROLLER",
        worker_capabilities="ZERO_P_E_I_A_AND_BOUNDING",
        namespace_deletion=False,
        activation="SEPARATE_EXACT_IMAGE_LIFECYCLE_AND_TRAFFIC_APPROVAL_REQUIRED",
    )


def _definitions(module) -> str:
    tree = ast.parse(Path(module.__file__).read_text())
    return "\n\n".join(
        ast.unparse(node)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        and node.name in {"local_dns_response", "IsolatedDNSProtocol", "serve_prebound", "_exact"}
    )


def prepare_dns_launcher(
    lease_file: Path, lease_sha: str, binding: RootBinding, output: Path
) -> dict:
    """Deterministic isolated bytes. Never invokes the privileged service."""
    lease = inspect_lease(lease_file, lease_sha, binding)
    controller = local_controller()
    scope = launcher_scope(binding, lease, lease_sha)
    config = scope | dict(uid=controller.uid, gid=os.getgid())
    source = service_source(config) + (
        b"\nif __name__ == '__main__':\n"
        b"    raise SystemExit('ISOLATED_DNS_LIFECYCLE_APPROVAL_REQUIRED')\n"
    )
    compile(source, "<reviewed-isolated-dns-child>", "exec")
    # Exclusive output: never replace an approved image or existing installation.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(source)
        stream.flush()
        os.fsync(stream.fileno())
    if read_held(output, owner=os.getuid(), limit=1024**2) != source:
        raise ValueError("DNS_LAUNCHER_IMAGE_MUTATED")
    return dict(
        state="BUILT_NOT_AUTHORIZED",
        image_sha256=hashlib.sha256(source).hexdigest(),
        scope_sha256=digest(scope),
        scope=scope,
        lease_sha256=lease_sha,
        traffic_executed=False,
        native_executed=False,
    )


def service_source(config: dict) -> bytes:
    """Shared immutable service; builders choose a guarded or validated entry."""
    return (
        "from __future__ import annotations\n"
        "import os, socket, select, struct, time\n"
        "from types import SimpleNamespace as IsolatedScope\n"
        f"QUESTION = {namespace_isolation.QUESTION!r}\n"
        + _definitions(namespace_isolation)
        + "\n"
        + _definitions(isolated_dns_worker)
        + "\n"
        + Path(__file__).with_name("isolated_dns_engine.py").read_text()
        + "\nDNS_CONFIG = "
        + repr(config)
        + "\n"
    ).encode()
