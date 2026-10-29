"""Read-only composition of the existing bounded Native review and installation contract.

No issuer, reservation, setns, service control, authentication or model permission.
The registered terminal remains the sole privileged lifecycle entry point.
"""

import hashlib
import json
import os
from pathlib import Path

from soc_agent.continuous.models import ContinuousConfig
from soc_agent.security_ai.ebpf_tc.namespace_isolation import HOST_NAMESPACE, IsolatedScope
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def evidence_directory(review: Path) -> Path:
    for parent in review.parents:
        if parent.name == ".git" and parent.is_dir():
            return parent
    raise ValueError("AGENT_NATIVE_OFFICIAL_EVIDENCE_DIRECTORY_REQUIRED")


def ledger_snapshot(path: Path) -> dict:
    """Check the existing append-only wire format without opening its write API."""
    from soc_agent.security_ai.ebpf_tc.installation import canonical

    body = read_local(path, 1024**2)
    lines = body.splitlines(keepends=True)
    if not lines or not body.endswith(b"\n"):
        raise ValueError("AGENT_NATIVE_LEDGER_FRAMING")
    rows = [json.loads(line) for line in lines]
    for index, row in enumerate(rows[1:], 1):
        if (
            not isinstance(row, dict)
            or not {"sequence", "previous_record_sha256", "record_sha256"} <= row.keys()
        ):
            raise ValueError("AGENT_NATIVE_LEDGER_CHAIN_SCHEMA")
        if (
            row["sequence"] != index
            or row["previous_record_sha256"] != hashlib.sha256(lines[index - 1]).hexdigest()
            or row["record_sha256"]
            != hashlib.sha256(
                canonical({k: v for k, v in row.items() if k != "record_sha256"})
            ).hexdigest()
        ):
            raise ValueError("AGENT_NATIVE_LEDGER_CHAIN")
    return dict(rows=len(rows), sha256=hashlib.sha256(body).hexdigest(), chain="VERIFIED")


def namespace_binding(namespace: str, review: Path | None = None, request=None) -> dict:
    """Inspect a held existing mount; identity is not permission to enter it."""
    scope = IsolatedScope(namespace=namespace)
    path = Path("/run/netns") / scope.name
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        actual = os.readlink("/proc/self/ns/net")
        if info.st_uid != 0 or namespace != f"net:[{info.st_ino}]":
            raise ValueError("AGENT_NATIVE_NAMESPACE_REPLACED")
        if actual not in (HOST_NAMESPACE, namespace):
            raise ValueError("AGENT_NATIVE_UNAPPROVED_CURRENT_NAMESPACE")
        result = dict(
            target=namespace,
            current=actual,
            inode=info.st_ino,
            dev=info.st_dev,
            lease="NOT_BOUND_WITHOUT_REVIEW",
            entered=False,
            internal_check="REQUIRED_IN_APPROVED_TARGET"
            if actual != namespace
            else "CURRENT_TARGET",
        )
        if review is not None:
            lease_path = evidence_directory(review) / (
                "native-stabilization-batch3/approved-namespace-setup-20261027-1/namespace-lease.json"
            )
            body = read_local(lease_path, 65536)
            lease = json.loads(body)
            binding = request["namespace"]
            if (
                hashlib.sha256(body).hexdigest() != binding["lease_sha256"]
                or (info.st_dev, info.st_ino) != (binding["dev"], binding["inode"])
                or lease["contract"] != "SOC_NAMESPACE_CREATION_LEASE_V1"
                or lease["namespace"] != namespace
                or binding["target"] != namespace
                or lease["host_namespace"] != HOST_NAMESPACE
                or binding["host"] != HOST_NAMESPACE
                or lease["deletion_authorized"] is not False
                or lease["owner_uid"] != 0
                or lease["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                or (lease["dev"], lease["inode"]) != (info.st_dev, info.st_ino)
            ):
                raise ValueError("AGENT_NATIVE_LEASE_BINDING")
            result.update(
                lease="VERIFIED_CREATION_PROVENANCE_NOT_ENTRY_AUTHORITY", release=lease["release"]
            )
        return result
    finally:
        os.close(fd)


def validate_plan(selected) -> dict:
    """Automatic preflight of an existing review. Never execute its Python while checking."""
    from soc_agent.agent_runtime import verify_review
    from soc_agent.continuous.store import Store

    if selected.review is None:
        raise ValueError("AGENT_NATIVE_APPROVAL_REVIEW_REQUIRED_NO_ROOT_EXECUTION")
    review = selected.review
    request = verify_review(review, selected.review_sha256)
    cfg = ContinuousConfig.model_validate_json(read_local(review / "runtime-config-v2.json", 32768))
    if (
        cfg.source != "NATIVE_SERVICE"
        or cfg != selected.configuration
        or selected.runtime != review / "future-runtime"
        or selected.backend_code_identity != request["code_identity"]
    ):
        raise ValueError("AGENT_NATIVE_RUNTIME_REVIEW_BINDING")
    sources = json.loads(read_local(review / "source-files.json", 131072))
    controller = {
        name.removeprefix("src/soc_agent/"): pin
        for name, pin in sources.items()
        if name.startswith("src/soc_agent/") and name.endswith(".py")
    }
    if not controller or digest(controller) != selected.backend_code_identity:
        raise ValueError("AGENT_NATIVE_CONTROLLER_SOURCE_IDENTITY")
    current = ledger_snapshot(
        evidence_directory(review)
        / ("native-stabilization-batch1/execution-v1/execution-ledger.jsonl")
    )
    if any(current[key] != request["ledger"][key] for key in ("rows", "sha256")):
        raise ValueError("AGENT_NATIVE_STALE_LEDGER_REVIEW")
    namespace = namespace_binding(cfg.namespace, review, request)
    from soc_agent.continuous.dns_review import verify_review as verify_dns_review

    dns = verify_dns_review(cfg, review, request)
    if any(
        (review / "execution" / name).exists()
        for name in (
            "scope-confirmed.json",
            "root-execution-admitted.json",
            "terminal-cancelled.json",
            "root-terminal-exit.json",
            "terminal-exit.json",
        )
    ):
        raise ValueError("AGENT_NATIVE_ONE_SHOT_CONSUMED_FRESH_SCOPE_REQUIRED")
    if selected.runtime.exists():
        if (
            Store(selected.runtime).config != cfg
            or read_local(selected.runtime / "code-identity", 128).decode()
            != selected.backend_code_identity
        ):
            raise ValueError("AGENT_NATIVE_INITIALIZED_RUNTIME_CHANGED")
    return dict(
        status="PREVIEW_ONLY_REQUIRES_DIRECT_SCOPE_R1_AND_SUDO",
        artifact="VERIFIED_EXISTING_FROZEN_REVIEW_NOT_EXECUTION_AUTHORITY",
        namespace=namespace,
        dns=dns,
        ledger=current,
        runtime=str(selected.runtime),
        model_action="SEPARATE_EXACT_SEALED_WINDOW_APPROVAL_REQUIRED",
        capture_started=False,
        root_executed=False,
        reservations_created=False,
        automatic_retry=False,
    )
