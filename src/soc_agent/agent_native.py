"""Read-only composition of the existing bounded Native review and installation contract.

No issuer, reservation, setns, service control, authentication or model permission.
The registered terminal remains the sole privileged lifecycle entry point.
"""

import ast
import hashlib
import json
import os
from pathlib import Path

from soc_agent.continuous.models import ContinuousConfig
from soc_agent.security_ai.ebpf_tc.namespace_isolation import HOST_NAMESPACE, IsolatedScope
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest

ROOT_TARGETS = frozenset(
    {
        "/etc/systemd/system/soc-continuous-collector.service.d/trial-limit.conf",
        "/etc/systemd/system/soc-continuous-tcp-trial.service",
        "/etc/soc-agent/continuous-installation.json",
        "/etc/systemd/system/soc-operations-runtime.service",
        "/etc/systemd/system/soc-continuous-dns.service",
        "/etc/systemd/system/soc-continuous-dnsmasq.service",
        "/usr/lib/soc-agent/continuous/service.py",
        "/etc/systemd/system/soc-continuous-dns.service.d/trial-deadline.conf",
    }
)


def _installation_assertion() -> ast.Assert:
    return ast.parse(
        "assert len(rows) == 8 and {r['target'] for r in rows} == "
        "set(INSTALL_FIXED_TARGETS) and "
        "{r['target'] for r in rows if r['current_sha256'] != r['new_sha256'] "
        "or r.get('repair_mode', False)} == set(INSTALL_WRITE_TARGETS), "
        "'FIXED_INSTALLATION_WRITE_SCOPE'"
    ).body[0]


def bind_installation_scope(template: str, rows: list[dict]) -> str:
    """Prepare a NEW Launcher artifact, never rewrite an approved/executed review.

    The caller must publish new file pins and obtain its own human approval.
    This pure source transformation issues no approval and performs no execution.
    """
    declared = tuple(
        sorted(
            r["target"]
            for r in rows
            if r["current_sha256"] != r["new_sha256"] or r.get("repair_mode", False)
        )
    )
    installation_write_scope(rows, declared)
    tree = ast.parse(template)
    installers = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "install"]
    if len(installers) != 1:
        raise ValueError("AGENT_NATIVE_INSTALLER_FUNCTION_REQUIRED")
    found = 0
    for index, node in enumerate(installers[0].body):
        if (
            isinstance(node, ast.Assert)
            and isinstance(node.msg, ast.Constant)
            and node.msg.value == "FIXED_INSTALLATION_WRITE_SCOPE"
        ):
            installers[0].body[index] = _installation_assertion()
            found += 1
    if found != 1:
        raise ValueError("AGENT_NATIVE_INSTALLER_SCOPE_ASSERTION_REQUIRED")
    names = {"INSTALL_FIXED_TARGETS", "INSTALL_WRITE_TARGETS"}
    tree.body = [
        n
        for n in tree.body
        if not (
            isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id in names for t in n.targets)
        )
    ]
    declarations = ast.parse(
        f"INSTALL_FIXED_TARGETS = {tuple(sorted(ROOT_TARGETS))!r}\n"
        f"INSTALL_WRITE_TARGETS = {declared!r}\n"
    ).body
    insertion = 0
    while insertion < len(tree.body) and (
        isinstance(tree.body[insertion], (ast.Import, ast.ImportFrom))
        or (
            isinstance(tree.body[insertion], ast.Expr)
            and isinstance(tree.body[insertion].value, ast.Constant)
            and isinstance(tree.body[insertion].value.value, str)
        )
    ):
        insertion += 1
    tree.body[insertion:insertion] = declarations
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def installation_write_scope(rows: list[dict], declared: tuple[str, ...]) -> tuple[str, ...]:
    """Compare exact paths, not a stale count copied from an earlier installation."""
    if not isinstance(rows, list) or any(
        not isinstance(row, dict)
        or not {"target", "current_sha256", "new_sha256"} <= row.keys()
        or not all(isinstance(row[k], str) for k in ("target", "current_sha256", "new_sha256"))
        or type(row.get("repair_mode", False)) is not bool
        for row in rows
    ):
        raise ValueError("AGENT_NATIVE_INSTALLATION_SCOPE_SCHEMA")
    targets = [row["target"] for row in rows]
    changed = tuple(
        sorted(
            row["target"]
            for row in rows
            if row["current_sha256"] != row["new_sha256"] or row.get("repair_mode", False)
        )
    )
    if (
        len(targets) != len(ROOT_TARGETS)
        or set(targets) != ROOT_TARGETS
        or len(set(declared)) != len(declared)
        or changed != tuple(sorted(declared))
    ):
        raise ValueError("AGENT_NATIVE_INSTALLATION_WRITE_SCOPE_MISMATCH")
    return changed


def installation_plan(review: Path, request: dict) -> dict:
    """Read-only manifest/Launcher agreement; never execute the Root Python to preview it."""
    manifest_path = review / "root-install-manifest-v3.json"
    binding = request["files"].get(manifest_path.name)
    if not binding or binding["path"] != str(manifest_path):
        raise ValueError("AGENT_NATIVE_INSTALLATION_MANIFEST_REQUIRED")
    manifest = json.loads(read_local(manifest_path, 131072))
    tree = ast.parse(read_local(review / "execution/root-trial.py", 131072))
    declarations = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "INSTALL_WRITE_TARGETS" for t in node.targets)
    ]
    if len(declarations) != 1:
        raise ValueError("AGENT_NATIVE_INSTALLER_WRITE_DECLARATION_REQUIRED")
    declared = ast.literal_eval(declarations[0])
    if not isinstance(declared, tuple) or not all(isinstance(p, str) for p in declared):
        raise ValueError("AGENT_NATIVE_INSTALLER_WRITE_DECLARATION_INVALID")
    rows = manifest["replacements"]
    changed = installation_write_scope(rows, declared)
    installers = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "install"]
    if len(installers) != 1 or not any(
        ast.dump(node) == ast.dump(_installation_assertion()) for node in installers[0].body
    ):
        raise ValueError("AGENT_NATIVE_INSTALLER_SCOPE_ASSERTION_MISMATCH")
    fixed = [
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "INSTALL_FIXED_TARGETS" for t in node.targets)
    ]
    if len(fixed) != 1 or tuple(sorted(ROOT_TARGETS)) != fixed[0]:
        raise ValueError("AGENT_NATIVE_INSTALLER_FIXED_TARGETS_MISMATCH")
    for row in rows:
        source = Path(row["new_source"])
        if hashlib.sha256(read_local(source, 2 * 1024**2)).hexdigest() != row["new_sha256"]:
            raise ValueError("AGENT_NATIVE_INSTALLATION_SOURCE_CHANGED")
        target = Path(row["target"])
        if row.get("current_state") == "ABSENT":
            if target.exists() or target.is_symlink():
                raise ValueError("AGENT_NATIVE_INSTALLATION_TARGET_CHANGED")
        elif (
            target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != row["current_sha256"]
        ):
            raise ValueError("AGENT_NATIVE_INSTALLATION_TARGET_CHANGED")
    return dict(
        status="VERIFIED_READ_ONLY_NOT_INSTALLATION_AUTHORITY",
        fixed_paths=len(rows),
        write_targets=list(changed),
        unchanged_paths=len(rows) - len(changed),
        root_commands_executed=False,
    )


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
    installation = installation_plan(review, request)
    cfg = ContinuousConfig.model_validate_json(read_local(review / "runtime-config-v2.json", 32768))
    if cfg.managed_authentication:
        from soc_agent.approval.errors import ApprovalError
        from soc_agent.continuous.authentication_lifecycle import preflight as auth_preflight
        from soc_agent.execution.errors import ExecutionError

        try:
            auth_preflight(Store(selected.runtime))
        except (ApprovalError, ExecutionError) as error:
            raise ValueError("AUTHENTICATION_EXACT_HUMAN_APPROVAL_REQUIRED") from error

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
        installation=installation,
        runtime=str(selected.runtime),
        model_action="SEPARATE_EXACT_SEALED_WINDOW_APPROVAL_REQUIRED",
        capture_started=False,
        root_executed=False,
        reservations_created=False,
        automatic_retry=False,
    )
