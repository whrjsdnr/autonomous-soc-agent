"""Existing-CLI DNS-only preparation/admission. No implicit policy or Root grant."""

import ast
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, local_controller
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import canonical, verify_package
from soc_agent.security_ai.ebpf_tc.isolated_dns_launcher import (
    inspect_lease,
    launcher_scope,
    service_source,
)
from soc_agent.security_ai.ebpf_tc.phase_d import runtime_bundle
from soc_agent.security_ai.ebpf_tc.reassessment import digest, held_json
from soc_agent.security_ai.ebpf_tc.root_operations import (
    RootBinding,
    RootOperations,
    implementation_sha,
)
from soc_agent.security_ai.ebpf_tc.runtime_recovery import host_identity
from soc_agent.security_ai.ebpf_tc.source_guard import SourceGuard


def prepare(
    output: Path,
    *,
    package: Path,
    root_manifest: str,
    origin: RootBinding,
    lease_file: Path,
    lease_sha: str,
    source_snapshot: str,
    plan: ApplicationPlan,
) -> dict:
    """Build the service and its metadata in one source/dependency observation window."""
    with SourceGuard(Path(__file__).parents[2]):
        before = host_identity()
        result = _prepare(
            output,
            package=package,
            root_manifest=root_manifest,
            origin=origin,
            lease_file=lease_file,
            lease_sha=lease_sha,
            source_snapshot=source_snapshot,
            plan=plan,
        )
        if host_identity() != before:
            raise ValueError("DNS_DEPENDENCIES_CHANGED_DURING_BUILD")
        return result


def _prepare(
    output: Path,
    *,
    package: Path,
    root_manifest: str,
    origin: RootBinding,
    lease_file: Path,
    lease_sha: str,
    source_snapshot: str,
    plan: ApplicationPlan,
) -> dict:
    controller = local_controller()
    lease = inspect_lease(lease_file, lease_sha, origin)
    release = verify_package(package, root_manifest)
    if plan.controller.uid != controller.uid or plan.scope.net_namespace != lease["namespace"]:
        raise ValueError("DNS_PREPARATION_PLAN_BINDING")
    if plan.scope.interface != "lo" or plan.scope.ifindex != 1 or plan.scope.hook != "INGRESS":
        raise ValueError("DNS_PREPARATION_PLAN_SCOPE")
    scope = launcher_scope(origin, lease, lease_sha) | dict(
        contract="SOC_NAMESPACE_DNS_DIAGNOSTIC_V1",
        session=str(plan.application_session),
        root_manifest=root_manifest,
        normal_stop_seconds=45,
        source_snapshot=source_snapshot,
        root_claim="/run/soc-agent-dns-<approval_sha256>.claimed",
        root_claim_retained_for_replay_protection=True,
        activation="EXACT_POLICY_AND_ROOT_DNS_EXECUTION_RECEIPTS_REQUIRED",
        native=False,
        install=False,
        password_policy="EXISTING_SEALED_BOOTSTRAP_UNIFIED_POLICY_CHECK_ONLY",
    )
    dependencies = [dict(path=d.path, sha256=d.sha256) for d in release.dependencies]
    for name in ("/usr/bin/python3", "/usr/bin/sudo"):
        path = Path(name).resolve(strict=True)
        dependencies.append(
            dict(path=str(path), sha256=hashlib.sha256(read_held(path, owner=0)).hexdigest())
        )
    config = scope | dict(
        scope=scope,
        uid=controller.uid,
        gid=os.getgid(),
        dependencies=dependencies,
        implementation_sha=implementation_sha(),
        release=release.version,
        password_policy_bootstrap_sha=release.payloads["bootstrap"].sha256,
    )
    # Reuse the fixed worker and sudo-parent validator, without Root project imports.
    from soc_agent.security_ai.ebpf_tc import unified_image_engine

    parent_tree = ast.parse(Path(unified_image_engine.__file__).read_text())
    validators = [
        n
        for n in parent_tree.body
        if isinstance(n, ast.FunctionDef)
        and n.name in {"_sudo_parent", "_safe_environment", "_candidate_policy"}
    ]
    policy_payload = dict(
        files=dict(
            bootstrap=dict(
                body=base64.b64encode(read_held(package / "bootstrap", owner=os.getuid())).decode(),
                sha256=release.payloads["bootstrap"].sha256,
            )
        )
    )
    tree = ast.parse(Path(__file__).with_name("dns_diagnostic_engine.py").read_text())
    tree.body = [
        n
        for n in tree.body
        if not (isinstance(n, ast.ImportFrom) and (n.module or "").startswith("soc_agent"))
    ]
    source = (
        service_source(config)
        + (
            "\nimport base64,fcntl,hashlib\n"
            + "\n".join(ast.unparse(n) for n in validators)
            + "\n"
            + ast.unparse(tree)
            + "\nDNS_POLICY_IMAGE = "
            + repr(policy_payload)
            + "\n"
            + "\nif __name__ == '__main__':\n"
            + "    try:\n        dns_root_main(DNS_CONFIG)\n"
            + "    except Exception as exc:\n"
            + "        value = dict(state='DNS_ROOT_FAILED', error_class=type(exc).__name__)\n"
            + "        value['error'] = str(exc)\n"
            + "        print(json.dumps(value), flush=True)\n"
            + "        raise SystemExit(1)\n"
        ).encode()
    )
    compile(source, "<sha-approved-dns-diagnostic>", "exec")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    fd = os.open(output / "dns-diagnostic.py", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(source)
        stream.flush()
        os.fsync(stream.fileno())
    metadata = dict(
        contract="SOC_ROOT_DNS_DIAGNOSTIC_IMAGE_V1",
        config=config,
        image_sha256=hashlib.sha256(source).hexdigest(),
        runtime_sources=runtime_bundle(),
        bundle=digest(runtime_bundle()),
    )
    (output / "dns-diagnostic.json").write_bytes(canonical(metadata))
    return dict(
        status="BUILT_REQUIRES_POLICY_ALLOCATION_AND_EXECUTION_APPROVAL",
        manifest=hashlib.sha256(canonical(metadata)).hexdigest(),
        image=metadata["image_sha256"],
        bundle=metadata["bundle"],
        root_manifest=root_manifest,
        scope=scope,
        executed=False,
    )


def verify(directory: Path, binding: RootBinding) -> dict:
    value = held_json(directory / "dns-diagnostic.json", binding.artifact.manifest)
    config = value["config"]
    body = read_held(directory / "dns-diagnostic.py", owner=os.getuid(), limit=1048576)
    if (
        value["contract"] != "SOC_ROOT_DNS_DIAGNOSTIC_IMAGE_V1"
        or value["runtime_sources"] != runtime_bundle()
        or value["bundle"] != digest(runtime_bundle())
        or value["bundle"] != binding.artifact.bundle
        or hashlib.sha256(body).hexdigest() != binding.artifact.image
        or value["image_sha256"] != binding.artifact.image
        or (directory / "dns-diagnostic.py").stat().st_mode & 0o777 != 0o400
        or config["session"] != binding.session
        or config["scope"]["session"] != binding.session
        or config["source_snapshot"] != binding.source_snapshot
        or config["root_manifest"] != binding.artifact.root_manifest
        or digest(config["scope"]) != binding.scope_sha
        or config["uid"] != os.getuid()
        or config["gid"] != os.getgid()
    ):
        raise ValueError("DNS_DIAGNOSTIC_IMAGE_BINDING")
    return value


def command(directory: Path, binding: RootBinding, envelope: dict) -> tuple[str, ...]:
    verify(directory, binding)
    uid = os.getuid()
    image = str((directory / "dns-diagnostic.py").absolute())
    arguments = ["soc-isolated-dns", json.dumps(envelope, sort_keys=True, separators=(",", ":"))]
    script = (
        "import os,stat,hashlib,sys;"
        f"f=os.open({image!r},os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(f);"
        f"assert stat.S_ISREG(s.st_mode) and s.st_uid=={uid} and s.st_nlink==1;"
        "assert stat.S_IMODE(s.st_mode)==256 and 0<s.st_size<=1048576;"
        "b=os.pread(f,s.st_size+1,0);os.close(f);"
        f"assert hashlib.sha256(b).hexdigest()=={binding.artifact.image!r};"
        f"sys.argv={arguments!r};exec(compile(b,'<sha-approved-dns-diagnostic>','exec'))"
    )
    if len(script.encode()) > 12000:
        raise ValueError("DNS_COMMAND_BOUND")
    return ("/usr/bin/sudo", "-k", "-u", "root", "--", "/usr/bin/python3", "-I", "-S", "-c", script)


def run_packet(mode: str, directory: Path, packet: dict) -> dict:
    """Administrative packet is never an approval; execution revalidates all pins."""
    local_controller()
    if mode == "prepare":
        if packet.get("kind") != "ROOT_DNS_PREPARATION_V1":
            raise ValueError("DNS_PREPARATION_PACKET")
        return prepare(
            directory,
            package=Path(packet["package"]),
            root_manifest=packet["root_manifest"],
            origin=RootBinding.model_validate(packet["origin"]),
            lease_file=Path(packet["lease_file"]),
            lease_sha=packet["lease_sha"],
            source_snapshot=packet["source_snapshot"],
            plan=ApplicationPlan.model_validate(packet["plan"]),
        )
    if mode not in ("check", "execute") or packet.get("kind") != "ROOT_DNS_EXECUTION_V1":
        raise ValueError("DNS_EXECUTION_PACKET")
    binding = RootBinding.model_validate(packet["binding"])
    from soc_agent.security_ai.ebpf_tc.operational_recovery import source_git_identity

    if source_git_identity() != (binding.artifact.git_commit, binding.artifact.git_tree):
        raise ValueError("DNS_SOURCE_GIT_BINDING")
    campaign = RootOperations(Path(packet["campaign"]), "BATCH3")
    fields = dict(
        policy_file=Path(packet["policy_file"]),
        policy_sha=packet["policy_sha"],
        approval_file=Path(packet["approval_file"]),
        approval_sha=packet["approval_sha"],
        root_manifest_file=Path(packet["root_manifest_file"]),
        dns_directory=directory,
        dns_lease_file=Path(packet["lease_file"]),
    )
    checked = campaign.check_root(binding, **fields)
    if checked["proposal"]["operation"] != "ROOT_DNS_DIAGNOSTIC":
        raise ValueError("DNS_OPERATION_REQUIRED")
    if mode == "check":
        return checked
    policy = held_json(fields["policy_file"], fields["policy_sha"])
    if any(label in policy["approver"].upper() for label in ("FIXTURE", "MOCK")):
        raise ValueError("DNS_FIXTURE_EXECUTION_FORBIDDEN")
    if (
        not sys.stdin.isatty()
        or not sys.stdout.isatty()
        or os.fstat(sys.stdin.fileno()).st_uid != os.getuid()
        or os.ttyname(sys.stdin.fileno()) != os.ttyname(sys.stdout.fileno())
    ):
        raise ValueError("DNS_DIRECT_OWNER_TERMINAL_REQUIRED")
    tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        if os.tcgetpgrp(tty) != os.getpgrp():
            raise ValueError("DNS_FOREGROUND_TERMINAL_REQUIRED")
        print(
            json.dumps(
                dict(
                    purpose="DNS ONLY; no install/Native",
                    artifact=binding.model_dump(),
                    scope=checked["proposal"]["scope"],
                    root_cost=1,
                    native_cost=0,
                ),
                indent=2,
            )
        )
        try:
            answer = input("Approve exactly this Scope? Type yes; otherwise cancel: ")
        except (EOFError, KeyboardInterrupt):
            answer = "no"
        if answer.strip().lower() != "yes":
            return dict(status="CANCELLED_BEFORE_RESERVATION", reserved=False, executed=False)
        if source_git_identity() != (binding.artifact.git_commit, binding.artifact.git_tree):
            raise ValueError("DNS_SOURCE_GIT_BINDING")
        campaign.check_root(binding, **fields)
        event = campaign.reserve_root(binding, **fields)
        attempt = event["attempt_id"]

        def evidence(value):
            body = canonical(value)
            pin = hashlib.sha256(body).hexdigest()
            report = directory / ("result-" + attempt + "-" + pin + ".json")
            fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            return pin

        campaign.record_root(
            attempt,
            state="START_INTENT",
            evidence_sha=evidence(dict(state="OS_AUTHENTICATION_INTENT", executed="UNKNOWN")),
        )
        envelope = {k: str(fields[k]) for k in ("policy_file", "approval_file")}
        envelope.update(
            policy_sha=packet["policy_sha"],
            approval_sha=packet["approval_sha"],
            manifest_file=str(directory / "dns-diagnostic.json"),
            manifest_sha=binding.artifact.manifest,
            image_sha=binding.artifact.image,
            ledger_file=str(campaign.directory / "execution-ledger.jsonl"),
            ledger_sha=hashlib.sha256(
                (campaign.directory / "execution-ledger.jsonl").read_bytes()
            ).hexdigest(),
        )
        started = False
        try:
            result = subprocess.run(
                command(directory, binding, envelope),
                stdin=tty,
                stderr=tty,
                stdout=subprocess.PIPE,
                timeout=240,
                check=False,
                close_fds=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "TERM": os.environ.get("TERM", "xterm")},
            )
            if len(result.stdout) > 65536:
                raise ValueError("DNS_RESULT_BOUND")
            messages = [json.loads(line) for line in result.stdout.splitlines()]
            started = any(m.get("state") == "DNS_ROOT_AUTHENTICATED" for m in messages)
            if started:
                campaign.record_root(
                    attempt, state="STARTED", evidence_sha=evidence(dict(messages=messages))
                )
            success = (
                started
                and result.returncode == 0
                and any(m.get("state") == "DNS_DIAGNOSTIC_COMPLETED" for m in messages)
            )
            value = dict(
                status="SUCCEEDED" if success else "FAILED" if started else "UNKNOWN",
                returncode=result.returncode,
                messages=messages,
                native=False,
                no_retry=True,
                first_failure=next(
                    (
                        m
                        for m in messages
                        if m.get("state") in ("DNS_ROOT_FAILED", "DNS_CHILD_FAILED")
                    ),
                    None,
                ),
            )
            campaign.record_root(attempt, state=value["status"], evidence_sha=evidence(value))
            return value
        except (OSError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            campaign.record_root(
                attempt,
                state="FAILED" if started else "UNKNOWN",
                evidence_sha=evidence(
                    dict(error_class=type(exc).__name__, error=str(exc), no_retry=True)
                ),
            )
            raise
    finally:
        os.close(tty)
