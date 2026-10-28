"""Atomic, read-only-qualified request handoff; never issues approval or executes.

READY is a synchronization receipt, not authority. The Controller repeats the
ordinary Namespace check and admission, and execute retains Scope/sudo gates.
"""

import ctypes
import errno
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.execution_request import ExecutionRequest
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.reassessment import (
    Artifact,
    Binding,
    CleanupEvidence,
    digest,
    held_json,
)


def ledger_snapshot(campaign: Path) -> dict:
    from soc_agent.security_ai.ebpf_tc.dns_diagnostic_engine import dns_held_json_ledger

    path = campaign / "execution-ledger.jsonl"
    body = read_held(path, owner=os.getuid(), limit=1048576)
    pin = hashlib.sha256(body).hexdigest()
    rows = dns_held_json_ledger(str(path), pin, os.getuid())
    return dict(sha256=pin, head=rows[-1]["record_sha256"], rows=len(rows))


def atomic_publish(path: Path, body: bytes) -> None:
    """Publish complete bytes without replacing an existing request or READY."""
    fd, temporary = tempfile.mkstemp(prefix=".request-pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        # Linux renameat2(NOREPLACE) is atomic and keeps nlink=1. A hard-link
        # publication exposes nlink=2 briefly and the trusted reader rejects it.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise ValueError("EXECUTION_REQUEST_PUBLICATION_REPLAY")
            raise OSError(error, "EXECUTION_REQUEST_ATOMIC_PUBLICATION_FAILED")
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def ready_path(request_file: Path) -> Path:
    return request_file.with_suffix(".ready.json")


def validate_request(request: ExecutionRequest) -> dict:
    from soc_agent.security_ai.ebpf_tc.operational_recovery import readiness
    from soc_agent.security_ai.ebpf_tc.reassessment_admission import ReassessedCampaign

    arguments = request.arguments(Path(request.directory))
    arguments["image"] = arguments.pop("image_sha")
    before = ledger_snapshot(Path(request.campaign))
    result = readiness(Path(request.directory), **arguments, preparation_only=True)
    if result["status"] != "REQUEST_PREPARATION_VERIFIED":
        raise ValueError("EXECUTION_REQUEST_PREPARATION_" + result.get("error", "FAILED"))
    ledger = ReassessedCampaign(
        Path(request.campaign),
        amendment_file=Path(request.amendment_file),
        amendment_sha=request.amendment_sha,
    )
    binding = ledger.amendment.binding
    if before != ledger_snapshot(Path(request.campaign)):
        raise ValueError("EXECUTION_REQUEST_LEDGER_CHANGED")
    return dict(
        session=binding.next_session,
        release=binding.next_artifact.release,
        artifact=binding.next_artifact.model_dump(mode="json"),
        namespace=json.loads((Path(request.directory) / "phase-d.json").read_bytes())["scope"][
            "namespace"
        ],
        ledger=before,
        r1_binding=binding.model_dump(mode="json"),
        r1_record_sha=ledger.amendment.reassessment_record_sha,
    )


def publish_request(request_file: Path, request: ExecutionRequest) -> dict:
    started = time.time_ns()
    # Some development validators inspect the fixed request path, so publish
    # complete request bytes first; READY remains absent throughout validation.
    atomic_publish(request_file, canonical(request.model_dump(mode="json")))
    context = validate_request(request)
    body = read_held(request_file, owner=os.getuid(), limit=65536)
    if body != canonical(request.model_dump(mode="json")):
        raise ValueError("EXECUTION_REQUEST_CHANGED_DURING_PUBLICATION")
    pin = hashlib.sha256(body).hexdigest()
    if context["ledger"] != ledger_snapshot(Path(request.campaign)):
        raise ValueError("EXECUTION_REQUEST_LEDGER_CHANGED")
    ready = dict(
        contract="SOC_EXECUTION_REQUEST_READY_V1",
        request_sha=pin,
        preparation_started_ns=started,
        preparation_completed_ns=time.time_ns(),
        ready_published_ns=time.time_ns(),
        authorizes_execution=False,
        **context,
    )
    atomic_publish(ready_path(request_file), canonical(ready))
    return ready


def verify_ready(request_file: Path) -> dict:
    marker = ready_path(request_file)
    if not marker.exists():
        raise ValueError("EXECUTION_REQUEST_NOT_READY")
    try:
        ready = json.loads(read_held(marker, owner=os.getuid(), limit=65536))
    except json.JSONDecodeError as exc:
        raise ValueError("EXECUTION_REQUEST_READY_JSON") from exc
    if not isinstance(ready, dict):
        raise ValueError("EXECUTION_REQUEST_READY_CONTRACT")
    if (
        ready.get("contract") != "SOC_EXECUTION_REQUEST_READY_V1"
        or ready.get("authorizes_execution") is not False
    ):
        raise ValueError("EXECUTION_REQUEST_READY_CONTRACT")
    try:
        body = read_held(request_file, owner=os.getuid(), limit=65536)
    except FileNotFoundError as exc:
        raise ValueError("EXECUTION_REQUEST_MISSING_AFTER_READY") from exc
    if hashlib.sha256(body).hexdigest() != ready.get("request_sha"):
        raise ValueError("EXECUTION_REQUEST_READY_SHA")
    request = ExecutionRequest.model_validate_json(body)
    if ready.get("ledger") != ledger_snapshot(Path(request.campaign)):
        raise ValueError("EXECUTION_REQUEST_READY_STALE_LEDGER")
    context = validate_request(request)
    if any(ready.get(k) != v for k, v in context.items()):
        raise ValueError("EXECUTION_REQUEST_READY_BINDING")
    return ready


def wait_for_request(request_file: Path, *, timeout: float = 300) -> dict:
    if not 0 <= timeout <= 300:
        raise ValueError("EXECUTION_REQUEST_WAIT_BOUND")
    deadline = time.monotonic() + timeout
    while not ready_path(request_file).exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("EXECUTION_REQUEST_READY_TIMEOUT")
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    return verify_ready(request_file)


def prepare_r1(directory: Path, packet: dict) -> dict:
    """Derive only a pending review from verified history and current official plan."""
    from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan
    from soc_agent.security_ai.ebpf_tc.operational_recovery import source_git_identity
    from soc_agent.security_ai.ebpf_tc.phase_d import validate_preparation

    campaign = Path(packet["campaign"])
    snapshot = ledger_snapshot(campaign)
    ready = held_json(Path(packet["controller_ready_file"]), packet["controller_ready_sha"])
    if (
        ready.get("stage") != "REQUEST_INPUT"
        or ready.get("root_entry", {}).get("state") != "SUCCEEDED"
        or ready.get("ledger_at_ack") != snapshot
        or ready["root_entry"].get("record_sha256") != snapshot["head"]
    ):
        raise ValueError("R1_PREPARATION_SETTLEMENT_BINDING")
    prior = held_json(Path(packet["historical_evidence_file"]), packet["historical_evidence_sha"])
    old = Binding.model_validate(prior["binding"])
    evidence = CleanupEvidence.model_validate(prior["evidence"])
    if digest(evidence.model_dump()) != old.evidence_sha:
        raise ValueError("R1_PREPARATION_EVIDENCE_BINDING")
    for name, pin in evidence.sources.items():
        if (
            hashlib.sha256(
                read_held(Path(prior["source_paths"][name]), owner=os.getuid(), limit=1048576)
            ).hexdigest()
            != pin
        ):
            raise ValueError("R1_PREPARATION_EVIDENCE_SHA")
    plan = ApplicationPlan.model_validate(held_json(Path(packet["plan_file"]), packet["plan_sha"]))
    value = validate_preparation(directory, packet["manifest"], packet["image_sha"])
    scope = value["scope"]
    if (
        plan.mode != "PHASE_A_NATIVE_BLOCKED"
        or plan.scope.net_namespace != scope["namespace"]
        or ready.get("namespace") != scope["namespace"]
        or plan.scope.interface != scope["interface"]
        or plan.scope.hook != scope["hook"]
    ):
        raise ValueError("R1_PREPARATION_PLAN_SCOPE")
    git, tree = source_git_identity()
    artifact = Artifact(
        git_commit=git,
        git_tree=tree,
        release=value["version"],
        manifest=packet["manifest"],
        image=packet["image_sha"],
        bundle=value["bundle"],
        root_manifest=value["tcx_manifest"],
    )
    target = ready.get("artifact", {})
    if any(
        target.get(k) != v
        for k, v in dict(
            directory=str(directory),
            campaign=str(campaign),
            manifest=artifact.manifest,
            image_sha=artifact.image,
        ).items()
    ):
        raise ValueError("R1_PREPARATION_TARGET_BINDING")
    binding = old.model_copy(
        update=dict(
            next_session=str(plan.application_session),
            next_artifact=artifact,
            scope_sha=digest(scope),
        )
    )
    from soc_agent.security_ai.ebpf_tc.dns_diagnostic_engine import dns_held_json_ledger

    rows = dns_held_json_ledger(
        str(campaign / "execution-ledger.jsonl"), snapshot["sha256"], os.getuid()
    )
    if any(r.get("binding", {}).get("next_session") == binding.next_session for r in rows):
        raise ValueError("R1_PREPARATION_SESSION_REPLAY")
    if snapshot != ledger_snapshot(campaign):
        raise ValueError("R1_PREPARATION_STALE_LEDGER")
    return dict(
        decision="PENDING_EXPLICIT_HUMAN_RISK_ACCEPTANCE",
        binding=binding.model_dump(mode="json"),
        evidence=evidence.model_dump(mode="json"),
        source_paths=prior["source_paths"],
        preparation_ledger=snapshot,
        authorizes_execution=False,
    )
