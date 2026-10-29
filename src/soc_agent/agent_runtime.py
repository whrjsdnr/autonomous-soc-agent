"""User-facing composition of existing lifecycle APIs, never a new approval authority."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal

from soc_agent.continuous import cli as service
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.continuous.store import Store
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.research.environment import catalogue, read_local
from soc_agent.security_ai.research.models import Frozen, digest


class AgentProfile(Frozen):
    contract: Literal["soc-agent-application-profile:v1"] = "soc-agent-application-profile:v1"
    runtime: Path
    configuration: ContinuousConfig
    backend_code_identity: str
    review: Path | None = None
    review_sha256: str | None = None
    entry_sha256: str | None = None
    authentication_runtime: Path | None = None


def home_path(value: Path | None = None) -> Path:
    return (
        value or Path(os.environ.get("SOC_AGENT_HOME", Path.home() / ".local/state/soc-agent"))
    ).absolute()


def profile(home: Path) -> AgentProfile:
    doc = json.loads(read_local(home / "agent.json", 65536))
    if (
        not isinstance(doc, dict)
        or set(doc) != {"profile", "digest"}
        or digest(doc["profile"]) != doc["digest"]
    ):
        raise ValueError("AGENT_PROFILE_INTEGRITY")
    result = AgentProfile.model_validate(doc["profile"])
    if not result.runtime.is_absolute():
        raise ValueError("AGENT_RUNTIME_ABSOLUTE_PATH_REQUIRED")
    return result


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_review(directory: Path, expected: str | None = None) -> dict:
    """Integrity of an existing review, not approval of its commands or future actions."""
    request_path = directory / "approval-request-final-v2.json"
    request_bytes = read_local(request_path, 131072)
    if expected and hashlib.sha256(request_bytes).hexdigest() != expected:
        raise ValueError("AGENT_NATIVE_REVIEW_CHANGED")
    request = json.loads(request_bytes)
    if request.get("contract") != "soc-operations-approval-review-only:v1":
        raise ValueError("AGENT_NATIVE_REVIEW_CONTRACT")
    from datetime import UTC, datetime

    if datetime.fromisoformat(request["expires_at"]) <= datetime.now(UTC):
        raise ValueError("AGENT_NATIVE_REVIEW_EXPIRED")
    for row in request["files"].values():
        if sha(Path(row["path"])) != row["sha256"]:
            raise ValueError("AGENT_NATIVE_ARTIFACT_CHANGED")
    for name, pin in json.loads(read_local(directory / "source-files.json", 131072)).items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "src":
            raise ValueError("AGENT_NATIVE_SOURCE_PATH")
        if sha(directory / "export" / relative) != pin:
            raise ValueError("AGENT_NATIVE_SOURCE_CHANGED")
    pins = json.loads(read_local(directory / "execution/execution-pins.json", 65536))
    entry = directory / "execution/terminal.py"
    if pins.get(str(entry)) != sha(entry):
        raise ValueError("AGENT_NATIVE_ENTRY_INTEGRITY")
    for path, pin in pins.items():
        if sha(Path(path)) != pin:
            raise ValueError("AGENT_NATIVE_EXECUTION_INTEGRITY")
    return request


def setup(
    home: Path,
    *,
    replay: Path | None = None,
    config: Path | None = None,
    runtime: Path | None = None,
    review: Path | None = None,
    ml_root: Path | None = None,
    authentication_runtime: Path | None = None,
) -> dict:
    if (home / "agent.json").exists():
        raise ValueError("AGENT_ALREADY_CONFIGURED_USE_EXISTING_PROFILE")
    create_private_directory(home)
    if review:
        review = review.absolute()
        request = verify_review(review)
        cfg = ContinuousConfig.model_validate_json(
            read_local(review / "runtime-config-v2.json", 32768)
        )
        if cfg.source != "NATIVE_SERVICE":
            raise ValueError("AGENT_NATIVE_SOURCE_REQUIRED")
        result = AgentProfile(
            runtime=review / "future-runtime",
            configuration=cfg,
            backend_code_identity=request["code_identity"],
            review=review,
            review_sha256=sha(review / "approval-request-final-v2.json"),
            entry_sha256=sha(review / "execution/terminal.py"),
        )
    elif runtime and not replay and not config:
        store = Store(runtime.absolute())
        result = AgentProfile(
            runtime=runtime.absolute(),
            configuration=store.config,
            backend_code_identity=read_local(runtime.absolute() / "code-identity", 128).decode(),
        )
    else:
        root = (ml_root or Path(__file__).parents[3] / "ML").absolute()
        if config:
            cfg = ContinuousConfig.model_validate_json(read_local(config.absolute(), 32768))
        else:
            source = replay.absolute() if replay else root / catalogue()["raw_relative_path"]
            cfg = ContinuousConfig(
                source="PCAP_REPLAY"
                if source.suffix.lower() in {".pcap", ".pcapng"}
                else "JSONL_REPLAY",
                input_file=source,
                input_sha256=sha(source),
                ml_root=root,
            )
        if cfg.source == "NATIVE_SERVICE":
            raise ValueError("AGENT_NATIVE_REQUIRES_EXISTING_APPROVED_REVIEW_OR_ATTACH")
        directory = (runtime or home / "runtime").absolute()
        Store.create(directory, cfg)
        (directory / "code-identity").write_text(service.code_identity())
        (directory / "code-identity").chmod(0o600)
        result = AgentProfile(
            runtime=directory, configuration=cfg, backend_code_identity=service.code_identity()
        )
    if authentication_runtime:
        from soc_agent.linux_runtime.__main__ import status as auth_status

        target = authentication_runtime.absolute()
        auth_status(target)  # Existing schema/audit checks; never start host collection here.
        result = result.model_copy(update={"authentication_runtime": target})
    # Exclusive creation preserves older profiles. No Root installation or permission grant.
    payload = result.model_dump(mode="json")
    path = home / "agent.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(dict(profile=payload, digest=digest(payload)), stream)
        stream.flush()
        os.fsync(stream.fileno())
    return dict(
        status="CONFIGURED_NOT_STARTED",
        source=result.configuration.source,
        runtime=str(result.runtime),
        root_installed=False,
        native_authority="EXISTING_REVIEW_REQUIRES_DIRECT_SCOPE_R1_AND_SUDO"
        if review
        else "NOT_GRANTED",
    )


def status(home: Path) -> dict:
    selected = profile(home)
    if not selected.runtime.exists():
        return dict(
            state="NOT_INITIALIZED",
            source=selected.configuration.source,
            collector="NOT_STARTED",
            pending="EXACT_SCOPE_R1_AND_DIRECT_TERMINAL_AUTHENTICATION",
        )
    # Health mirrors avoid SQLite contention; they never authorize start or models.
    mirror = selected.runtime / "observation.json"
    if mirror.exists():
        record = json.loads(read_local(mirror, 262144))
        if record.get("configuration") != selected.configuration.model_dump(mode="json"):
            raise ValueError("AGENT_RUNTIME_CONFIGURATION_CHANGED")
    current = service.observed_status(selected.runtime)
    if current.get("source", selected.configuration.source) != selected.configuration.source:
        raise ValueError("AGENT_RUNTIME_SOURCE_CHANGED")
    return current | dict(
        runtime=str(selected.runtime),
        dns_collection="NOT_COLLECTED_IN_NATIVE_TCP_TRIAL"
        if selected.configuration.source == "NATIVE_SERVICE"
        else "INPUT_DEPENDENT",
        dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
    )


def doctor(home: Path) -> dict:
    from soc_agent.security_ai.dns9_contract import inspect_training

    selected = profile(home)
    checks = dict(
        python=sys.version.split()[0],
        gui_available=bool(os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")),
        source=selected.configuration.source,
        runtime=str(selected.runtime),
        model_action="EXACT_SEALED_NATIVE_JOB_APPROVAL_REQUIRED"
        if selected.configuration.source == "NATIVE_SERVICE"
        else "EXISTING_OFFLINE_READ_ONLY_POLICY",
        dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
        root_commands_executed=False,
    )
    if selected.review:
        verify_review(selected.review, selected.review_sha256)
        checks["artifact_integrity"] = "VERIFIED_EXISTING_REVIEW_NOT_EXECUTION_AUTHORITY"
        checks["native_scope"] = "ONE_SHOT_REVIEW_NOT_PERMANENT_SERVICE_AUTHORITY"
    elif sha(selected.configuration.input_file) != selected.configuration.input_sha256:
        raise ValueError("AGENT_INPUT_SHA_MISMATCH")
    else:
        checks["artifact_integrity"] = "INPUT_SHA_VERIFIED"
    if (
        selected.configuration.source != "NATIVE_SERVICE"
        and service.code_identity() != selected.backend_code_identity
    ):
        raise ValueError("AGENT_EXECUTABLE_INTEGRITY_CHANGED")
    if selected.configuration.ml_root:
        from soc_agent.security_ai.research.models import SPECS

        checks["models"] = {}
        for name, spec in SPECS.items():
            model = (
                selected.configuration.ml_root
                / "models/network-research-v1-final"
                / spec["directory"]
                / "model.joblib"
            )
            checks["models"][name] = (
                "VERIFIED_SHA"
                if model.exists() and sha(model) == spec["sha256"]
                else "UNAVAILABLE_OR_CHANGED"
            )
    checks["dns9_training_contract"] = inspect_training(selected.configuration.ml_root)
    return dict(status="PREFLIGHT_ONLY_NO_INFERENCE", checks=checks, runtime=status(home))


def start(home: Path) -> dict:
    selected = profile(home)
    with exclusive_runtime_lock(home / "application-start.lock"):
        doctor(home)
        current = status(home)
        if current.get("state") in {"RUNNING", "DEGRADED", "STOPPING"}:
            raise ValueError("AGENT_ALREADY_RUNNING")
        if selected.configuration.source == "NATIVE_SERVICE":
            if not selected.review:
                raise ValueError("AGENT_NATIVE_APPROVAL_REVIEW_REQUIRED_NO_ROOT_EXECUTION")
            verify_review(selected.review, selected.review_sha256)
            if (selected.review / "execution/root-execution-admitted.json").exists() or (
                selected.review / "execution/scope-confirmed.json"
            ).exists():
                raise ValueError("AGENT_NATIVE_ONE_SHOT_CONSUMED_FRESH_SCOPE_REQUIRED")
            if not sys.stdin.isatty():
                raise ValueError("AGENT_DIRECT_USER_TTY_SCOPE_AND_SUDO_REQUIRED")
            entry = selected.review / "execution/terminal.py"
            if sha(entry) != selected.entry_sha256:
                raise ValueError("AGENT_NATIVE_ENTRY_CHANGED")
            print(
                "Existing exact Native review: direct Scope/R1 confirmation and OS authentication "
                "follow. No model grants are generated.",
                flush=True,
            )
            # Fixed registered existing Entry Point, shell=False; it retains all
            # receipts, one-shot markers, Root manifest/Scope and TTY gates.
            child = subprocess.run([sys.executable, str(entry)], check=False)
            return dict(
                status="NATIVE_REVIEW_ENTRY_EXITED",
                returncode=child.returncode,
                automatic_retry=False,
                runtime=status(home),
            )
        if Store(selected.runtime).config != selected.configuration:
            raise ValueError("AGENT_AUTHORITATIVE_CONFIG_CHANGED")
        return service.start(selected.runtime) | dict(runtime=status(home))


def stop(home: Path, timeout: float | None = None) -> dict:
    selected = profile(home)
    current = status(home)
    if current.get("state") == "STOPPED":
        return dict(status="ALREADY_STOPPED", runtime=current)
    if not selected.runtime.exists():
        raise ValueError("AGENT_RUNTIME_NOT_STARTED")
    store = Store(selected.runtime)
    if store.config != selected.configuration:
        raise ValueError("AGENT_AUTHORITATIVE_CONFIG_CHANGED")
    store.control(stop=True)
    deadline = time.monotonic() + (
        timeout if timeout is not None else selected.configuration.shutdown_seconds + 35
    )
    while time.monotonic() < deadline:
        current = status(home)
        if (
            current.get("cleanup", "").startswith("UNVERIFIED")
            and current.get("collector") == "STOPPED"
        ):
            raise ValueError("AGENT_STOP_CLEANUP_UNVERIFIED_EVIDENCE_PRESERVED")
        if current.get("state") == "STOPPED":
            if current.get("cleanup") != "VERIFIED":
                raise ValueError("AGENT_STOP_CLEANUP_UNVERIFIED_EVIDENCE_PRESERVED")
            return dict(status="STOPPED_CLEANUP_VERIFIED", runtime=current)
        time.sleep(0.1)
    raise ValueError("AGENT_STOP_TIMEOUT_EVIDENCE_PRESERVED_NO_RETRY")


def gui(home: Path) -> int:
    from soc_agent.gui.__main__ import main as gui_main

    selected = profile(home)
    args = ["--continuous-runtime", str(selected.runtime), "--data-directory", str(home / "gui")]
    if selected.review:
        args += ["--continuous-execution-evidence", str(selected.review / "execution")]
    if selected.authentication_runtime:
        args += ["--runtime", str(selected.authentication_runtime)]
    return gui_main(args)
