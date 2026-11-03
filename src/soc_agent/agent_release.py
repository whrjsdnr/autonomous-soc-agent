"""Installed review lifecycle composition, not an approval or execution authority.

The existing frozen source, model, dependency and launcher contracts remain the
release. Registration pins their bytes; fresh drafts never inherit decisions.
"""

import json
import os
from pathlib import Path
from uuid import uuid4

from soc_agent.agent_runtime import profile, sha, verify_review
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def save(path: Path, value: dict) -> None:
    body = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def register(home: Path, review: Path) -> dict:
    """Explicit setup/update candidate; expiry is not renewed or treated as authority."""
    from soc_agent.agent_native import evidence_directory

    review = review.absolute()
    request = verify_review(review, require_active=False)
    evidence_directory(review)
    create_private_directory(home)
    if (home / "installed-release.json").exists():
        raise ValueError("AGENT_RELEASE_ALREADY_REGISTERED_EXPLICIT_UPDATE_REQUIRED")
    if (home / "agent.json").exists():
        selected = profile(home)
        if selected.review != review or prior_session(home) not in {"PREPARED", "EXPIRED_UNUSED"}:
            raise ValueError("AGENT_EXISTING_PROFILE_REQUIRES_EXPLICIT_UPDATE")
    # Pin the existing executable artifacts, not runtime data or human decisions.
    paths = {review / "approval-request-final-v2.json", review / "execution/execution-pins.json"}
    paths.update(
        Path(p) for p in json.loads(read_local(review / "execution/execution-pins.json", 65536))
    )
    paths.update(Path(row["path"]) for row in request["files"].values())
    for name in ("scope-input.json", "runtime-config.json", "controller-python-binding.json"):
        paths.add(review / name)
    value = dict(
        contract="soc-installed-review-reference:v1",
        review=str(review),
        release=request["code_identity"],
        git_commit=request["git_commit"],
        files={str(p): sha(p) for p in sorted(paths)},
        execution_authority=False,
    )
    save(home / "installed-release.json", dict(release=value, digest=digest(value)))
    return dict(status="RELEASE_REGISTERED_NOT_AUTHORIZED", release=value["release"])


def installed(home: Path) -> dict:
    doc = json.loads(read_local(home / "installed-release.json", 131072))
    value = doc["release"]
    if (
        doc.get("digest") != digest(value)
        or value.get("contract") != "soc-installed-review-reference:v1"
        or value.get("execution_authority") is not False
    ):
        raise ValueError("AGENT_INSTALLED_RELEASE_INTEGRITY")
    for name, pin in value["files"].items():
        if sha(Path(name)) != pin:
            raise ValueError("AGENT_INSTALLED_RELEASE_CHANGED_EXPLICIT_UPDATE_REQUIRED")
    request = verify_review(Path(value["review"]), require_active=False)
    if request["code_identity"] != value["release"] or request["git_commit"] != value["git_commit"]:
        raise ValueError("AGENT_INSTALLED_RELEASE_IDENTITY")
    return value


def session_profiles(home: Path) -> list[dict]:
    """Read-only catalogue: index 0 is current, previous profiles remain immutable."""
    paths = [home / "agent.json"]
    archive = home / "sessions"
    if archive.exists():
        paths += sorted(archive.glob("*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    result = []
    from soc_agent.agent_runtime import AgentProfile

    for path in paths:
        if not path.exists():
            continue
        doc = json.loads(read_local(path, 65536))
        if doc.get("digest") != digest(doc.get("profile")):
            raise ValueError("AGENT_ARCHIVED_PROFILE_INTEGRITY")
        selected = AgentProfile.model_validate(doc["profile"])
        result.append(
            dict(
                index=len(result),
                profile=str(path),
                runtime=str(selected.runtime),
                source=selected.configuration.source,
                current=path == paths[0],
            )
        )
    return result


def operator_context(home: Path, runtime: Path | None) -> dict:
    """Display only: approval waiting is not an execution error or a grant."""
    fixed = installed(home)
    matching = [row for row in session_profiles(home) if row["runtime"] == str(runtime)]
    if not matching:
        return dict(status="UNREGISTERED_SESSION", integrity="UNVERIFIED")
    from soc_agent.agent_runtime import AgentProfile

    selected = AgentProfile.model_validate(
        json.loads(read_local(Path(matching[0]["profile"]), 65536))["profile"]
    )
    if selected.review is None:
        raise ValueError("AGENT_SESSION_RELEASE_MISMATCH")
    request = verify_review(selected.review, selected.review_sha256, require_active=False)
    if selected.backend_code_identity != request["code_identity"]:
        raise ValueError("AGENT_SESSION_RELEASE_MISMATCH")
    from datetime import UTC, datetime

    return dict(
        operation_mode="INSTALLED_RESEARCH_MVP",
        release=request["git_commit"],
        current_release=fixed["git_commit"],
        session=request["runtime_session"],
        integrity="PASS",
        policy_expires_at=request["expires_at"],
        policy_status="RENEWAL_REQUIRED"
        if datetime.fromisoformat(request["expires_at"]) <= datetime.now(UTC)
        else "PROPOSAL_VALIDITY_NOT_EXECUTION_AUTHORITY",
        model_authority="EXACT_SEALED_ELIGIBLE_HUMAN_REVIEW",
        api_authority="EXACT_INCIDENT_REVISION_HUMAN_REVIEW",
        execution_authority="INDEPENDENT_POLICY_SCOPE_R1_AND_SUDO_REQUIRED",
    )


def prior_session(home: Path) -> str:
    """Do not turn a failed/cancelled one-shot trial into an automatic retry."""
    if not (home / "agent.json").exists():
        return "ABSENT"
    from soc_agent.agent_runtime import status

    selected = profile(home)
    execution = selected.review / "execution" if selected.review else None
    current = status(home)
    if current.get("state") in {"RUNNING", "DEGRADED", "STOPPING"}:
        raise ValueError("AGENT_ALREADY_RUNNING")
    markers = (
        "scope-confirmed.json",
        "terminal-cancelled.json",
        "root-execution-admitted.json",
        "terminal-exit.json",
        "root-terminal-exit.json",
    )
    if execution is None or not any((execution / name).exists() for name in markers):
        from datetime import UTC, datetime

        request = json.loads(read_local(selected.review / "approval-request-final-v2.json", 131072))
        return (
            "PREPARED"
            if datetime.fromisoformat(request["expires_at"]) > datetime.now(UTC)
            else "EXPIRED_UNUSED"
        )
    # A successful Runtime stop alone cannot prove the Root/Helper lifecycle.
    # Reuse the exact final evidence; absent/failed evidence blocks rotation.
    finished = json.loads(read_local(execution / "root-finished.json", 65536))
    terminal = json.loads(read_local(execution / "operator-terminal-result.json", 32768))
    if (
        finished.get("primary_error") is not None
        or finished.get("socket_exists") is not False
        or not finished.get("cleanup")
        or any(row.get("returncode") != 0 for row in finished["cleanup"])
        or terminal.get("returncode") != 0
        or current.get("state") != "STOPPED"
        or current.get("cleanup") != "VERIFIED"
        or current.get("collector_cleanup") != "VERIFIED"
        or current.get("dns_transport", {}).get("cleanup") != "VERIFIED"
        or current.get("dns_transport", {}).get("transport_final_counter_verified") is not True
    ):
        raise ValueError("AGENT_PREVIOUS_SESSION_REQUIRES_REVIEW_NO_AUTOMATIC_RETRY")
    for unit in (
        "soc-continuous-collector",
        "soc-continuous-dns",
        "soc-continuous-dnsmasq",
        "soc-continuous-tcp-trial",
        "soc-operations-runtime",
    ):
        final = json.loads(read_local(execution / (unit + ".service-final.json"), 32768))
        if final.get("ActiveState") != "inactive" or final.get("MainPID") != "0":
            raise ValueError("AGENT_PREVIOUS_ROOT_RESOURCE_CLEANUP_UNVERIFIED")
    for name in ("namespace-after.json", "namespace-after-tcx.json"):
        result = json.loads(read_local(execution / name, 65536))
        if result.get("returncode") != 0:
            raise ValueError("AGENT_PREVIOUS_NAMESPACE_CLEANUP_UNVERIFIED")
        if name == "namespace-after-tcx.json":
            links = json.loads(result["stdout"])
            if not isinstance(links, list) or any(row.get("tc") != [] for row in links):
                raise ValueError("AGENT_PREVIOUS_TCX_CLEANUP_UNVERIFIED")
    return "CLOSED"


def update(home: Path, review: Path) -> dict:
    """Explicit ordinary-user Release update, with a fresh unapproved Session.

    Root installation and rollback remain the existing authenticated launcher job.
    Prior reference/profile bytes are preserved; no old Session is resumed.
    """
    with exclusive_runtime_lock(home / "application-start.lock"):
        installed(home)
        prior_session(home)
        staging = home / ("update-" + uuid4().hex)
        create_private_directory(staging, exist_ok=False)
        register(staging, review)
        prepare(staging)
        archive = home / "release-history"
        create_private_directory(archive)
        record = archive / uuid4().hex
        create_private_directory(record, exist_ok=False)
        names = ("agent.json", "installed-release.json")
        for name in names:
            save(record / name, json.loads(read_local(home / name, 131072)))
        previous_sessions = home / "sessions"
        create_private_directory(previous_sessions)
        save(
            previous_sessions / (uuid4().hex + ".json"),
            json.loads(read_local(home / "agent.json", 65536)),
        )
        # No privileged operation occurs during publication. Any interrupted mixed
        # pair is denied by the Session/Release identity check, never auto-approved.
        for name in names:
            os.replace(staging / name, home / name)
        descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return dict(
            status="RELEASE_UPDATED_NOT_AUTHORIZED",
            previous=str(record),
            runtime=str(profile(home).runtime),
        )


def prepare(home: Path) -> dict:
    """Prepare once under the profile lock; no process launch or authority issuance."""
    from soc_agent.agent_runtime import setup
    from soc_agent.agent_session import draft

    with exclusive_runtime_lock(home / "release-session.lock"):
        release = installed(home)
        previous = prior_session(home)
        if (
            previous == "PREPARED"
            and (profile(home).review.parent / "preparation-result.json").exists()
        ):
            return dict(status="EXISTING_UNCONSUMED_SESSION", runtime=str(profile(home).runtime))
        template = Path(release["review"])
        from soc_agent.agent_native import evidence_directory

        parent = evidence_directory(template) / ("operator-session-" + uuid4().hex)
        create_private_directory(parent, exist_ok=False)
        try:
            review = draft(template, parent)
            staging = home / ("prepared-" + uuid4().hex)
            create_private_directory(staging, exist_ok=False)
            setup(staging, review=review)
            from soc_agent.agent_native import validate_plan

            validate_plan(profile(staging))
            # Archive the exact former profile, never its Queue/Audit or permission files.
            if (home / "agent.json").exists():
                archive = home / "sessions"
                create_private_directory(archive)
                save(
                    archive / (uuid4().hex + ".json"),
                    json.loads(read_local(home / "agent.json", 65536)),
                )
            os.replace(staging / "agent.json", home / "agent.json")
            staging.rmdir()
            descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            save(
                parent / "preparation-result.json",
                dict(
                    status="PREPARED_NOT_AUTHORIZED",
                    release=release["release"],
                    review=str(review),
                    receipts=0,
                    executions=0,
                ),
            )
            return dict(
                status="NEW_SESSION_PREPARED_NOT_AUTHORIZED", runtime=str(profile(home).runtime)
            )
        except (OSError, ValueError, KeyError) as error:
            save(
                parent / "preparation-failed.json",
                dict(
                    status="FAILED_NOT_EXECUTED",
                    error_type=type(error).__name__,
                    automatic_retry=False,
                ),
            )
            raise
