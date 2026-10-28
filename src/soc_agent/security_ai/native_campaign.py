"""Qualification bookkeeping only; OS authentication remains the authority boundary.

Never installs, captures or executes a privileged command. The existing Phase D
entry is called once only after an exact, explicitly supplied approval receipt.
The initial budget and historical ledger prefix are never rewritten.
"""

import fcntl
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.operation_budget import guard_reservation, totals


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class NativeCampaign:
    def __init__(self, directory: Path):
        self.directory = directory
        self.budget_body = read_held(directory / "budget.json", owner=os.getuid(), limit=65536)
        self.budget = json.loads(self.budget_body)
        self.baseline_body = read_held(directory / "baseline.json", owner=os.getuid(), limit=262144)
        if self.budget["campaign"] != "NATIVE_SOC_PHASE_D":
            raise ValueError("NATIVE_CAMPAIGN_IDENTITY")
        if any(
            type(self.budget[k]) is not int
            for k in (
                "native_used",
                "native_max",
                "root_installations_used",
                "root_installations_max",
            )
        ):
            raise ValueError("NATIVE_CAMPAIGN_BUDGET_RANGE")
        if (
            not 0 < self.budget["native_max"] <= 5
            or not 0 < self.budget["root_installations_max"] <= 5
        ):
            raise ValueError("NATIVE_CAMPAIGN_BUDGET_RANGE")
        if (
            not 0 <= self.budget["native_used"] <= self.budget["native_max"]
            or not 0
            <= self.budget["root_installations_used"]
            <= self.budget["root_installations_max"]
        ):
            raise ValueError("NATIVE_CAMPAIGN_BUDGET_RANGE")

    def _locked(self, operation):
        fd = os.open(
            self.directory / "execution-ledger.jsonl", os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            st = os.fstat(fd)
            if (
                st.st_uid != os.getuid()
                or st.st_nlink != 1
                or st.st_mode & 0o022
                or st.st_size > 1048576
            ):
                raise ValueError("NATIVE_CAMPAIGN_LEDGER_TRUST")
            body = os.pread(fd, st.st_size, 0)
            lines = body.splitlines(keepends=True)
            if not lines or not body.endswith(b"\n"):
                raise ValueError("NATIVE_CAMPAIGN_LEDGER_FRAMING")
            rows = [json.loads(line) for line in lines]
            first = rows[0]
            if (
                first["campaign"] != self.budget["campaign"]
                or first["event"] != "CAMPAIGN_CREATED_DEVELOPMENT_ONLY"
                or first["budget_sha256"] != sha(self.budget_body)
                or first["baseline_sha256"] != sha(self.baseline_body)
            ):
                raise ValueError("NATIVE_CAMPAIGN_LEDGER_ANCHOR")
            for n, row in enumerate(rows[1:], 1):
                unsigned = {k: v for k, v in row.items() if k != "record_sha256"}
                if (
                    row["sequence"] != n
                    or row["previous_record_sha256"] != sha(lines[n - 1])
                    or row["record_sha256"] != sha(canonical(unsigned))
                ):
                    raise ValueError("NATIVE_CAMPAIGN_LEDGER_CHAIN")
            event = operation(rows)
            guard_reservation(rows, event, self.budget, getattr(self, "batch", None))
            event.update(
                sequence=len(rows),
                campaign=self.budget["campaign"],
                at_utc=datetime.now(UTC).isoformat(),
                previous_record_sha256=sha(lines[-1]),
            )
            event["record_sha256"] = sha(canonical(event))
            data = canonical(event)
            while data:
                sent = os.write(fd, data)
                if sent <= 0:
                    raise OSError("NATIVE_CAMPAIGN_LEDGER_WRITE")
                data = data[sent:]
            os.fsync(fd)  # A failed reservation never invokes the execution callback.
            return event
        finally:
            os.close(fd)

    def reserve(
        self,
        identity: dict,
        scope: dict,
        dns_scope: dict,
        approval_file: Path,
        approval_sha: str,
        *,
        root_cost: int,
        git_commit: str | None = None,
    ) -> dict:
        body = read_held(approval_file, owner=os.getuid(), limit=65536)
        approval = json.loads(body)
        scoped = self.budget["scope"]
        names = dict(
            namespace="namespace",
            interface="interface",
            hook="tcx_hook",
            duration="max_duration_seconds",
            events="tcx_metadata_events",
            queue="queue_capacity",
            address_space_mib="privileged_address_space_mib",
            cpu_seconds="privileged_cpu_seconds",
        )
        namespace = (
            scope.get("namespace")
            if approval.get("development_session_sha")
            else scoped["namespace"]
        )
        if any(
            scope.get(k) != (namespace if k == "namespace" else scoped[v]) for k, v in names.items()
        ):
            raise ValueError("NATIVE_CAMPAIGN_APPROVED_SCOPE_CHANGED")
        dns_names = dict(
            capture_seconds="max_capture_seconds",
            max_seconds="max_active_seconds",
            records="max_packets",
            snaplen="snaplen_bytes",
            target="endpoint",
            qname="qname",
            qtype="qtype",
            udp_queries="udp_queries",
            tcp_queries="tcp_queries",
        )
        if (
            any(dns_scope.get(k) != scoped["dns"][v] for k, v in dns_names.items())
            or dns_scope.get("namespace") != namespace
            or dns_scope.get("interface") != scoped["interface"]
        ):
            raise ValueError("NATIVE_CAMPAIGN_APPROVED_SCOPE_CHANGED")
        if (
            sha(body) != approval_sha
            or approval.get("decision") != "APPROVED"
            or approval.get("campaign") != self.budget["campaign"]
            or approval.get("release") != identity
            or approval.get("scope") != scope
            or approval.get("dns_scope") != dns_scope
            or approval.get("native_attempts") != 1
            or type(approval.get("native_attempts")) is not int
            or approval.get("root_installations") != root_cost
            or type(approval.get("root_installations")) is not int
            or type(root_cost) is not int
            or root_cost not in (0, 1)
        ):
            raise ValueError("NATIVE_CAMPAIGN_EXACT_APPROVAL_REQUIRED")

        def event(rows):
            reservations = [r for r in rows if r["event"] == "NATIVE_ATTEMPT_RESERVED"]
            if any(r["approval_sha256"] == approval_sha for r in reservations):
                raise ValueError("NATIVE_CAMPAIGN_APPROVAL_ALREADY_CONSUMED")
            native_cost, root_cost_used = totals(rows)
            native = self.budget["native_used"] + native_cost
            root = self.budget["root_installations_used"] + root_cost_used
            proposal = dict(
                event="NATIVE_ATTEMPT_RESERVED",
                scope=scope,
                dns_scope=dns_scope,
                release=identity,
                git_commit=git_commit,
                development_session_sha=approval.get("development_session_sha"),
            )
            from soc_agent.security_ai.ebpf_tc.development_session import metered

            development = metered(rows, proposal, self.budget, getattr(self, "batch", None))
            if (
                native + 1 > self.budget["native_max"]
                or root + root_cost > self.budget["root_installations_max"]
            ) and not development:
                raise ValueError("NATIVE_CAMPAIGN_BUDGET_EXHAUSTED")
            return dict(
                event="NATIVE_ATTEMPT_RESERVED",
                attempt_id=uuid4().hex,
                native_used=native + 1,
                root_installations_used=root + root_cost,
                root_cost=root_cost,
                operation="ROOT_AND_NATIVE" if root_cost else "NATIVE_DIAGNOSTIC",
                release=identity,
                scope=scope,
                dns_scope=dns_scope,
                approval_sha256=approval_sha,
                git_commit=git_commit,
                automatic_retry=False,
                **(
                    {"development_session_sha": approval["development_session_sha"]}
                    if development
                    else {}
                ),
            )

        return self._locked(event)

    def finish(self, attempt_id: str, *, outcome: str, evidence: dict) -> dict:
        def event(rows):
            matching = [r for r in rows if r.get("attempt_id") == attempt_id]
            if len(matching) != 1 or matching[0]["event"] != "NATIVE_ATTEMPT_RESERVED":
                raise ValueError("NATIVE_CAMPAIGN_ATTEMPT_STATE")
            if outcome not in {"FAILED", "RETURNED_PENDING_EVIDENCE_REVIEW"}:
                raise ValueError("NATIVE_CAMPAIGN_OUTCOME")
            return dict(
                event="NATIVE_ATTEMPT_FINISHED",
                attempt_id=attempt_id,
                outcome=outcome,
                evidence=evidence,
                native_verified=False,
            )

        return self._locked(event)


def execute_phase_d(
    directory: Path,
    manifest: str,
    image: str,
    *,
    campaign: Path,
    approval_file: Path,
    approval_sha: str,
    gui: bool = False,
):
    from soc_agent.security_ai.ebpf_tc import phase_d
    from soc_agent.security_ai.ebpf_tc.unified_image import installed_release

    value = phase_d.validate(directory, manifest, image)  # Before reservation/auth.
    identity = dict(
        manifest=manifest, bundle=value["bundle"], image=image, tcx_manifest=value["tcx_manifest"]
    )
    dns = json.loads((directory / "dns-sidecar/release.json").read_bytes())["scope"]
    previous = installed_release()
    ledger = NativeCampaign(campaign)
    reserved = ledger.reserve(
        identity,
        value["scope"],
        dns,
        approval_file,
        approval_sha,
        root_cost=int(previous.identity != value["tcx_manifest"]),
        git_commit=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).parents[3], text=True
        ).strip(),
    )
    try:
        result = phase_d.execute(directory, manifest, image, gui=gui)
    except BaseException as exc:
        try:
            ledger.finish(
                reserved["attempt_id"],
                outcome="FAILED",
                evidence=dict(
                    exception_class=type(exc).__name__,
                    errno=getattr(exc, "errno", None),
                    signal=getattr(exc, "signum", None),
                ),
            )
        except (OSError, ValueError) as audit_error:
            exc.add_note("NATIVE_CAMPAIGN_FINAL_AUDIT_FAILED:" + type(audit_error).__name__)
            raise exc from audit_error
        raise
    else:
        failed = (
            bool(result.get("last_error"))
            or result.get("cleanup_status") != "PROCESS_AND_AUDIT_VERIFIED"
        )
        path = directory / "supervised-result.json"
        ledger.finish(
            reserved["attempt_id"],
            outcome="FAILED" if failed else "RETURNED_PENDING_EVIDENCE_REVIEW",
            evidence=dict(
                application_session=result.get("broker_session"),
                result_sha256=sha(path.read_bytes()),
                native_verified=False,
            ),
        )
        return result
