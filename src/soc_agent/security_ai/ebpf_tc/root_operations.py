"""Policy-gated Root-only reservations; no sudo, setns, install or traffic.

Uses the existing locked campaign writer. A policy pin is an explicit operator
trust anchor, as in reassessment; development permission is not such a receipt.
Native operations stay on the existing exact-artifact/R1/R2 admission path.
"""

import hashlib
import time
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan
from soc_agent.security_ai.ebpf_tc.namespace_isolation import setup_proposal
from soc_agent.security_ai.ebpf_tc.reassessment import (
    Artifact,
    Contract,
    Hash,
    Identity,
    digest,
    held_json,
)
from soc_agent.security_ai.ebpf_tc.runtime_recovery import inspect_retained
from soc_agent.security_ai.native_campaign import NativeCampaign
from soc_agent.security_ai.operation_budget import ROOT_FINISHED, ROOT_RESERVED, guard_reservation
from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign


class RootBinding(Contract):
    campaign: Literal["SOC_NATIVE_STABILIZATION"] = "SOC_NATIVE_STABILIZATION"
    batch: Literal["BATCH3"] = "BATCH3"
    session: Identity
    artifact: Artifact
    source_snapshot: Hash
    scope_sha: Hash
    installed_manifest: Hash
    rollback_manifest: Hash

    @model_validator(mode="after")
    def session_uuid(self):
        if str(UUID(self.session)) != self.session:
            raise ValueError("ROOT_SESSION_IDENTITY")
        return self


def setup_binding(
    plan: ApplicationPlan,
    artifact: Artifact,
    *,
    source_snapshot: str,
    installed_manifest: str,
    rollback_manifest: str,
) -> RootBinding:
    """Reuse an official ApplicationPlan session; never derive one from a name/inode."""
    return RootBinding(
        session=str(plan.application_session),
        artifact=artifact,
        source_snapshot=source_snapshot,
        scope_sha=digest(setup_proposal()),
        installed_manifest=installed_manifest,
        rollback_manifest=rollback_manifest,
    )


class RootPolicy(Contract):
    contract: Literal["SOC_ROOT_ONLY_ACCOUNTING_POLICY_V1"] = "SOC_ROOT_ONLY_ACCOUNTING_POLICY_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    binding: RootBinding
    implementation_sha: Hash
    budget_sha: Hash
    baseline_sha: Hash
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    authorize_native: Literal[False] = False
    refund: Literal[False] = False


class RootApproval(Contract):
    contract: Literal["SOC_ROOT_OPERATION_APPROVAL_V1"] = "SOC_ROOT_OPERATION_APPROVAL_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    policy_sha: Hash
    binding: RootBinding
    operation: Literal["ROOT_SETUP", "ROOT_INSTALL", "ROOT_DNS_DIAGNOSTIC"]
    scope: dict
    ledger_tip_sha: Hash
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    native_cost: Literal[0] = 0
    root_cost: Literal[1] = 1


def implementation_sha() -> str:
    root = Path(__file__).parents[1]
    files = [root / "operation_budget.py", root / "native_campaign.py", Path(__file__)]
    files += [
        Path(__file__).with_name(n)
        for n in (
            "root_governance.py",
            "dns_diagnostic.py",
            "dns_diagnostic_engine.py",
            "isolated_dns_engine.py",
            "isolated_dns_worker.py",
            "isolated_dns_launcher.py",
        )
    ]
    return digest({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files})


class RootOperations(StabilizationCampaign):
    def reserve_root(
        self,
        binding: RootBinding,
        *,
        policy_file: Path,
        policy_sha: str,
        approval_file: Path,
        approval_sha: str,
        root_manifest_file: Path,
        dns_directory: Path | None = None,
        dns_lease_file: Path | None = None,
    ) -> dict:
        policy = RootPolicy.model_validate(held_json(policy_file, policy_sha))
        approval = RootApproval.model_validate(held_json(approval_file, approval_sha))
        now = time.time()
        if (
            policy.binding != binding
            or approval.binding != binding
            or approval.policy_sha != policy_sha
            or self.batch != binding.batch
            or policy.implementation_sha != implementation_sha()
            or policy.budget_sha != hashlib.sha256(self.budget_body).hexdigest()
            or policy.baseline_sha != hashlib.sha256(self.baseline_body).hexdigest()
            or not policy.issued_at <= now < policy.expires_at
            or not approval.issued_at <= now < approval.expires_at <= policy.expires_at
        ):
            raise ValueError("ROOT_POLICY_OR_APPROVAL_BINDING")
        manifest = held_json(root_manifest_file, binding.artifact.root_manifest)
        from soc_agent.security_ai.ebpf_tc.installation import ReleaseManifest

        release = ReleaseManifest.model_validate(manifest)
        if release.version != binding.artifact.release:
            raise ValueError("ROOT_RELEASE_IDENTITY")
        if approval.operation in ("ROOT_INSTALL", "ROOT_DNS_DIAGNOSTIC"):
            from soc_agent.security_ai.ebpf_tc.installation import verify_package

            verify_package(root_manifest_file.parent, binding.artifact.root_manifest)
        inspect_retained(binding.installed_manifest)
        inspect_retained(binding.rollback_manifest, rollback=True)
        expected_scope = (
            setup_proposal()
            if approval.operation == "ROOT_SETUP"
            else dict(
                operation="ROOT_INSTALL",
                root_manifest=binding.artifact.root_manifest,
                installed_manifest=binding.installed_manifest,
                rollback_manifest=binding.rollback_manifest,
                start_native=False,
            )
        )
        if approval.operation == "ROOT_DNS_DIAGNOSTIC":
            from soc_agent.security_ai.ebpf_tc.dns_diagnostic import verify
            from soc_agent.security_ai.ebpf_tc.isolated_dns_launcher import inspect_lease

            if dns_directory is None or dns_lease_file is None:
                raise ValueError("ROOT_DNS_ARTIFACT_AND_LEASE_REQUIRED")
            metadata = verify(dns_directory, binding)
            expected_scope = metadata["config"]["scope"]
            inspect_lease(
                dns_lease_file,
                expected_scope["lease_sha256"],
                RootBinding.model_validate(expected_scope["setup_binding"]),
            )
        if approval.scope != expected_scope or digest(approval.scope) != binding.scope_sha:
            raise ValueError("ROOT_OPERATION_SCOPE")

        def reserve(rows):
            if not (
                policy.issued_at <= time.time() < policy.expires_at
                and approval.issued_at <= time.time() < approval.expires_at
            ):
                raise ValueError("ROOT_APPROVAL_EXPIRED")
            if any(r.get("approval_sha256") == approval_sha for r in rows):
                raise ValueError("ROOT_APPROVAL_REPLAY")
            if any(
                r.get("event") == ROOT_RESERVED
                and r.get("binding", {}).get("session") == binding.session
                and r.get("operation") == approval.operation
                for r in rows
            ):
                raise ValueError("ROOT_SESSION_ALREADY_RESERVED")
            if rows[-1].get("record_sha256", digest(rows[-1])) != approval.ledger_tip_sha:
                raise ValueError("ROOT_APPROVAL_STALE_LEDGER")
            if approval.operation == "ROOT_DNS_DIAGNOSTIC" and not any(
                r.get("event") == "ROOT_POLICY_ACTIVATED_V1"
                and r.get("policy_sha256") == policy_sha
                and r.get("binding") == binding.model_dump()
                for r in rows
            ):
                raise ValueError("ROOT_DNS_POLICY_ACTIVATION_REQUIRED")
            # A live legacy reservation also excludes concurrent infrastructure work.
            finished = {
                r.get("attempt_id")
                for r in rows
                if r.get("event") in ("NATIVE_ATTEMPT_FINISHED", "EXECUTION_RESERVATION_SETTLED_V1")
            }
            if any(
                r["event"] == "NATIVE_ATTEMPT_RESERVED" and r["attempt_id"] not in finished
                for r in rows
            ):
                raise ValueError("ROOT_PREVIOUS_ATTEMPT_PENDING")
            # Approval identity is also a stable reservation identity, never a generated session.
            return dict(
                event=ROOT_RESERVED,
                attempt_id=approval_sha,
                approval_sha256=approval_sha,
                policy_sha256=policy_sha,
                operation=approval.operation,
                binding=binding.model_dump(),
                batch=self.batch,
                native_cost=0,
                root_cost=1,
                state="RESERVED_NOT_STARTED",
                scope=approval.scope,
            )

        return self._locked(reserve)

    def record_root(
        self,
        attempt_id: str,
        *,
        state: Literal[
            "START_INTENT",
            "STARTED",
            "SUCCEEDED",
            "FAILED",
            "UNKNOWN",
            "CANCELLED_BEFORE_EXECUTION",
        ],
        evidence_sha: str,
    ) -> dict:
        class Evidence(Contract):
            sha: Hash

        Evidence(sha=evidence_sha)
        if state not in (
            "START_INTENT",
            "STARTED",
            "SUCCEEDED",
            "FAILED",
            "UNKNOWN",
            "CANCELLED_BEFORE_EXECUTION",
        ):
            raise ValueError("ROOT_STATE")

        def transition(rows):
            events = [r for r in rows if r.get("attempt_id") == attempt_id]
            if (
                not events
                or events[0]["event"] != ROOT_RESERVED
                or events[0]["batch"] != self.batch
            ):
                raise ValueError("ROOT_RESERVATION_UNKNOWN")
            if any(r["event"] == ROOT_FINISHED for r in events):
                raise ValueError("ROOT_ALREADY_SETTLED")
            phases = [r.get("state") for r in events]
            allowed = {
                "RESERVED_NOT_STARTED": {"START_INTENT", "CANCELLED_BEFORE_EXECUTION", "UNKNOWN"},
                "START_INTENT": {"STARTED", "UNKNOWN", "FAILED"},
                "STARTED": {"SUCCEEDED", "FAILED", "UNKNOWN"},
            }
            if state not in allowed.get(phases[-1], set()):
                raise ValueError("ROOT_TRANSITION")
            terminal = state not in ("START_INTENT", "STARTED")
            return dict(
                event=ROOT_FINISHED if terminal else "ROOT_OPERATION_PROGRESS_V1",
                attempt_id=attempt_id,
                state=state,
                outcome=state,
                evidence_sha=evidence_sha,
                root_evidence="ORDINARY_USER_RECORD_NOT_KERNEL_PROOF",
                refund=False,
                approval_reusable=False,
                native_started=False,
            )

        return self._locked(transition)

    def check_root(self, *args, **kwargs) -> dict:
        """All operational validators, no append/reservation/approval consumption."""

        class Checked(Exception):
            def __init__(self, event):
                self.event = event

        def preview(operation):
            def inspect(rows):
                event = operation(rows)
                guard_reservation(rows, event, self.budget, self.batch)
                raise Checked(event)

            return NativeCampaign._locked(self, inspect)

        # A separate instance prevents changing a live launcher's writer method.
        candidate = RootOperations(self.directory, self.batch)
        candidate._locked = preview
        try:
            candidate.reserve_root(*args, **kwargs)
        except Checked as checked:
            return dict(status="CHECKED_NOT_RESERVED", proposal=checked.event, executes=False)
        raise ValueError("ROOT_CHECK_UNEXPECTED_RETURN")


def launcher_scope() -> dict:
    """Exact proposed privilege lifecycle, NOT an executable Root command runner."""
    return dict(
        status="DESIGN_REQUIRES_POLICY_AND_EXACT_EXECUTION_APPROVAL",
        setup_argv=setup_proposal()["proposed_root_argv"],
        caller="ORDINARY_UID_ZERO_CAPABILITIES",
        privileged_steps=[
            dict(
                action="CREATE_NAMED_NAMESPACE",
                uid=0,
                capabilities=["CAP_SYS_ADMIN"],
                changes=["/run/netns/soc-native-b3"],
                collision="FAIL_NO_REUSE_OR_DELETE",
            ),
            dict(
                action="LO_UP_IN_NEW_NAMESPACE",
                uid=0,
                capabilities=["CAP_SYS_ADMIN", "CAP_NET_ADMIN"],
                changes=["dedicated lo flags"],
            ),
            dict(
                action="ENTER_CHILD_ONLY_USING_HELD_NAMESPACE_FD",
                uid=0,
                capabilities=["CAP_SYS_ADMIN"],
                changes=["new child network namespace"],
            ),
            dict(
                action="BIND_PREBOUND_UDP_TCP",
                uid=0,
                capabilities=["CAP_NET_BIND_SERVICE"],
                capability_condition="REQUIRED_IF_PORT_53_IS_PRIVILEGED_IN_TARGET_NETNS",
                endpoint="127.0.0.53:53",
                changes=["two dedicated listener sockets"],
            ),
            dict(
                action="DROP_GROUPS_UID_GID_CAPABILITIES_SET_NO_NEW_PRIVS",
                uid=0,
                capabilities=["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"],
                changes=["child credentials only"],
            ),
        ],
        worker=dict(
            uid="ORIGINAL_ORDINARY_UID",
            capabilities=[],
            entrypoint="isolated_dns_worker.serve_prebound",
            udp=2,
            tcp=1,
            maximum_seconds=60,
            memory_mib=256,
            cpu_seconds=20,
            parent_death="FAIL_CLOSED_OWNED_CHILD_ONLY",
            socket_scope="CURRENT_NAMESPACE_COOKIE_MUST_MATCH_BOTH_LISTENERS",
        ),
        cleanup=dict(
            worker="OWNED_PID_START_TICKS_AND_LISTENER_FDS_ONLY",
            namespace="RETAIN_UNTIL_SEPARATE_OWNERSHIP_BOUND_DELETION_APPROVAL",
            delete_by_name=False,
        ),
        arbitrary_command=False,
        install=False,
        native=False,
        tcx=False,
        host_service_change=False,
        veth=False,
        external_route=False,
    )
