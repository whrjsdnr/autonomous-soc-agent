"""Opt-in execution lifecycle; never refunds budgets or resurrects an approval.

Write-ahead observations are ordinary-user evidence, not proof of privileged
atomicity. Old reservations without these observations remain UNKNOWN. The
existing governance database and campaign chain writer own persistence.
"""

import fcntl
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.security_ai.ebpf_native.contracts import alive, local_controller
from soc_agent.security_ai.ebpf_tc.reassessment import (
    Binding,
    Contract,
    Hash,
    Identity,
    digest,
    held_json,
)
from soc_agent.security_ai.native_campaign import NativeCampaign

Phase = Literal[
    "APPROVED",
    "AWAITING_USER_CONFIRMATION",
    "USER_CONFIRMED",
    "RESERVED",
    "AUTHENTICATING",
    "ROOT_INSTALLATION_VERIFIED",
    "NATIVE_START_INTENT",
    "NATIVE_CAPTURE_STARTED",
    "COMPLETED",
    "FAILED",
    "CANCELLED_BEFORE_EXECUTION",
    "UNKNOWN",
]


class ManagementApproval(Contract):
    contract: Literal["SOC_EXECUTION_MANAGEMENT_POLICY_V1"] = "SOC_EXECUTION_MANAGEMENT_POLICY_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    binding: Binding
    implementation_sha: Hash
    budget_sha: Hash
    baseline_sha: Hash
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    activate_delayed_reservation: Literal[True]
    authorize_root: Literal[False] = False
    authorize_native: Literal[False] = False
    refund_budget: Literal[False] = False
    reuse_consumed_approval: Literal[False] = False


def implementation_sha() -> str:
    root = Path(__file__).parent
    names = (
        "execution_management.py",
        "execution_request.py",
        "operational_recovery.py",
        "reassessment_admission.py",
        "phase_d.py",
        "supervisor_startup.py",
        "termination.py",
    )
    return digest({n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in names})


def verify_policy(path: Path, pin: str, campaign, binding: Binding) -> ManagementApproval:
    value = ManagementApproval.model_validate(held_json(path, pin))
    if (
        value.binding != binding
        or value.implementation_sha != implementation_sha()
        or value.budget_sha != hashlib.sha256(campaign.budget_body).hexdigest()
        or value.baseline_sha != hashlib.sha256(campaign.baseline_body).hexdigest()
        or not value.issued_at <= time.time() < value.expires_at
    ):
        raise ValueError("EXECUTION_MANAGEMENT_POLICY_BINDING")
    return value


class LifecycleJournal:
    """One immutable attempt identity, exclusive launcher, transactional hash chain."""

    def __init__(self, directory: Path):
        self.directory = directory.absolute()
        self.database = GovernanceDatabase(self.directory / "lifecycle.sqlite")
        self.events()  # Reject truncation/tampering before interpreting absence.

    @classmethod
    def create(cls, directory: Path, binding_sha: str, session: str):
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        db = GovernanceDatabase.create(directory.absolute() / "lifecycle.sqlite")
        with db.transaction() as c:
            c.execute(
                "CREATE TABLE lifecycle(sequence INTEGER PRIMARY KEY, payload TEXT, sha TEXT)"
            )
        result = object.__new__(cls)
        result.directory, result.database = directory.absolute(), db
        result._append(
            "APPROVED",
            dict(
                binding_sha=binding_sha,
                session=session,
                owner=local_controller().model_dump(),
                boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            ),
        )
        return result

    @staticmethod
    def _rows(c):
        rows, previous = [], "0" * 64
        for i, row in enumerate(c.execute("SELECT * FROM lifecycle ORDER BY sequence")):
            value = json.loads(row["payload"])
            if row["sequence"] != i or value["previous"] != previous or digest(value) != row["sha"]:
                raise ValueError("EXECUTION_JOURNAL_INTEGRITY")
            rows.append(value)
            previous = row["sha"]
        if not rows or rows[0]["phase"] != "APPROVED":
            raise ValueError("EXECUTION_JOURNAL_ANCHOR")
        return rows

    def events(self):
        with self.database.transaction(write=False) as c:
            return self._rows(c)

    def _append(self, phase: Phase, details: dict, expected: str | None = None):
        with self.database.transaction() as c:
            count = c.execute("SELECT COUNT(*) FROM lifecycle").fetchone()[0]
            rows = self._rows(c) if count else []
            if expected is not None and (not rows or rows[-1]["phase"] != expected):
                raise ValueError("EXECUTION_JOURNAL_CONCURRENT_TRANSITION")
            if count >= 64:
                raise ValueError("EXECUTION_JOURNAL_BOUND")
            value = dict(
                phase=phase,
                details=details,
                monotonic_ns=time.monotonic_ns(),
                previous=digest(rows[-1]) if rows else "0" * 64,
            )
            c.execute(
                "INSERT INTO lifecycle VALUES(?,?,?)", (count, json.dumps(value), digest(value))
            )

    def step(self, phase: Phase, **details):
        allowed = {
            "APPROVED": {"AWAITING_USER_CONFIRMATION"},
            "AWAITING_USER_CONFIRMATION": {"USER_CONFIRMED"},
            "USER_CONFIRMED": {"RESERVED"},
            "RESERVED": {"AUTHENTICATING"},
            "AUTHENTICATING": {"ROOT_INSTALLATION_VERIFIED"},
            "ROOT_INSTALLATION_VERIFIED": {"NATIVE_START_INTENT"},
            "NATIVE_START_INTENT": {"NATIVE_CAPTURE_STARTED"},
            "NATIVE_CAPTURE_STARTED": {"COMPLETED"},
        }
        current = self.events()[-1]["phase"]
        if phase not in allowed.get(current, set()):
            raise ValueError("EXECUTION_LIFECYCLE_TRANSITION")
        self._append(phase, details, expected=current)

    def outcome(self) -> dict:
        rows = self.events()
        phases = {r["phase"] for r in rows}
        root = (
            "STARTED"
            if "ROOT_INSTALLATION_VERIFIED" in phases
            else ("UNKNOWN" if "AUTHENTICATING" in phases else "NOT_STARTED")
        )
        native = (
            "STARTED"
            if "NATIVE_CAPTURE_STARTED" in phases
            else (
                "UNKNOWN" if "NATIVE_START_INTENT" in phases or root == "UNKNOWN" else "NOT_STARTED"
            )
        )
        last = rows[-1]["phase"]
        state = (
            last
            if last in {"COMPLETED", "FAILED", "CANCELLED_BEFORE_EXECUTION", "UNKNOWN"}
            else (
                last
                if self.owner_alive()
                else "CANCELLED_BEFORE_EXECUTION"
                if root == native == "NOT_STARTED"
                else "UNKNOWN"
            )
        )
        return dict(
            disposition=state,
            root=root,
            native=native,
            journal_sha=digest(rows),
            evidence_kind="ORDINARY_USER_WRITE_AHEAD_NOT_KERNEL_PROOF",
        )

    def end(self, failed: bool):
        current = self.events()[-1]["phase"]
        if current in {"COMPLETED", "FAILED", "CANCELLED_BEFORE_EXECUTION", "UNKNOWN"}:
            raise ValueError("EXECUTION_JOURNAL_ALREADY_TERMINAL")
        observed = self.outcome()
        phase = (
            "CANCELLED_BEFORE_EXECUTION"
            if observed["root"] == observed["native"] == "NOT_STARTED"
            else "FAILED"
            if failed and "STARTED" in {observed["root"], observed["native"]}
            else "UNKNOWN"
            if failed
            else "COMPLETED"
        )
        self._append(phase, {}, expected=current)
        return self.outcome()

    def owner_alive(self) -> bool:
        from soc_agent.security_ai.ebpf_native.contracts import ProcessIdentity

        anchor = self.events()[0]["details"]
        return anchor["boot"] == Path(
            "/proc/sys/kernel/random/boot_id"
        ).read_text().strip() and alive(ProcessIdentity.model_validate(anchor["owner"]))


class ExecutionControl:
    """Owns only ordinary-user state. Supervisor remains the sole privileged executor."""

    def __init__(
        self,
        journal: LifecycleJournal,
        reserve,
        *,
        policy_file: Path,
        policy_sha: str,
        campaign,
        binding: Binding,
    ):
        self.journal, self.reserve = journal, reserve
        self.policy_file, self.policy_sha = policy_file, policy_sha
        self.campaign, self.binding = campaign, binding
        anchor = journal.events()[0]["details"]
        if (
            anchor["binding_sha"] != digest(binding.model_dump())
            or anchor["session"] != binding.next_session
        ):
            raise ValueError("EXECUTION_JOURNAL_BINDING")
        self.verify()
        self.reservation = None
        self.fd = -1

    def verify(self):
        return verify_policy(self.policy_file, self.policy_sha, self.campaign, self.binding)

    def __enter__(self):
        self.verify()
        self.fd = os.open(
            self.journal.directory / "launcher.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        st = os.fstat(self.fd)
        if (
            st.st_uid != os.getuid()
            or not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_mode & 0o077
        ):
            os.close(self.fd)
            raise ValueError("EXECUTION_LOCK_TRUST")
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.journal.events()[-1]["phase"] != "APPROVED":
                raise ValueError("EXECUTION_LAUNCH_ALREADY_CLAIMED")
            self.journal.step("AWAITING_USER_CONFIRMATION")
            return self
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def __exit__(self, *_):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def waiting(self):
        self.verify()
        if self.journal.events()[-1]["phase"] != "AWAITING_USER_CONFIRMATION":
            raise ValueError("EXECUTION_CONFIRMATION_STATE")

    def confirmed(self):
        self.verify()
        self.journal.step("USER_CONFIRMED")
        self.reservation = self.reserve()  # All existing validators run atomically now.
        self.journal.step("RESERVED", attempt_id=self.reservation["attempt_id"])

    def step(self, phase: Phase):
        self.verify()
        self.journal.step(phase)


class SettlementApproval(Contract):
    contract: Literal["SOC_EXECUTION_SETTLEMENT_V1"] = "SOC_EXECUTION_SETTLEMENT_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    attempt_id: Identity
    implementation_sha: Hash
    management_policy_sha: Hash
    ledger_tip_sha: Hash
    evidence_sha: Hash
    disposition: Literal[
        "CANCELLED_BEFORE_EXECUTION", "EXECUTION_STARTED", "UNKNOWN", "EVIDENCE_INCOMPLETE"
    ]
    root: Literal["STARTED", "NOT_STARTED", "UNKNOWN"]
    native: Literal["STARTED", "NOT_STARTED", "UNKNOWN"]
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    refund_budget: Literal[False] = False
    reuse_approval: Literal[False] = False


def settle(
    campaign,
    *,
    receipt_file: Path,
    receipt_sha: str,
    evidence_file: Path,
    evidence_sha: str,
    policy_file: Path | None = None,
    policy_sha: str | None = None,
) -> dict:
    """Explicit human accounting only; raw reservation budgets remain unchanged."""
    if policy_file is None or policy_sha is None:
        raise ValueError("EXECUTION_MANAGEMENT_POLICY_REQUIRED")
    activation = ManagementApproval.model_validate(held_json(policy_file, policy_sha))
    verify_policy(policy_file, policy_sha, campaign, activation.binding)
    approval = SettlementApproval.model_validate(held_json(receipt_file, receipt_sha))
    evidence = held_json(evidence_file, evidence_sha)
    if (
        approval.management_policy_sha != policy_sha
        or approval.implementation_sha != implementation_sha()
        or approval.evidence_sha != evidence_sha
        or not approval.issued_at <= time.time() < approval.expires_at
        or any(evidence.get(k) != getattr(approval, k) for k in ("disposition", "root", "native"))
        or evidence.get("attempt_id") != approval.attempt_id
    ):
        raise ValueError("EXECUTION_SETTLEMENT_BINDING")
    if approval.disposition == "CANCELLED_BEFORE_EXECUTION" and (
        approval.root != "NOT_STARTED"
        or approval.native != "NOT_STARTED"
        or evidence.get("verified_write_ahead_no_auth") is not True
    ):
        raise ValueError("EXECUTION_SETTLEMENT_INSUFFICIENT_EVIDENCE")

    journal_rows = None
    if "NOT_STARTED" in {approval.root, approval.native}:
        if not evidence.get("journal_directory"):
            raise ValueError("EXECUTION_SETTLEMENT_JOURNAL_REQUIRED")
        journal = LifecycleJournal(Path(evidence["journal_directory"]))
        observed = journal.outcome()
        if (
            observed["journal_sha"] != evidence.get("journal_sha")
            or observed["root"] != approval.root
            or observed["native"] != approval.native
            or (
                approval.disposition == "CANCELLED_BEFORE_EXECUTION"
                and observed["disposition"] != approval.disposition
            )
        ):
            raise ValueError("EXECUTION_SETTLEMENT_JOURNAL_BINDING")
        journal_rows = journal.events()

    def append(rows):
        if time.time() >= min(approval.expires_at, activation.expires_at):
            raise ValueError("EXECUTION_SETTLEMENT_EXPIRED_UNDER_LOCK")
        if rows[-1]["record_sha256"] != approval.ledger_tip_sha:
            raise ValueError("EXECUTION_SETTLEMENT_STALE_LEDGER")
        events = [r for r in rows if r.get("attempt_id") == approval.attempt_id]
        matches = [r for r in events if r["event"] == "NATIVE_ATTEMPT_RESERVED"]
        closed = [
            r
            for r in events
            if r["event"] in {"NATIVE_ATTEMPT_FINISHED", "EXECUTION_RESERVATION_SETTLED_V1"}
        ]
        if len(matches) != 1 or closed:
            raise ValueError("EXECUTION_SETTLEMENT_ALREADY_CLOSED_OR_UNKNOWN")
        a = activation.binding.next_artifact
        if (
            matches[0].get("next_session") != activation.binding.next_session
            or matches[0].get("git_commit") != a.git_commit
            or matches[0].get("release")
            != dict(
                manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest
            )
        ):
            raise ValueError("EXECUTION_SETTLEMENT_POLICY_SCOPE")
        if journal_rows is not None and (
            journal_rows[0]["details"].get("session") != matches[0].get("next_session")
            or [r["details"].get("attempt_id") for r in journal_rows if r["phase"] == "RESERVED"]
            != [approval.attempt_id]
        ):
            raise ValueError("EXECUTION_SETTLEMENT_RESERVATION_BINDING")
        return dict(
            event="EXECUTION_RESERVATION_SETTLED_V1",
            attempt_id=approval.attempt_id,
            disposition=approval.disposition,
            root=approval.root,
            native=approval.native,
            receipt_sha256=receipt_sha,
            evidence_sha256=evidence_sha,
            reviewer=approval.approver,
            budget_action="KEEP_RESERVATION_CHARGE",
            approval_reusable=False,
            authorizes_execution=False,
        )

    return NativeCampaign._locked(campaign, append)


def inspect_reservation(campaign, attempt_id: str) -> dict:
    """Read existing chain under its real lock, never settle based on missing files."""

    class Inspected(Exception):
        def __init__(self, rows):
            self.rows = rows

    def inspect(rows):
        raise Inspected(rows)

    try:
        NativeCampaign._locked(campaign, inspect)
    except Inspected as state:
        rows = state.rows
    matches = [r for r in rows if r.get("attempt_id") == attempt_id]
    if not matches or matches[0]["event"] != "NATIVE_ATTEMPT_RESERVED":
        raise ValueError("EXECUTION_RESERVATION_UNKNOWN")
    settled = [r for r in matches if r["event"] == "EXECUTION_RESERVATION_SETTLED_V1"]
    finished = [r for r in matches if r["event"] == "NATIVE_ATTEMPT_FINISHED"]
    return dict(
        attempt_id=attempt_id,
        disposition=settled[-1]["disposition"]
        if settled
        else "EXECUTION_RESULT_RECORDED"
        if finished
        else "EVIDENCE_INCOMPLETE",
        root=settled[-1]["root"] if settled else "UNKNOWN",
        native=settled[-1]["native"] if settled else "UNKNOWN",
        reservation=matches[0],
        ledger_tip_sha=rows[-1]["record_sha256"],
        approval_reusable=False,
        budget_action="KEEP_RESERVATION_CHARGE",
        reserved_native=sum(r["event"] == "NATIVE_ATTEMPT_RESERVED" for r in rows),
        reserved_root=sum(
            r.get("root_cost", 0) for r in rows if r["event"] == "NATIVE_ATTEMPT_RESERVED"
        ),
    )
