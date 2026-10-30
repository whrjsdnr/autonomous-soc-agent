"""Owned nonprivileged analysis jobs and verified reports for the existing desktop.

No Root/collector command, API credential, approval issuer or response executor.
Native capture remains on the separately governed Supervisor/terminal path.
"""

import asyncio
import hashlib
import os
import signal
import sys
import time
from pathlib import Path
from uuid import uuid4

from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.offline_workflow import verify_result
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.workflow_models import JOB, AnalysisOutcome


def project_result(result: AnalysisOutcome) -> dict:
    origins = sorted({e.origin for e in result.evidence})
    return dict(
        incident_id=str(result.incident_id),
        classification=result.classification,
        classification_basis=result.classification_basis,
        eligibility=result.eligibility,
        eligibility_scope=result.eligibility_scope,
        input_origins=origins,
        evidence_domains=sorted({e.domain for e in result.evidence}),
        capture_windows=[
            p.removeprefix("CAPTURE_WINDOW:")
            for e in result.evidence
            for p in e.provenance
            if p.startswith("CAPTURE_WINDOW:")
        ],
        inference_count=len(result.inference),
        models=[r.model_id for r in result.inference],
        predictions=[
            dict(
                model=r.model_id,
                prediction=r.prediction,
                score=r.score,
                score_semantics=r.score_semantics,
                inferred_at=r.inferred_at.isoformat(),
                inference_latency_ms=r.latency_ms,
                model_artifact_sha256=r.artifact_digest,
                feature_fingerprint=r.feature_fingerprint,
                flow_id=r.event_identity,
                evidence_references=list(r.evidence_references),
            )
            for r in result.inference
        ],
        llm_mode=result.llm_mode,
        external_provider_calls=result.external_provider_calls,
        investigation_status=(result.investigation or {}).get("status", "NOT_REQUESTED"),
        investigation_detail=investigation_view(result),
        response_status=(result.response or {}).get("postcondition", "NOT_REQUESTED"),
        audit="VERIFIED",
        capture_started_by_gui=False,
        detail=result.model_dump(mode="json"),
    )


def investigation_view(result: AnalysisOutcome) -> dict:
    """Keep recorded assessment and completed steps, without synthesizing checkpoints."""
    source = result.investigation or {}
    assessment = source.get("assessment") or {}
    completed = source.get("result") or {}
    plan = completed.get("plan") or source.get("plan") or {}
    return dict(
        incident_id=str(result.incident_id),
        status=source.get("status", "NOT_REQUESTED"),
        llm_mode=result.llm_mode,
        external_provider_calls=result.external_provider_calls,
        api_status=source.get("api_status"),
        assessment={"threat_assessment": assessment.get("threat_assessment", {})},
        plan={
            "goal": plan.get("goal"),
            "steps": [
                {key: step.get(key) for key in ("step_id", "tool_name", "status", "evidence_id")}
                for step in plan.get("steps", [])[:16]
            ],
        },
        timeline=source.get("timeline"),
        unresolved=source.get("unresolved", []),
    )


class AnalysisService:
    def __init__(
        self, directory: Path, ml_root: Path | None = None, *, defer_investigation: bool = False
    ):
        self.directory = directory.absolute()
        create_private_directory(self.directory)
        self.ml_root = ml_root
        self.defer_investigation = defer_investigation
        self.state = "IDLE"
        self.session = None
        self.process = None
        self.monitor = None
        self.result = None
        self.error = None
        self.cleanup = "NOT_STARTED"
        self.output = None
        self.closed = False
        self._lock = asyncio.Lock()

    def snapshot(self):
        return dict(
            state=self.state,
            session_id=self.session,
            mode="OFFLINE_ANALYSIS",
            collection_live=False,
            worker_running=bool(self.process and self.process.returncode is None),
            child_returncode=self.process.returncode if self.process else None,
            cleanup=self.cleanup,
            last_error=self.error,
            result=self.result,
            output=str(self.output) if self.output else None,
            native_start="EXTERNAL_GOVERNED_TERMINAL_REQUIRED",
            dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
            api_calls_started_by_gui=0,
        )

    async def start(self, input_file: Path):
        return await self._start(input_file)

    async def start_retained_tcx(self, input_file: Path, *, approvals: Path | None = None):
        """Continuous composition only: existing exact action approvals, no issuer.

        Stable output binding allows an operator to prepare the existing action
        approval before starting the retained job. Fixture remains explicitly Fixture.
        """
        return await self._start(input_file, retained=True, approvals=approvals)

    async def _start(self, input_file: Path, *, retained=False, approvals=None):
        async with self._lock:
            if (
                self.closed
                or self.state in ("STARTING", "RUNNING", "VERIFYING", "STOPPING")
                or self.cleanup == "UNVERIFIED"
            ):
                raise ValueError("ANALYSIS_ALREADY_RUNNING_OR_CLOSED")
            body = await asyncio.to_thread(read_local, input_file.absolute(), 1024 * 1024)
            job = JOB.validate_json(body)
            if job.kind == "native_checkpoint" or (job.kind == "tcx_analysis" and not retained):
                raise ValueError("NATIVE_ANALYSIS_REQUIRES_EXISTING_APPROVAL_ENTRYPOINT")
            if retained and job.kind != "tcx_analysis":
                raise ValueError("RETAINED_TCX_JOB_REQUIRED")
            from soc_agent.security_ai.research.models import digest

            self.session = digest(job.model_dump(mode="json")) if retained else str(uuid4())
            self.error = None
            self.result = None
            submitted = self.directory / (self.session + ".input.json")
            fd = os.open(submitted, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            self.state = "STARTING"
            self.output = self.directory / ("run-" + self.session)
            args = [
                sys.executable,
                "-m",
                "soc_agent.cli",
                "analyze-offline",
                "--parent-pid",
                str(os.getpid()),
                "--input",
                str(submitted),
                "--input-sha256",
                hashlib.sha256(body).hexdigest(),
                "--output",
                str(self.output),
            ]
            if retained and approvals:
                approval = approvals / (self.session + ".json")
                if approval.exists():
                    pin = hashlib.sha256(read_local(approval, 32768)).hexdigest()
                    args += ["--tcx-approval", str(approval), "--tcx-approval-sha256", pin]
            if self.ml_root:
                args += ["--research-ml-root", str(self.ml_root)]
            if self.defer_investigation:
                args += ["--defer-investigation"]
            try:
                self.process = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError:
                self.state = "ERROR"
                self.error = "ANALYSIS_START_FAILED"
                self.cleanup = "VERIFIED"
                raise
            self.state = "RUNNING"
            self.cleanup = "PENDING"
            self.monitor = asyncio.create_task(
                self._watch(), name="soc-offline-analysis-" + self.session
            )
            return self.snapshot()

    async def _watch(self):
        try:
            output, _ = await asyncio.wait_for(self.process.communicate(), 180)
            if self.process.returncode or len(output) > 1024 * 1024:
                self.error = "ANALYSIS_CLI_FAILED"
                self.state = "ERROR"
            else:
                try:
                    self.state = "VERIFYING"
                    result = await asyncio.to_thread(verify_result, self.output)
                except (ValueError, OSError):
                    self.error = "ANALYSIS_RESULT_OR_AUDIT_INVALID"
                    self.state = "ERROR"
                else:
                    self.result = project_result(result)

        except TimeoutError:
            self.error = "ANALYSIS_TIMEOUT_NO_RETRY"
            self.state = "ERROR"
        finally:
            if self.state != "STOPPING":
                self.cleanup = await self._reap()
                if self.cleanup != "VERIFIED":
                    self.state = "ERROR"
                    self.error = self.error or "ANALYSIS_SHUTDOWN_UNVERIFIED"
                elif self.state == "VERIFYING":
                    self.state = "COMPLETED"

    async def _reap(self):
        if not self.process:
            return "NOT_STARTED"
        # The owned CLI starts a new OS session. Only its descendants can share
        # this process group; attached reports and external workers are untouched.
        pid = self.process.pid
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(pid, sig)
            except ProcessLookupError:
                await self.process.wait()
                return "VERIFIED"
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    os.killpg(pid, 0)
                except ProcessLookupError:
                    await self.process.wait()
                    return "VERIFIED"
                await asyncio.sleep(0.05)
        return "UNVERIFIED"

    async def stop(self):
        async with self._lock:
            if self.state not in ("STARTING", "RUNNING", "VERIFYING", "STOPPING"):
                return self.snapshot()
            self.state = "STOPPING"
            if self.monitor and not self.monitor.done():
                self.monitor.cancel()
                try:
                    await self.monitor
                except asyncio.CancelledError:
                    pass
            self.cleanup = await self._reap()
            self.state = "STOPPED" if self.cleanup == "VERIFIED" else "ERROR"
            if self.cleanup != "VERIFIED":
                self.error = "ANALYSIS_SHUTDOWN_UNVERIFIED"
            return self.snapshot()

    async def attach(self, directory: Path):
        async with self._lock:
            if (
                self.closed
                or self.cleanup == "UNVERIFIED"
                or self.state in ("STARTING", "RUNNING", "VERIFYING", "STOPPING")
            ):
                raise ValueError("ANALYSIS_MUST_STOP_BEFORE_ATTACH")
            result = await asyncio.to_thread(verify_result, directory.absolute())
            self.result = project_result(result)
            self.output = directory.absolute()
            self.session = str(result.incident_id)
            self.state = "IMPORTED_VERIFIED_REPORT"
            self.cleanup = "EXTERNAL_REPORT_NOT_OWNED"
            self.error = None
            return self.snapshot()

    async def close(self):
        await self.stop()
        if self.cleanup == "UNVERIFIED":
            raise ValueError("ANALYSIS_SHUTDOWN_UNVERIFIED")
        self.closed = True
        return self.snapshot()
