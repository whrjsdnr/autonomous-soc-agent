"""Linux local operator transport. The running monitor remains the only DB writer.

No HTTP, shell, OS response handler, automatic review, or configurable command execution.
An OS UID is a local trust identity, not proof of a physical person's presence.
"""

import asyncio
import errno
import json
import os
import socket
import stat
import struct
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from soc_agent.approval.errors import ApprovalError
from soc_agent.execution.errors import ExecutionError
from soc_agent.experience.failure import FailureQuery, capture_failure
from soc_agent.improvement_review.models import ReviewDecision
from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop, FailureFeedbackRequest
from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop, RuntimeFeedbackRequest
from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import create_private_directory, validate_directory
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp, utc_now

LIMIT = 8192
TIMEOUT = 5
PROTOCOL = "soc-local-operator:v1"


class OperatorRequest(Snapshot):
    protocol: Literal["soc-local-operator:v1"] = PROTOCOL
    request_id: UUID
    challenge: UUID
    created_at: UTCTimestamp
    command: Literal[
        "pending",
        "detail",
        "approve",
        "reject",
        "execute",
        "audit",
        "feedback",
        "experience",
        "feedback-submit",
        "feedback-list",
        "candidates",
        "candidate-review",
        "failure-experience",
        "failure-submit",
        "failure-list",
    ]
    candidate_id: Hash | None = None
    expected_digest: Hash | None = None
    finding_id: Hash | None = None
    feedback_request: RuntimeFeedbackRequest | None = None
    failure_query: FailureQuery | None = None
    failure_feedback: FailureFeedbackRequest | None = None
    review_decision: ReviewDecision | None = None
    expected_evaluation: Hash | None = None
    # No actor, credential, arbitrary tool, action target, or command field.


def peer_uid(sock) -> int:
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def endpoint(directory: Path) -> Path:
    validate_directory(directory)
    parent = directory / "operator"
    validate_directory(parent)
    return parent / "review.sock"


def socket_identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("OPERATOR_SOCKET_SECURITY_REJECTED")
    return info.st_dev, info.st_ino


def view(record, now=None):
    body = record.model_dump(mode="json")
    display = {
        "PENDING_REVIEW": "PENDING_APPROVAL",
        "DENIED": "BLOCKED",
        "STARTED": "UNCERTAIN",
    }.get(record.status, record.status)
    if (
        record.status in ("PENDING_REVIEW", "APPROVED")
        and record.approval.expires_at is not None
        and (now or utc_now()) >= record.approval.expires_at
    ):
        display = "EXPIRED"
    return {"record": body, "record_digest": content_digest_payload(body), "status": display}


class OperatorServer:
    def __init__(self, monitor, allowed_uids: tuple[int, ...]):
        if not allowed_uids or any(
            type(uid) is not int or uid != os.geteuid() for uid in allowed_uids
        ):
            raise ValueError("OPERATOR_ALLOWLIST_REJECTED")
        self.monitor = monitor
        self.allowed_uids = frozenset(allowed_uids)
        self.lock = asyncio.Lock()
        self.tasks: set[asyncio.Task] = set()
        self.server = None
        self.path = None
        self.identity = None
        self.closing = False

    async def start(self):
        directory = self.monitor.directory
        validate_directory(directory)
        create_private_directory(directory / "operator")
        self.path = endpoint(directory)
        if len(os.fsencode(self.path)) > 100:
            raise ValueError("OPERATOR_SOCKET_PATH_TOO_LONG")
        if self.path.exists() or self.path.is_symlink():
            identity = socket_identity(self.path)
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(0.1)
                try:
                    probe.connect(str(self.path))
                except OSError as error:
                    if error.errno != errno.ECONNREFUSED:
                        raise ValueError("OPERATOR_SOCKET_UNAVAILABLE") from error
                else:
                    raise ValueError("OPERATOR_SOCKET_ALREADY_ACTIVE")
            if socket_identity(self.path) != identity:
                raise ValueError("OPERATOR_SOCKET_IDENTITY_CHANGED")
            self.path.unlink()  # Only own stale socket under private directory and writer lock.
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(self.path))
            self.path.chmod(0o600)
            self.identity = socket_identity(self.path)
            sock.setblocking(False)
            self.server = await asyncio.start_unix_server(self.handle, sock=sock, limit=LIMIT + 1)
            self.monitor.store.event(
                "OPERATOR_STARTED",
                {
                    "allowed_uids": sorted(self.allowed_uids),
                    "actual_response_execution": "DISABLED",
                },
            )
        except BaseException:
            sock.close()
            await self.close()
            raise

    async def close(self):
        self.closing = True
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        tasks = tuple(t for t in self.tasks if t is not asyncio.current_task())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.path is not None and self.identity is not None and self.path.exists():
            if socket_identity(self.path) != self.identity:
                raise ValueError("OPERATOR_SOCKET_IDENTITY_CHANGED")
            self.path.unlink()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        overloaded = len(self.tasks) >= 8
        self.tasks.add(task)
        uid = None
        try:
            if (
                endpoint(self.monitor.directory) != self.path
                or socket_identity(self.path) != self.identity
            ):
                raise ValueError("OPERATOR_SOCKET_IDENTITY_CHANGED")
            sock = writer.get_extra_info("socket")
            uid = peer_uid(sock)
            if self.closing or overloaded or uid not in self.allowed_uids:
                raise ValueError("OPERATOR_PEER_DENIED")
            challenge = uuid4()
            writer.write(
                json.dumps({"protocol": PROTOCOL, "challenge": str(challenge)}).encode() + b"\n"
            )
            await writer.drain()
            raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=TIMEOUT)
            if len(raw) > LIMIT:
                raise ValueError("OPERATOR_REQUEST_TOO_LARGE")
            request = OperatorRequest.model_validate_json(raw)
            if (
                request.challenge != challenge
                or not 0 <= (utc_now() - request.created_at).total_seconds() <= 30
            ):
                raise ValueError("OPERATOR_FRESHNESS_REJECTED")
            await asyncio.wait_for(self.lock.acquire(), timeout=TIMEOUT)
            try:
                if (
                    endpoint(self.monitor.directory) != self.path
                    or socket_identity(self.path) != self.identity
                ):
                    raise ValueError("OPERATOR_SOCKET_IDENTITY_CHANGED")
                if (
                    self.closing
                    or self.monitor.stop_event.is_set()
                    or self.monitor.store.state()["stop_requested"]
                ):
                    raise ValueError("OPERATOR_RUNTIME_STOPPING")
                if peer_uid(sock) not in self.allowed_uids:
                    raise ValueError("OPERATOR_PEER_DENIED")
                self.monitor.store.verify_audit()
                with self.monitor.store.database.transaction() as c:
                    events = self.monitor.simulation._events(c)
                    if any(
                        e["kind"] == "OPERATOR_REQUEST"
                        and e["details"]["request_id"] == str(request.request_id)
                        for e in events
                    ):
                        raise ValueError("OPERATOR_REPLAY_DENIED")
                    self.monitor.store._audit(
                        c,
                        "OPERATOR_REQUEST",
                        {
                            "request_id": str(request.request_id),
                            "uid": uid,
                            "command": request.command,
                            "candidate": request.candidate_id,
                        },
                    )
                result = await asyncio.wait_for(self.dispatch(request, sock), timeout=TIMEOUT)
                self.monitor.store.event(
                    "OPERATOR_RECEIPT",
                    {
                        "request_id": str(request.request_id),
                        "uid": uid,
                        "result_digest": content_digest_payload({"result": result}),
                    },
                )
                response = {"ok": True, "request_id": str(request.request_id), "result": result}
            finally:
                self.lock.release()
        except (
            ValueError,
            OSError,
            StorageError,
            ApprovalError,
            ExecutionError,
            TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ) as error:
            # Failed audit means no success response. Never log raw request/error text.
            try:
                self.monitor.store.event(
                    "OPERATOR_DENIED", {"uid": uid, "category": type(error).__name__}
                )
            except (ValueError, OSError, StorageError):
                self.monitor.request_stop()
                self.closing = True
            response = {"ok": False, "status": "BLOCKED", "error": type(error).__name__}
        except asyncio.CancelledError:
            raise
        finally:
            self.tasks.discard(task)
            if "response" in locals() and not writer.is_closing():
                writer.write(json.dumps(response).encode() + b"\n")
                try:
                    await asyncio.wait_for(writer.drain(), timeout=TIMEOUT)
                except (OSError, TimeoutError):
                    pass  # Response transport failed; never replay a committed decision.
            writer.close()
            await writer.wait_closed()

    async def dispatch(self, request: OperatorRequest, sock):
        simulation = self.monitor.simulation
        feedback = RuntimeFeedbackLoop(self.monitor)
        failures = FailureFeedbackLoop(self.monitor)
        if request.command == "failure-experience":
            if request.failure_query is None:
                raise ValueError("FAILURE_QUERY_REQUIRED")
            return capture_failure(self.monitor, request.failure_query)
        if request.command == "failure-submit":
            if request.failure_feedback is None:
                raise ValueError("FAILURE_FEEDBACK_REQUIRED")
            return failures.submit(request.failure_feedback, sock).model_dump(mode="json")
        if request.command == "failure-list":
            return [v.model_dump(mode="json") for v in failures.records()]
        if request.command == "experience":
            from soc_agent.experience.runtime import capture_runtime_experience

            if request.finding_id is None:
                raise ValueError("FEEDBACK_FINDING_REQUIRED")
            return capture_runtime_experience(self.monitor, request.finding_id).model_dump(
                mode="json"
            )
        if request.command == "feedback-submit":
            if request.feedback_request is None:
                raise ValueError("FEEDBACK_REQUEST_REQUIRED")
            return feedback.submit(request.feedback_request, sock).model_dump(mode="json")
        if request.command == "feedback-list":
            return [v.model_dump(mode="json") for v in feedback.records()]
        if request.command == "candidates":
            return {
                "candidates": [
                    v.model_dump(mode="json")
                    for v in (*feedback.prepare_candidates(), *failures.prepare_candidates())
                ],
                "reviews": feedback.review_records(),
                "support_requirement": "TWO_NONOVERLAPPING_HUMAN_FP_OPINIONS",
            }
        if request.command == "candidate-review":
            if (
                request.candidate_id is None
                or request.review_decision is None
                or request.expected_evaluation is None
            ):
                raise ValueError("CANDIDATE_REVIEW_BINDING_REQUIRED")
            return feedback.review(
                request.candidate_id, request.review_decision, request.expected_evaluation, sock
            )
        if request.command == "feedback":
            from soc_agent.linux_runtime.feedback_projection import project_feedback

            return project_feedback(self.monitor)
        if request.command == "pending":
            return [
                view(r, simulation.clock())
                for r in simulation.records()
                if r.status == "PENDING_REVIEW"
            ]
        if request.command == "audit":
            with self.monitor.store.database.transaction(write=False) as c:
                rows = list(
                    c.execute(
                        "SELECT sequence,digest,payload FROM monitor_audit "
                        "ORDER BY sequence DESC LIMIT 100"
                    )
                )
            return [
                {
                    "sequence": r["sequence"],
                    "digest": r["digest"],
                    "kind": json.loads(r["payload"])["kind"],
                }
                for r in rows
            ]
        if request.candidate_id is None:
            raise ValueError("OPERATOR_CANDIDATE_REQUIRED")
        current = simulation.load(request.candidate_id)
        if request.command == "detail":
            return view(current, simulation.clock())
        if request.expected_digest != content_digest_payload(current.model_dump(mode="json")):
            raise ValueError("OPERATOR_REVIEW_SNAPSHOT_CHANGED")
        if request.command in ("approve", "reject"):
            result = simulation.review_peer(
                request.candidate_id, approve=request.command == "approve", peer_socket=sock
            )
        else:
            result = await simulation.execute(request.candidate_id)
        return view(result, simulation.clock())


async def operator_request(
    directory: Path,
    command: str,
    *,
    candidate_id=None,
    expected_digest=None,
    request_id=None,
    finding_id=None,
    feedback_request=None,
    failure_query=None,
    failure_feedback=None,
    review_decision=None,
    expected_evaluation=None,
):
    """Client performs no database writes, approvals, local fallbacks, or automatic retries."""
    path = endpoint(directory)
    identity = socket_identity(path)
    reader, writer = await asyncio.wait_for(
        asyncio.open_unix_connection(str(path), limit=1024 * 1024), timeout=TIMEOUT
    )
    try:
        if socket_identity(path) != identity:
            raise ValueError("OPERATOR_SOCKET_IDENTITY_CHANGED")
        if peer_uid(writer.get_extra_info("socket")) != os.geteuid():
            raise ValueError("OPERATOR_SERVER_IDENTITY_REJECTED")
        hello = json.loads(await asyncio.wait_for(reader.readuntil(b"\n"), timeout=TIMEOUT))
        if hello["protocol"] != PROTOCOL:
            raise ValueError("OPERATOR_PROTOCOL_REJECTED")
        request = OperatorRequest(
            request_id=request_id or uuid4(),
            challenge=UUID(hello["challenge"]),
            created_at=utc_now(),
            command=command,
            candidate_id=candidate_id,
            expected_digest=expected_digest,
            finding_id=finding_id,
            feedback_request=feedback_request,
            failure_query=failure_query,
            failure_feedback=failure_feedback,
            review_decision=review_decision,
            expected_evaluation=expected_evaluation,
        )
        writer.write(request.model_dump_json(exclude_none=True).encode() + b"\n")
        await writer.drain()
        return json.loads(await asyncio.wait_for(reader.readuntil(b"\n"), timeout=TIMEOUT))
    finally:
        writer.close()
        await writer.wait_closed()
