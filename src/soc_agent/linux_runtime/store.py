"""Private companion job ledger. Does not migrate or rewrite existing incident databases."""

import json
from datetime import datetime
from pathlib import Path

from soc_agent.linux_runtime.models import Finding, RuntimeConfig
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.state.evidence import utc_now


class RuntimeStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.database = GovernanceDatabase(directory / "monitor.sqlite")
        with self.database.transaction(write=False) as c:
            row = c.execute("SELECT payload,digest FROM monitor_config WHERE id=1").fetchone()
            self.config = RuntimeConfig.model_validate_json(row["payload"])
            if self.config.digest != row["digest"]:
                raise ValueError("RUNTIME_CONFIG_INTEGRITY_REJECTED")
        self.verify_audit()

    @classmethod
    def create(cls, directory: Path, config: RuntimeConfig):
        db = GovernanceDatabase.create(directory / "monitor.sqlite")
        with db.transaction() as c:
            c.execute(
                "CREATE TABLE monitor_config(id INTEGER PRIMARY KEY,payload TEXT,digest TEXT)"
            )
            c.execute(
                "INSERT INTO monitor_config VALUES(1,?,?)",
                (config.model_dump_json(), config.digest),
            )
            c.execute(
                "CREATE TABLE monitor_state(id INTEGER PRIMARY KEY,payload TEXT,digest "
                "TEXT,stop_requested INTEGER NOT NULL)"
            )
            initial = {
                "state": "STOPPED",
                "heartbeat": utc_now().isoformat(),
                "last_error": None,
                "collector": "NOT_STARTED",
                "cursor_health": "UNKNOWN",
                "llm": "NOT_CONFIGURED",
                "started_at": None,
                "last_collection": None,
                "last_investigation": None,
                "circuit_open": False,
                "llm_failures": 0,
                "collection_failures": 0,
            }
            c.execute(
                "INSERT INTO monitor_state VALUES(1,?,?,0)",
                (json.dumps(initial), content_digest_payload(initial)),
            )
            c.execute(
                "CREATE TABLE monitor_findings(id TEXT PRIMARY KEY,payload TEXT NOT "
                "NULL,digest TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT "
                "NULL,result TEXT,result_digest TEXT,next_attempt TEXT,state_digest TEXT "
                "NOT NULL)"
            )
            c.execute("CREATE INDEX monitor_jobs ON monitor_findings(status)")
            c.execute(
                "CREATE TABLE monitor_audit(sequence INTEGER PRIMARY KEY,payload TEXT NOT "
                "NULL,digest TEXT NOT NULL)"
            )
        result = cls(directory)
        result.event("INITIALIZED", {"config_digest": config.digest})
        return result

    @staticmethod
    def _audit(c, kind, details):
        last = c.execute(
            "SELECT sequence,digest FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        payload = {
            "sequence": last["sequence"] + 1 if last else 1,
            "previous": last["digest"] if last else "0" * 64,
            "kind": kind,
            "details": details,
            "at": utc_now().isoformat(),
        }
        c.execute(
            "INSERT INTO monitor_audit VALUES(?,?,?)",
            (payload["sequence"], json.dumps(payload), content_digest_payload(payload)),
        )

    def verify_audit(self):
        previous = "0" * 64
        with self.database.transaction(write=False) as c:
            for index, row in enumerate(
                c.execute("SELECT * FROM monitor_audit ORDER BY sequence"), 1
            ):
                payload = json.loads(row["payload"])
                if (
                    payload["sequence"] != index
                    or payload["previous"] != previous
                    or content_digest_payload(payload) != row["digest"]
                ):
                    raise ValueError("RUNTIME_AUDIT_INTEGRITY_REJECTED")
                previous = row["digest"]
        return previous

    def event(self, kind, details):
        with self.database.transaction() as c:
            self._audit(c, kind, details)

    def invocation_event(self, finding: Finding, attempt: int, kind: str, details: dict):
        """Commit safe invocation metadata before/after the nontransactional provider call."""
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT * FROM monitor_findings WHERE id=?", (finding.finding_id,)
            ).fetchone()
            if row is None or self._decode(row) != finding:
                raise ValueError("LLM_INVOCATION_BINDING_REJECTED")
            if row["status"] != "RUNNING" or row["attempts"] != attempt:
                raise ValueError("LLM_INVOCATION_ATTEMPT_REJECTED")
            self._audit(c, kind, details | {"finding": finding.finding_id, "attempt": attempt})

    def state(self):
        with self.database.transaction(write=False) as c:
            row = c.execute("SELECT * FROM monitor_state WHERE id=1").fetchone()
            body = json.loads(row["payload"])
            if content_digest_payload(body) != row["digest"] or row["stop_requested"] not in (0, 1):
                raise ValueError("RUNTIME_STATE_INTEGRITY_REJECTED")
            return body | {"stop_requested": bool(row["stop_requested"])}

    def update(self, **fields):
        with self.database.transaction() as c:
            row = c.execute("SELECT * FROM monitor_state WHERE id=1").fetchone()
            body = json.loads(row["payload"])
            if content_digest_payload(body) != row["digest"]:
                raise ValueError("RUNTIME_STATE_INTEGRITY_REJECTED")
            body.update(fields)
            body["heartbeat"] = utc_now().isoformat()
            c.execute(
                "UPDATE monitor_state SET payload=?,digest=? WHERE id=1",
                (json.dumps(body), content_digest_payload(body)),
            )

    def request_stop(self, requested=True):
        with self.database.transaction() as c:
            c.execute("UPDATE monitor_state SET stop_requested=? WHERE id=1", (int(requested),))
            self._audit(c, "STOP_REQUEST" if requested else "START_REQUEST", {})

    def recover(self):
        with self.database.transaction() as c:
            rows = c.execute("SELECT * FROM monitor_findings").fetchall()
            for row in rows:
                finding = self._decode(row)  # Never repair a tampered row by restamping it.
                if row["status"] != "RUNNING":
                    continue
                if self.config.assessment_mode == "REAL_LLM":
                    # No atomicity exists between SQLite and the provider. Fail closed even
                    # if this crash preceded submission; legacy ledgers have no call intent.
                    result = {
                        "finding_digest": finding.digest,
                        "failure": "INTERRUPTED_REAL_LLM_REQUIRES_REVIEW",
                        "invocation_outcome": "UNKNOWN",
                        "llm_calls": None,
                        "token_usage": None,
                        "cost_estimate": None,
                        "write_disposition": "WRITE_DENIED",
                    }
                    c.execute(
                        "UPDATE monitor_findings SET status='BLOCKED',result=?,result_digest=? "
                        "WHERE id=?",
                        (json.dumps(result), content_digest_payload(result), row["id"]),
                    )
                else:
                    c.execute(
                        "UPDATE monitor_findings SET status='PENDING' WHERE id=?", (row["id"],)
                    )
                self._stamp(c, row["id"])
                self._audit(
                    c,
                    "INVESTIGATION_RECOVERED",
                    {
                        "finding": row["id"],
                        "requires_review": self.config.assessment_mode == "REAL_LLM",
                    },
                )

    def put(self, finding: Finding):
        with self.database.transaction() as c:
            old = c.execute(
                "SELECT * FROM monitor_findings WHERE id=?", (finding.finding_id,)
            ).fetchone()
            if old:
                self._decode(old)
                return False  # Preserve first triggering snapshot per rule/source/window.
            if (
                c.execute(
                    "SELECT count(*) FROM monitor_findings WHERE status IN ('PENDING','RUNNING')"
                ).fetchone()[0]
                >= self.config.pending_limit
            ):
                raise ValueError("INVESTIGATION_BACKPRESSURE")
            c.execute(
                "INSERT INTO monitor_findings VALUES(?,?,?,'PENDING',0,NULL,NULL,NULL,'UNSTAMPED')",
                (finding.finding_id, finding.model_dump_json(), finding.digest),
            )
            self._audit(
                c,
                "FINDING_RECORDED",
                {"finding": finding.finding_id, "source_count": len(finding.event_references)},
            )
            self._stamp(c, finding.finding_id)
            return True

    @staticmethod
    def _stamp(c, identity):
        row = c.execute("SELECT * FROM monitor_findings WHERE id=?", (identity,)).fetchone()
        payload = {
            k: row[k]
            for k in ("id", "digest", "status", "attempts", "result_digest", "next_attempt")
        }
        c.execute(
            "UPDATE monitor_findings SET state_digest=? WHERE id=?",
            (content_digest_payload(payload), identity),
        )

    @staticmethod
    def _decode(row):
        state = {
            k: row[k]
            for k in ("id", "digest", "status", "attempts", "result_digest", "next_attempt")
        }
        if content_digest_payload(state) != row["state_digest"] or row["status"] not in (
            "PENDING",
            "RUNNING",
            "DONE",
            "DONE_READ_ONLY",
            "DONE_SCRIPTED",
            "FAILED",
            "BLOCKED",
        ):
            raise ValueError("INVESTIGATION_STATE_INTEGRITY_REJECTED")
        finding = Finding.model_validate_json(row["payload"])
        if finding.finding_id != row["id"] or finding.digest != row["digest"]:
            raise ValueError("FINDING_INTEGRITY_REJECTED")
        if (
            row["result"] is not None
            and content_digest_payload(json.loads(row["result"])) != row["result_digest"]
        ):
            raise ValueError("INVESTIGATION_RESULT_INTEGRITY_REJECTED")
        if (
            row["status"] in ("DONE", "DONE_READ_ONLY", "DONE_SCRIPTED", "FAILED", "BLOCKED")
            and row["result"] is None
        ):
            raise ValueError("INVESTIGATION_COMPLETION_RECEIPT_MISSING")
        if (
            row["result"] is not None
            and json.loads(row["result"]).get("finding_digest") != finding.digest
        ):
            raise ValueError("INVESTIGATION_RESULT_BINDING_MISMATCH")
        return finding

    def claim(self):
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT * FROM monitor_findings WHERE status='PENDING' AND (next_attempt "
                "IS NULL OR next_attempt<=?) ORDER BY rowid LIMIT 1",
                (utc_now().isoformat(),),
            ).fetchone()
            if not row:
                return None
            finding = self._decode(row)
            if row["attempts"] >= self.config.investigation_retry_limit + 2:
                result = {
                    "finding_digest": finding.digest,
                    "failure": "RECOVERY_ATTEMPT_LIMIT",
                    "llm_calls": None,
                    "token_usage": None,
                    "cost_estimate": None,
                }
                c.execute(
                    "UPDATE monitor_findings SET status='FAILED',result=?,result_digest=? "
                    "WHERE id=?",
                    (json.dumps(result), content_digest_payload(result), row["id"]),
                )
                self._stamp(c, row["id"])
                self._audit(c, "RECOVERY_ATTEMPT_LIMIT", {"finding": row["id"]})
                return None
            c.execute(
                "UPDATE monitor_findings SET status='RUNNING',attempts=attempts+1 WHERE id=?",
                (row["id"],),
            )
            self._stamp(c, row["id"])
            self._audit(c, "INVESTIGATION_STARTED", {"finding": row["id"]})
            return finding, row["attempts"] + 1

    def finish(
        self, finding: Finding, status: str, result: dict, *, next_attempt: datetime | None = None
    ):
        if status not in (
            "PENDING",
            "DONE",
            "DONE_READ_ONLY",
            "DONE_SCRIPTED",
            "FAILED",
            "BLOCKED",
        ):
            raise ValueError("INVALID_JOB_STATUS")
        if result.get("finding_digest") != finding.digest:
            raise ValueError("INVESTIGATION_RESULT_BINDING_MISMATCH")
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT * FROM monitor_findings WHERE id=?", (finding.finding_id,)
            ).fetchone()
            if row is None or self._decode(row) != finding:
                raise ValueError("INVESTIGATION_COMPLETION_BINDING_REJECTED")
            changed = c.execute(
                "UPDATE monitor_findings SET "
                "status=?,result=?,result_digest=?,next_attempt=? WHERE id=? AND "
                "status='RUNNING' AND digest=?",
                (
                    status,
                    json.dumps(result),
                    content_digest_payload(result),
                    next_attempt.isoformat() if next_attempt else None,
                    finding.finding_id,
                    finding.digest,
                ),
            ).rowcount
            if changed != 1:
                raise ValueError("STALE_INVESTIGATION_COMPLETION")
            self._stamp(c, finding.finding_id)
            self._audit(
                c,
                "INVESTIGATION_" + status,
                {"finding": finding.finding_id, "result_digest": content_digest_payload(result)},
            )

    def jobs(self):
        counts = {}
        with self.database.transaction(write=False) as c:
            for row in c.execute("SELECT * FROM monitor_findings"):
                self._decode(row)
                counts[row["status"]] = counts.get(row["status"], 0) + 1
        return counts
