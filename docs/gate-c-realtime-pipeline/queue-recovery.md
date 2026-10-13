# Queue recovery and delivery contract

Isolated private `ingestion.sqlite` uses the existing GovernanceDatabase secure connection
lifecycle and POSIX/NTFS owner, ACL, symlink/reparse, inode and SQLite sidecar checks.
Its additive realtime_queue_config version 1 is independent of operating DB migrations.
The governance schema number is not relabelled. Existing runtime v16 storage is reused.

Defaults: 256 active events; retries 3; configuration must match on reopen. Capacity counts
PENDING + CLAIMED. Overflow rejects with backpressure, without changing the cursor. Retained
DONE/POISON tombstones stop at 100,000 records (no silent pruning; operator archival required).
Disk exhaustion also fails closed. These are record bounds, not an operational disk quota.

Enqueue, deduplication and checksummed cursor publication commit in one SQLite transaction.
Collector cursor may advance after durable enqueue, before inference: committed pending work
remains in SQLite. It never advances independently of an event commit. Source digest and
cursor linkage are revalidated. Checksums detect corruption; they are not signatures against
an attacker who already has write access to the trusted private storage.

```text
PENDING -> CLAIMED (unique token, attempt increment)
CLAIMED -> DONE (Runtime publication completed; guarded token acknowledgement)
CLAIMED -> PENDING / POISON (bounded failure)
crashed CLAIMED -> PENDING / POISON under exclusive process lock on restart
```

The service holds existing cross-platform advisory runtime lock for its entire lifetime.
OS releases the lock after process death; no stale mkdir lock is introduced. Direct Python
queue APIs require trusted callers to hold the same exclusive service lock before recovery.
No multi-worker distribution or untrusted in-process isolation is claimed.

At-least-once processing attempts with persistent dedup, NOT exactly-once execution. Runtime
and queue commits are separate. Ack loss can replay a committed runtime; stable incident/source
binding and checkpoint restore preserve the completed result. A no-op assessment does not
force incident revision. Conflicting source content/incident binding is rejected.

Graceful interrupt leaves committed work retained. A hard exit after claim is tested in a real
subprocess. Retry exhaustion preserves POISON records; failure category is sanitized and
never includes exception payload/raw evidence. An interrupted required external context can
remain fail-closed instead of being silently re-inferred or downgraded; inspect/reconcile it.
