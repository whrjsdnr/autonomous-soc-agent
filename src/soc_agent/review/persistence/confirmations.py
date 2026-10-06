"""Provider-verified confirmation consumption on the authoritative governance database."""

from copy import copy
from sqlite3 import Connection
from typing import Self
from uuid import UUID

from pydantic import model_validator

from soc_agent.review.authentication import HumanVerificationRecord
from soc_agent.review.authorization import permission_for
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError
from soc_agent.review.validation import checked
from soc_agent.state.evidence import UTCTimestamp, utc_now


class StoredConfirmation(Frozen):
    verification: HumanVerificationRecord
    consumed: bool
    consumed_at: UTCTimestamp | None = None
    consumer_reference: Hash | None = None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.consumed:
            if self.consumed_at is None or self.consumer_reference != content_digest(
                self.verification.context
            ):
                raise ValueError("Invalid confirmation consumption binding")
            if (
                not self.verification.confirmed_at
                <= self.consumed_at
                < self.verification.expires_at
            ):
                raise ValueError("Confirmation consumed outside validity interval")
        elif self.consumed_at is not None or self.consumer_reference is not None:
            raise ValueError("Unconsumed confirmation has consumer metadata")
        return self


def migrate_confirmations(database: GovernanceDatabase) -> None:
    """Explicit v2 -> v3; v1 callers first explicitly apply the execution migration."""
    with database.transaction() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version in (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):
            return
        if version != 2:
            raise UnsupportedSchemaError("Confirmation migration requires governance schema v2")
        connection.execute("""CREATE TABLE human_confirmations (
            provider_id TEXT NOT NULL, confirmation_id TEXT NOT NULL,
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
            consumed INTEGER NOT NULL CHECK(consumed IN (0,1)),
            payload TEXT NOT NULL, digest TEXT NOT NULL,
            PRIMARY KEY(provider_id, confirmation_id))""")
        connection.execute("PRAGMA user_version=3")


class SQLiteConfirmationConsumer:
    """Only consumes provider-verified receipts; never issues identity or human approval.

    Direct low-level storage calls are trusted application APIs. Model shape/digest
    does not establish authenticity. Inject into ProviderHumanAuthority, not Tool/LLM inputs.
    """

    def __init__(self, database: GovernanceDatabase) -> None:
        self.database = database
        self._connection: Connection | None = None
        with database.transaction(write=False) as connection:
            self._schema(connection)

    @staticmethod
    def _schema(connection: Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] not in (
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
        ):
            raise UnsupportedSchemaError("Explicit confirmation schema migration required")
        connection.execute("SELECT provider_id FROM human_confirmations LIMIT 0")

    def for_transaction(self, repository_id: UUID, connection: Connection) -> Self:
        if repository_id != self.database.store_id or not connection.in_transaction:
            raise StoredDataError("Confirmation transaction belongs to another store")
        # Verify the supplied connection identity as well, not only the caller's UUID.
        if self.database._metadata(connection) != repository_id:
            raise StoredDataError("Confirmation connection store identity mismatch")
        bound = copy(self)
        bound._connection = connection
        return bound

    @staticmethod
    def _load(connection: Connection, provider: str, identity: str) -> StoredConfirmation | None:
        row = connection.execute(
            "SELECT * FROM human_confirmations WHERE provider_id=? AND confirmation_id=?",
            (provider, identity),
        ).fetchone()
        if row is None:
            return None
        value = ledger.decode(StoredConfirmation, row)
        receipt = value.verification
        if (
            receipt.provider_id != row["provider_id"]
            or receipt.confirmation_id != row["confirmation_id"]
            or str(receipt.context.incident_id) != row["incident_id"]
            or value.consumed != bool(row["consumed"])
        ):
            raise StoredDataError("Stored confirmation columns mismatch")
        return value

    def load(self, provider: str, identity: str) -> StoredConfirmation | None:
        """Fresh idempotent query after uncertain commit; never grants permission."""
        with self.database.transaction(write=False) as connection:
            self._schema(connection)
            return self._load(connection, provider, identity)

    def consume(self, record: HumanVerificationRecord) -> None:
        record = checked(HumanVerificationRecord, record)
        if self._connection is not None:
            self._consume(self._connection, record)
        else:
            with self.database.transaction() as connection:
                self._consume(connection, record)

    def _consume(self, connection: Connection, record: HumanVerificationRecord) -> None:
        self._schema(connection)
        # Read wall clock after acquiring SQLite's write lock, not before waiting for it.
        now = utc_now()
        if not record.confirmed_at <= now < record.expires_at:
            raise HumanAuthorizationDenied("Confirmation expired or not yet valid")
        if record.permission != permission_for(record.context.action):
            raise HumanAuthorizationDenied("Confirmation permission/purpose mismatch")
        old = self._load(connection, record.provider_id, record.confirmation_id)
        if old is not None:
            # Verification time can change between processes; all identity/context fields cannot.
            if old.verification.model_dump(exclude={"verified_at"}) != record.model_dump(
                exclude={"verified_at"}
            ):
                raise HumanAuthorizationDenied("Confirmation reference binding changed")
            if old.consumed:
                raise HumanAuthorizationDenied("Confirmation already durably consumed")
        else:
            old = StoredConfirmation(verification=record, consumed=False)
            cursor = connection.execute(
                "INSERT INTO human_confirmations VALUES (?,?,?,?,?,?)",
                (
                    record.provider_id,
                    record.confirmation_id,
                    str(record.context.incident_id),
                    0,
                    ledger.serialize(old),
                    content_digest(old),
                ),
            )
            if cursor.rowcount != 1:
                raise StoredDataError("Confirmation registration failed")
        new = StoredConfirmation(
            verification=old.verification,
            consumed=True,
            consumed_at=now,
            consumer_reference=content_digest(record.context),
        )
        cursor = connection.execute(
            "UPDATE human_confirmations SET consumed=1,payload=?,digest=? "
            "WHERE provider_id=? AND confirmation_id=? AND consumed=0 AND digest=?",
            (
                ledger.serialize(new),
                content_digest(new),
                record.provider_id,
                record.confirmation_id,
                content_digest(old),
            ),
        )
        if cursor.rowcount != 1:
            raise HumanAuthorizationDenied("Concurrent or changed confirmation consumption")
