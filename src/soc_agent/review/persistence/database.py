"""Explicit private SQLite files and bounded transactions on local filesystems."""

import sqlite3
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from uuid import UUID, uuid4

from soc_agent.review.persistence.models import (
    CommitOutcomeUnknown,
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from soc_agent.review.persistence.schema import SCHEMA_VERSION, statements
from soc_agent.review.persistence.secure_storage import (
    StorageSecurityError,
    create_private_file,
    guard_directory,
    require_supported_platform,
    validate_database_files,
    validate_directory,
    validate_sidecars,
)


class GovernanceDatabase:
    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        self.path = self._path(path)
        if not 0 < timeout <= 60:
            raise ValueError("Database lock timeout must be in (0, 60] seconds")
        self.timeout = timeout
        self._identity = validate_database_files(self.path)
        with self.transaction(write=False, check_identity=False) as connection:
            self.store_id = self._metadata(connection)

    @staticmethod
    def _path(path: Path) -> Path:
        require_supported_platform()
        path = Path(path)
        if not path.is_absolute() or path.name in ("", ":memory:"):
            raise ValueError("An explicit absolute database file path is required")
        if not path.parent.is_dir():
            raise ValueError("Create a private database directory explicitly first")
        validate_directory(path.parent)
        return path

    def _permissions(self) -> None:
        if validate_database_files(self.path) != self._identity:
            raise StorageSecurityError("Database file identity changed; reopen requires inspection")

    @classmethod
    def create(cls, path: Path, *, timeout: float = 5.0) -> "GovernanceDatabase":
        if not 0 < timeout <= 60:
            raise ValueError("Database lock timeout must be in (0, 60] seconds")
        path = cls._path(path)
        validate_sidecars(path)
        create_private_file(path)
        with guard_directory(path.parent):
            identity = validate_database_files(path)
            connection = sqlite3.connect(
                path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=timeout
            )
            try:
                connection.execute("PRAGMA temp_store=MEMORY")
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                for statement in statements():
                    connection.execute(statement)
                connection.execute("INSERT INTO metadata VALUES (1, ?)", (str(uuid4()),))
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                if validate_database_files(path) != identity:
                    raise StorageSecurityError("Database file identity changed during creation")
                connection.commit()
            except sqlite3.Error as error:
                connection.rollback()
                raise StorageError("Schema creation failed; file was not silently reset") from error
            finally:
                connection.close()
        return cls(path, timeout=timeout)

    def _connect(self) -> sqlite3.Connection:
        self._permissions()
        # mode=rw prevents accidental re-creation if a file has disappeared.
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=self.timeout
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            self._permissions()
            return connection
        except BaseException:
            connection.close()
            raise

    def _metadata(self, connection: sqlite3.Connection) -> UUID:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        # v2 execution, v3 confirmations, v4 checkpoints are explicit additive migrations.
        if version not in (SCHEMA_VERSION, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14):
            raise UnsupportedSchemaError(
                "Unsupported governance schema version; migration required"
            )
        row = connection.execute("SELECT store_id FROM metadata WHERE singleton=1").fetchone()
        try:
            return UUID(row[0])
        except (TypeError, ValueError) as error:
            raise StoredDataError("Invalid persistent store identity") from error

    def core_schema_version(self, connection: sqlite3.Connection) -> int:
        """Validated legacy layout; extension readers must explicitly override this view."""
        self._metadata(connection)
        return connection.execute("PRAGMA user_version").fetchone()[0]

    def _commit(self, connection: sqlite3.Connection) -> None:
        connection.commit()

    @contextmanager
    def transaction(
        self, *, write: bool = True, check_identity: bool = True
    ) -> Iterator[sqlite3.Connection]:
        connection = None
        guards = ExitStack()
        try:
            guards.enter_context(guard_directory(self.path.parent))
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            store_id = self._metadata(connection)
            if check_identity and store_id != self.store_id:
                raise StoredDataError("Persistent store identity changed")
            try:
                self._permissions()
                yield connection
                self._permissions()
            except BaseException:
                connection.rollback()
                raise
            try:
                self._commit(connection)
            except (sqlite3.Error, OSError) as error:
                if connection.in_transaction:
                    try:
                        connection.rollback()
                    except sqlite3.Error as rollback_error:
                        raise CommitOutcomeUnknown(
                            "Rollback uncertain; reconcile persistent records"
                        ) from rollback_error
                    raise StorageError("Commit failed and transaction was rolled back") from error
                raise CommitOutcomeUnknown(
                    "Commit result uncertain; reconcile persistent records"
                ) from error
        except sqlite3.Error as error:
            raise StorageError("SQLite operation failed; transaction did not commit") from error
        finally:
            try:
                if connection is not None:
                    connection.close()
            finally:
                guards.close()
