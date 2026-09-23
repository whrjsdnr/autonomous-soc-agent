"""Explicit private SQLite files and bounded transactions on local filesystems."""

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID, uuid4

from soc_agent.review.persistence.models import (
    CommitOutcomeUnknown,
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from soc_agent.review.persistence.schema import SCHEMA_VERSION, statements


class GovernanceDatabase:
    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        self.path = self._path(path)
        if not 0 < timeout <= 60:
            raise ValueError("Database lock timeout must be in (0, 60] seconds")
        self.timeout = timeout
        self._permissions()
        with self.transaction(write=False, check_identity=False) as connection:
            self.store_id = self._metadata(connection)

    @staticmethod
    def _path(path: Path) -> Path:
        path = Path(path)
        if not path.is_absolute() or path.name in ("", ":memory:"):
            raise ValueError("An explicit absolute database file path is required")
        if not path.parent.is_dir():
            raise ValueError("Create a private database directory explicitly first")
        if path.parent.stat().st_mode & 0o077:
            raise ValueError("Database directory must be private (mode 0700)")
        return path

    def _permissions(self) -> None:
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Database must be a regular private file (mode 0600), not a symlink")

    @classmethod
    def create(cls, path: Path, *, timeout: float = 5.0) -> "GovernanceDatabase":
        if not 0 < timeout <= 60:
            raise ValueError("Database lock timeout must be in (0, 60] seconds")
        path = cls._path(path)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        connection = sqlite3.connect(path, isolation_level=None, timeout=timeout)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            for statement in statements():
                connection.execute(statement)
            connection.execute("INSERT INTO metadata VALUES (1, ?)", (str(uuid4()),))
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
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
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.Error:
            connection.close()
            raise

    def _metadata(self, connection: sqlite3.Connection) -> UUID:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise UnsupportedSchemaError(
                "Unsupported governance schema version; migration required"
            )
        row = connection.execute("SELECT store_id FROM metadata WHERE singleton=1").fetchone()
        try:
            return UUID(row[0])
        except (TypeError, ValueError) as error:
            raise StoredDataError("Invalid persistent store identity") from error

    def _commit(self, connection: sqlite3.Connection) -> None:
        connection.commit()

    @contextmanager
    def transaction(
        self, *, write: bool = True, check_identity: bool = True
    ) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            store_id = self._metadata(connection)
            if check_identity and store_id != self.store_id:
                raise StoredDataError("Persistent store identity changed")
            try:
                yield connection
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
            if connection is not None:
                connection.close()
