"""Actual POSIX storage checks and SQLite sidecar lifecycle; no Windows security claim."""

import os
import sqlite3

import pytest

from soc_agent.application import open_application_store
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.secure_storage import (
    StorageSecurityError,
    validate_database_files,
)
from soc_agent.state import IncidentState

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Actual POSIX filesystem required")


@pytest.mark.parametrize("suffix", ("-journal", "-wal", "-shm"))
def test_insecure_sidecar_rejected_before_sqlite_open_and_not_deleted(tmp_path, suffix):
    path = tmp_path / "store.sqlite"
    store = SQLiteGovernanceStore.create(path)
    sidecar = path.with_name(path.name + suffix)
    sidecar.write_bytes(b"untrusted sidecar")
    sidecar.chmod(0o644)
    with pytest.raises(StorageSecurityError):
        store.events()
    with pytest.raises(StorageSecurityError):
        SQLiteGovernanceStore(path)
    assert sidecar.read_bytes() == b"untrusted sidecar"
    assert sidecar.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("suffix", ("-journal", "-wal", "-shm"))
def test_sidecar_symlink_rejected_without_touching_target(tmp_path, suffix):
    path = tmp_path / "store.sqlite"
    store = SQLiteGovernanceStore.create(path)
    target = tmp_path / "external"
    target.write_bytes(b"unchanged")
    sidecar = path.with_name(path.name + suffix)
    sidecar.symlink_to(target)
    with pytest.raises(StorageSecurityError):
        store.events()
    assert sidecar.is_symlink() and target.read_bytes() == b"unchanged"


def test_parent_permissions_revalidated_on_each_transaction(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    store = SQLiteGovernanceStore.create(directory / "store.sqlite")
    directory.chmod(0o755)
    with pytest.raises(StorageSecurityError):
        store.events()
    directory.chmod(0o700)
    assert not store.events()
    store.database.path.chmod(0o644)
    with pytest.raises(StorageSecurityError):
        store.events()


def test_parent_symlink_and_inode_replacement_rejected(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    link = tmp_path / "redirect"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(StorageSecurityError):
        SQLiteGovernanceStore.create(link / "store.sqlite")
    path = directory / "store.sqlite"
    store = SQLiteGovernanceStore.create(path)
    original = directory / "original.sqlite"
    path.rename(original)
    SQLiteGovernanceStore.create(path)
    with pytest.raises(StorageSecurityError, match="identity"):
        store.events()


def test_unsafe_preexisting_sidecar_blocks_creation_without_database(tmp_path):
    path = tmp_path / "new.sqlite"
    sidecar = tmp_path / "new.sqlite-journal"
    sidecar.write_text("untrusted")
    sidecar.chmod(0o644)
    with pytest.raises(StorageSecurityError):
        SQLiteGovernanceStore.create(path)
    assert not path.exists() and sidecar.read_text() == "untrusted"


def test_real_wal_shm_unicode_path_schema_restart(tmp_path):
    directory = tmp_path / "private storage 한글"
    directory.mkdir(mode=0o700)
    path = directory / "SOC data 한글.sqlite"
    store = open_application_store(path, create=True)
    state = IncidentState()
    # Explicit test fixture sets WAL. Application never forces a journal mode.
    with sqlite3.connect(path) as keeper:
        assert keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        keeper.execute("BEGIN")
        keeper.execute("SELECT store_id FROM metadata").fetchone()
        store.register(state)
        for suffix in ("-wal", "-shm"):
            sidecar = path.with_name(path.name + suffix)
            assert sidecar.is_file()
            assert sidecar.stat().st_mode & 0o777 == 0o600
        validate_database_files(path)
        for _ in range(2):
            reopened = open_application_store(path)
            assert reopened.load(state.incident_id).state == state
            with reopened.database.transaction(write=False) as connection:
                assert connection.execute("PRAGMA user_version").fetchone()[0] == 14
                assert connection.execute("PRAGMA temp_store").fetchone()[0] == 2
                assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    keeper.close()
    assert open_application_store(path).load(state.incident_id).state == state


def test_actual_rollback_journal_private_and_failure_rolls_back(tmp_path):
    store = SQLiteGovernanceStore.create(tmp_path / "store.sqlite")
    journal = tmp_path / "store.sqlite-journal"
    with pytest.raises(StorageSecurityError):
        with store.database.transaction() as connection:
            assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            connection.execute("CREATE TABLE private_test (value INTEGER)")
            assert journal.exists() and journal.stat().st_mode & 0o777 == 0o600
            journal.chmod(0o644)
    # SQLite's normal rollback, not application code deleting sidecars.
    with store.database.transaction() as connection:
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='private_test'"
            ).fetchone()
            is None
        )


def test_owner_check_rejects_different_runtime_uid(tmp_path, monkeypatch):
    from soc_agent.review.persistence.secure_storage import validate_directory, validate_file

    path = tmp_path / "store.sqlite"
    SQLiteGovernanceStore.create(path)
    # Isolate the ownership predicate without changing actual ownership or elevating.
    monkeypatch.setattr(os, "geteuid", lambda: path.lstat().st_uid + 1)
    with pytest.raises(StorageSecurityError, match="owned"):
        validate_directory(tmp_path)
    with pytest.raises(StorageSecurityError, match="owned"):
        validate_file(path)
