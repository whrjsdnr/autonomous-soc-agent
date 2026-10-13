"""Actual Windows/NTFS tests only. Linux skip is NOT native security evidence."""

import ctypes
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from soc_agent.application import open_application_store
from soc_agent.desktop import initialize, prepare
from soc_agent.local_events import LocalJSONLSource
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.secure_storage import StorageSecurityError
from soc_agent.review.persistence.windows_storage import (
    FULL_ACCESS,
    INHERITED,
    NativeWin32,
    WindowsStorage,
    verify,
)
from soc_agent.state import IncidentState

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual native Windows/NTFS required")
ROOT = Path(__file__).parents[3]


@pytest.fixture
def native_directory(tmp_path):
    directory = tmp_path / "SOC private 한글 space"
    prepare(directory)
    return directory


def dacl_protected(api, path):
    """Query actual descriptor control even when a deliberately null DACL prevents snapshot."""
    descriptor = ctypes.c_void_p()
    with api.hold(str(path), share_delete=True) as handle:
        status = api.security.GetSecurityInfo(
            handle, 1, 4, None, None, None, None, ctypes.byref(descriptor)
        )
        api._check(status == 0)
        try:
            control, revision = ctypes.c_uint16(), ctypes.c_uint32()
            api._check(
                api.security.GetSecurityDescriptorControl(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)
                )
            )
            return bool(control.value & 0x1000)
        finally:
            api.kernel.LocalFree(descriptor)


def apply_dacl(api, path, descriptor, *, protected):
    function = api.security.SetNamedSecurityInfoW
    function.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    function.restype = ctypes.c_uint32
    present, defaulted, dacl = ctypes.c_int32(), ctypes.c_int32(), ctypes.c_void_p()
    api._check(
        api.security.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        )
    )
    assert present.value, "Fixture descriptor must include a DACL"
    control = 0x80000000 if protected else 0x20000000
    api._check(function(str(path), 1, 4 | control, None, None, dacl, None) == 0)
    observed = dacl_protected(api, path)
    assert observed == protected, "Fixture did not apply requested DACL protection state"


def set_dacl(api, path, text, *, protected=True):
    """Test-only mutation of dedicated temporary fixtures; no elevation or production repair."""
    descriptor = ctypes.c_void_p()
    api._check(
        api.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text, 1, ctypes.byref(descriptor), None
        )
    )
    try:
        apply_dacl(api, path, descriptor, protected=protected)
    finally:
        api.kernel.LocalFree(descriptor)


def restore_dacl(api, path, *, directory):
    with api.descriptor(directory=directory) as attributes:
        apply_dacl(api, path, attributes.descriptor, protected=True)


def test_secure_creation_reopen_owner_migration_and_restart(native_directory):
    path = native_directory / "SOC data 한글.sqlite"
    store = open_application_store(path, create=True)
    state = IncidentState()
    store.register(state)
    api = NativeWin32()
    with api.hold(str(path), share_delete=True) as handle:
        snapshot = api.snapshot(handle)
        owner_matches = snapshot.owner == api.user
        assert owner_matches, "Current-user ownership required"
        verify(snapshot, api.user, directory=False)
        assert all(ace.mask == FULL_ACCESS for ace in snapshot.aces)
    for _ in range(2):
        restarted = open_application_store(path)
        assert restarted.load(state.incident_id).state == state
        assert restarted.events()[0].event_type == "incident_registered"
        with restarted.database.transaction() as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 14


@pytest.mark.parametrize("principal", ("WD", "BU", "AU"))
def test_unsafe_broad_file_dacl_rejected_before_reopen(native_directory, principal):
    path = native_directory / "store.sqlite"
    store = SQLiteGovernanceStore.create(path)
    api = NativeWin32()
    try:
        set_dacl(api, path, f"D:P(A;;FA;;;{api.user})(A;;FA;;;{principal})")
        with pytest.raises(StorageSecurityError):
            store.events()
        with pytest.raises(StorageSecurityError):
            SQLiteGovernanceStore(path)
    finally:
        restore_dacl(api, path, directory=False)


@pytest.mark.parametrize("suffix", ("-journal", "-wal", "-shm"))
def test_unsafe_sqlite_sidecar_rejected_without_repair(native_directory, suffix):
    path = native_directory / "sidecar.sqlite"
    store = open_application_store(path, create=True)
    sidecar = path.with_name(path.name + suffix)
    backend = WindowsStorage()
    backend.create_file(sidecar)
    api = NativeWin32()
    try:
        set_dacl(api, sidecar, f"D:P(A;;FA;;;{api.user})(A;;FA;;;WD)")
        with pytest.raises(StorageSecurityError):
            store.events()
        with pytest.raises(StorageSecurityError):
            open_application_store(path)
        assert sidecar.exists(), "Unsafe sidecar must not be removed to hide failure"
        with api.hold(str(sidecar), share_delete=True) as handle:
            unchanged = any(ace.sid == "S-1-1-0" for ace in api.snapshot(handle).aces)
            assert unchanged, "Validation must not repair the unsafe sidecar"
    finally:
        restore_dacl(api, sidecar, directory=False)


def test_inherited_broad_ace_is_detected(native_directory):
    api = NativeWin32()
    child = native_directory / "inherited.txt"
    try:
        set_dacl(api, native_directory, f"D:P(A;OICI;FA;;;{api.user})(A;OICI;FA;;;WD)")
        child.write_bytes(b"synthetic fixture only")
        with api.hold(str(child), share_delete=True) as handle:
            snapshot = api.snapshot(handle)
            assert any(ace.flags & INHERITED and ace.sid == "S-1-1-0" for ace in snapshot.aces)
            with pytest.raises(StorageSecurityError):
                verify(snapshot, api.user, directory=False)
        with pytest.raises(StorageSecurityError):
            WindowsStorage(api).validate_directory(native_directory)
    finally:
        restore_dacl(api, native_directory, directory=True)
        if child.exists():
            restore_dacl(api, child, directory=False)


@pytest.mark.parametrize("principal", ("OW", "WD", "BU", "AU"))
def test_private_directory_rejects_owner_rights_and_broad_principals(native_directory, principal):
    api = NativeWin32()
    try:
        set_dacl(
            api,
            native_directory,
            f"D:P(A;OICI;FA;;;{api.user})(A;OICI;FA;;;{principal})",
        )
        assert dacl_protected(api, native_directory), "Protected alone does not make a DACL safe"
        with pytest.raises(StorageSecurityError, match="Broad or ambiguous"):
            WindowsStorage(api).validate_directory(native_directory)
    finally:
        restore_dacl(api, native_directory, directory=True)


def test_explicit_deny_and_unprotected_directory_rejected(native_directory):
    api = NativeWin32()
    try:
        set_dacl(api, native_directory, f"D:P(D;;WD;;;WD)(A;OICI;FA;;;{api.user})")
        with pytest.raises(StorageSecurityError):
            WindowsStorage(api).validate_directory(native_directory)
    finally:
        restore_dacl(api, native_directory, directory=True)


def test_actual_sqlite_journal_wal_shm(native_directory):
    path = native_directory / "store.sqlite"
    store = open_application_store(path, create=True)
    backend = WindowsStorage()
    with store.database.transaction() as connection:
        connection.execute("CREATE TABLE native_fixture (value INTEGER)")
        backend.validate_file(path.with_name(path.name + "-journal"))
    keeper = sqlite3.connect(path)
    try:
        assert keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        keeper.execute("BEGIN")
        keeper.execute("SELECT store_id FROM metadata").fetchone()
        state = IncidentState()
        store.register(state)
        for suffix in ("-wal", "-shm"):
            backend.validate_file(path.with_name(path.name + suffix))
        assert open_application_store(path).load(state.incident_id).state == state
    finally:
        keeper.close()


def test_network_and_device_namespace_paths_fail_closed():
    backend = WindowsStorage()
    for path in (r"\\unavailable\share\SOC", r"\\?\C:\SOC", r"C:\SOC\data:stream"):
        with pytest.raises(StorageSecurityError):
            backend.validate_directory(path)


def test_reparse_point_rejection_when_unprivileged_symlinks_available(native_directory):
    target = native_directory / "target"
    prepare(target)
    link = native_directory / "redirect"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Unprivileged symlink creation unavailable; no elevation attempted")
    with pytest.raises(StorageSecurityError):
        WindowsStorage().validate_directory(link)


def test_actual_windows_desktop_three_models_human_guard_restart(native_directory):
    from tests.scenarios.test_security_ai_fusion import PINS

    command = [
        sys.executable,
        "-m",
        "soc_agent.desktop",
        "--directory",
        str(native_directory),
        "--input",
        str(ROOT / "examples/live_security_ai_events.jsonl"),
    ]
    for kind, pin, _ in PINS:
        name = "auth" if kind == "authentication_anomaly" else kind.replace("_", "-")
        command.extend(
            [
                f"--{name}-package",
                str(ROOT / "tests/fixtures/security_ai_packages" / kind),
                "--manifest-digest" if name == "auth" else f"--{name}-digest",
                pin,
            ]
        )
    first = subprocess.run(command, capture_output=True, timeout=120)
    # Only fixed startup codes are included; arbitrary captured stderr is never echoed.
    diagnostic = "unclassified; raw output withheld"
    for line in first.stderr.decode("utf-8", errors="replace").splitlines():
        import re

        match = re.fullmatch(
            r"INPUT / CONFIGURATION / STARTUP \[(llm_configuration|package_auth|"
            r"package_network_classifier|package_network_anomaly|input_path|storage_prepare|"
            r"writer_lock|application_initialize|runtime_replay):"
            r"(dependency_unavailable|platform_api_unavailable|schema_validation|file_access|"
            r"validation|startup_failure)\]: Desktop unavailable; no fallback",
            line,
        )
        if match:
            diagnostic = f"{match[1]}:{match[2]}"
            break
    assert first.returncode == 0, f"Native Desktop CLI failed: {diagnostic}"
    service = initialize(native_directory).service
    assert service.dashboard_security_ai(lambda _: True).retained_signal_count == 3
    revisions = {}
    for event in LocalJSONLSource(ROOT / "examples/live_security_ai_events.jsonl").events():
        identity = service.ingest(event).incident_id
        workflow = service.workflow(identity)
        assert workflow.waiting_for_human
        revisions[identity] = workflow.checkpoint_revision
        checkpoint = service.checkpoint(identity)
        assert checkpoint.artifacts.execution_intent_id is None
        fusion = checkpoint.artifacts.assessment.model_derived_context
        assert len(fusion.signals) == (2 if event.event_type == "network" else 1)
        assert fusion.confidence_state == "unknown"
    with service.store.database.transaction() as connection:
        for table in ("reviews", "authorizations", "applications", "execution_records"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    assert subprocess.run(command, capture_output=True, timeout=120).returncode == 0
    restarted = initialize(native_directory).service
    assert all(
        restarted.workflow(identity).checkpoint_revision == revision
        for identity, revision in revisions.items()
    )


def test_null_dacl_and_unprotected_directory_fail_closed(native_directory):
    api = NativeWin32()
    try:
        set_dacl(api, native_directory, "D:NO_ACCESS_CONTROL")
        with pytest.raises(StorageSecurityError):
            WindowsStorage(api).validate_directory(native_directory)
        restore_dacl(api, native_directory, directory=True)
        set_dacl(api, native_directory, f"D:(A;OICI;FA;;;{api.user})", protected=False)
        assert dacl_protected(api, native_directory) is False
        with api.hold(str(native_directory)) as handle:
            assert api.snapshot(handle).protected is False
        with pytest.raises(StorageSecurityError, match="protected DACL"):
            WindowsStorage(api).validate_directory(native_directory)
    finally:
        restore_dacl(api, native_directory, directory=True)


def test_foreign_system_object_owner_or_dacl_is_not_private_storage():
    api = NativeWin32()
    get_directory = api.kernel.GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    get_directory.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(512)
    length = get_directory(buffer, len(buffer))
    assert 0 < length < len(buffer), "System directory metadata unavailable"
    path = Path(buffer.value) / "kernel32.dll"
    with api.hold(str(path), share_delete=True) as handle:
        metadata = api.snapshot(handle)
        with pytest.raises(StorageSecurityError):
            verify(metadata, api.user, directory=False)


def test_actual_unsupported_volume_fail_closed(pytestconfig):
    root = pytestconfig.getoption("--windows-unsupported-root")
    if root is None:
        pytest.skip("Actual FAT/exFAT/removable/remote drive fixture required")
    from soc_agent.review.persistence.windows_storage import DWORD, canonical_path

    path = canonical_path(root)
    api = NativeWin32()
    if api.fixed_drive(path.anchor):
        with api.hold(str(path)) as handle:
            filesystem = ctypes.create_unicode_buffer(32)
            flags, serial, maximum = DWORD(), DWORD(), DWORD()
            api._check(
                api.kernel.GetVolumeInformationByHandleW(
                    handle,
                    None,
                    0,
                    ctypes.byref(serial),
                    ctypes.byref(maximum),
                    ctypes.byref(flags),
                    filesystem,
                    len(filesystem),
                )
            )
            unsupported = filesystem.value != "NTFS" or not flags.value & 8
            assert unsupported, "Fixture must be an actual unsupported filesystem"
    with pytest.raises(StorageSecurityError):
        WindowsStorage(api).validate_directory(path)


def test_actual_drive_root_policy_and_pinned_path_walk(tmp_path):
    api = NativeWin32()
    root = Path(tmp_path.anchor)
    with WindowsStorage(api).guard(root, private=False):
        with api.hold(str(root)) as handle:
            metadata = api.snapshot(handle)
            verify(
                metadata,
                api.user,
                directory=True,
                private=False,
                volume_root_owner=api.volume_root_owner(),
            )
    # An existing ordinary user path remains subject to the ancestor policy.
    with WindowsStorage(api).guard(tmp_path, private=False):
        pass


def test_actual_owner_rights_ancestor_preserves_private_dacl_policy(native_directory):
    api = NativeWin32()
    backend = WindowsStorage(api)
    ancestor = native_directory / "OWNER RIGHTS ancestor"
    backend.create_directory(ancestor)
    try:
        set_dacl(api, ancestor, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-3-4)")
        with api.hold(str(ancestor)) as handle:
            metadata = api.snapshot(handle)
            assert metadata.owner == api.user, "Dedicated fixture must retain current-user owner"
            assert any(ace.sid == "S-1-3-4" and ace.mask == FULL_ACCESS for ace in metadata.aces)
        with backend.guard(ancestor, private=False):
            pass
        with pytest.raises(StorageSecurityError, match="Broad or ambiguous"):
            backend.validate_directory(ancestor)
        private_child = ancestor / "private child"
        backend.create_directory(private_child)
        backend.validate_directory(private_child)
        # Owner rights do not excuse a distinct broad WRITE_DAC grant on the ancestor.
        set_dacl(
            api,
            ancestor,
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-3-4)(A;;WD;;;BU)",
        )
        with pytest.raises(StorageSecurityError, match="Unsafe ancestor"):
            with backend.guard(ancestor, private=False):
                pass
    finally:
        restore_dacl(api, ancestor, directory=True)


def test_actual_unprotected_directory_inherits_and_private_child_is_protected(native_directory):
    api = NativeWin32()
    backend = WindowsStorage(api)
    child = native_directory / "inheritance fixture"
    backend.create_directory(child)
    try:
        set_dacl(api, child, f"D:(A;OICI;FA;;;{api.user})", protected=False)
        assert dacl_protected(api, child) is False
        with api.hold(str(child)) as handle:
            metadata = api.snapshot(handle)
            assert metadata.protected is False
            assert any(ace.flags & INHERITED for ace in metadata.aces)
        with pytest.raises(StorageSecurityError, match="protected DACL"):
            backend.validate_directory(child)
        backend.create_directory(child / "protected private child")
        assert dacl_protected(api, child / "protected private child") is True
        backend.validate_directory(child / "protected private child")
    finally:
        restore_dacl(api, child, directory=True)
