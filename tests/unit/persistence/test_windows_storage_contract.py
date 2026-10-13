"""Mocked Windows API CONTRACT only; these tests never establish native Windows safety."""

import ctypes
from contextlib import contextmanager
from dataclasses import replace
from pathlib import PureWindowsPath
from unittest.mock import Mock

import pytest

from soc_agent.review.persistence.secure_storage import FileIdentity, StorageSecurityError
from soc_agent.review.persistence.windows_storage import (
    ACE,
    ADMINISTRATORS,
    FULL_ACCESS,
    INHERITED,
    OWNER_RIGHTS,
    SYSTEM,
    NativeWin32,
    SecurityAttributes,
    Snapshot,
    WindowsStorage,
    canonical_path,
    verify,
)

USER = "contract-current-user"


def snapshot(*, directory=True, private=True):
    return Snapshot(
        FileIdentity(17, 42),
        directory,
        False,
        "NTFS",
        True,
        USER,
        private,
        tuple(
            ACE(sid, FULL_ACCESS, 3 if directory else INHERITED)
            for sid in (USER, SYSTEM, ADMINISTRATORS)
        ),
    )


@pytest.mark.parametrize(
    "change",
    [
        {"owner": "other-owner"},
        {"protected": False},
        {"reparse": True},
        {"filesystem": "FAT32"},
        {"filesystem": "ReFS"},
        {"persistent_acls": False},
        {"directory": False},
        {"aces": ()},
        {"aces": (ACE(USER, FULL_ACCESS, 3, kind=1),)},
        {"aces": (ACE(USER, FULL_ACCESS, 3, kind=5),)},
        {"aces": (ACE(USER, FULL_ACCESS, 3 | INHERITED),)},
        {"aces": (ACE(USER, FULL_ACCESS, 11),)},
        {"aces": (ACE("Everyone", FULL_ACCESS, 3),)},
        {"aces": (ACE("Users", FULL_ACCESS, 3 | INHERITED),)},
        {"aces": (ACE(USER, 0x120089, 3),)},
    ],
)
def test_restricted_acl_policy_fail_closed(change):
    with pytest.raises(StorageSecurityError):
        verify(replace(snapshot(), **change), USER, directory=True)


def test_creation_acl_and_inherited_file_contract():
    verify(snapshot(), USER, directory=True)
    verify(snapshot(directory=False, private=False), USER, directory=False)
    with pytest.raises(StorageSecurityError):
        verify(
            replace(
                snapshot(directory=False),
                aces=(ACE("Authenticated Users", FULL_ACCESS, INHERITED),),
            ),
            USER,
            directory=False,
        )


@pytest.mark.parametrize(
    "path",
    [
        r"relative\db.sqlite",
        r"C:\folder\..\db.sqlite",
        r"\\server\share\db.sqlite",
        r"\\?\C:\folder\db.sqlite",
        r"C:\folder\db.sqlite:payload",
        r"C:\CON\db.sqlite",
        "C:\\folder \\db.sqlite",
        "C:\\folder.\\db.sqlite",
    ],
)
def test_reject_unsupported_path_contract(path):
    with pytest.raises(StorageSecurityError):
        canonical_path(path)


def test_unicode_and_spaces_path_contract():
    assert (
        str(canonical_path(r"C:\private storage 한글\SOC data.sqlite"))
        == r"C:\private storage 한글\SOC data.sqlite"
    )


class ContractAPI:
    user = USER

    def __init__(self):
        self.events = []
        self.fixed = True
        self.fail_at = None

    def volume_root_owner(self):
        return "os-resolved-servicing-owner"

    def fixed_drive(self, root):
        return self.fixed

    @contextmanager
    def hold(self, path, *, share_delete=False):
        self.events.append(("open", path, share_delete))
        try:
            if path == self.fail_at:
                raise StorageSecurityError("Mock API failure")
            yield path
        finally:
            self.events.append(("close", path))

    def snapshot(self, handle):
        return snapshot(directory=not handle.endswith(".sqlite"))

    def create(self, path, *, directory):
        self.events.append(("create", path, directory))


def test_ancestor_handles_pin_no_delete_and_cleanup_on_failure():
    api = ContractAPI()
    api.fail_at = r"C:\private\child"
    with pytest.raises(StorageSecurityError):
        with WindowsStorage(api).guard(api.fail_at):
            pass
    assert api.events == [
        ("open", "C:\\", False),
        ("open", r"C:\private", False),
        ("open", r"C:\private\child", False),
        ("close", r"C:\private\child"),
        ("close", r"C:\private"),
        ("close", "C:\\"),
    ]
    api.events.clear()
    api.fixed = False
    with pytest.raises(StorageSecurityError):
        WindowsStorage(api).validate_directory(r"C:\private")
    assert not api.events


def test_secure_file_create_under_verified_parent_and_handle_identity():
    api = ContractAPI()
    path = PureWindowsPath(r"C:\private\db.sqlite")
    backend = WindowsStorage(api)
    backend.create_file(path)
    assert ("create", str(path), False) in api.events
    assert ("open", str(path), True) in api.events
    assert backend.validate_file(path) == FileIdentity(17, 42)
    assert api.events[0] == ("open", "C:\\", False)
    assert api.events[-1] == ("close", "C:\\")


def test_broad_ancestor_mutation_rights_rejected_even_if_inherited():
    base = snapshot(private=False)
    read_only = ACE("Users", 0x120089, INHERITED)
    verify(replace(base, aces=base.aces + (read_only,)), USER, directory=True, private=False)
    for mask in (0x10000, 0x40000, 0x80000, 0x40, 0x100, 0x40000000):
        with pytest.raises(StorageSecurityError):
            verify(
                replace(base, aces=base.aces + (ACE("Users", mask, INHERITED),)),
                USER,
                directory=True,
                private=False,
            )


@pytest.mark.parametrize("directory", (True, False))
def test_win32_creation_receives_descriptor_at_creation_and_closes_handle(directory):
    api = NativeWin32.__new__(NativeWin32)
    api.kernel = Mock()
    api.kernel.CreateFileW.return_value = 123
    api.kernel.CreateDirectoryW.return_value = True
    api._no_impersonation = Mock()
    api.user = USER
    api.snapshot = lambda _: snapshot(directory=False)

    @contextmanager
    def descriptor(*, directory):
        yield SecurityAttributes(ctypes.sizeof(SecurityAttributes), 456, False)

    api.descriptor = descriptor
    api.create(r"C:\private\new", directory=directory)
    function = api.kernel.CreateDirectoryW if directory else api.kernel.CreateFileW
    args = function.call_args.args
    security = ctypes.cast(args[1 if directory else 3], ctypes.POINTER(SecurityAttributes)).contents
    assert security.descriptor == 456 and not security.inherit
    if not directory:
        assert args[4] == 1  # CREATE_NEW; never open then repair permissions
        api.kernel.CloseHandle.assert_called_once_with(123)


# Public OS service identity from the reported observation; no user SID is retained.
OBSERVED_ROOT_OWNER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


class ObservedPathAPI(ContractAPI):
    def __init__(self):
        super().__init__()
        self.metadata = {
            "C:\\": replace(
                snapshot(private=False),
                owner=OBSERVED_ROOT_OWNER,
                aces=snapshot(private=False).aces + (ACE(OBSERVED_ROOT_OWNER, FULL_ACCESS, 0),),
            ),
            r"C:\Users": replace(snapshot(private=False), owner=SYSTEM),
            r"C:\Users\synthetic-user": replace(snapshot(private=False), owner=SYSTEM),
        }

    def volume_root_owner(self):
        return OBSERVED_ROOT_OWNER

    def snapshot(self, handle):
        return self.metadata.get(handle, snapshot())


def test_reported_root_owner_reproduces_original_ancestor_failure():
    api = ObservedPathAPI()
    # The old, ordinary ancestor policy rejects the reported root before any ACE checks.
    with pytest.raises(StorageSecurityError, match="Unexpected Windows storage owner"):
        verify(api.snapshot("C:\\"), USER, directory=True, private=False)


def test_observed_root_users_profile_appdata_chain_uses_scoped_root_policy():
    api = ObservedPathAPI()
    target = r"C:\Users\synthetic-user\AppData\Local\SOC"
    with WindowsStorage(api).guard(target):
        opens = [event for event in api.events if event[0] == "open"]
        assert opens[0] == ("open", "C:\\", False)
        assert opens[-1] == ("open", target, False)
        assert not any(event[0] == "close" for event in api.events)
    assert [event[1] for event in api.events if event[0] == "close"] == [
        event[1] for event in reversed(opens)
    ]


@pytest.mark.parametrize("private", (False, True))
def test_os_servicing_owner_not_allowed_on_ordinary_ancestor_or_private_storage(private):
    api = ObservedPathAPI()
    target = r"C:\Users\synthetic-user\SOC"
    location = target if private else r"C:\Users"
    api.metadata[location] = replace(snapshot(), owner=OBSERVED_ROOT_OWNER)
    with pytest.raises(StorageSecurityError, match="Unexpected Windows storage owner"):
        with WindowsStorage(api).guard(target):
            pass


@pytest.mark.parametrize("owner", ("untrusted-owner", "S-1-5-80-1-2-3-4-5"))
def test_unknown_root_owner_including_other_services_still_rejected(owner):
    api = ObservedPathAPI()
    api.metadata["C:\\"] = replace(api.metadata["C:\\"], owner=owner)
    with pytest.raises(StorageSecurityError, match="Unexpected Windows storage owner"):
        with WindowsStorage(api).guard(r"C:\Users\synthetic-user\SOC"):
            pass
    assert api.events == [("open", "C:\\", False), ("close", "C:\\")]


@pytest.mark.parametrize("location", ("C:\\", r"C:\Users", r"C:\Users\synthetic-user\SOC"))
@pytest.mark.parametrize("defect", ("reparse", "write_dac", "delete_child"))
def test_all_path_roles_keep_reparse_and_broad_mutation_guards(location, defect):
    api = ObservedPathAPI()
    base = api.snapshot(location)
    if defect == "reparse":
        api.metadata[location] = replace(base, reparse=True)
    else:
        mask = 0x40000 if defect == "write_dac" else 0x40
        api.metadata[location] = replace(base, aces=base.aces + (ACE("Users", mask, INHERITED),))
    with pytest.raises(StorageSecurityError):
        with WindowsStorage(api).guard(r"C:\Users\synthetic-user\SOC"):
            pass
    assert len([event for event in api.events if event[0] == "open"]) == len(
        [event for event in api.events if event[0] == "close"]
    )


def test_root_identity_resolution_failure_closes_root_and_does_not_open_descendants():
    api = ObservedPathAPI()
    api.volume_root_owner = Mock(side_effect=StorageSecurityError("Identity unavailable"))
    with pytest.raises(StorageSecurityError, match="Identity unavailable"):
        with WindowsStorage(api).guard(r"C:\Users\synthetic-user\SOC"):
            pass
    assert api.events == [("open", "C:\\", False), ("close", "C:\\")]


def test_private_drive_root_is_not_authorized_by_root_policy():
    with pytest.raises(StorageSecurityError, match="Unexpected Windows storage owner"):
        with WindowsStorage(ObservedPathAPI()).guard("C:\\"):
            pass


@pytest.mark.parametrize("domain,kind", (("NT SERVICE", 5), ("OTHER", 5), ("NT SERVICE", 1)))
def test_native_lookup_contract_checks_exact_namespace_and_type(monkeypatch, domain, kind):
    from soc_agent.review.persistence import windows_storage as windows

    api = NativeWin32.__new__(NativeWin32)
    api.security = Mock()
    api._no_impersonation = Mock()
    api._sid = Mock(return_value=OBSERVED_ROOT_OWNER)
    api.security.IsValidSid.return_value = True
    api.security.GetLengthSid.return_value = 32

    def lookup(system, name, sid, sid_size, domain_buffer, domain_size, use):
        assert system is None and name == r"NT SERVICE\TrustedInstaller"
        ctypes.cast(sid_size, ctypes.POINTER(windows.DWORD)).contents.value = 32
        ctypes.cast(domain_size, ctypes.POINTER(windows.DWORD)).contents.value = 32
        ctypes.cast(use, ctypes.POINTER(windows.DWORD)).contents.value = kind
        if sid is None:
            return False
        domain_buffer.value = domain
        return True

    api.security.LookupAccountNameW.side_effect = lookup
    monkeypatch.setattr(windows.c, "get_last_error", lambda: 122, raising=False)
    if domain == "NT SERVICE" and kind == 5:
        assert api.volume_root_owner() == OBSERVED_ROOT_OWNER
    else:
        with pytest.raises(StorageSecurityError, match="namespace"):
            api.volume_root_owner()


@pytest.mark.parametrize("owner", (USER, SYSTEM, ADMINISTRATORS))
@pytest.mark.parametrize("flags", (3, 3 | INHERITED))
def test_owner_rights_full_control_binds_to_trusted_ancestor_owner(owner, flags):
    # Reported pytest ancestor: SYSTEM/Admin/OWNER RIGHTS, with no explicit user ACE.
    metadata = replace(
        snapshot(private=False),
        owner=owner,
        aces=(
            ACE(SYSTEM, FULL_ACCESS, 3),
            ACE(ADMINISTRATORS, FULL_ACCESS, 3),
            ACE(OWNER_RIGHTS, FULL_ACCESS, flags),
        ),
    )
    verify(metadata, USER, directory=True, private=False)


@pytest.mark.parametrize("mask", (0x120089, 0x40000, 0x80000, 0x40))
def test_owner_rights_evaluates_explicit_read_or_mutation_grants_for_trusted_owner(mask):
    metadata = replace(snapshot(private=False), aces=(ACE(OWNER_RIGHTS, mask, 3),))
    verify(metadata, USER, directory=True, private=False)


@pytest.mark.parametrize("mask", (0x120089, FULL_ACCESS))
def test_owner_rights_does_not_authorize_unknown_owner_even_for_read_only(mask):
    metadata = replace(
        snapshot(private=False), owner="untrusted-owner", aces=(ACE(OWNER_RIGHTS, mask, 3),)
    )
    with pytest.raises(StorageSecurityError, match="Unexpected Windows storage owner"):
        verify(metadata, USER, directory=True, private=False)


@pytest.mark.parametrize("principal", ("Everyone", "Users", "Authenticated Users"))
def test_owner_rights_does_not_mask_other_broad_ancestor_mutation_grants(principal):
    metadata = replace(
        snapshot(private=False),
        aces=(ACE(OWNER_RIGHTS, FULL_ACCESS, 3), ACE(principal, 0x40000, INHERITED)),
    )
    with pytest.raises(StorageSecurityError, match="Unsafe ancestor"):
        verify(metadata, USER, directory=True, private=False)


@pytest.mark.parametrize(
    "ace",
    (
        ACE(OWNER_RIGHTS, FULL_ACCESS, 3, kind=1),
        ACE(OWNER_RIGHTS, FULL_ACCESS, 3, kind=5),
        ACE(OWNER_RIGHTS, FULL_ACCESS, 0x20),
        ACE(OWNER_RIGHTS, 0x02000000, 3),  # MAXIMUM_ALLOWED: ambiguous ACE access mask
        ACE(OWNER_RIGHTS, 0x00000200, 3),  # undefined file-access bit
    ),
)
def test_ambiguous_owner_rights_ace_still_fails_closed(ace):
    metadata = replace(snapshot(private=False), aces=(ace,))
    with pytest.raises(StorageSecurityError):
        verify(metadata, USER, directory=True, private=False)


@pytest.mark.parametrize("directory", (True, False))
def test_private_storage_rejects_owner_rights_even_with_explicit_current_user(directory):
    metadata = snapshot(directory=directory)
    metadata = replace(metadata, aces=metadata.aces + (ACE(OWNER_RIGHTS, FULL_ACCESS, 3),))
    with pytest.raises(StorageSecurityError, match="Broad or ambiguous"):
        verify(metadata, USER, directory=directory)


def test_owner_rights_uses_servicing_owner_only_in_verified_root_scope():
    metadata = replace(
        snapshot(private=False),
        owner=OBSERVED_ROOT_OWNER,
        aces=(ACE(OWNER_RIGHTS, FULL_ACCESS, 3),),
    )
    verify(
        metadata,
        USER,
        directory=True,
        private=False,
        volume_root_owner=OBSERVED_ROOT_OWNER,
    )
    with pytest.raises(StorageSecurityError, match="Unexpected Windows storage owner"):
        verify(metadata, USER, directory=True, private=False)


def test_owner_rights_pytest_ancestor_path_preserves_pinned_handle_walk():
    api = ObservedPathAPI()
    ancestor = r"C:\Users\synthetic-user\AppData\Local\Temp\pytest-root"
    target = ancestor + r"\SOC"
    api.metadata[ancestor] = replace(
        snapshot(private=False),
        aces=(
            ACE(SYSTEM, FULL_ACCESS, 3),
            ACE(ADMINISTRATORS, FULL_ACCESS, 3),
            ACE(OWNER_RIGHTS, FULL_ACCESS, 3),
        ),
    )
    with WindowsStorage(api).guard(target):
        opens = [event for event in api.events if event[0] == "open"]
        assert all(event[2] is False for event in opens)
        assert ("open", ancestor, False) in opens
        assert not any(event[0] == "close" for event in api.events)
    assert [event[1] for event in api.events if event[0] == "close"] == [
        event[1] for event in reversed(opens)
    ]


@pytest.mark.parametrize("protected", (True, False))
def test_native_fixture_uses_named_security_api_and_rechecks_protection(monkeypatch, protected):
    from tests.unit.persistence import test_native_windows_storage as fixture

    api = Mock()
    api._check = lambda ok: (
        None if ok else (_ for _ in ()).throw(StorageSecurityError("API failed"))
    )

    def get_dacl(descriptor, present, dacl, defaulted):
        ctypes.cast(present, ctypes.POINTER(ctypes.c_int32)).contents.value = 1
        ctypes.cast(dacl, ctypes.POINTER(ctypes.c_void_p)).contents.value = 456
        return True

    api.security.GetSecurityDescriptorDacl.side_effect = get_dacl
    api.security.SetNamedSecurityInfoW.return_value = 0
    observed = Mock(return_value=protected)
    monkeypatch.setattr(fixture, "dacl_protected", observed)
    fixture.apply_dacl(api, "test-fixture-only", ctypes.c_void_p(123), protected=protected)
    args = api.security.SetNamedSecurityInfoW.call_args.args
    assert args[1] == 1 and args[2] == (4 | (0x80000000 if protected else 0x20000000))
    assert args[5].value == 456
    observed.assert_called_once_with(api, "test-fixture-only")
    observed.return_value = not protected
    with pytest.raises(AssertionError, match="Fixture did not apply"):
        fixture.apply_dacl(api, "test-fixture-only", ctypes.c_void_p(123), protected=protected)
