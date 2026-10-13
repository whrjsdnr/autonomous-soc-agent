"""Native Windows NTFS storage: restricted ACL policy and narrow ctypes API adapter.

Linux contract tests exercise policy/adapter orchestration only. Native Windows
validation is mandatory before any supported-platform or production claim.
"""

import ctypes as c
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Protocol

from soc_agent.review.persistence.secure_storage import FileIdentity, StorageSecurityError

DWORD = c.c_uint32
BOOL = c.c_int32
WORD = c.c_uint16
PTR = c.c_void_p
FULL_ACCESS = 0x001F01FF
SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
OWNER_RIGHTS = "S-1-3-4"
REPARSE = 0x400
DIRECTORY = 0x10
INHERIT_ONLY = 0x08
INHERITED = 0x10
PROTECTED = 0x1000
DANGEROUS_PARENT = 0x500D0150  # generic write/all, delete, write DAC/owner, child delete, EA/attrs


@dataclass(frozen=True)
class ACE:
    sid: str
    mask: int
    flags: int
    kind: int = 0  # ACCESS_ALLOWED_ACE_TYPE only; deny/object/callback types fail closed


@dataclass(frozen=True)
class Snapshot:
    identity: FileIdentity
    directory: bool
    reparse: bool
    filesystem: str
    persistent_acls: bool
    owner: str
    protected: bool
    aces: tuple[ACE, ...]


def canonical_path(path: Path | str) -> PureWindowsPath:
    text = str(path)
    value = PureWindowsPath(text)
    if (
        not value.is_absolute()
        or not re.fullmatch(r"[A-Za-z]:", value.drive)
        or len(text) > 240
        or any(part in (".", "..") for part in re.split(r"[\\/]", text)[1:])
    ):
        raise StorageSecurityError(
            "Explicit local Windows drive path required; no namespaces/traversal"
        )
    for part in value.parts[1:]:
        name = part.split(".")[0].upper()
        if (
            ":" in part
            or part.endswith((".", " "))
            or name in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", name)
        ):
            raise StorageSecurityError("Unsupported Windows storage path component")
    return value


def verify(
    snapshot: Snapshot,
    user: str,
    *,
    directory: bool,
    private: bool = True,
    volume_root_owner: str | None = None,
) -> None:
    if snapshot.reparse or snapshot.directory != directory:
        raise StorageSecurityError("Storage reparse points or unexpected object types forbidden")
    if snapshot.filesystem != "NTFS" or not snapshot.persistent_acls:
        raise StorageSecurityError("Local NTFS with persistent ACLs required")
    allowed = {user, SYSTEM, ADMINISTRATORS}
    # Only guard's canonical drive-root branch supplies this OS-resolved identity.
    # An owner has implicit ACL authority; unknown root owners cannot simply be ignored.
    if volume_root_owner is not None:
        if private or not directory:
            raise StorageSecurityError("Volume-root policy cannot authorize private storage")
        allowed.add(volume_root_owner)
    if snapshot.owner not in ({user} if private else allowed):
        raise StorageSecurityError("Unexpected Windows storage owner")
    if private and directory and not snapshot.protected:
        raise StorageSecurityError("Storage directory requires a protected DACL")
    if not snapshot.aces or len(snapshot.aces) > 64:
        raise StorageSecurityError("Missing or unsupported Windows DACL")
    user_access = False
    for ace in snapshot.aces:
        if ace.kind != 0 or ace.flags & ~0x1F:
            raise StorageSecurityError(
                "Unsupported deny/object/callback ACE; no permission inference"
            )
        if private:
            if ace.sid not in allowed or ace.mask != FULL_ACCESS or ace.flags & INHERIT_ONLY:
                raise StorageSecurityError("Broad or ambiguous Windows storage access rejected")
            if directory and (ace.flags & 3 != 3 or ace.flags & (INHERITED | 4)):
                raise StorageSecurityError(
                    "Private directory requires explicit inheritable allow ACEs"
                )
            if ace.sid == user:
                user_access = True
        else:
            # OWNER RIGHTS denotes this object's validated owner, not a broad group
            # or CREATOR OWNER substitution. Evaluate the actual allow mask only;
            # do not assume implicit READ_CONTROL/WRITE_DAC in its presence.
            grantee = ace.sid
            if ace.sid == OWNER_RIGHTS:
                if ace.mask & ~(FULL_ACCESS | 0xF0000000):
                    raise StorageSecurityError("Unsupported OWNER RIGHTS access mask")
                grantee = snapshot.owner
            if not ace.flags & INHERIT_ONLY and grantee not in allowed:
                if ace.mask & DANGEROUS_PARENT:
                    raise StorageSecurityError("Unsafe ancestor directory modification rights")
    if private and not user_access:
        raise StorageSecurityError("Current user lacks explicit full storage access")


class FileTime(c.Structure):
    _fields_ = [("low", DWORD), ("high", DWORD)]


class FileInformation(c.Structure):
    _fields_ = [
        ("attributes", DWORD),
        ("created", FileTime),
        ("accessed", FileTime),
        ("written", FileTime),
        ("volume", DWORD),
        ("size_high", DWORD),
        ("size_low", DWORD),
        ("links", DWORD),
        ("index_high", DWORD),
        ("index_low", DWORD),
    ]


class SecurityAttributes(c.Structure):
    _fields_ = [("length", DWORD), ("descriptor", PTR), ("inherit", BOOL)]


class TokenUser(c.Structure):
    _fields_ = [("sid", PTR), ("attributes", DWORD)]


class ACLSize(c.Structure):
    _fields_ = [("count", DWORD), ("used", DWORD), ("free", DWORD)]


class ACEHeader(c.Structure):
    _fields_ = [("kind", c.c_ubyte), ("flags", c.c_ubyte), ("size", WORD)]


class NativeWin32:
    """Own all native handles/LocalAlloc buffers; no elevation or impersonation."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise StorageSecurityError("Native Windows security API unavailable")
        try:
            self.kernel = c.WinDLL("kernel32", use_last_error=True)
            self.security = c.WinDLL("advapi32", use_last_error=True)
            self._bind()
            self.user = self._user()
        except (AttributeError, OSError):
            raise StorageSecurityError("Windows security APIs unavailable; no fallback") from None

    def _bind(self) -> None:
        def bind(dll, name, args, result):
            function = getattr(dll, name)
            function.argtypes, function.restype = args, result

        p = c.POINTER
        for name, args, result in (
            ("GetCurrentProcess", [], PTR),
            ("GetCurrentThread", [], PTR),
            ("CloseHandle", [PTR], BOOL),
            ("LocalFree", [PTR], PTR),
            ("GetDriveTypeW", [c.c_wchar_p], DWORD),
            ("CreateFileW", [c.c_wchar_p, DWORD, DWORD, PTR, DWORD, DWORD, PTR], PTR),
            ("CreateDirectoryW", [c.c_wchar_p, PTR], BOOL),
            ("GetFileInformationByHandle", [PTR, p(FileInformation)], BOOL),
            (
                "GetVolumeInformationByHandleW",
                [PTR, c.c_wchar_p, DWORD, p(DWORD), p(DWORD), p(DWORD), c.c_wchar_p, DWORD],
                BOOL,
            ),
        ):
            bind(self.kernel, name, args, result)
        for name, args, result in (
            ("OpenProcessToken", [PTR, DWORD, p(PTR)], BOOL),
            ("OpenThreadToken", [PTR, DWORD, BOOL, p(PTR)], BOOL),
            ("GetTokenInformation", [PTR, DWORD, PTR, DWORD, p(DWORD)], BOOL),
            ("ConvertSidToStringSidW", [PTR, p(PTR)], BOOL),
            ("IsValidSid", [PTR], BOOL),
            ("GetLengthSid", [PTR], DWORD),
            (
                "LookupAccountNameW",
                [c.c_wchar_p, c.c_wchar_p, PTR, p(DWORD), c.c_wchar_p, p(DWORD), p(DWORD)],
                BOOL,
            ),
            (
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                [c.c_wchar_p, DWORD, p(PTR), p(DWORD)],
                BOOL,
            ),
            ("GetSecurityInfo", [PTR, DWORD, DWORD, p(PTR), p(PTR), p(PTR), p(PTR), p(PTR)], DWORD),
            ("IsValidSecurityDescriptor", [PTR], BOOL),
            ("GetSecurityDescriptorOwner", [PTR, p(PTR), p(BOOL)], BOOL),
            ("GetSecurityDescriptorDacl", [PTR, p(BOOL), p(PTR), p(BOOL)], BOOL),
            ("GetSecurityDescriptorControl", [PTR, p(WORD), p(DWORD)], BOOL),
            ("IsValidAcl", [PTR], BOOL),
            ("GetAclInformation", [PTR, PTR, DWORD, DWORD], BOOL),
            ("GetAce", [PTR, DWORD, p(PTR)], BOOL),
        ):
            bind(self.security, name, args, result)

    @staticmethod
    def _check(ok) -> None:
        if not ok:
            raise StorageSecurityError(
                "Win32 storage verification failed or permission unavailable"
            )

    def _no_impersonation(self) -> None:
        token = PTR()
        if self.security.OpenThreadToken(self.kernel.GetCurrentThread(), 8, True, c.byref(token)):
            self.kernel.CloseHandle(token)
            raise StorageSecurityError("Impersonated storage operations are unsupported")
        if c.get_last_error() != 1008:  # ERROR_NO_TOKEN
            raise StorageSecurityError("Thread security context cannot be verified")

    def _sid(self, sid) -> str:
        self._check(sid and self.security.IsValidSid(sid))
        value = PTR()
        self._check(self.security.ConvertSidToStringSidW(sid, c.byref(value)))
        try:
            return c.wstring_at(value)
        finally:
            self.kernel.LocalFree(value)

    def _user(self) -> str:
        self._no_impersonation()
        token, size = PTR(), DWORD()
        self._check(
            self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 8, c.byref(token))
        )
        try:
            elevation = DWORD()
            self._check(
                self.security.GetTokenInformation(
                    token, 20, c.byref(elevation), c.sizeof(elevation), c.byref(size)
                )
            )
            if elevation.value:
                raise StorageSecurityError(
                    "Elevated Desktop storage is unsupported; run without elevation"
                )
            self.security.GetTokenInformation(token, 1, None, 0, c.byref(size))
            if c.get_last_error() != 122 or not c.sizeof(TokenUser) <= size.value <= 65536:
                raise StorageSecurityError("Process user cannot be verified")
            buffer = c.create_string_buffer(size.value)
            self._check(self.security.GetTokenInformation(token, 1, buffer, size, c.byref(size)))
            return self._sid(TokenUser.from_buffer(buffer).sid)
        finally:
            self.kernel.CloseHandle(token)

    def volume_root_owner(self) -> str:
        """Resolve one local OS servicing identity; never trust an arbitrary service SID."""
        self._no_impersonation()
        sid_size, domain_size, kind = DWORD(), DWORD(), DWORD()
        name = r"NT SERVICE\TrustedInstaller"
        if self.security.LookupAccountNameW(
            None, name, None, c.byref(sid_size), None, c.byref(domain_size), c.byref(kind)
        ):
            raise StorageSecurityError("Unexpected Windows servicing identity lookup")
        if (
            c.get_last_error() != 122
            or not 8 <= sid_size.value <= 68
            or not 1 <= domain_size.value <= 256
        ):
            raise StorageSecurityError("Windows servicing identity cannot be verified")
        sid = c.create_string_buffer(sid_size.value)
        domain = c.create_unicode_buffer(domain_size.value)
        self._check(
            self.security.LookupAccountNameW(
                None, name, sid, c.byref(sid_size), domain, c.byref(domain_size), c.byref(kind)
            )
        )
        # NT SERVICE is the OS-managed service namespace, not a local/domain account.
        if domain.value.casefold() != "nt service" or kind.value != 5:
            raise StorageSecurityError("Unexpected Windows servicing identity namespace")
        self._check(self.security.IsValidSid(sid))
        if self.security.GetLengthSid(sid) > len(sid):
            raise StorageSecurityError("Malformed Windows servicing identity")
        identity = self._sid(sid)
        if not re.fullmatch(r"S-1-5-80-(?:[0-9]+-){4}[0-9]+", identity):
            raise StorageSecurityError("Unexpected Windows servicing identity type")
        return identity

    @contextmanager
    def hold(self, path: str, *, share_delete: bool = False) -> Iterator[int]:
        self._no_impersonation()
        # OPEN_REPARSE_POINT inspects rather than follows the final component.
        handle = self.kernel.CreateFileW(
            path, 0x20080, 3 | (4 if share_delete else 0), None, 3, 0x02200000, None
        )
        if handle == c.c_void_p(-1).value:
            error = c.get_last_error()
            if error in (2, 3):
                raise FileNotFoundError("Storage object absent")
            raise StorageSecurityError("Storage handle unavailable; no fallback")
        try:
            yield handle
        finally:
            self.kernel.CloseHandle(handle)

    def snapshot(self, handle: int) -> Snapshot:
        info, flags, serial, maximum = FileInformation(), DWORD(), DWORD(), DWORD()
        filesystem = c.create_unicode_buffer(32)
        self._check(self.kernel.GetFileInformationByHandle(handle, c.byref(info)))
        self._check(
            self.kernel.GetVolumeInformationByHandleW(
                handle,
                None,
                0,
                c.byref(serial),
                c.byref(maximum),
                c.byref(flags),
                filesystem,
                len(filesystem),
            )
        )
        descriptor = PTR()
        if self.security.GetSecurityInfo(handle, 1, 5, None, None, None, None, c.byref(descriptor)):
            raise StorageSecurityError("Windows descriptor cannot be read")
        try:
            self._check(self.security.IsValidSecurityDescriptor(descriptor))
            owner, dacl, present, defaulted, control, revision = (
                PTR(),
                PTR(),
                BOOL(),
                BOOL(),
                WORD(),
                DWORD(),
            )
            self._check(
                self.security.GetSecurityDescriptorOwner(
                    descriptor, c.byref(owner), c.byref(defaulted)
                )
            )
            self._check(
                self.security.GetSecurityDescriptorDacl(
                    descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)
                )
            )
            self._check(
                self.security.GetSecurityDescriptorControl(
                    descriptor, c.byref(control), c.byref(revision)
                )
            )
            if not present.value or not dacl.value or defaulted.value:
                raise StorageSecurityError("Null/defaulted/missing DACL rejected")
            self._check(self.security.IsValidAcl(dacl))
            size = ACLSize()
            self._check(self.security.GetAclInformation(dacl, c.byref(size), c.sizeof(size), 2))
            if size.count > 64 or not 8 <= size.used <= 65535:
                raise StorageSecurityError("Unbounded or malformed ACL rejected")
            aces = []
            for index in range(size.count):
                pointer = PTR()
                self._check(self.security.GetAce(dacl, index, c.byref(pointer)))
                if (
                    not pointer.value
                    or not dacl.value + 8 <= pointer.value <= dacl.value + size.used - 16
                ):
                    raise StorageSecurityError("Malformed ACE pointer")
                header = ACEHeader.from_address(pointer.value)
                if (
                    header.kind != 0
                    or header.size < 16
                    or pointer.value + header.size > dacl.value + size.used
                ):
                    raise StorageSecurityError("Unsupported or malformed ACE rejected")
                sid = PTR(pointer.value + 8)
                self._check(self.security.IsValidSid(sid))
                if self.security.GetLengthSid(sid) > header.size - 8:
                    raise StorageSecurityError("Malformed ACE SID length")
                aces.append(
                    ACE(
                        self._sid(sid),
                        DWORD.from_address(pointer.value + 4).value,
                        header.flags,
                        header.kind,
                    )
                )
            return Snapshot(
                FileIdentity(info.volume, (info.index_high << 32) | info.index_low),
                bool(info.attributes & DIRECTORY),
                bool(info.attributes & REPARSE),
                filesystem.value,
                bool(flags.value & 8),
                self._sid(owner),
                bool(control.value & PROTECTED),
                tuple(aces),
            )
        finally:
            self.kernel.LocalFree(descriptor)

    def fixed_drive(self, root: str) -> bool:
        return self.kernel.GetDriveTypeW(root) == 3

    @contextmanager
    def descriptor(self, *, directory: bool) -> Iterator[SecurityAttributes]:
        inheritance = "OICI" if directory else ""
        text = f"O:{self.user}D:P" + "".join(
            f"(A;{inheritance};FA;;;{sid})" for sid in (self.user, SYSTEM, ADMINISTRATORS)
        )
        descriptor = PTR()
        self._check(
            self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text, 1, c.byref(descriptor), None
            )
        )
        try:
            yield SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    def create(self, path: str, *, directory: bool) -> None:
        self._no_impersonation()
        with self.descriptor(directory=directory) as attributes:
            if directory:
                if not self.kernel.CreateDirectoryW(path, c.byref(attributes)):
                    if c.get_last_error() == 183:
                        raise FileExistsError("Storage directory exists")
                    raise StorageSecurityError("Secure directory creation denied")
            else:
                handle = self.kernel.CreateFileW(
                    path, 0x40020080, 3, c.byref(attributes), 1, 0x00200080, None
                )
                if handle == c.c_void_p(-1).value:
                    if c.get_last_error() in (80, 183):
                        raise FileExistsError("Storage file exists")
                    raise StorageSecurityError("Secure file creation denied")
                try:
                    verify(self.snapshot(handle), self.user, directory=False)
                finally:
                    self.kernel.CloseHandle(handle)


class SecurityAPI(Protocol):
    user: str

    def hold(self, path: str, *, share_delete: bool = False): ...
    def snapshot(self, handle: int) -> Snapshot: ...
    def fixed_drive(self, root: str) -> bool: ...
    def volume_root_owner(self) -> str: ...
    def create(self, path: str, *, directory: bool) -> None: ...


class WindowsStorage:
    def __init__(self, api: SecurityAPI | None = None):
        self.api = api if api is not None else NativeWin32()

    @contextmanager
    def guard(self, path: Path | str, *, private: bool = True) -> Iterator[None]:
        from contextlib import ExitStack

        value = canonical_path(path)
        if not self.api.fixed_drive(value.anchor):
            raise StorageSecurityError(
                "Fixed local NTFS drive required; remote/removable storage unsupported"
            )
        with ExitStack() as stack:
            for parent in reversed((value, *value.parents)):
                handle = stack.enter_context(self.api.hold(str(parent)))
                private_storage = private and parent == value
                # Never skip the root: its ACL/reparse/volume checks and pinned handle
                # still protect every descendant. Ordinary ancestors retain their policy.
                root_owner = (
                    self.api.volume_root_owner()
                    if parent == PureWindowsPath(value.anchor) and not private_storage
                    else None
                )
                verify(
                    self.api.snapshot(handle),
                    self.api.user,
                    directory=True,
                    private=private_storage,
                    volume_root_owner=root_owner,
                )
            yield

    def validate_directory(self, path: Path | str) -> None:
        with self.guard(path):
            pass

    def validate_file(self, path: Path | str) -> FileIdentity:
        value = canonical_path(path)
        with self.guard(value.parent):
            with self.api.hold(str(value), share_delete=True) as handle:
                snapshot = self.api.snapshot(handle)
                verify(snapshot, self.api.user, directory=False)
                return snapshot.identity

    def create_directory(self, path: Path, *, exist_ok: bool = True) -> None:
        canonical_path(path)
        if path.exists():
            if not exist_ok:
                raise FileExistsError("Storage directory exists")
            self.validate_directory(path)
            return
        if path.parent == path:
            raise StorageSecurityError("Windows drive root unavailable")
        if not path.parent.exists():
            self.create_directory(path.parent)
        with self.guard(path.parent, private=False):
            self.api.create(str(path), directory=True)
            self.validate_directory(path)

    def create_file(self, path: Path) -> None:
        value = canonical_path(path)
        with self.guard(value.parent):
            self.api.create(str(value), directory=False)
            self.validate_file(path)
