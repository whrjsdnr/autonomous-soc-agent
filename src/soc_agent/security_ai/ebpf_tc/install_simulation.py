"""Bounded ordinary-UID filesystem transaction fixture; never a root installation."""

import hashlib
import json
import os
import shutil
from pathlib import Path
from uuid import uuid4

from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import (
    _write,
    canonical,
    verify_package,
)
from soc_agent.security_ai.ebpf_tc.release import _directory
from soc_agent.security_ai.ebpf_tc.trust import execution_manifest


class InstallationSimulation:
    def __init__(self, directory: Path):
        if os.geteuid() == 0:
            raise ValueError("INSTALL_SIMULATION_NON_ROOT_REQUIRED")
        self.directory = directory.absolute()
        # Existing directory must have been explicitly created private by the caller.
        self.fd = os.open(
            self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            _directory(os.fstat(self.fd), os.getuid())
            entries = os.listdir(self.fd)
            if not entries:
                _write(
                    self.fd,
                    "simulation.json",
                    canonical(
                        {
                            "contract": "soc-install-simulation:v1",
                            "uid": os.getuid(),
                            "instance": uuid4().hex,
                        }
                    ),
                    0o444,
                )
                os.fsync(self.fd)
            elif "simulation.json" not in entries:
                raise ValueError("INSTALL_SIMULATION_FOREIGN_DIRECTORY")
            marker = read_held(self.directory / "simulation.json", owner=os.getuid(), limit=1024)
            value = json.loads(marker)
            if (
                value.get("contract") != "soc-install-simulation:v1"
                or value.get("uid") != os.getuid()
            ):
                raise ValueError("INSTALL_SIMULATION_IDENTITY")
            self.marker_sha = hashlib.sha256(marker).hexdigest()
        except BaseException:
            os.close(self.fd)
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _identity(self) -> None:
        _directory(os.fstat(self.fd), os.getuid())
        marker = read_held(self.directory / "simulation.json", owner=os.getuid(), limit=1024)
        if hashlib.sha256(marker).hexdigest() != self.marker_sha:
            raise ValueError("INSTALL_SIMULATION_IDENTITY_CHANGED")
        for name in os.listdir(self.fd):
            if (
                name not in {"simulation.json", "active.json", "journal.jsonl"}
                and not (len(name) == 64 and all(c in "0123456789abcdef" for c in name))
                and not name.startswith((".pending-", ".active-"))
            ):
                raise ValueError("INSTALL_SIMULATION_FOREIGN_EVIDENCE")

    def _journal(self, kind: str, release: str) -> None:
        records = self._records()
        row = {
            "kind": kind,
            "release": release,
            "ordinal": len(records) + 1,
            "previous": records[-1]["digest"] if records else "0" * 64,
            "source": "INSTALLATION_SIMULATION_NOT_ROOT",
        }
        row["digest"] = hashlib.sha256(canonical(row)).hexdigest()
        fd = os.open(
            "journal.jsonl",
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        try:
            body = canonical(row)
            if os.write(fd, body) != len(body):
                raise ValueError("INSTALL_SIMULATION_JOURNAL_PARTIAL")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _records(self) -> list[dict]:
        path = self.directory / "journal.jsonl"
        if not path.exists():
            return []
        body = read_held(path, owner=os.getuid(), limit=65536)
        records = []
        previous = "0" * 64
        for line in body.splitlines():
            row = json.loads(line)
            checksum = row.pop("digest")
            if (
                row.get("previous") != previous
                or row.get("ordinal") != len(records) + 1
                or hashlib.sha256(canonical(row)).hexdigest() != checksum
            ):
                raise ValueError("INSTALL_SIMULATION_JOURNAL_CORRUPT")
            row["digest"] = checksum
            records.append(row)
            previous = checksum
        if len(records) >= 128:
            raise ValueError("INSTALL_SIMULATION_JOURNAL_BUDGET")
        return records

    def activate(self, package: Path, expected: str, *, rollback: bool = False) -> dict:
        self._identity()
        prior = self.recover()
        if prior["state"] == "CRASH_REVIEW_REQUIRED":
            raise ValueError("INSTALL_SIMULATION_CRASH_REVIEW_REQUIRED")
        manifest = verify_package(package, expected)
        _directory(os.fstat(self.fd), os.getuid())
        entries = os.listdir(self.fd)
        releases = [n for n in entries if len(n) == 64 or n.startswith(".pending-")]
        if (len(releases) >= 8 and not rollback) or shutil.disk_usage(
            self.directory
        ).free < 64 * 1024**2:
            raise ValueError("INSTALL_SIMULATION_DISK_BUDGET")
        target = self.directory / manifest.identity
        if target.exists():
            if not rollback:
                raise ValueError("INSTALL_SIMULATION_RELEASE_REUSE")
            verify_package(target, expected)
        else:
            if rollback:
                raise ValueError("INSTALL_SIMULATION_ROLLBACK_NOT_RETAINED")
            temporary = ".pending-" + uuid4().hex
            os.mkdir(temporary, 0o700, dir_fd=self.fd)
            stage = os.open(
                temporary,
                os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY | os.O_CLOEXEC,
                dir_fd=self.fd,
            )
            try:
                for name in (*manifest.payloads, "release.json", "release.trust"):
                    body = read_held((package / name).absolute(), owner=os.getuid(), limit=1048576)
                    wanted = (
                        manifest.identity
                        if name == "release.json"
                        else hashlib.sha256(execution_manifest(manifest)).hexdigest()
                        if name == "release.trust"
                        else manifest.payloads[name].sha256
                    )
                    if hashlib.sha256(body).hexdigest() != wanted:
                        raise ValueError("INSTALL_SIMULATION_SOURCE_CHANGED")
                    # No executable or setuid bits, even for the bootstrap.
                    _write(stage, name, body, 0o444)
                os.fsync(stage)
            finally:
                os.close(stage)
            verify_package(self.directory / temporary, expected)
            _publish(self.fd, temporary, manifest.identity)
            os.fsync(self.fd)
        self._journal("ROLLBACK_PREPARED" if rollback else "RELEASE_PREPARED", expected)
        temporary = ".active-" + uuid4().hex
        _write(
            self.fd,
            temporary,
            canonical({"manifest": expected, "source": "SIMULATION_ONLY"}),
            0o444,
        )
        os.replace(temporary, "active.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self._journal("ROLLBACK_COMMITTED" if rollback else "RELEASE_COMMITTED", expected)
        return self.recover()

    def recover(self) -> dict:
        self._identity()
        _directory(os.fstat(self.fd), os.getuid())
        records = self._records()
        active = None
        state = "NOT_OBSERVED"
        if (self.directory / "active.json").exists():
            body = read_held(self.directory / "active.json", owner=os.getuid(), limit=1024)
            value = json.loads(body)
            active = value.get("manifest")
            # Strict Hash parsing before path use prevents traversal from a corrupted selector.
            from pydantic import TypeAdapter

            from soc_agent.review.models import Hash

            TypeAdapter(Hash).validate_python(active)
            verify_package(self.directory / active, active)
            state = (
                "FIXTURE_VERIFIED"
                if records
                and records[-1]["kind"] in {"RELEASE_COMMITTED", "ROLLBACK_COMMITTED"}
                and records[-1]["release"] == active
                else "CRASH_REVIEW_REQUIRED"
            )
        return {
            "source": "INSTALLATION_SIMULATION_NOT_ROOT",
            "state": state,
            "active_manifest": active,
            "journal_digest": records[-1]["digest"] if records else None,
            "native_release": "BLOCKED",
            "root_installation": "PENDING",
            "authentication_restored": False,
            "automatic_attach": False,
            "automatic_inference": False,
        }


def _publish(directory: int, temporary: str, release: str) -> None:
    """Linux directory publish with NOREPLACE, only inside an ordinary-UID fixture."""
    import ctypes

    if os.geteuid() == 0:
        raise ValueError("INSTALL_SIMULATION_NON_ROOT_REQUIRED")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(directory, temporary.encode(), directory, release.encode(), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
