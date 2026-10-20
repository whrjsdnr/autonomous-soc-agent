"""B-2A admission/ABI bridge. No Root subprocess, PAM, load or attach is launched."""

import errno
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from soc_agent.security_ai.ebpf_broker.controller import Controller
from soc_agent.security_ai.ebpf_broker.identity import sealed_object
from soc_agent.security_ai.ebpf_native.loader import file_sha
from soc_agent.security_ai.ebpf_tc.build import bundle, compile_native
from soc_agent.security_ai.ebpf_tc.contracts import NativePlan
from soc_agent.security_ai.research.models import digest

INSTALL = Path("/usr/libexec/soc-agent-ebpf")
NATIVE_ERROR = "EBPF_B2A_NATIVE_EXECUTION_BLOCKED"


def native_admitted() -> bool:
    # No environment/argument/fixture override. B-2B requires a reviewed release.
    return False


def native_handoff(
    plan: NativePlan, channel_fd: int, plan_fd: int, journal_fd: int = -1
) -> subprocess.Popen:
    if not native_admitted():
        raise ValueError(NATIVE_ERROR)
    # Future fixed-path handoff implementation. Never reached by a B-2A entrypoint.
    # C independently refuses every Native operation in the current artifacts.
    expected = {
        "bootstrap": plan.bootstrap_sha256,
        "broker": plan.native_broker_sha256,
        "libnative-tc.so": plan.loader_sha256,
    }
    for parent in (INSTALL, *INSTALL.parents):
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("NATIVE_INSTALLATION_UNTRUSTED")
    for name, sha in expected.items():
        path = INSTALL / name
        info = path.lstat()
        if (
            path.is_symlink()
            or info.st_uid
            or info.st_mode & 0o022
            or (hashlib.sha256(path.read_bytes()).hexdigest() != sha)
        ):
            raise ValueError("NATIVE_INSTALLATION_UNTRUSTED")
    if os.getuid() == 0 or not os.isatty(0) or len({channel_fd, plan_fd, journal_fd}) != 3:
        raise ValueError("NATIVE_TERMINAL_OR_DESCRIPTOR_INVALID")
    if not all(3 <= fd <= 31 for fd in (channel_fd, plan_fd, journal_fd)):
        raise ValueError("NATIVE_DESCRIPTOR_INVALID")
    return subprocess.Popen(
        [str(INSTALL / "bootstrap"), str(channel_fd), str(plan_fd), str(journal_fd)],
        pass_fds=(channel_fd, plan_fd, journal_fd),
        close_fds=True,
        start_new_session=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )


def manifest(plan: NativePlan) -> bytes:
    return b"".join(
        bytes.fromhex(value)
        for value in (
            plan.bootstrap_sha256,
            plan.native_broker_sha256,
            plan.loader_sha256,
            plan.program_sha256,
            plan.bundle_digest,
        )
    )


def inspect_artifacts(directory: Path, expected: dict | None = None) -> dict:
    hashes = {}
    for name in ("bootstrap", "broker", "libnative-tc.so", "tc-fixture"):
        path = directory / name
        hashes[name] = file_sha(path)
        try:
            if os.getxattr(path, "security.capability"):
                raise ValueError("NATIVE_PRIVILEGED_ARTIFACT_DENIED")
        except OSError as exc:
            if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
                raise ValueError("NATIVE_ARTIFACT_METADATA_UNVERIFIED") from exc
    if expected is None:
        with tempfile.TemporaryDirectory(prefix="soc-native-reference-") as temporary:
            reference = compile_native(Path(temporary))
        expected = {k: reference[k] for k in hashes}
    if hashes != expected:
        raise ValueError("NATIVE_ARTIFACT_SOURCE_REFERENCE_MISMATCH")
    for name in ("bootstrap", "broker"):
        result = subprocess.run(
            [str((directory / name).absolute()), "--inspect"],
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if result.returncode or len(result.stdout) > 2048:
            raise ValueError("NATIVE_INSPECTION_REJECTED")
        status = json.loads(result.stdout)
        if status.get("native_gate") is not False:
            raise ValueError("NATIVE_GATE_NOT_CLOSED")
    return hashes


class Preparation:
    def __init__(self, controller: Controller, artifacts: Path):
        self.controller, self.artifacts = controller, artifacts
        self.hashes = inspect_artifacts(artifacts)
        self.plan = NativePlan(
            broker=controller.plan,
            bootstrap_sha256=self.hashes["bootstrap"],
            native_broker_sha256=self.hashes["broker"],
            loader_sha256=self.hashes["libnative-tc.so"],
            program_sha256=controller.application.scope.program_sha256,
            bundle_digest=digest(bundle()),
        )

    def prepare(self) -> dict:
        self.controller.prepare()
        # Actual B-1 sealed-FD implementation reused, not a second object transport.
        import os

        fd = sealed_object(self.controller.application.program, self.plan.program_sha256)
        try:
            self.controller._event(
                "NATIVE_IMPLEMENTATION_PREPARED",
                plan=self.plan.model_dump(mode="json"),
                native_scope_digest=self.plan.approval,
                native_authentication_attempted=False,
            )
        finally:
            os.close(fd)
        return self.snapshot()

    def approve(self, value: str) -> None:
        if value != self.plan.approval:
            raise ValueError("NATIVE_APPROVAL_DIGEST_MISMATCH")
        self.validate()
        self.controller.approve(self.controller.plan.identity)

    def validate(self) -> None:
        current = inspect_artifacts(self.artifacts, self.hashes)
        if current != self.hashes or digest(bundle()) != self.plan.bundle_digest:
            raise ValueError("NATIVE_ARTIFACT_OR_BUNDLE_MISMATCH")
        self.controller.application._validate()

    def transaction_fixture(self, scenario: int = 0) -> dict:
        if type(scenario) is not int or not 0 <= scenario <= 14:
            raise ValueError("NATIVE_FIXTURE_SCENARIO_INVALID")
        self.validate()
        result = subprocess.run(
            [str((self.artifacts / "tc-fixture").absolute()), str(scenario)],
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if result.returncode or len(result.stdout) > 8192:
            raise ValueError("NATIVE_TRANSACTION_FIXTURE_FAILED")
        value = json.loads(result.stdout)
        if value["native_gate"] or value["source"] != "C_TRANSACTION_CORE_FAKE_OPS_ONLY":
            raise ValueError("NATIVE_FIXTURE_ORIGIN_INVALID")
        self.controller._event(
            "NATIVE_TRANSACTION_FIXTURE", result=value, native_kernel_called=False
        )
        return value

    def snapshot(self) -> dict:
        value = self.controller.snapshot()
        value["input_origin"] = "B2A_PREPARATION_OR_EXPLICIT_FIXTURE_NOT_NATIVE"
        value["ebpf"].update(
            bootstrap_sha256=self.plan.bootstrap_sha256,
            compiled_native_broker_sha256=self.plan.native_broker_sha256,
            compiled_native_loader_sha256=self.plan.loader_sha256,
            compiled_native_bundle_digest=self.plan.bundle_digest,
            interface="lo",
            namespace=self.controller.application.scope.net_namespace,
            native_gate="B2A_CLOSED",
            native_hook="NOT_ATTACHED",
            native_authentication="PENDING_NOT_EXECUTED",
        )
        return value
