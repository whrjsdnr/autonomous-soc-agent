"""B-2A admission/ABI bridge. No Root subprocess, PAM, load or attach is launched."""

import errno
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
    # No pathname-execution fallback while trusted installation, dependencies and
    # safe detach are unqualified. Monkeypatching a Python gate cannot admit Native.
    raise ValueError(NATIVE_ERROR)


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
    for name in (
        "entry",
        "bootstrap",
        "broker",
        "libnative-tc.so",
        "tc-fixture",
        "tcx-dispatch-fixture",
        "tcx.bpf.o",
    ):
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
        self._installation = None
        self._os_handoff = None
        self._tcx_result = None
        self._tcx_used = False
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
        from soc_agent.security_ai.ebpf_tc.release import installation_plan

        planned = installation_plan(self.hashes, self.plan.program_sha256)
        self.controller._event(
            "NATIVE_RELEASE_BLOCKED",
            installation_manifest_digest=planned.artifacts["manifest.bin"],
            native_scope_digest=self.plan.approval,
            release="BLOCKED",
            safe_detach="BLOCKED_NO_ATOMIC_OWNERSHIP",
            input_origin="UNPRIVILEGED_PREPARATION_NOT_NATIVE",
            native_execution=False,
        )
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

    @property
    def tcx_fixture_approval(self) -> str:
        return digest(
            {"plan": self.plan.approval, "attach_mode": "TCX_FIXTURE", "pin": "FORBIDDEN"}
        )

    def tcx_fixture(self, approval: str, scenario: int = 0) -> dict:
        from soc_agent.security_ai.ebpf_tc.tcx import LinkFixtureResult

        self.validate()
        if approval != self.tcx_fixture_approval or self._tcx_used:
            raise ValueError("TCX_FIXTURE_APPROVAL_OR_REPLAY_DENIED")
        if type(scenario) is not int or not 0 <= scenario <= 20:
            raise ValueError("TCX_FIXTURE_SCENARIO_INVALID")
        if not self.controller.application._authenticated or self.controller.broker is None:
            raise ValueError("TCX_FIXTURE_APPLICATION_AUTH_REQUIRED")
        self.controller.broker.request("STATUS")  # Existing PID/peer/sequence-checked supervisor.
        self._tcx_used = True  # Consumed on failure too; no automatic retry.
        result = subprocess.run(
            [str((self.artifacts / "tc-fixture").absolute()), "--tcx", str(scenario)],
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if result.returncode or len(result.stdout) > 4096:
            raise ValueError("TCX_FIXTURE_FAILED")
        value = LinkFixtureResult.model_validate_json(result.stdout)
        self.controller._event(
            "TCX_LINK_LIFECYCLE_FIXTURE",
            native_plan_digest=self.plan.approval,
            program_sha256=self.plan.program_sha256,
            approval_digest=approval,
            result=value.model_dump(),
            native_execution=False,
        )
        self._tcx_result = value.snapshot()
        return value.model_dump()

    def qualify_package(self, directory: Path, manifest_sha: str) -> dict:
        from soc_agent.security_ai.ebpf_tc.installation import verify_package

        self.validate()
        release = verify_package(directory, manifest_sha)
        if (
            release.bundle_digest != self.plan.bundle_digest
            or release.payloads["tc.bpf.o"].sha256 != self.hashes["tcx.bpf.o"]
        ):
            raise ValueError("RELEASE_APPLICATION_BUNDLE_MISMATCH")
        self.controller._event(
            "INSTALLATION_PACKAGE_VERIFIED",
            release_manifest_digest=release.identity,
            input_origin="UNPRIVILEGED_PACKAGE_NOT_ROOT",
            native_execution=False,
            capability_scope="CANDIDATE_CAP_BPF_CAP_NET_ADMIN_NATIVE_UNKNOWN",
            release_gate="BLOCKED",
            authentication_handoff=release.authentication_handoff,
            entry_architecture=release.entry_architecture,
            entry_sha256=release.payloads["entry"].sha256,
            privilege_lifetime=release.privilege_lifetime,
            dependency_verification="STATIC_GRAPH_WITH_NSS_MODULES",
            pam_trust="ABSOLUTE_MODULE_NATIVE_PENDING",
            nss_trust="BLOCKED_NATIVE_LOOKUP_NOT_OBSERVED",
        )
        self._installation = {
            "release_candidate": "B2F_BLOCKED_NATIVE_QUALIFICATION",
            "dynamic_loader_trust": "STATIC_ENTRY_FIXTURE_NATIVE_PENDING",
            "entry_architecture": release.entry_architecture,
            "authentication_handoff": release.authentication_handoff,
            "entry_sha256": release.payloads["entry"].sha256,
            "authentication_nss_scope": "NUMERIC_ENTRY_BROKER_OS_PAM_NSS_UNKNOWN",
            "broker_identity_scope": "NUMERIC_KERNEL_CREDENTIALS_NO_NSS_CALLS",
            "runtime_mapping_attestation": "PROCESS_WIDE_EXECUTABLE_SNAPSHOT_LIMITED",
            "environment_contract": release.dynamic_trust.environment_contract,
            "nss_scope_policy": release.dynamic_trust.nss.scope_policy,
            "pam_nss_trust": "STATIC_SNAPSHOTS_DYNAMIC_CLOSURE_UNKNOWN",
            "dependency_integrity": "STATIC_GRAPH_VERIFIED_NATIVE_MAPPINGS_PENDING",
            "pam_trust": "ABSOLUTE_MODULE_PINNED_NATIVE_AUTH_PENDING",
            "nss_trust": "BLOCKED_REQUIRED_ROLE_MODULE_MISSING"
            if release.dynamic_trust.unresolved_required_nss_services
            else "BLOCKED_OS_AUTH_SCOPE_NOT_QUALIFIED",
            "nss_missing_configured_services": release.dynamic_trust.unresolved_nss_services,
            "installed_release": None,
            "package_version": release.version,
            "release_manifest_digest": release.identity,
            "installation_integrity": "PACKAGE_VERIFIED_ROOT_NOT_OBSERVED",
            "authentication": "NATIVE_PENDING",
            "capability_state": "UNKNOWN_NATIVE_TRANSFER",
            "kernel_compatibility": "UNKNOWN_NOT_PROBED",
            "native_release": "BLOCKED",
        }
        return self.snapshot()

    @property
    def tcx_dispatch_approval(self) -> str:
        return digest(
            {
                "plan": self.plan.approval,
                "mode": "TCX_DISPATCH_FIXTURE",
                "program": self.hashes["tcx.bpf.o"],
            }
        )

    def tcx_dispatch_fixture(self, approval: str, scenario: int = 0) -> dict:
        from soc_agent.security_ai.ebpf_tc.tcx import DispatchFixtureResult

        self.validate()
        if approval != self.tcx_dispatch_approval or self._tcx_used:
            raise ValueError("TCX_FIXTURE_APPROVAL_OR_REPLAY_DENIED")
        if type(scenario) is not int or not 0 <= scenario <= 9:
            raise ValueError("TCX_FIXTURE_SCENARIO_INVALID")
        if not self.controller.application._authenticated or self.controller.broker is None:
            raise ValueError("TCX_FIXTURE_APPLICATION_AUTH_REQUIRED")
        self.controller.broker.request("STATUS")
        self._tcx_used = True
        result = subprocess.run(
            [str((self.artifacts / "tcx-dispatch-fixture").absolute()), str(scenario)],
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
        if result.returncode or len(result.stdout) > 12288:
            raise ValueError("TCX_FIXTURE_FAILED")
        value = DispatchFixtureResult.model_validate_json(result.stdout)
        self.controller._event(
            "TCX_DISPATCHER_FIXTURE",
            native_plan_digest=self.plan.approval,
            tcx_program_sha256=self.hashes["tcx.bpf.o"],
            approval_digest=approval,
            result=value.model_dump(),
            native_execution=False,
        )
        self._tcx_result = value.snapshot()
        return value.model_dump()

    def os_auth_handoff(
        self,
        package: Path,
        manifest_sha: str,
        *,
        qualification_only: bool = False,
        live_qualification: bool = False,
        unified_image=None,
        supervisor_image=None,
    ):
        from soc_agent.security_ai.ebpf_tc.os_handoff import Handoff

        if (
            sum(
                (
                    qualification_only,
                    live_qualification,
                    unified_image is not None,
                    supervisor_image is not None,
                )
            )
            > 1
        ):
            raise ValueError("QUALIFICATION_MODE_CONFLICT")
        if live_qualification:
            from soc_agent.security_ai.ebpf_tc.auth_session import LiveQualification

            Handoff = LiveQualification
        if qualification_only:
            from soc_agent.security_ai.ebpf_tc.auth_session import AuthenticationQualification

            Handoff = AuthenticationQualification
        if unified_image is not None:
            from soc_agent.security_ai.ebpf_tc.unified import UnifiedSession

            Handoff = UnifiedSession
        if supervisor_image is not None:
            from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession

            Handoff = SupervisedSession
        if self._os_handoff is not None:
            raise ValueError("OS_HANDOFF_ALREADY_PREPARED")
        from soc_agent.security_ai.ebpf_tc.installation import verify_package

        release = verify_package(package, manifest_sha)
        scope = self.plan.broker.application.scope.model_copy(
            update={"program_sha256": self.hashes["tcx.bpf.o"]}
        )
        broker = self.plan.broker.model_copy(
            update={"application": self.plan.broker.application.model_copy(update={"scope": scope})}
        )
        plan = NativePlan(
            broker=broker,
            bootstrap_sha256=self.hashes["bootstrap"],
            native_broker_sha256=self.hashes["broker"],
            loader_sha256=self.hashes["libnative-tc.so"],
            program_sha256=self.hashes["tcx.bpf.o"],
            bundle_digest=release.bundle_digest,
            mode="B2D_TCX_BLOCKED",
        )
        self._os_handoff = Handoff(
            self.controller.application,
            plan,
            package,
            manifest_sha,
            self.artifacts,
            **(
                {"image": supervisor_image if supervisor_image is not None else unified_image}
                if supervisor_image is not None or unified_image is not None
                else {}
            ),
        )
        self._os_handoff.prepare()
        return self._os_handoff

    def snapshot(self) -> dict:
        value = self.controller.snapshot()
        from soc_agent.security_ai.ebpf_tc.qualification import (
            unobserved as installation_unobserved,
        )
        from soc_agent.security_ai.ebpf_tc.release import ReleaseEvidence
        from soc_agent.security_ai.ebpf_tc.tcx import unobserved

        value["installation"] = self._installation or installation_unobserved()
        value["os_auth_handoff"] = (
            self._os_handoff.snapshot()
            if self._os_handoff
            else {
                "state": "NOT_PREPARED",
                "os_authentication": "REQUIRED",
                "native_gate": "BLOCKED",
                "cleanup_status": "NOT_OBSERVED",
            }
        )
        value["tcx"] = self._tcx_result or unobserved()
        value["tcx"].update(
            program_sha256=self.hashes["tcx.bpf.o"],
            coexistence="APPEND_ONLY_VISIBILITY_NOT_ATTESTED",
            dispatcher="COMPILED_NATIVE_GATE_CLOSED",
            broker_state=value.get("state", "UNKNOWN"),
        )
        if self._os_handoff:
            handoff = self._os_handoff.snapshot()
            value["state"] = handoff["state"]
            value["collector"].update(type="EBPF_OS_HANDOFF_B2J", health=handoff["state"])
            value["ebpf"]["authentication_state"] = handoff["os_authentication"]
        value["native_release"] = ReleaseEvidence().snapshot()
        value["input_origin"] = (
            self._os_handoff.origin
            if self._os_handoff
            else "B2A_PREPARATION_OR_EXPLICIT_FIXTURE_NOT_NATIVE"
        )
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
