"""One application approval and one OS password, same Broker through capture/cleanup."""

import hashlib

from soc_agent.security_ai.ebpf_tc.auth_session import LiveQualification
from soc_agent.security_ai.ebpf_tc.build import bundle
from soc_agent.security_ai.ebpf_tc.installation import validate_root_release
from soc_agent.security_ai.ebpf_tc.unified_image import (
    UnifiedImage,
    installed_release,
    pinned_command,
)
from soc_agent.security_ai.ebpf_tc.unified_image_engine import LABEL
from soc_agent.security_ai.research.models import digest


class UnifiedSession(LiveQualification):
    entry_mode = "--unified-handoff"
    native_origin = "TCX_UNIFIED_SESSION_NATIVE"

    def __init__(self, *args, image: UnifiedImage, **kwargs):
        self.image = image
        self.installation = "PENDING"
        super().__init__(*args, **kwargs)
        if image.manifest != self.release.identity or image.version != self.release.version:
            raise ValueError("UNIFIED_IMAGE_RELEASE_MISMATCH")

    @property
    def approval(self) -> str:
        return hashlib.sha256(
            LABEL
            + self.envelope
            + bytes.fromhex(self.image.sha256)
            + bytes.fromhex(self.image.previous_manifest)
        ).hexdigest()

    def sudo_command(self) -> tuple[str, ...]:
        return pinned_command(
            self.image, self.envelope, self.approval, self.plan.broker.uid, self.plan.broker.gid
        )

    def _authentication_preflight(self) -> None:
        self.image.verify()
        if self.release.bundle_digest != digest(bundle()):
            raise ValueError("UNIFIED_SOURCE_VERSION_CHANGED")
        installed = installed_release()
        if (installed.identity if installed else "0" * 64) != self.image.previous_manifest:
            raise ValueError("UNIFIED_INSTALLED_VERSION_CHANGED")

    def _authentication_verified(self) -> None:
        validate_root_release(self.release)
        self.installation = "ROOT_FILES_VERIFIED_NATIVE"
        self._event("UNIFIED_INSTALLATION_VERIFIED", manifest=self.release.identity)

    def approval_scope(self) -> dict:
        scope = super().approval_scope()
        scope["unified_session"] = self.image.model_dump(mode="json")
        scope["password_requests"] = "ONCE_AT_APP_START_OS_TERMINAL_ONLY"
        scope["capabilities"] = ["CAP_BPF", "CAP_NET_ADMIN"]
        scope["gui_and_ai_privilege"] = "ORDINARY_USER_NO_PRIVILEGED_FDS"
        scope["installation_modes"] = "root:root; executables 0555; other files 0444"
        scope["previous_release_retention"] = (
            "/usr/libexec/.soc-agent-ebpf.rollback-" + self.image.previous_manifest
        )
        scope["failure_policy"] = "STOP_NO_AUTOMATIC_RETRY"
        return scope

    def snapshot(self) -> dict:
        value = super().snapshot()
        value["unified_installation"] = self.installation
        value["unified_image"] = self.image.model_dump(mode="json")
        return value
