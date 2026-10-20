"""Preserve B-1's four screens/charts; add compiled Native identity and closed Gate."""

from soc_agent.security_ai.ebpf_broker.gui import Backend, BrokerDesktop, BrokerWorker
from soc_agent.security_ai.ebpf_tc.bridge import Preparation


class PreparedBackend(Backend):
    def __init__(self, preparation: Preparation):
        super().__init__(preparation.controller)
        self.preparation = preparation

    async def production_status(self):
        self.controller.observe()
        return self.preparation.snapshot()

    async def collector_stop(self):
        self.controller.stop()
        return self.preparation.snapshot()

    async def broker_start(self):
        self.preparation.validate()
        self.preparation.transaction_fixture()
        self.controller.start()
        return self.preparation.snapshot()


class PreparedWorker(BrokerWorker):
    async def _create(self, preparation):
        return PreparedBackend(preparation)


class PreparedDesktop(BrokerDesktop):
    def _render_current(self):
        previous = self.last_render
        super()._render_current()
        if self.page != "System" or self.last_render == previous:
            return
        detail = self.snapshot.get("ebpf", {})
        rows = ["", "B-2A NATIVE IMPLEMENTATION · COMPILED / NOT EXECUTED"]
        for title, key in (
            ("Bootstrap SHA", "bootstrap_sha256"),
            ("Native Broker SHA", "compiled_native_broker_sha256"),
            ("Native Loader SHA", "compiled_native_loader_sha256"),
            ("Native Bundle", "compiled_native_bundle_digest"),
            ("Interface", "interface"),
            ("Namespace", "namespace"),
            ("Native Gate", "native_gate"),
            ("Native authentication", "native_authentication"),
        ):
            rows.append(title + "   " + str(detail.get(key, "UNKNOWN")))
        release = self.snapshot.get("native_release", {})
        for key in ("state", "safe_detach", "kernel_compatibility"):
            rows.append("Native release " + key + "   " + str(release.get(key, "UNKNOWN")))
        tcx = self.snapshot.get("tcx", {})
        for key in (
            "attach_mode",
            "program_sha256",
            "dispatcher",
            "broker_state",
            "link_id",
            "link_state",
            "ownership",
            "program_semantics",
            "coexistence",
            "broker_pin_policy",
            "external_pins",
        ):
            observed = tcx.get(key)
            rows.append("TCX " + key + "   " + ("UNKNOWN" if observed is None else str(observed)))
        installation = self.snapshot.get("installation", {})
        for key in (
            "release_candidate",
            "release_manifest_digest",
            "pam_nss_trust",
            "dynamic_loader_trust",
            "runtime_mapping_attestation",
            "environment_contract",
            "nss_scope_policy",
            "dependency_integrity",
            "pam_trust",
            "nss_trust",
            "installed_release",
            "package_version",
            "installation_integrity",
            "authentication",
            "capability_state",
            "kernel_compatibility",
            "native_release",
        ):
            observed = installation.get(key)
            rows.append(
                "Installation " + key + "   " + ("UNKNOWN" if observed is None else str(observed))
            )
        self._text(self.system, self.system.get("1.0", "end") + "\n".join(rows))


def launch(preparation: Preparation) -> int:
    import tkinter as tk

    from soc_agent.gui.backend import GUIConfig

    root = tk.Tk()
    PreparedDesktop(
        root,
        GUIConfig(data_directory=preparation.controller.application.directory),
        worker=PreparedWorker(preparation),
    )
    root.title("SOC B-2A · NATIVE GATE CLOSED / MOCK AUTH ONLY")
    root.mainloop()
    return 0
