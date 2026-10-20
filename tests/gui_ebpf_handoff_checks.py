"""WSLg handoff fixture rendering/shutdown; no OS authentication or Kernel activity."""

import tkinter as tk

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS
from soc_agent.security_ai.ebpf_tc.bridge import Preparation
from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.gui import PreparedDesktop, PreparedWorker
from soc_agent.security_ai.ebpf_tc.installation import create_package
from soc_agent.security_ai.ebpf_tc.os_handoff import AuthenticationFixture
from tests.ebpf_broker_support import controller
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_handoff_four_screens_charts_stop_and_app_close(tmp_path):
    artifacts = tmp_path / "build"
    compile_native(artifacts)
    manifest = create_package(artifacts, tmp_path / "package", "0.2.11")
    owner = controller(tmp_path / "application", authenticate=False)
    prep = Preparation(owner, artifacts)
    handoff = prep.os_auth_handoff(tmp_path / "package", manifest.identity)
    handoff.approve(handoff.approval)
    handoff.authenticate_fixture(AuthenticationFixture())
    pid = handoff.identity
    root = tk.Tk()
    worker = PreparedWorker(prep)
    app = PreparedDesktop(root, GUIConfig(data_directory=tmp_path / "gui"), worker=worker)
    root.title("SOC B-2J TRANSPORT FIXTURE / NATIVE BLOCKED")
    try:
        await idle(root, app)
        for screen in SCREENS:
            app.navigate(screen, refresh=False)
            root.update()
        app.navigate("System", refresh=False)
        root.update()
        text = app.system.get("1.0", "end")
        assert "MOCK_VERIFIED_NOT_NATIVE" in text
        assert "B2J_TRANSPORT_FIXTURE_NOT_OS_AUTH" in text
        assert "OS Handoff native_gate   BLOCKED" in text
        assert "UNKNOWN_NATIVE_PENDING" in text
        assert not app.snapshot["collection_live"] and app.snapshot["native_ai"] == "BLOCKED"
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        assert handoff.state == "BROKER_READY" and handoff.identity == pid
        assert handoff.authentication == "MOCK_VERIFIED_NOT_NATIVE"
    finally:
        await close(root, app)
    assert handoff.ended and handoff.child.poll() == 0
    assert handoff.cleanup == "FIXTURE_VERIFIED" and handoff.authentication == "REVOKED"
    assert not worker.thread.is_alive()
