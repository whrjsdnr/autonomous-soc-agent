"""One-command orchestration with terminal auth mock and actual OFFLINE Zeek.

The Native protocol is exercised, but the Docker argv is replaced with a pinned,
capability-free --network=none PCAP command. This is not Native capture evidence.
"""

import asyncio
import json
import subprocess

from tests.zeek_producer_support import valid_wire, write_pcap

from soc_agent.security_ai.collectors import startup
from soc_agent.security_ai.collectors.live_contract import docker_argv
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.offline import OfflineZeek


def test_one_command_approval_auth_gui_handoff_actual_offline_zeek_drain(tmp_path, monkeypatch):
    OfflineZeek().environment()
    pcap = tmp_path / "input.pcap"
    write_pcap(
        pcap, [(1800000000000000000 + i * 1000000, valid_wire(flags=16)) for i in range(4097)]
    )
    monkeypatch.setattr(startup, "preflight", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    calls = []
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", lambda: calls.append("auth"))
    original_argv = docker_argv

    def offline(plan, policy, **kwargs):
        assert kwargs["fixture"] is None
        return original_argv(plan, policy, fixture=pcap)

    monkeypatch.setattr("soc_agent.security_ai.collectors.live_process.docker_argv", offline)
    original_popen = subprocess.Popen

    def unprivileged(argv, **kwargs):
        assert argv[:3] == ["sudo", "-n", "--"]
        assert "--network=none" in argv and "--cap-add=NET_RAW" not in argv
        calls.append("offline_process")
        return original_popen(argv[3:], **kwargs)

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.live_process.subprocess.Popen", unprivileged
    )
    # Restrict replacement to the Native runner subprocess; environment uses subprocess.run
    # (which internally calls Popen), so cache its already-verified official image check.
    monkeypatch.setattr(OfflineZeek, "environment", lambda _: {})
    original_run = subprocess.run

    def docker(self, *args):
        # Cleanup/inventory retains the same verified-container logic, with no sudo.
        with monkeypatch.context() as local:
            local.setattr(subprocess, "Popen", original_popen)
            return original_run(["docker", *args], capture_output=True, timeout=7, check=False)

    monkeypatch.setattr(StreamProcess, "_docker", docker)
    captured = {}

    def gui(args, *, prepared):
        calls.append("gui_ready")
        owner = prepared.worker.backend._owners["zeek_collector"]
        assert not prepared.runner._launched and owner.state == "STARTING"

        class Ready:
            def render(self, _):
                pass

            def call(self, method, runner, **kwargs):
                prepared.worker.submit(method, runner).result(5)

        prepared.gui_ready(Ready())

        async def finished():
            await asyncio.wait_for(owner.task, 40)
            owner.store.verify()
            return owner.snapshot()

        snap = asyncio.run_coroutine_threadsafe(finished(), prepared.worker.loop).result(45)
        assert snap["state"] == "STOPPED", snap["last_error"]
        assert snap["packet_budget"]["used"] == 4096
        assert snap["closed_status"] == "OBSERVED" and snap["cleanup_verified"]
        assert owner.queue_depth == 0 and owner.queue_peak <= 32
        assert snap["research"]["records"] == [] and owner.producer is None
        assert snap["finalization_state"] == "DEGRADED"
        captured.update(session=owner.directory, snapshot=snap)
        return 0

    monkeypatch.setattr("soc_agent.gui.__main__.main", gui)
    assert startup.start(tmp_path / "gui") == 0
    assert calls == ["auth", "gui_ready", "offline_process"]
    path = captured["session"]
    proof = json.loads((path / "cli-exit.json").read_text())
    assert proof["safe_shutdown"] and proof["audit_integrity"] == "VERIFIED"
    assert proof["cleanup"] == "VERIFIED"
    # recover is read-only in behavior: no collector/AI restart and same audit chain.
    from soc_agent.security_ai.collectors.live import LiveZeekCollector

    async def recover():
        c = LiveZeekCollector(tmp_path / "gui")
        snap = await c.recover()
        assert snap["state"] == "STOPPED" and snap["runtime_audit_integrity"] == "VERIFIED"
        assert c.producer is None and c.task is None
        assert snap["research"]["records"] == []
        await c.stop()

    asyncio.run(recover())
