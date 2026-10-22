import base64
import json
from pathlib import Path

import pytest
from tests.unit.collectors.test_checksum_evidence import aux, packet

from soc_agent.security_ai.collectors.offload_copy import analysis_copy
from soc_agent.security_ai.collectors.offload_session import execute, verify_frame
from soc_agent.security_ai.ebpf_tc.dns_copy_engine import capture_analysis


def row():
    original = packet(partial=True)
    metadata = aux(original, 9)
    result = analysis_copy(original, metadata)
    return dict(
        receipt=result.receipt(),
        auxiliary_hex=metadata.hex(),
        analysis_frame=base64.b64encode(result.packet).decode(),
    )


def test_original_can_be_reconstructed_without_persisting_payload():
    value = row()
    assert verify_frame(value) == base64.b64decode(value["analysis_frame"])
    value["receipt"]["original_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="DIGEST"):
        verify_frame(value)


def test_changed_analysis_copy_and_missing_status_fail_closed():
    value = row()
    body = bytearray(base64.b64decode(value["analysis_frame"]))
    body[-1] ^= 1
    value["analysis_frame"] = base64.b64encode(body).decode()
    with pytest.raises(ValueError, match="DIGEST"):
        verify_frame(value)
    value = row()
    value["receipt"]["status"] = "CHECKSUM_UNKNOWN"
    with pytest.raises(ValueError, match="STATUS"):
        verify_frame(value)


def test_wrong_manifest_fails_before_any_authentication(tmp_path, monkeypatch):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("must not authenticate"))
    (tmp_path / "release.json").write_text("{}")
    with pytest.raises(ValueError, match="MANIFEST_MISMATCH"):
        execute(tmp_path, "0" * 64, "0" * 64, probe=Path("unused"))


def test_capture_drop_failure_closes_socket_and_preserves_stage(monkeypatch):
    from soc_agent.security_ai.ebpf_tc import dns_copy_engine as engine

    events = []

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            events.append("close")

        def setsockopt(self, *args):
            pass

        def bind(self, *args):
            raise PermissionError(1, "test binding denied")

    monkeypatch.setattr(engine.os, "geteuid", lambda: 0)
    monkeypatch.setattr(engine.os, "readlink", lambda path: "net:[4026531833]")
    monkeypatch.setattr(engine.socket, "if_nametoindex", lambda name: 1)
    monkeypatch.setattr(engine.socket, "socket", lambda *args: Channel())
    monkeypatch.setattr(engine, "emit_result", lambda value: events.append(value))
    with pytest.raises(PermissionError):
        capture_analysis(
            1000,
            1000,
            lambda sock: None,
            lambda: pytest.fail("no drop"),
            lambda *args: pytest.fail("no normalize"),
            lambda *args: pytest.fail("no chain"),
            "0" * 64,
        )
    assert events[0] == "close"
    assert events[1]["stage"] == "SOCKET_BIND" and events[1]["errno"] == 1
    assert "packet" not in json.dumps(events[1])


def test_exact_embedded_image_wiring_without_running_privileged_entry(tmp_path, monkeypatch):
    import sys
    import types

    from soc_agent.security_ai.ebpf_tc.checksum_image import prepare

    image = prepare(tmp_path / "image.py", analysis=True)
    image.verify()
    module = types.ModuleType("reviewed_dns_copy_image")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    # __name__ is deliberately not __main__: no authentication, socket or install.
    exec(compile(image.path.read_bytes(), "<reviewed-candidate>", "exec"), module.__dict__)
    value = packet(partial=True)
    copy = module.analysis_copy(value, aux(value, 9))
    assert copy.status == "CHECKSUM_PARTIAL_CONFIRMED"
    assert module.analysis_copy(copy.packet, aux(value)).status == "CHECKSUM_VALID"
    calls = []
    module.capture_analysis = lambda *args, **kwargs: calls.append((args, kwargs))
    module.capture(1000, 1000)
    args, kwargs = calls[0]
    assert args[:2] == (1000, 1000)
    assert args[2] is module.attach_filter
    assert args[4] is module.analysis_copy
    assert args[5] is module.chain_receipt
    assert args[6] == module.SCOPE_DIGEST
    assert kwargs == {"start_gate": True, "session_started": None}


def test_analysis_feed_has_one_total_queue32_budget():
    from soc_agent.security_ai.collectors.analysis_feed import AnalysisFeed

    feed = AnalysisFeed()
    for i in range(32):
        feed.put(i, packet())
    assert feed.count == feed.peak == 32
    assert feed.take() is not None
    with pytest.raises(ValueError, match="LIMIT"):
        feed.put(33, packet())  # Consuming does not reset the total packet budget.
    feed.clear()
    assert feed.exhausted
    with pytest.raises(ValueError, match="CLOSED"):
        feed.put(0, packet())


@pytest.mark.parametrize("expired", [False, True])
def test_wrong_start_token_or_expired_session_never_opens_capture_socket(monkeypatch, expired):
    from soc_agent.security_ai.ebpf_tc import dns_copy_engine as engine

    monkeypatch.setattr(engine.os, "geteuid", lambda: 0)
    monkeypatch.setattr(engine.os, "readlink", lambda path: "net:[4026531833]")
    monkeypatch.setattr(engine.socket, "if_nametoindex", lambda name: 1)
    monkeypatch.setattr(engine.select, "select", lambda *args: ([0], [], []))
    monkeypatch.setattr(engine.os, "read", lambda *args: b"BAD\n")
    monkeypatch.setattr(engine, "emit_result", lambda value: None)
    monkeypatch.setattr(engine.socket, "socket", lambda *args: pytest.fail("no capture"))
    import time

    with pytest.raises(ValueError, match="SESSION_DEADLINE" if expired else "START_REQUIRED"):
        capture_analysis(
            1000,
            1000,
            None,
            None,
            None,
            None,
            "0" * 64,
            start_gate=True,
            session_started=time.monotonic() - 20 if expired else None,
        )


def test_expired_analysis_budget_rejects_before_docker_lookup(tmp_path, monkeypatch):
    from soc_agent.security_ai.collectors.live_contract import new_plan
    from soc_agent.security_ai.collectors.live_process import StreamProcess
    from soc_agent.security_ai.collectors.offload_copy import memory_pcap

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: pytest.fail("no launch"))
    runner = StreamProcess(tmp_path, new_plan(), pcap_input=memory_pcap([]), analysis_deadline=0)
    with pytest.raises(ValueError, match="DEADLINE_BEFORE_LAUNCH"):
        runner.run()
    assert not (tmp_path / "process.json").exists()


def test_analysis_deadline_cannot_change_existing_native_path(tmp_path):
    from soc_agent.security_ai.collectors.live_contract import new_plan
    from soc_agent.security_ai.collectors.live_process import StreamProcess

    with pytest.raises(ValueError, match="DEADLINE_SCOPE"):
        StreamProcess(tmp_path, new_plan(), analysis_deadline=1)
