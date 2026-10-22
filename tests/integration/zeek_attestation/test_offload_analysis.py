"""Real pinned Zeek, synthetic memory input; never Native capture or traffic."""

import json
import struct
import threading
import time
from pathlib import Path

import pytest
from tests.integration.zeek_attestation.test_c3_dns import dns_frames, tcp_segment
from tests.integration.zeek_attestation.test_checksum_root_cause import modeled_frame
from tests.unit.collectors.test_checksum_evidence import aux

from soc_agent.security_ai.collectors.live_contract import docker_argv, new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.offload_copy import analysis_copy, memory_pcap


@pytest.mark.parametrize("transport", ["udp", "tcp"])
@pytest.mark.parametrize("bounded_deadline,streamed", [(False, False), (True, False), (True, True)])
def test_confirmed_partial_memory_copies_reach_real_zeek_dns(
    tmp_path, transport, bounded_deadline, streamed
):
    q, r = dns_frames(tmp_path / "fixture.pcap")
    frames = [q, r]
    if transport == "tcp":
        qb, rb = q[42:], r[42:]
        qb, rb = struct.pack("!H", len(qb)) + qb, struct.pack("!H", len(rb)) + rb
        frames = [
            tcp_segment(q),
            tcp_segment(q, reverse=True, seq=500, ack=101, flags=18),
            tcp_segment(q, seq=101, ack=501, flags=16),
            tcp_segment(q, seq=101, ack=501, flags=24, payload=qb),
            tcp_segment(q, reverse=True, seq=501, ack=101 + len(qb), flags=24, payload=rb),
            tcp_segment(q, seq=101 + len(qb), ack=501 + len(rb), flags=17),
            tcp_segment(q, reverse=True, seq=501 + len(rb), ack=102 + len(qb), flags=17),
            tcp_segment(q, seq=102 + len(qb), ack=502 + len(rb), flags=16),
        ]
    copies = []
    for i, frame in enumerate(frames):
        # Rebind fixture's endpoint pair to the explicitly supported local scope,
        # then recompute IP checksum before modeling the partial seed.
        from soc_agent.security_ai.collectors.offload_copy import checksum

        changed = bytearray(frame)
        changed[26:30] = b"\x7f\0\0\x35" if frame[34:36] == b"\0\x35" else b"\x7f\0\0\1"
        changed[30:34] = b"\x7f\0\0\1" if changed[26:30] == b"\x7f\0\0\x35" else b"\x7f\0\0\x35"
        changed[24:26] = bytes(2)
        changed[24:26] = struct.pack("!H", checksum(changed[14:34]))
        raw = modeled_frame(bytes(changed), "partial_seed")[14:]
        result = analysis_copy(raw, aux(raw, 9))
        assert result.status == "CHECKSUM_PARTIAL_CONFIRMED"
        copies.append((1800000000000000000 + i * 50_000_000, result.packet))
    plan = new_plan()
    from soc_agent.security_ai.collectors.analysis_feed import AnalysisFeed

    feed = AnalysisFeed() if streamed else None
    runner = StreamProcess(
        tmp_path,
        plan,
        pcap_input=None if streamed else memory_pcap(copies),
        analysis_feed=feed,
        analysis_deadline=time.monotonic() + 5 if bounded_deadline else None,
    )
    from soc_agent.security_ai.collectors.live_stream import Stream, decode
    from soc_agent.security_ai.collectors.models import Source

    stream = Stream(
        Source(session_id=plan.session_id, source_digest="0" * 64, origin="SYNTHETIC_ZEEK_JSON")
    )
    from soc_agent.security_ai.collectors.store import CollectorStore

    diagnostics = CollectorStore(tmp_path / "diagnostics", stream.source)
    errors = []
    ready = threading.Event()

    def consume(line):
        message = decode(line)
        event = stream.accept(message)
        if event is not None:
            diagnostics.commit(event.kind, [event], dict(sequence=message.sequence))
        if message.kind == "ready":
            ready.set()

    def run():
        try:
            runner.run(on_line=consume)
        except (OSError, ValueError) as exc:
            errors.append(exc)
            ready.set()

    if streamed:
        worker = threading.Thread(target=run)
        worker.start()
        try:
            assert ready.wait(4), "Zeek must be READY before any packet or EOF"
            assert not errors
            assert runner.phase_times["script_init"] <= runner.phase_times["ready"]
            assert not feed.exhausted
            for stamp, packet in copies:
                feed.put(stamp, packet)
        finally:
            feed.close()
            worker.join(10)
        assert not worker.is_alive() and not errors
    else:
        runner.run(on_line=consume)
    assert stream.dns_count == 1
    assert stream.dns_adapter_rejected == 0
    assert stream.closed and stream.dns_stages.transaction_matched == 1
    recovered = CollectorStore(tmp_path / "diagnostics")
    recovered.verify()  # Normalized DNS event + append-only Audit survives read-only recovery.
    assert recovered.counts()["dns"] == 1
    rows = [json.loads(x) for x in (tmp_path / "stream.jsonl").read_text().splitlines()]
    assert rows[-1]["kind"] == "closed"
    dns = rows[-1]["data"]["dns_diagnostics"]
    assert dns["query_parsed"] == dns["response_parsed"] == dns["transaction_matched"] == 1
    assert dns["transport_checksum_rejected"] == 0
    receipt = json.loads((tmp_path / "exit.json").read_text())
    assert receipt["protocol_finalized"] and receipt["cleanup_verified"]
    assert receipt["analysis_copy_input"] and not receipt["native_capture"]
    if streamed:
        timing = runner.analysis_container_timing()
        (tmp_path / "container-timing.json").write_text(json.dumps(timing))
        assert timing["verified"]
        actions = {event["action"]: event["wall_ns"] for event in timing["events"]}
        assert actions["create"] <= actions["start"] <= runner.phase_wall_ns["ready"]
        assert runner.phase_times["ready"] < runner.phase_times["input_closed"]
        assert runner.phase_times["input_closed"] <= runner.phase_times["counter"]
        assert runner.phase_times["counter"] <= runner.phase_times["closed"]
    argv = docker_argv(plan, tmp_path, stdin_pcap=True)
    assert "--network=none" in argv and "--cap-drop=ALL" in argv
    assert "--cap-add=NET_RAW" not in argv and "-C" not in argv
    assert "-r -" in argv[-3]


def test_existing_supervisor_proxy_needs_no_stdin_attribute(tmp_path, monkeypatch):
    """Mock authentication, actual file-only Zeek. Never open a Native interface."""
    import subprocess
    from types import SimpleNamespace

    source = tmp_path / "input.pcap"
    dns_frames(source)
    plan = new_plan()
    process = None

    class FixtureSupervisor:
        def start(self, requested):
            nonlocal process
            process = subprocess.Popen(
                docker_argv(
                    requested,
                    Path(__file__).resolve().parents[3] / "src/soc_agent/security_ai/collectors",
                    fixture=source,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            # The production ZeekProcess proxy intentionally has no stdin.
            return SimpleNamespace(stdout=process.stdout, poll=process.poll, wait=process.wait)

        def stop_zeek(self):
            if process and process.poll() is None:
                subprocess.run(
                    ["docker", "stop", "--time=2", "soc-zeek-" + plan.session_id.hex],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            result = subprocess.run(
                [
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    "name=^/soc-zeek-" + plan.session_id.hex + "$",
                    "--format",
                    "{{.ID}}",
                ],
                capture_output=True,
                timeout=3,
                check=False,
            )
            return result.returncode == 0 and not result.stdout.strip()

    runner = StreamProcess(tmp_path, plan, supervisor=FixtureSupervisor())
    runner._authenticated_plan = plan.identity  # Test-only auth fixture, never Native success.
    monkeypatch.setattr(runner, "_controller", lambda *args: {})
    with pytest.raises(ValueError, match="ZEEK_NATIVE_UNREQUESTED_EXIT"):
        runner.run()  # File EOF must still be rejected as an unsolicited Native exit.
    exit_record = json.loads((tmp_path / "exit.json").read_text())
    assert exit_record["closed_observed"] and exit_record["cleanup_verified"]
