"""Fail-closed accounting and process/stream/cleanup independence, without capture."""

import asyncio
import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from soc_agent.security_ai.collectors.finalization import (
    Closed,
    Ledger,
    publish,
    termination_reason,
)
from soc_agent.security_ai.collectors.live_contract import new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.live_stream import Envelope


def proof(**updates):
    return Closed(
        **dict(
            dict(
                stop_reason="ZEEK_DONE",
                packet_records=0,
                network_events=0,
                dns_events=0,
                messages_before_closed=1,
                bytes_before_closed=43,
                omitted_packet_records=0,
                omitted_events=0,
                pkts_recvd=0,
                pkts_dropped=0,
                pkts_link=0,
                bytes_recvd=0,
            ),
            **updates,
        )
    )


@pytest.mark.parametrize(
    "updates",
    [
        dict(packet_records=4097),
        dict(messages_before_closed=8192),
        dict(pkts_dropped=-1),
        dict(pkts_recvd=None),
        dict(pkts_recvd=True),
        dict(bytes_before_closed=8388608),
        dict(secret="never"),
    ],
)
def test_invalid_or_unknown_counter_rejected(updates):
    with pytest.raises(ValueError):
        proof(**updates)


@pytest.mark.parametrize(
    "updates",
    [
        dict(packet_records=1),
        dict(messages_before_closed=2),
        dict(omitted_events=1),
        dict(stop_reason="PACKET_LIMIT_REACHED"),
        dict(stop_reason="EVENT_LIMIT_REACHED"),
        dict(pkts_dropped=1),
    ],
)
def test_terminal_accounting_failure(updates):
    with pytest.raises(ValueError):
        proof(**updates).verify(sequence=2, packets=0, network=0, dns=0)


@pytest.mark.parametrize(
    "reason,code,requested,expected",
    [
        ("ZEEK_DONE", 0, "USER_STOP", "USER_STOP"),
        ("ZEEK_DONE", 0, "CONTROLLER_STOP", "CONTROLLER_STOP"),
        ("ZEEK_DONE", 124, None, "SESSION_TIMEOUT"),
        ("PACKET_LIMIT_REACHED", 124, "USER_STOP", "PACKET_LIMIT_REACHED"),
        ("EVENT_LIMIT_REACHED", 0, "USER_STOP", "EVENT_LIMIT_REACHED"),
        ("OUTPUT_LIMIT_REACHED", 0, None, "OUTPUT_LIMIT_REACHED"),
    ],
)
def test_first_zeek_budget_reason_wins_stop_race(reason, code, requested, expected):
    assert termination_reason(proof(stop_reason=reason), code, requested) == expected


def test_duplicate_closed_and_exact_byte_integrity():
    ledger = Ledger()
    ready = Envelope(sequence=1, kind="ready", data={})
    ledger.accept(ready, b"r" * 43)
    end = Envelope(sequence=2, kind="closed", data=proof().model_dump())
    ledger.accept(end, b"closed\n")
    with pytest.raises(ValueError, match="SEQUENCE_INTEGRITY"):
        ledger.accept(end, b"closed\n")
    bad = Ledger()
    bad.accept(ready, b"different")
    with pytest.raises(ValueError, match="ACCOUNTING_MISMATCH"):
        bad.accept(end, b"closed\n")


def runner(tmp_path, monkeypatch, scenario):
    from soc_agent.security_ai.collectors.offline import OfflineZeek

    monkeypatch.setattr(OfflineZeek, "environment", lambda self: {})
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.live_process.docker_argv",
        lambda *a, **kw: [sys.executable, "-m", "tests.zeek_finalization_child", scenario],
    )
    r = StreamProcess(tmp_path, new_plan(), fixture=tmp_path / "no-capture.pcap")
    monkeypatch.setattr(r, "_absent", lambda: True)
    return r


@pytest.mark.parametrize(
    "scenario,error",
    [
        ("normal", None),
        ("timeout", None),
        ("exit1", "EXIT_UNVERIFIED"),
        ("missing", "EXIT_UNVERIFIED"),
        ("partial", "PARTIAL_RECORD"),
        ("duplicate", "SEQUENCE_INTEGRITY"),
    ],
)
def test_process_stdout_eof_not_exit_alone(tmp_path, monkeypatch, scenario, error):
    r = runner(tmp_path, monkeypatch, scenario)
    if error:
        with pytest.raises(ValueError, match=error):
            r.run()
    else:
        r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["container_absent"]
    assert result["cleanup_verified"]
    assert result["protocol_finalized"] is (error is None)
    assert not result["native_capture"] and result["capture_integrity"] == "UNVERIFIED"
    if scenario == "timeout":
        assert result["termination_reason"] == "SESSION_TIMEOUT"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stop_reason,expected", [(None, "USER_STOP"), ("GUI_CLOSE", "CONTROLLER_STOP")]
)
async def test_stop_keeps_draining_while_container_waits(
    tmp_path, monkeypatch, stop_reason, expected
):
    r = runner(tmp_path, monkeypatch, "stop_flush")
    calls = []

    def stop():
        calls.append(1)
        r.process.send_signal(signal.SIGINT)
        r.process.wait(timeout=3)
        return True

    monkeypatch.setattr(r, "_stop_container", stop)
    task = asyncio.create_task(asyncio.to_thread(r.run))
    for _ in range(200):
        if (tmp_path / "stream.jsonl").exists() and (tmp_path / "stream.jsonl").stat().st_size:
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.1)  # Fixture has installed its signal handler.
    if stop_reason:
        publish(tmp_path / "stop.request", dict(reason=stop_reason))
    r.stop()
    r.stop()
    await asyncio.wait_for(task, 8)
    result = json.loads((tmp_path / "exit.json").read_text())
    assert calls == [1] and result["sequence"] == 1002
    assert result["closed_detail"]["network_events"] == 1000
    assert result["protocol_finalized"] and result["cleanup_verified"]
    assert result["termination_reason"] == expected


def test_cleanup_needs_successful_exact_name_query(tmp_path, monkeypatch):
    r = runner(tmp_path, monkeypatch, "normal")
    monkeypatch.undo()
    r = StreamProcess(tmp_path, new_plan(), fixture=Path("/fixture.pcap"))
    responses = iter(
        [
            subprocess.CompletedProcess([], 1, b"", b"denied"),
            subprocess.CompletedProcess([], 0, b"running-id\n", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
    )
    monkeypatch.setattr(r, "_docker", lambda *args: next(responses))
    assert not r._absent()
    assert not r._absent()
    assert r._absent()


def test_cleanup_failure_cannot_be_repaired_by_valid_closed(tmp_path, monkeypatch):
    r = runner(tmp_path, monkeypatch, "normal")
    monkeypatch.setattr(r, "_absent", lambda: False)
    monkeypatch.setattr(r, "_stop_container", lambda: False)
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["closed_observed"] and result["exit_code"] == 0
    assert not result["container_absent"] and not result["cleanup_verified"]
    assert not result["protocol_finalized"] and result["error"]


def test_container_cleanup_after_client_exit_preserves_original_failure(tmp_path, monkeypatch):
    r = runner(tmp_path, monkeypatch, "normal")
    responses = iter([False, False, True])
    monkeypatch.setattr(r, "_absent", lambda: next(responses))
    calls = []
    monkeypatch.setattr(r, "_stop_container", lambda: calls.append(1) or True)
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    assert calls == [1] and result["cleanup_verified"]
    assert result["error"] and not result["protocol_finalized"]


def test_closed_without_eof_has_bounded_drain_and_no_orphan(tmp_path, monkeypatch):
    import time
    from types import SimpleNamespace

    r = runner(tmp_path, monkeypatch, "closed_hang")
    offset = [0]
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.live_process.time",
        SimpleNamespace(monotonic=lambda: time.monotonic() + offset[0], time_ns=time.time_ns),
    )

    def observed(line):
        if b'"closed"' in line:
            offset[0] = 11

    def stop():
        r.process.terminate()
        r.process.wait(timeout=2)
        return True

    monkeypatch.setattr(r, "_stop_container", stop)
    with pytest.raises(ValueError, match="STOP_DEADLINE_UNVERIFIED"):
        r.run(on_line=observed)
    assert r.process.poll() is not None
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["closed_observed"] and result["error"]
    assert not result["protocol_finalized"]


@pytest.mark.parametrize("labels", [None, [], "not-a-label-map"])
def test_malformed_docker_labels_never_signal_an_unverified_container(
    tmp_path, monkeypatch, labels
):
    r = StreamProcess(tmp_path, new_plan(), fixture=Path("/offline-fixture.pcap"))
    monkeypatch.setattr(r, "_absent", lambda: False)
    calls = []

    def docker(*args):
        calls.append(args[0])
        raw = json.dumps(dict(id="a" * 64, image=r.plan.image, labels=labels)).encode()
        return subprocess.CompletedProcess([], 0, raw, b"")

    monkeypatch.setattr(r, "_docker", docker)
    assert not r._stop_container()
    assert calls == ["inspect"]


def test_adapter_failure_still_records_valid_closed_and_cleanup(tmp_path, monkeypatch):
    r = runner(tmp_path, monkeypatch, "normal")
    monkeypatch.setattr(r, "_stop_container", lambda: True)

    def failed_adapter(_):
        raise ValueError("ZEEK_RECORD_SCHEMA_REJECTED")

    with pytest.raises(ValueError, match="ZEEK_RECORD_SCHEMA_REJECTED"):
        r.run(on_line=failed_adapter)
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["closed_observed"] and result["closed_detail"] is not None
    assert not result["protocol_finalized"] and result["cleanup_verified"]
    assert result["error"] == result["adapter_failure"] == "ZEEK_RECORD_SCHEMA_REJECTED"
    assert result["discarded_after_adapter_failure"] == 1


def test_status_rpc_failure_cannot_skip_exit_evidence_or_replace_first_error(tmp_path, monkeypatch):
    r = runner(tmp_path, monkeypatch, "missing")
    monkeypatch.setattr(r, "_stop_container", lambda: True)
    original = subprocess.Popen

    class StatusFailure:
        def __init__(self, *args, **kwargs):
            self.real = original(*args, **kwargs)
            self.stdout = self.real.stdout

        def poll(self):
            raise ValueError("SUPERVISOR_STATUS_LOST")

        def wait(self, timeout):
            return self.real.wait(timeout=timeout)

        def kill(self):
            raise ValueError("SUPERVISOR_STOP_LOST")

    monkeypatch.setattr(subprocess, "Popen", StatusFailure)
    with pytest.raises(ValueError, match="ZEEK_CONTAINER_EXIT_UNVERIFIED"):
        r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["error"] == "ZEEK_CONTAINER_EXIT_UNVERIFIED"
    assert not result["closed_observed"] and result["exit_code"] is None
    assert any(x["stage"] == "STATUS" for x in result["cleanup_failures"])
    assert result["container_absent"] and result["cleanup_verified"]


def test_missing_closed_retains_original_failure_before_normalization(tmp_path, monkeypatch):
    r = runner(tmp_path, monkeypatch, "missing")
    with pytest.raises(ValueError):
        r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    first = result["first_failure"]
    assert first["stage"] == "STREAM_FINALIZE"
    assert first["original_code"] == "ZEEK_CONTAINER_EXIT_UNVERIFIED"
    assert first["api"] == "CLOSED_AND_EXIT_VALIDATION"
    assert first["errno"] is None and not first["closed_observed"]
    assert result["cleanup_verified"] and not result["protocol_finalized"]


@pytest.mark.parametrize(
    "failure", [OSError(5, "private secret text"), ValueError("ZEEK_NEW_PARSER_FAULT")]
)
def test_original_stream_failure_is_preserved_even_if_cleanup_also_fails(
    tmp_path, monkeypatch, failure
):
    r = runner(tmp_path, monkeypatch, "normal")

    def denied(_):
        raise failure

    monkeypatch.setattr("soc_agent.security_ai.collectors.live_process.decode", denied)
    monkeypatch.setattr(r, "_absent", lambda: False)
    monkeypatch.setattr(r, "_stop_container", lambda: False)
    with pytest.raises(ValueError):
        r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    first = result["first_failure"]
    assert first["stage"] == "STREAM_DECODE"
    assert first["exception_class"] == type(failure).__name__
    assert first["errno"] == (5 if isinstance(failure, OSError) else None)
    assert first["original_code"] == (None if isinstance(failure, OSError) else str(failure))
    assert "private secret text" not in json.dumps(result)
    assert not result["cleanup_verified"] and not result["protocol_finalized"]


def test_wrapped_docker_errno_retained_without_secret_exception_text():
    from soc_agent.security_ai.collectors.handoff import failure_evidence

    try:
        try:
            raise OSError(13, "sensitive system path")
        except OSError as exc:
            raise ValueError("ZEEK_DOCKER_START_FAILED") from exc
    except ValueError as exc:
        result = failure_evidence(exc, stage="LAUNCH", api="SupervisorClient.start")
    assert result["original_code"] == "ZEEK_DOCKER_START_FAILED"
    assert result["causes"][0]["errno"] == 13
    assert "sensitive system path" not in str(result)
