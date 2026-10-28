"""Ordinary Controller/CLI with real temporary bytes; no Root, sockets or execution."""

import hashlib
import json
from pathlib import Path

import pytest
from tests.unit.ebpf_tc.test_namespace_runtime import NS, config

from soc_agent.security_ai.ebpf_tc import namespace_controller as controller
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.request_handoff import wait_for_request as actual_wait


def sha(body):
    return hashlib.sha256(body).hexdigest()


def append(path, **event):
    lines = path.read_bytes().splitlines(keepends=True)
    unsigned = dict(sequence=len(lines), previous_record_sha256=sha(lines[-1]), **event)
    with path.open("ab") as stream:
        stream.write(canonical(unsigned | dict(record_sha256=sha(canonical(unsigned)))))


@pytest.fixture
def context(tmp_path, monkeypatch):
    data = config(tmp_path)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(canonical(dict(event="SYNTHETIC_GENESIS")))
    append(
        ledger,
        attempt_id="synthetic-attempt",
        event="ROOT_OPERATION_FINISHED_V1",
        state="SUCCEEDED",
    )
    ack = tmp_path / "ack.json"
    ack.write_bytes(canonical(dict(ledger_sha=sha(ledger.read_bytes()))))
    request = dict(
        data["target"],
        amendment_file=str(tmp_path / "amendment.json"),
        amendment_sha="d" * 64,
        approval_file=str(tmp_path / "approval.json"),
        approval_sha="e" * 64,
        traffic_file=str(tmp_path / "traffic.json"),
        traffic_sha="f" * 64,
        claim_file=str(tmp_path / "claim"),
    )
    Path(data["request_file"]).write_bytes(canonical(request))
    data.update(
        namespace=NS,
        cookie="0011223344556677",
        attempt="synthetic-attempt",
        ack=str(ack),
        ledger=str(ledger),
        entry=dict(
            session="SYNTHETIC_CONTROLLER_SESSION",
            release="SYNTHETIC_RELEASE",
            root_manifest="b" * 64,
            source_snapshot="c" * 64,
        ),
    )
    # Only OS Namespace/socket boundaries are substituted. Source, SHA, ACK,
    # chain, request schema and CLI exception handling use their real functions.
    monkeypatch.setattr(controller.os, "readlink", lambda *_: NS)

    class Cookie:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def getsockopt(self, *_):
            return bytes.fromhex(data["cookie"])

    monkeypatch.setattr(controller.socket, "socket", lambda *_: Cookie())
    monkeypatch.setattr("builtins.input", lambda *_: sha(Path(data["request_file"]).read_bytes()))
    from soc_agent.security_ai.ebpf_tc import auth_session

    monkeypatch.setattr(auth_session, "open_authentication_tty", lambda *_: pytest.fail("No auth"))
    # These diagnostic unit tests isolate the handoff qualifier. Its real image,
    # receipts and Ledger path is exercised in test_request_handoff.
    from soc_agent.security_ai.ebpf_tc import request_handoff

    monkeypatch.setattr(request_handoff, "wait_for_request", lambda *_: {})
    monkeypatch.setattr(
        request_handoff,
        "verify_ready",
        lambda *_: dict(request_sha=sha(Path(data["request_file"]).read_bytes())),
    )
    return data, ledger, ack, request


def outcome(data):
    return json.loads(Path(data["ack"]).with_suffix(".controller-result.json").read_bytes())


@pytest.mark.parametrize("fault", ["stale", "sha", "chain", "other_attempt", "unfinished"])
def test_controller_real_ack_ledger_failures_precede_prompt(context, monkeypatch, fault):
    data, ledger, ack, _ = context
    if fault == "stale":
        append(ledger, event="SYNTHETIC_NEW_R1_RECORD")
    elif fault == "sha":
        ack.write_bytes(canonical(dict(ledger_sha="0" * 64)))
    else:
        rows = [json.loads(x) for x in ledger.read_bytes().splitlines()]
        if fault == "chain":
            rows[-1]["record_sha256"] = "0" * 64
        else:
            rows[-1]["attempt_id" if fault == "other_attempt" else "state"] = "UNKNOWN"
            unsigned = {k: v for k, v in rows[-1].items() if k != "record_sha256"}
            rows[-1]["record_sha256"] = sha(canonical(unsigned))
        ledger.write_bytes(b"".join(canonical(r) for r in rows))
        ack.write_bytes(canonical(dict(ledger_sha=sha(ledger.read_bytes()))))
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("Prompt before settlement"))
    before = ledger.read_bytes()
    expected = (
        "DNS_LEDGER_SHA"
        if fault in {"stale", "sha"}
        else ("DNS_LEDGER_CHAIN" if fault == "chain" else "NAMESPACE_CONTROLLER_ENTRY_NOT_SETTLED")
    )
    with pytest.raises(ValueError, match=expected):
        controller.child_main(data)
    result = outcome(data)
    assert result["first_failure"]["error"] == expected
    assert result["stage"] == "SETTLEMENT_LEDGER"
    assert result["ledger_at_exit"]["sha256"] == sha(before)
    assert result["entry"]["session"] == "SYNTHETIC_CONTROLLER_SESSION"
    assert result["frames"][-1]["function"] in {"dns_held_json_ledger", "_child_main"}
    assert result["native_cleanup"] == "NOT_STARTED"
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("body", [b'{"ledger_sha":"a","ledger_sha":"b"}', b"{}", b"[]"])
def test_duplicate_or_malformed_ack_is_not_authority(context, body):
    data, ledger, ack, _ = context
    ack.write_bytes(body)
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="ACK_"):
        controller.child_main(data)
    assert outcome(data)["stage"] == "SETTLEMENT_ACK"
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("fault", ["request_pin", "target", "schema", "runtime", "namespace"])
def test_controller_real_request_failures_do_not_authenticate(context, monkeypatch, fault):
    data, ledger, _, request = context
    if fault == "request_pin":
        monkeypatch.setattr("builtins.input", lambda *_: "0" * 64)
    elif fault == "target":
        request["image_sha"] = "0" * 64
    elif fault == "schema":
        request["unexpected"] = "not-a-grant"
    elif fault == "namespace":
        data["namespace"] = "net:[4000000001]"
    else:
        # Actual source/interpreter pin verifier, not a mocked validation result.
        data["interpreter_sha"] = "0" * 64
    Path(data["request_file"]).write_bytes(canonical(request))
    before = ledger.read_bytes()
    with pytest.raises((ValueError, SystemExit)):
        controller.child_main(data)
    result = outcome(data)
    assert result["status"] == "FAILED" and result["returncode"] != 0
    assert result["first_failure"] and result["frames"]
    assert result["artifact"] == data["target"]
    assert result["native_cleanup"] == "NOT_STARTED"
    assert ledger.read_bytes() == before


def test_real_controller_dispatches_real_cli_and_preserves_inner_origin(context):
    data, ledger, ack, _ = context
    before = ledger.read_bytes()
    # Valid ACK/chain/request reaches real CLI. Absent synthetic image metadata
    # blocks readiness; this is not a successful Runtime or Native test.
    with pytest.raises(SystemExit) as stopped:
        controller.child_main(data)
    assert stopped.value.code == 2
    result = outcome(data)
    assert result["stage"] == "NATIVE_CHECK"
    assert result["first_failure"]["status"] == "BLOCKED"
    assert result["first_failure"]["errno"] == 2
    assert result["first_failure"]["origin"][-1]["function"] in {"open", "read_text", "read_bytes"}
    assert result["controller_cleanup"] == "COOKIE_SOCKET_CLOSED"
    assert result["request_sha256"] == sha(Path(data["request_file"]).read_bytes())
    previous = Path(data["ack"]).with_suffix(".controller-result.json").read_bytes()
    # Re-reading an ACK grants nothing; existing receipt/admission validation
    # still runs, and an exclusive diagnostic cannot overwrite first evidence.
    with pytest.raises(ValueError, match="READY_DIAGNOSTIC_UNAVAILABLE"):
        controller.child_main(data)
    assert Path(data["ack"]).with_suffix(".controller-result.json").read_bytes() == previous
    assert ledger.read_bytes() == before and json.loads(ack.read_bytes())["ledger_sha"] == sha(
        before
    )


def test_cancel_records_normal_exit_without_admission(context, monkeypatch):
    data, ledger, _, _ = context
    before = ledger.read_bytes()
    monkeypatch.setattr("builtins.input", lambda *_: "cancel")
    controller.child_main(data)
    result = outcome(data)
    assert result["status"] == "CANCELLED_BEFORE_NATIVE_ADMISSION" and result["returncode"] == 0
    assert "first_failure" not in result and result["frames"] == []
    assert ledger.read_bytes() == before


def test_ack_verified_marker_precedes_new_request_and_append(context, monkeypatch):
    data, ledger, _, _ = context
    before = ledger.read_bytes()

    def operator(_prompt):
        ready = json.loads(Path(data["ack"]).with_suffix(".controller-ready.json").read_bytes())
        assert ready["stage"] == "REQUEST_INPUT"
        assert ready["ledger_at_ack"]["sha256"] == sha(before)
        assert ready["root_entry"]["state"] == "SUCCEEDED"
        append(ledger, event="SYNTHETIC_LATER_R1")
        return sha(Path(data["request_file"]).read_bytes())

    monkeypatch.setattr("builtins.input", operator)
    with pytest.raises(SystemExit):
        controller.child_main(data)
    result = outcome(data)
    assert result["ack_ledger_sha"] == sha(before)
    assert result["ledger_at_request"]["rows"] == 3
    assert result["ledger_at_ack"]["rows"] == 2
    # This case only proves the ACK/request handoff; absent synthetic metadata
    # still blocks the real CLI. Actual stale admission has a separate test.
    assert result["stage"] == "NATIVE_CHECK"


def test_first_error_is_durable_before_controller_unwinds(tmp_path, monkeypatch):
    data = dict(attempt="synthetic-attempt", ack=str(tmp_path / "ack.json"))

    def child(_config, state, observe):
        state["stage"] = "NATIVE_CHECK"
        observe(dict(status="BLOCKED", error="FIRST_ERROR"))
        first = tmp_path / "ack.controller-first-error.json"
        snapshot = json.loads(first.read_bytes())
        assert snapshot["first_failure"]["error"] == "FIRST_ERROR"
        assert snapshot["status"] == "FIRST_ERROR_OBSERVED_EXIT_PENDING"
        assert snapshot["returncode"] is None
        observe(dict(status="BLOCKED", error="SECOND_ERROR"))
        assert json.loads(first.read_bytes())["first_failure"]["error"] == "FIRST_ERROR"
        raise SystemExit(2)

    monkeypatch.setattr(controller, "_child_main", child)
    with pytest.raises(SystemExit):
        controller.child_main(data)


def test_native_primary_error_survives_cleanup_and_outer_exit(tmp_path, monkeypatch):
    data = dict(attempt="synthetic-attempt", ack=str(tmp_path / "ack.json"))

    def child(_config, state, observe):
        state["stage"] = "NATIVE_EXECUTE"
        observe(
            dict(
                first_failure=dict(
                    original_code="TCX_START_FAILED:-1",
                    stage="TCX_START",
                    errno=13,
                    return_value=-1,
                    private_text="not persisted",
                ),
                cleanup_status="CLEANUP_UNVERIFIED",
            )
        )
        first = json.loads((tmp_path / "ack.controller-first-error.json").read_bytes())
        assert first["first_failure"]["error"] == "TCX_START_FAILED:-1"
        assert first["first_failure"]["stage"] == "TCX_START"
        assert first["returncode"] is None
        observe(dict(status="BLOCKED", error="LATER_CLEANUP_ERROR"))
        raise SystemExit(1)

    monkeypatch.setattr(controller, "_child_main", child)
    with pytest.raises(SystemExit):
        controller.child_main(data)
    result = outcome(data)
    assert result["returncode"] == 1 and result["first_failure"]["errno"] == 13
    assert result["first_failure"]["return_value"] == -1
    assert result["native_cleanup"] == "CLEANUP_UNVERIFIED"
    assert "not persisted" not in json.dumps(result)


def test_missing_ready_preserves_first_error_before_input(context, monkeypatch):
    from soc_agent.security_ai.ebpf_tc import request_handoff

    data, ledger, _, _ = context
    before = ledger.read_bytes()
    monkeypatch.setattr(
        request_handoff, "wait_for_request", lambda path: actual_wait(path, timeout=0)
    )
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("Input before READY"))
    with pytest.raises(TimeoutError, match="EXECUTION_REQUEST_READY_TIMEOUT"):
        controller.child_main(data)
    result = outcome(data)
    assert result["first_failure"]["error"] == "EXECUTION_REQUEST_READY_TIMEOUT"
    assert result["stage"] == "REQUEST_READY_WAIT"
    assert result["returncode"] == 1 and result["frames"][-1]["function"] == "wait_for_request"
    assert result["controller_cleanup"] == "COOKIE_SOCKET_CLOSED"
    assert result["native_cleanup"] == "NOT_STARTED"
    assert ledger.read_bytes() == before
