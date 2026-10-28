"""Ordinary Controller/CLI with real temporary bytes; no Root, sockets or execution."""

import hashlib
import json
from pathlib import Path

import pytest
from tests.unit.ebpf_tc.test_namespace_runtime import NS, config

from soc_agent.security_ai.ebpf_tc import namespace_controller as controller
from soc_agent.security_ai.ebpf_tc.installation import canonical


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
    with pytest.raises(SystemExit):
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
