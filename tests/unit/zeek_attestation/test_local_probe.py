"""Probe codec/approval tests only: no sockets, live capture or generated traffic."""

import struct
from unittest.mock import patch

import pytest
from tests import native_dns_live_probe as probe


def test_scope_display_and_wrong_approval_cannot_send(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["probe"])
    with patch.object(probe.socket, "socket", side_effect=AssertionError("No socket authorized")):
        probe.main()
        with pytest.raises(ValueError, match="EXACT_APPROVAL"):
            probe.execute("0" * 64)
    assert probe.APPROVAL in capsys.readouterr().out
    assert probe.PLAN["max_queries"] == 2 and probe.TARGET == ("127.0.0.53", 53)
    assert probe.NAME.endswith(".localhost.")


@pytest.mark.parametrize("rcode", [0, 2, 3])
def test_fixed_question_response_identity_and_error_codes(rcode):
    transaction = 0xC201
    body = struct.pack("!6H", transaction, 0x8180 | rcode, 1, 0, 0, 0) + probe.QUESTION
    assert probe.response_header(body, transaction)["rcode"] == rcode
    for invalid in (body[:12], body[:2] + bytes(2) + body[4:], body + bytes(4096)):
        with pytest.raises(ValueError):
            probe.response_header(invalid, transaction)
    with pytest.raises(ValueError, match="IDENTITY"):
        probe.response_header(body, 0xC202)


def test_tcp_partial_frame_and_timeout_are_errors():
    class Parts:
        def __init__(self):
            self.parts = iter([b"\x00", b"\x02", b""])

        def recv(self, length):
            return next(self.parts)

        def settimeout(self, value):
            pass

    with patch.object(probe.time, "monotonic", return_value=10):
        channel = Parts()
        assert probe.receive_exact(channel, 2, 11) == b"\x00\x02"
        with pytest.raises(EOFError, match="PARTIAL"):
            probe.receive_exact(channel, 1, 11)
        with pytest.raises(TimeoutError, match="DEADLINE"):
            probe.receive_exact(channel, 1, 9)
