"""Managed-mode envelope over the existing bounded authenticated reader."""

import socket
from collections import deque

from pydantic import Field

from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.helper_transport import (
    HelperCapture,
    Message,
)
from soc_agent.security_ai.operational.network_capture.stream_session import MODULE


class StreamMessage(Message):
    dns_queries: int = Field(default=0, ge=0, le=250000)
    dns_responses: int = Field(default=0, ge=0, le=250000)
    dns_parse_failures: int = Field(default=0, ge=0, le=250000)
    sequence: int | None = Field(default=None, ge=1, le=250000)
    received_frames: int | None = Field(default=None, ge=0, le=250000)
    sent_packets: int | None = Field(default=None, ge=0, le=250000)
    counter_sequence: int | None = Field(default=None, ge=1, le=250000)
    elapsed_seconds: float | None = Field(default=None, ge=0, le=1802, allow_inf_nan=False)


class StreamingCapture(HelperCapture):
    helper_module = MODULE

    def __init__(self, directory, session):
        super().__init__(directory, session, queue_capacity=session.policy.transport_capacity)
        self.seals = deque()
        self.last_seal = None
        self.dns_totals = (0, 0, 0)

    def message(self):
        body, _, flags, _ = self.channel.recvmsg(8192)
        if flags & socket.MSG_TRUNC or not body:
            raise CaptureUnavailable("HELPER_DISCONNECTED_OR_RECORD_LIMIT")
        value = StreamMessage.model_validate_json(body)
        if value.session_id != self.session.session_id:
            raise CaptureUnavailable("HELPER_SESSION_FORGERY")
        return value

    def handshake(self):
        super().handshake()
        if (self.ready.dns_queries, self.ready.dns_responses, self.ready.dns_parse_failures) != (
            0,
            0,
            0,
        ):
            raise CaptureUnavailable("STREAM_READY_DNS_COUNTER_INVALID")

    def _receive_record(self, message):
        if message.kind == "PACKET" and message.counter_sequence != self.counter_sequence:
            raise CaptureUnavailable("STREAM_PACKET_COUNTER_WINDOW_MISMATCH")
        dns = (message.dns_queries, message.dns_responses, message.dns_parse_failures)
        if (
            any(a > b for a, b in zip(self.dns_totals, dns, strict=True))
            or sum(dns)
            > (message.sent_packets if message.sent_packets is not None else self.sequence) + 1
        ):
            raise CaptureUnavailable("STREAM_DNS_COUNTER_MISMATCH")
        self.dns_totals = dns
        packet = super()._receive_record(message)
        if packet is not None:
            if len(self.seals) >= self.session.policy.transport_capacity:
                raise CaptureUnavailable("STREAM_SEAL_BACKPRESSURE")
            self.seals.append((message.sequence, self.counter_sequence))
        return packet

    def receive(self):
        with self.reader_lock:
            packet = super().receive()
            if packet is not None:
                if not self.seals:
                    raise CaptureUnavailable("STREAM_PACKET_SEAL_MISSING")
                self.last_seal = self.seals.popleft()
                if self.last_seal[0] != self.delivered:
                    raise CaptureUnavailable("STREAM_PACKET_SEQUENCE_MISMATCH")
            return packet

    def request_stop(self):
        with self.transport_lock:
            if self.channel is not None:
                try:
                    self.channel.send(b"STOP")
                except OSError:
                    raise CaptureUnavailable("STREAM_STOP_DISCONNECTED") from None

    def extra_metrics(self):
        with self.reader_lock:
            verified = self.ready is not None and self.counter_issue is None
            return {
                **super().extra_metrics(),
                "dns_queries": self.dns_totals[0],
                "dns_responses": self.dns_totals[1],
                "dns_parse_failures": self.dns_totals[2],
                "dns_collection": "HEADERS_ONLY_NO_FQDN"
                if self.ready is not None and self.session.policy.dns_headers
                else "NOT_COLLECTED",
                "dns_operational_inference": "BLOCKED",
                "dns9_producer_parity": "UNVERIFIED",
                "kernel_packets_total": self.counter_totals[0] if verified else None,
                "capture_drops": self.counter_totals[1] if verified else None,
                "counter_status": "COUNTER_VERIFIED" if verified else "UNKNOWN",
            }

    def close(self, **kwargs):
        super().close(**kwargs)
        with self.reader_lock:
            while not self.packets.empty():
                self.packets.get_nowait()
            self.seals.clear()
