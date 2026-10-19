"""v3 envelope; existing bounded reader, Counter checks and DNS isolation are reused."""

import socket
import time
from typing import Literal

from pydantic import Field

from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable
from soc_agent.security_ai.operational.network_capture.direction_peer import validate_peer
from soc_agent.security_ai.operational.network_capture.direction_session import MODULE
from soc_agent.security_ai.operational.network_capture.live_session import write_private
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamMessage
from soc_agent.security_ai.operational.network_capture.total_transport import TotalCapture
from soc_agent.security_ai.research.models import Frozen


class Failure(Frozen):
    budget_type: Literal["OBSERVATION", "ANALYSIS"]
    token_balance: float = Field(ge=0, allow_inf_nan=False)
    monotonic_seconds: float = Field(ge=0, allow_inf_nan=False)
    since_last_consume_seconds: float = Field(ge=0, allow_inf_nan=False)
    frame_sequence: int = Field(ge=1, le=154624, strict=True)
    consumed: int = Field(ge=0, le=154624, strict=True)
    elapsed_monotonic_seconds: float = Field(ge=0, le=302, allow_inf_nan=False)
    average_observed_rate: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    counter_sequence: int | None = Field(default=None, ge=1, le=250000, strict=True)
    kernel_packets_total: int | None = Field(default=None, ge=0, strict=True)
    integrity_scope: Literal["CAPTURE_WIDE"]
    abort_reason: Literal[
        "V3_OBSERVATION_BUDGET_EXCEEDED",
        "V3_ANALYSIS_BUDGET_EXCEEDED",
        "V3_DIRECTION_UNKNOWN",
        "STREAM_MONOTONIC_CLOCK_REVERSED",
    ]


class DirectionMessage(StreamMessage):
    accounting_contract: Literal["soc-direction-accounting:v3"]
    accepted_raw_frames: int = Field(ge=0, le=154624, strict=True)
    outbound_frames: int = Field(ge=0, le=154624, strict=True)
    inbound_frames: int = Field(ge=0, le=154624, strict=True)
    unknown_direction_frames: int = Field(ge=0, le=154624, strict=True)
    direction_filtered_frames: int = Field(ge=0, le=154624, strict=True)
    analysis_accepted: int = Field(ge=0, le=77312, strict=True)
    normalized_packets: int = Field(ge=0, le=77312, strict=True)
    observation_tokens: float = Field(ge=0, le=1024, allow_inf_nan=False)
    analysis_tokens: float = Field(ge=0, le=512, allow_inf_nan=False)
    budget_failure: Failure | None = None


class DirectionCapture(TotalCapture):
    helper_module = MODULE

    def __init__(self, directory, session):
        super().__init__(directory, session)
        self.accounting = None

    def handshake(self):
        # Operator authentication has no hidden expiry. Only explicit Stop/GUI close
        # ends this wait; the helper's capture watchdog remains independently bounded.
        while not self.closed.is_set():
            try:
                channel, _ = self.listener.accept()
                break
            except TimeoutError:
                continue
        else:
            raise CaptureUnavailable("HELPER_LISTENER_CLOSED")
        with self.transport_lock:
            if self.closed.is_set():
                channel.close()
                raise CaptureUnavailable("HELPER_LISTENER_CLOSED")
            self.channel = channel
            # Exactly one authenticated helper per session; no queued reconnects.
            self.listener.close()
        channel.settimeout(2)
        ready = self.message()
        validate_peer(channel, ready, self.session, self.directory)
        self._account(ready)
        if any((ready.dns_queries, ready.dns_responses, ready.dns_parse_failures)):
            raise CaptureUnavailable("STREAM_READY_DNS_COUNTER_INVALID")
        try:
            self.accept_counters(ready)
        except CaptureUnavailable:
            write_private(self.directory / "counter-failure.json", self.counter_issue)
            raise
        with self.transport_lock:
            if self.closed.is_set():
                raise CaptureUnavailable("HELPER_LISTENER_CLOSED")
            write_private(self.directory / "verified-ready.json", ready.model_dump(mode="json"))
            self.ready = ready
            self.alive = True
            self.last_heartbeat = time.monotonic()
        self.usage = {
            "helper_rss_peak_bytes": ready.rss_peak_bytes,
            "helper_cpu_seconds": ready.cpu_seconds,
            "received_frames": ready.received_frames,
            "metadata_packets": ready.sent_packets,
        }
        channel.setblocking(False)

    def message(self):
        body, _, flags, _ = self.channel.recvmsg(8192)
        if flags & socket.MSG_TRUNC or not body:
            raise CaptureUnavailable("HELPER_DISCONNECTED_OR_RECORD_LIMIT")
        value = DirectionMessage.model_validate_json(body)
        if value.session_id != self.session.session_id:
            raise CaptureUnavailable("HELPER_SESSION_FORGERY")
        return value

    def _account(self, m):
        failure = m.budget_failure
        if failure is not None and (
            m.kind != "CLOSED"
            or m.error != failure.abort_reason
            or failure.frame_sequence != m.received_frames
            or failure.counter_sequence != m.counter_sequence
            or failure.kernel_packets_total != m.kernel_packets_total
        ):
            raise CaptureUnavailable("V3_BUDGET_DIAGNOSTIC_BINDING_FAILED")
        if m.error in {"V3_OBSERVATION_BUDGET_EXCEEDED", "V3_ANALYSIS_BUDGET_EXCEEDED"} and (
            failure is None
            or failure.token_balance >= 1
            or failure.budget_type
            != ("OBSERVATION" if m.error == "V3_OBSERVATION_BUDGET_EXCEEDED" else "ANALYSIS")
            or failure.consumed
            != (
                m.accepted_raw_frames
                if failure.budget_type == "OBSERVATION"
                else m.analysis_accepted
            )
        ):
            raise CaptureUnavailable("V3_BUDGET_DIAGNOSTIC_BINDING_FAILED")
        if m.received_frames is None or not (
            m.received_frames == m.outbound_frames + m.inbound_frames + m.unknown_direction_frames
            and m.direction_filtered_frames <= m.inbound_frames
            and m.normalized_packets <= m.analysis_accepted <= m.outbound_frames
            and m.analysis_accepted + m.direction_filtered_frames
            <= m.accepted_raw_frames
            <= m.received_frames
            and m.received_frames <= self.session.max_packets
        ):
            raise CaptureUnavailable("V3_ACCOUNTING_INTEGRITY_FAILED")
        counters = (
            m.received_frames,
            m.accepted_raw_frames,
            m.outbound_frames,
            m.inbound_frames,
            m.unknown_direction_frames,
            m.direction_filtered_frames,
            m.analysis_accepted,
            m.normalized_packets,
        )
        if self.accounting and any(
            a > b for a, b in zip(self.accounting[0], counters, strict=True)
        ):
            raise CaptureUnavailable("V3_ACCOUNTING_REGRESSION")
        if m.kind == "READY" and any(counters):
            raise CaptureUnavailable("V3_READY_ACCOUNTING_INVALID")
        if m.kind == "PACKET" and m.normalized_packets != m.sequence:
            raise CaptureUnavailable("V3_PACKET_ACCOUNTING_MISMATCH")
        if (
            m.kind == "CLOSED"
            and m.error is None
            and not (
                m.unknown_direction_frames == 0
                and m.accepted_raw_frames == m.received_frames
                and m.direction_filtered_frames == m.inbound_frames
                and m.analysis_accepted
                == m.normalized_packets
                == m.sent_packets
                == m.outbound_frames
            )
        ):
            raise CaptureUnavailable("V3_INCOMPLETE_ACCOUNTING")
        self.accounting = (counters, m)

    def _receive_record(self, message):
        try:
            self._account(message)
        except CaptureUnavailable as error:
            if message.kind == "CLOSED":
                self._record_rejected_closed(message, str(error))
            raise
        if message.kind == "CLOSED" and message.error and message.error.startswith("V3_"):
            # Reject before publishing terminal; do not widen v2's error allowlist.
            try:
                self.accept_counters(message)
            finally:
                self._record_rejected_closed(message, message.error)
            raise CaptureUnavailable(message.error)
        return super()._receive_record(message)

    def _record_rejected_closed(self, message, reason):
        super()._record_rejected_closed(message, reason)
        write_private(
            self.directory / "v3-rejected-accounting.json", message.model_dump(mode="json")
        )

    def extra_metrics(self):
        with self.reader_lock:
            result = super().extra_metrics()
            if self.accounting:
                m = self.accounting[1]
                result.update(
                    m.model_dump(
                        include={
                            "received_frames",
                            "sent_packets",
                            "accounting_contract",
                            "accepted_raw_frames",
                            "outbound_frames",
                            "inbound_frames",
                            "unknown_direction_frames",
                            "direction_filtered_frames",
                            "analysis_accepted",
                            "normalized_packets",
                            "observation_tokens",
                            "analysis_tokens",
                            "budget_failure",
                        },
                        mode="json",
                    )
                )
            return result
