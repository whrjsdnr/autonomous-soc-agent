"""Bounded DNS diagnostics. Never builds a DNS9 vector or authorizes a model."""

from collections import Counter, deque

from soc_agent.security_ai.research.live_input import timestamp_ns
from soc_agent.security_ai.research.models import digest


class DNSDiagnostics:
    def __init__(self, session_id):
        self.session_id = str(session_id)
        self.pending = {}
        self.ambiguous = {}
        self.events = deque(maxlen=128)
        self.counts = Counter()
        self.observations = 0

    def _event(self, kind, packet_ns, reference, **fields):
        self.counts[kind] += 1
        value = dict(
            status=kind,
            event_ns=packet_ns,
            source_reference=reference,
            capture_session=self.session_id,
            dns9_inference="BLOCKED",
            validation="DNS_METADATA_DIAGNOSTIC_ONLY",
            **fields,
        )
        value["event_id"] = digest(value)
        self.events.append(value)
        return value

    def observe(self, packet, sequence):
        self.observations += 1
        if self.observations > 38656:
            raise ValueError("TOTAL_DNS_OBSERVATION_LIMIT")
        now = timestamp_ns(packet)
        reference = digest(
            dict(
                session=self.session_id,
                packet_sequence=sequence,
                input_digest=digest(packet.model_dump(mode="json")),
                origin=packet.timestamp_origin,
            )
        )
        result = []
        self.ambiguous = {key: until for key, until in self.ambiguous.items() if now <= until}
        for key, (start, ref) in list(self.pending.items()):
            if now - start > 5_000_000_000:
                result.append(self._event("MISSING_RESPONSE", now, ref))
                del self.pending[key]
        question = packet.dns
        if question is None:
            if 53 in (packet.source_port, packet.destination_port):
                result.append(
                    self._event("PARSE_FAILURE", now, reference, reason=packet.dns_status)
                )
            elif 443 in (packet.source_port, packet.destination_port) or 853 in (
                packet.source_port,
                packet.destination_port,
            ):
                result.append(self._event("ENCRYPTED_VISIBILITY_UNKNOWN", now, reference))
            return result
        if question.query_name is not None:
            raise ValueError("TOTAL_DNS_NAME_RETENTION_DENIED")
        origin = (str(packet.source_address), packet.source_port)
        destination = (str(packet.destination_address), packet.destination_port)
        client, server = (destination, origin) if question.response else (origin, destination)
        key = digest(
            (
                self.session_id,
                packet.transport,
                client,
                server,
                question.transaction_id,
                question.query_type,
                question.query_class,
                question.query_name_digest,
            )
        )
        fields = dict(
            transport=packet.transport,
            query_type=question.query_type,
            query_digest=question.query_name_digest,
            response_code=question.response_code,
        )
        if key in self.ambiguous:
            result.append(
                self._event(
                    "AMBIGUOUS_RESPONSE" if question.response else "AMBIGUOUS_QUERY",
                    now,
                    reference,
                    **fields,
                )
            )
        elif question.response:
            previous = self.pending.pop(key, None)
            result.append(
                self._event(
                    "MATCHED_RESPONSE" if previous else "UNMATCHED_RESPONSE",
                    now,
                    reference,
                    query_reference=previous[1] if previous else None,
                    latency_seconds=(now - previous[0]) / 1e9 if previous else None,
                    **fields,
                )
            )
        elif key in self.pending:
            # Retransmission/ID reuse is not silently asserted to be a unique query.
            del self.pending[key]
            if len(self.ambiguous) >= 128:
                raise ValueError("TOTAL_DNS_AMBIGUITY_BACKPRESSURE")
            self.ambiguous[key] = now + 5_000_000_000
            result.append(self._event("AMBIGUOUS_QUERY", now, reference, **fields))
        else:
            if len(self.pending) >= 128:
                raise ValueError("TOTAL_DNS_PENDING_BACKPRESSURE")
            self.pending[key] = (now, reference)
            result.append(self._event("QUERY", now, reference, **fields))
        return result

    def finish(self, *, aborted=False):
        result = [
            self._event("UNVERIFIED_ABORT" if aborted else "MISSING_RESPONSE", at, ref)
            for at, ref in self.pending.values()
        ]
        self.pending.clear()
        self.ambiguous.clear()
        return result

    def snapshot(self):
        return dict(
            counts=dict(self.counts),
            pending=len(self.pending),
            recent_events=list(self.events),
            dns9_inference="BLOCKED",
            producer_parity="UNVERIFIED",
            names_retained=False,
            tcp_support="SINGLE_COMPLETE_MESSAGE_ONLY_NO_REASSEMBLY",
            encrypted_dns="UNKNOWN_NOT_DECRYPTED",
        )
