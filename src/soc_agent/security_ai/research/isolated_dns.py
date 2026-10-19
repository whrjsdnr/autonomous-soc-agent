"""Connection-local DNS diagnostics; no shared Network watermark or DNS9 producer."""

from collections import Counter, deque

from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.research.live_input import timestamp_ns
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.total_dns import DNSDiagnostics


class IsolatedDNS:
    def __init__(self, session_id, *, max_observations=38656):
        if type(max_observations) is not int or not 1 <= max_observations <= 77312:
            raise ValueError("TOTAL_DNS_OBSERVATION_BUDGET_INVALID")
        self.max_observations = max_observations
        self.session_id = str(session_id)
        self.connections = {}
        self.last_ns = {}
        self.quarantined = set()
        self.events = deque(maxlen=128)
        self.counts = Counter()
        self.observations = 0
        self.blocked = False

    def _record(self, events):
        for event in events:
            self.events.append(event)
            self.counts[event["status"]] += 1
        return events

    def _fault(self, kind, now, reference, **fields):
        value = dict(
            status=kind,
            event_ns=now,
            source_reference=reference,
            capture_session=self.session_id,
            dns9_inference="BLOCKED",
            validation="DNS_METADATA_DIAGNOSTIC_ONLY",
            **fields,
        )
        value["event_id"] = digest(value)
        return value

    @property
    def diagnostic_status(self) -> str:
        """Authoritative status without materializing the retained event ring."""
        return (
            "DNS_DIAGNOSTIC_BLOCKED"
            if self.blocked
            else "DEGRADED"
            if self.quarantined or self.counts.get("PARSE_FAILURE")
            else "HEALTHY"
        )

    def changes_projection(self, packet: PacketObservation) -> bool:
        """Only the existing irrelevant-packet path leaves every projected field intact.

        observe() must still run: observation limits, privacy rejection and blocked
        counters are enforced even when no DNS event is produced.
        """
        return (
            self.blocked
            or packet.dns is not None
            or packet.source_port in (53, 443, 853)
            or packet.destination_port in (53, 443, 853)
        )

    def observe(self, packet, sequence):
        self.observations += 1
        if packet.dns is not None and packet.dns.query_name is not None:
            raise ValueError("TOTAL_DNS_NAME_RETENTION_DENIED")
        if self.observations > self.max_observations:
            raise ValueError("TOTAL_DNS_OBSERVATION_LIMIT")
        if self.blocked:
            self.counts["BLOCKED_PACKET_EXCLUDED"] += 1
            return []
        if packet.dns is None:
            if not self.changes_projection(packet):
                return []  # Unrelated packets never expire DNS queries.
            return self._record(DNSDiagnostics(self.session_id).observe(packet, sequence))
        key, now = digest(FlowTable.key(packet)), timestamp_ns(packet)
        reference = digest(dict(session=self.session_id, sequence=sequence, connection=key))
        if key in self.quarantined:
            self.counts["QUARANTINED_PACKET_EXCLUDED"] += 1
            return []
        if key in self.last_ns and now < self.last_ns[key]:
            self.quarantined.add(key)
            events = self.connections[key].finish(aborted=True)
            events.append(
                self._fault(
                    "DNS_TIMESTAMP_QUARANTINED",
                    now,
                    reference,
                    connection_digest=key,
                    previous_event_ns=self.last_ns[key],
                    regression_ns=self.last_ns[key] - now,
                )
            )
            return self._record(events)
        if key not in self.connections:
            if len(self.connections) >= 128:
                return self._block(now, reference, "DNS_CONNECTION_BUDGET")
            self.connections[key] = DNSDiagnostics(self.session_id)
        engine = self.connections[key]
        if sum(len(e.pending) + len(e.ambiguous) for e in self.connections.values()) >= 128:
            return self._block(now, reference, "DNS_PENDING_BUDGET")
        self.last_ns[key] = now
        events = engine.observe(packet, sequence)
        # Base engine is bounded independently, but keep only one shared event ring.
        engine.events.clear()
        return self._record(events)

    def _block(self, now, reference, reason):
        self.blocked = True
        events = self.finish(aborted=True)
        return [
            *events,
            *self._record([self._fault("DNS_DIAGNOSTIC_BLOCKED", now, reference, reason=reason)]),
        ]

    def finish(self, *, aborted=False):
        return self._record(
            [
                event
                for engine in self.connections.values()
                for event in engine.finish(aborted=aborted)
            ]
        )

    def snapshot(self):
        return dict(
            counts=dict(self.counts),
            pending=sum(len(e.pending) for e in self.connections.values()),
            recent_events=list(self.events),
            dns9_inference="BLOCKED",
            producer_parity="UNVERIFIED",
            names_retained=False,
            tcp_support="SINGLE_COMPLETE_MESSAGE_ONLY_NO_REASSEMBLY",
            encrypted_dns="UNKNOWN_NOT_DECRYPTED",
            diagnostic_status=self.diagnostic_status,
            quarantined_connections=len(self.quarantined),
            event_time_policy="CONNECTION_LOCAL_NO_NETWORK_EXPIRY",
        )
