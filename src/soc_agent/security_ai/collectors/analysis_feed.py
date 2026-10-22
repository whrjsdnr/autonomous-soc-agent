"""Bounded, memory-only PCAP handoff to the existing capless Zeek consumer."""

import queue
import threading

from soc_agent.security_ai.collectors.offload_copy import memory_pcap


class AnalysisFeed:
    """One producer, one consumer; at most 32 packets over the entire session."""

    def __init__(self):
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=32)
        self._closed = threading.Event()
        self.count = 0
        self.peak = 0

    def put(self, timestamp_ns: int, packet: bytes) -> None:
        if self._closed.is_set() or self.count >= 32:
            raise ValueError("DNS_ANALYSIS_FEED_CLOSED_OR_LIMIT")
        body = memory_pcap([(timestamp_ns, packet)])[24:]
        try:
            self._queue.put_nowait(body)
        except queue.Full as exc:
            raise ValueError("DNS_ANALYSIS_QUEUE_FULL") from exc
        self.count += 1
        self.peak = max(self.peak, self._queue.qsize())

    def take(self) -> bytes | None:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def close(self) -> None:
        self._closed.set()

    @property
    def exhausted(self) -> bool:
        return self._closed.is_set() and self._queue.empty()

    def clear(self) -> None:
        self.close()
        while self.take() is not None:
            pass
