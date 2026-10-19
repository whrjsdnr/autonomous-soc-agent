"""Deterministic raw-arrival simulation, never Native measurements or model output."""

import heapq

from soc_agent.security_ai.operational.network_capture.calibrated_policy import policy
from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget


def trace():
    return [0.0] * 384 + [i / 128 for i in range(1, 257)] + [2 + i / 512 for i in range(1, 2049)]


def simulate(name, arrivals, *, service_seconds, paused_until=0.0):
    p = policy(name)
    limiter = RateBudget(p.frames_per_second, p.burst_frames, 0)
    queue = []
    tail = 0.0
    received = delivered = peak = 0
    failure = None
    for now in arrivals:
        received += 1
        if received > p.frame_budget:
            failure = "TOTAL_FRAME_LIMIT"
            break
        try:
            limiter.consume(now)
        except ValueError as error:
            failure = str(error)
            break
        while queue and queue[0] <= now:
            heapq.heappop(queue)
            delivered += 1
        if received % 2 == 0:  # Explicit synthetic outbound/inbound pair, not a Native assumption.
            if len(queue) >= p.transport_capacity:
                failure = "HELPER_TRANSPORT_BACKPRESSURE"
                break
            tail = max(tail, now, paused_until) + service_seconds
            heapq.heappush(queue, tail)
            peak = max(peak, len(queue))
    return dict(
        policy=name,
        attempted_raw_frames=received,
        accepted_metadata=delivered,
        queued=len(queue),
        peak_queue=peak,
        failure=failure,
        completion="REJECTED" if failure else "SIMULATED_DRAIN",
        model_eligible=not bool(failure),
        automatic_retry=False,
        scope="DISCRETE_EVENT_SIMULATION_NOT_NATIVE",
    )
