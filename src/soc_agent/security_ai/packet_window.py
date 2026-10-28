"""Reuse the pinned Network14 producer/worker for completed offline packet windows.

Offline eligibility is not Native capture attestation or operating model promotion.
No diagnostic receipt, native origin or native model-action grant is accepted here.
"""

from uuid import uuid4

from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.live_input import LiveRequest, timestamp_ns
from soc_agent.security_ai.research.models import LiveReceipt, digest
from soc_agent.security_ai.workflow_models import EvidenceEnvelope, InferenceRecord


def validate_window(job):
    if job.quality != "ELIGIBLE":
        return job.quality
    if len(job.packets) != len(job.identities) or len(set(job.identities)) != len(job.identities):
        return "INVALID"
    if not job.profiles or len(set(job.profiles)) != len(job.profiles):
        return "INVALID"
    times = [timestamp_ns(p) for p in job.packets]
    if job.close_reason == "IDLE_TIMEOUT":
        witnessed = job.witness_ns - times[-1] >= 30_000_000_000
    elif job.close_reason == "ACTIVE_TIMEOUT":
        witnessed = job.witness_ns - times[0] >= 120_000_000_000
    else:
        witnessed = False
    if not witnessed:
        return "INCOMPLETE"
    try:
        request(job, job.profiles[0])
    except ValueError:
        return "INVALID"
    return "ELIGIBLE"


def request(job, profile):
    return LiveRequest(
        research_mode=True,
        origin=job.origin,
        profile=profile,
        invocation_id=uuid4(),
        capture_session=job.session,
        flow_id=digest(tuple(map(str, job.identities))),
        provenance_digest=digest(job.model_dump(mode="json")),
        packet_event_ids=job.identities,
        packets=tuple(p.model_copy(update={"dns": None}) for p in job.packets),
    )


async def analyze_window(job, directory, paths, record):
    state = validate_window(job)
    evidence = EvidenceEnvelope(
        event_identity=digest(job.model_dump(mode="json")),
        domain="NETWORK",
        origin=job.origin,
        source_digest=job.source_sha256,
        collector_identity="continuous-packet-replay:v1",
        observed_at=job.packets[0].timestamp,
        schema_version="Network14/1.1.0",
        session=str(job.session),
        integrity="REPLAY_VERIFIED" if job.origin == "OFFLINE_PCAP" else "FIXTURE",
        provenance=(
            job.clock_epoch,
            "OFFLINE_METADATA_WINDOW_" + state,
            "Replay metadata; not Native capture integrity attestation",
        ),
    )
    if state != "ELIGIBLE":
        return state, (evidence,), ["PACKET_WINDOW_" + state]
    adapter = ResearchAdapter(directory / "workers", paths=paths, live_metadata=True)
    for profile in job.profiles:
        result = await adapter.infer(request(job, profile))
        if result.get("status") != "SUCCESS":
            raise ValueError("PACKET_WINDOW_MODEL_FAILURE_NO_RETRY")
        receipt = LiveReceipt.model_validate(result["receipt"])
        record(
            InferenceRecord(
                event_identity=receipt.flow_id,
                model_id=receipt.model_id,
                model_version="manifest-sha256:" + receipt.model_manifest_digest,
                model_manifest_digest=receipt.model_manifest_digest,
                artifact_digest=receipt.artifact_digest,
                feature_fingerprint=receipt.feature_digest,
                evidence_references=(receipt.source_digest, receipt.provenance_digest),
                prediction=receipt.prediction,
                score=receipt.score,
                score_semantics="Research ranking, uncalibrated; not attack probability",
                inferred_at=receipt.inferred_at,
                latency_ms=receipt.inference_latency_ms,
                receipt=receipt.model_dump(mode="json"),
            )
        )
    return state, (evidence,), []
