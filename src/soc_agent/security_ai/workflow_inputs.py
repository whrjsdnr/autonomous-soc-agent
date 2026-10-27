"""Reuse pinned replay workers and schema-specific packages; no Native admission."""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from soc_agent.security_ai.authentication import AuthenticationWindowExtractor
from soc_agent.security_ai.authentication.anomaly import feature_matrix as auth_matrix
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.fusion import FusionInput, MultiModelFusionEngine, binding_from_package
from soc_agent.security_ai.model_analysis import ADAPTERS
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor
from soc_agent.security_ai.packaging import load_package
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.dns import catalogue as dns_catalogue
from soc_agent.security_ai.research.environment import catalogue
from soc_agent.security_ai.research.models import DNSReceipt, Request, digest, parse_receipt
from soc_agent.security_ai.signals import create_ai_signal
from soc_agent.security_ai.workflow_models import (
    DNSFixtureJob,
    EvidenceEnvelope,
    InferenceRecord,
    RecordsJob,
    ReplayJob,
)
from soc_agent.state import IncidentState


class QualityFailure(ValueError):
    """Failure before model execution, never a fallback prediction."""


def record_envelopes(job: RecordsJob) -> tuple[EvidenceEnvelope, ...]:
    return tuple(
        EvidenceEnvelope(
            event_identity=str(r.record_id),
            domain="AUTHENTICATION" if r.record_type == "authentication_event" else "NETWORK",
            origin=job.origin,
            source_digest=digest(r.model_dump(mode="json")),
            collector_identity=r.source,
            observed_at=r.observed_at,
            source_incident=r.incident_id,
            schema_version=r.record_schema_version,
            integrity="FIXTURE" if job.origin == "FIXTURE" else "DECLARED_UNATTESTED",
            provenance=(r.source_reference.model_dump_json(),),
        )
        for r in job.records
    )


def extract_records(job: RecordsJob, state: IncidentState) -> dict[str, tuple[FeatureSet, ...]]:
    if any(r.record_type not in ("network_flow", "authentication_event") for r in job.records):
        raise QualityFailure("UNSUPPORTED_RECORD_DOMAIN")
    if len({r.record_id for r in job.records}) != len(job.records):
        raise QualityFailure("DUPLICATE_SOURCE_RECORD")
    try:
        network = tuple(
            NetworkFeatureExtractor().extract(r, state=state if r.incident_id is not None else None)
            for r in job.records
            if r.record_type == "network_flow"
        )
        auth = tuple(
            w.features
            for w in AuthenticationWindowExtractor().extract(
                tuple(r for r in job.records if r.record_type == "authentication_event"),
                state=state
                if any(
                    r.incident_id is not None
                    for r in job.records
                    if r.record_type == "authentication_event"
                )
                else None,
            )
        )
    except (ValueError, TypeError) as exc:
        raise QualityFailure("FEATURE_SOURCE_OR_WINDOW_INVALID") from exc
    return dict(network_classifier=network, network_anomaly=network, authentication_anomaly=auth)


async def packaged(
    job: RecordsJob,
    state: IncidentState,
    record: Callable[[InferenceRecord], None],
) -> dict:
    # All source extraction/compatibility checks precede the first predict call.
    features = extract_records(job, state)
    packages = tuple(
        load_package(Path(p.directory), expected_manifest_digest=p.manifest_sha256)
        for p in job.packages
    )
    if len({p.manifest.model_kind for p in packages}) != len(packages):
        raise QualityFailure("DUPLICATE_MODEL_KIND")
    for package in packages:
        manifest = package.manifest
        if not features[manifest.model_kind]:
            raise QualityFailure("MODEL_SOURCE_DOMAIN_MISSING")
        contract = getattr(package.profile, "contract", package.profile)
        for f in features[manifest.model_kind]:
            if (
                f.feature_schema != contract.feature_schema
                or tuple(x.name for x in f.feature_schema.features)
                != manifest.ordered_feature_names
                or f.provenance.extractor_name != manifest.extractor_name
                or f.provenance.extractor_version != manifest.extractor_version
            ):
                raise QualityFailure("MODEL_FEATURE_SCHEMA_INCOMPATIBLE")
            f.feature_schema.validate_payload(f.input_payload())
            # Compare in Python before NumPy can overflow while coercing a huge scalar.
            if any(v < 0 or v > 3.4028234663852886e38 for v in f.feature_values):
                raise QualityFailure("MODEL_NUMERIC_INPUT_INCOMPATIBLE")
        try:
            if manifest.model_kind == "authentication_anomaly":
                auth_matrix(features[manifest.model_kind])
            else:
                feature_matrix(features[manifest.model_kind], contract)
        except ValueError as exc:
            raise QualityFailure("MODEL_NUMERIC_INPUT_INCOMPATIBLE") from exc
    inputs = []
    for package in packages:
        manifest = package.manifest
        model = ADAPTERS[manifest.model_kind](package).as_security_ai()
        for feature in features[manifest.model_kind]:
            start = time.perf_counter()
            result = await model.predict(
                SecurityAIRequest(incident_id=state.incident_id, input=feature)
            )
            signal = create_ai_signal(result, state=state)
            inputs.append(FusionInput(signal=signal, features=feature))
            refs = tuple(str(s.record_id) for s in feature.provenance.sources)
            record(
                InferenceRecord(
                    event_identity=digest(refs),
                    model_id=manifest.model_id,
                    model_version=manifest.model_version,
                    model_manifest_digest=package.manifest_digest,
                    artifact_digest=digest([e.model_dump() for e in manifest.file_hashes]),
                    feature_fingerprint=feature.input_fingerprint,
                    evidence_references=refs,
                    prediction=result.prediction,
                    score=result.confidence,
                    score_semantics="Classifier confidence; IF raw/rank scores in original receipt",
                    inferred_at=result.created_at,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    receipt={
                        "result": result.model_dump(mode="json"),
                        "features": feature.model_dump(mode="json"),
                    },
                )
            )
    fusion = MultiModelFusionEngine(
        tuple(binding_from_package(p) for p in packages), tuple(ADAPTERS)
    ).fuse(incident_id=state.incident_id, inputs=tuple(inputs))
    return fusion.model_dump(mode="json")


def replay_envelope(job: ReplayJob | DNSFixtureJob) -> EvidenceEnvelope:
    if isinstance(job, DNSFixtureJob):
        doc = dns_catalogue()
        item = doc["fixtures"][job.fixture_index]
        return EvidenceEnvelope(
            event_identity=item["id"],
            domain="DNS",
            origin="FIXTURE",
            source_digest=item["input_digest"],
            collector_identity="dns9_reviewed_fixture",
            observed_at=None,
            schema_version=doc["model"]["feature_schema_version"],
            integrity="FIXTURE",
            provenance=("PRECOMPUTED_DNS9_NOT_PACKET_EXTRACTED",),
        )
    if not job.profiles or len(set(job.profiles)) != len(job.profiles) or len(job.profiles) > 2:
        raise QualityFailure("UNIQUE_BOUNDED_REPLAY_PROFILES_REQUIRED")
    doc = catalogue()
    item = doc["samples"][job.flow_index]
    return EvidenceEnvelope(
        event_identity=item["flow_id"],
        domain="NETWORK",
        origin="OFFLINE_PCAP",
        source_digest=doc["raw_sha256"],
        collector_identity="network_v1_1_offline_pcap",
        observed_at=datetime.fromtimestamp(item["start_ns"] / 1e9, UTC),
        schema_version="Network14/1.1.0",
        integrity="UNVERIFIED",
        provenance=(item["source_digest"], item["feature_digest"]),
    )


async def replay(
    job: ReplayJob | DNSFixtureJob,
    adapter: ResearchAdapter,
    record: Callable[[InferenceRecord], None],
) -> None:
    profiles = ("dns",) if isinstance(job, DNSFixtureJob) else job.profiles
    index = job.fixture_index if isinstance(job, DNSFixtureJob) else job.flow_index
    for profile in profiles:
        request = Request(
            research_mode=True,
            profile=profile,
            flow_index=index,
            origin="FIXTURE" if profile == "dns" else "OFFLINE_PCAP",
            invocation_id=uuid4(),
        )
        outcome = await adapter.infer(request)
        if outcome["status"] != "SUCCESS":
            raise ValueError(outcome.get("error", "REPLAY_INFERENCE_UNAVAILABLE"))
        r = parse_receipt(outcome["receipt"])
        if isinstance(r, DNSReceipt):
            version = r.model_version
            fp = r.input_digest
            event = r.fixture_id
            manifest = digest(dns_catalogue()["model"])
            refs = (r.provenance_digest, r.input_digest)
        else:
            version = "manifest-sha256:" + r.model_manifest_digest
            fp = r.feature_digest
            event = r.flow_id
            manifest = r.model_manifest_digest
            refs = (r.source_sha256, r.source_digest)
        record(
            InferenceRecord(
                event_identity=event,
                model_id=r.model_id,
                model_version=version,
                model_manifest_digest=manifest,
                artifact_digest=r.artifact_digest,
                feature_fingerprint=fp,
                evidence_references=refs,
                prediction=r.prediction,
                score=r.score,
                score_semantics="Research ranking / uncalibrated score, not attack probability",
                inferred_at=r.inferred_at,
                latency_ms=r.inference_latency_ms,
                receipt=r.model_dump(mode="json"),
            )
        )
