"""Bind existing declared journal windows to existing IF jobs, without inference.

The operational store remains NOT_INFERABLE. This adapter verifies the exact
parser/extractor/package contract and requires a separate human model Action.
Host distribution/generalization and kernel attestation are NOT established.
"""

import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from soc_agent.continuous.authentication import validate_window
from soc_agent.continuous.authentication_lifecycle import action as collection_action
from soc_agent.continuous.store import Store
from soc_agent.linux_runtime.service import open_pipeline
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.authentication import AuthenticationWindowExtractor
from soc_agent.security_ai.authentication.anomaly import AuthenticationInferenceProfile
from soc_agent.security_ai.features import SecurityRecord, SourceReference
from soc_agent.security_ai.operational.source_records import AuthenticationSource
from soc_agent.security_ai.packaging.files import read_package, strict_json
from soc_agent.security_ai.packaging.package import load_package
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import AuthenticationWindowJob, HostAuthenticationBinding


def implementation_digest() -> str:
    root = Path(__file__).parents[1]
    names = (
        "continuous/host_authentication.py",
        "continuous/authentication.py",
        "continuous/authentication_lifecycle.py",
        "security_ai/authentication/aggregation.py",
        "security_ai/authentication/anomaly.py",
        "security_ai/operational/native_authentication.py",
        "security_ai/operational/source_store.py",
        "security_ai/packaging/package.py",
        "security_ai/packaging/forest.py",
        "security_ai/workflow_inputs.py",
        "security_ai/authentication_action.py",
    )
    return digest({name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names})


def package_contract(packages) -> dict:
    if len(packages) != 1:
        raise ValueError("HOST_IF_EXACT_PACKAGE_REQUIRED")
    item = packages[0]
    values = read_package(Path(item.directory))
    if strict_json(values["manifest.json"])["model_kind"] != "authentication_anomaly":
        raise ValueError("HOST_IF_PACKAGE_KIND_REQUIRED")
    model = load_package(Path(item.directory), expected_manifest_digest=item.manifest_sha256)
    if not isinstance(model.profile, AuthenticationInferenceProfile):
        raise ValueError("HOST_IF_PROFILE_REQUIRED")
    return dict(
        manifest_sha256=model.manifest_digest,
        model_id=model.manifest.model_id,
        model_sha256=next(
            f.sha256 for f in model.manifest.file_hashes if f.path == "model/model.json"
        ),
        feature_names=list(model.manifest.ordered_feature_names),
        schema=model.profile.contract.feature_schema.model_dump(mode="json"),
        extractor=model.profile.contract.extractor_name,
        extractor_version=model.profile.contract.extractor_version,
        preprocessing=model.profile.contract.preprocessing,
        threshold=model.profile.config.threshold,
        operating_point=model.manifest.operating_point.model_dump(mode="json"),
        technical_parity="VERIFIED_SHARED_EXTRACTOR_SCHEMA_FROZEN_SCALER_AND_PROFILE",
        source_assurance="DECLARED_UNATTESTED_NOT_KERNEL_ATTESTED",
        deployment_assurance="RESEARCH_MODEL_HOST_DISTRIBUTION_UNVERIFIED",
    )


def _sources(store, pipeline):
    result = []
    with pipeline.store.database.transaction(write=False) as c:
        for row in c.execute(
            "SELECT * FROM operational_sources WHERE incident_id=? AND status='ACCEPTED' "
            "ORDER BY source_key",
            (str(store.database.store_id),),
        ):
            item = pipeline.store._decode(row)
            if not isinstance(item, AuthenticationSource):
                raise ValueError("HOST_AUTHENTICATION_SOURCE_KIND")
            if item.header.collector_id != "journald-auth-pam-failure:v1":
                raise ValueError("HOST_AUTHENTICATION_COLLECTOR_IDENTITY")
            record = SecurityRecord(
                record_id=uuid5(NAMESPACE_URL, row["source_key"]),
                incident_id=None,
                record_type="authentication_event",
                record_schema_version="1.0.0",
                source=item.header.collector_id,
                source_reference=SourceReference(
                    source_type="stream",
                    source_name=item.header.source.namespace,
                    source_version="1.0.0",
                    record_id=row["source_key"],
                ),
                fields=item.event.model_dump(mode="json"),
                observed_at=item.header.observed_at,
            )
            result.append((item, record))
    return result


def sealed_jobs(store: Store) -> tuple[AuthenticationWindowJob, ...]:
    cfg = store.config
    if not cfg.managed_authentication or not cfg.authentication_packages:
        return ()
    contract = package_contract(cfg.authentication_packages)
    auth = RuntimeStore(cfg.authentication_runtime)
    intent = json.loads(read_local(store.directory / "authentication-start-intent.json", 32768))
    expected = collection_action(store)
    actual = dict(intent["action"])
    actual.pop("created_at", None)
    if actual != expected.model_dump(mode="json", exclude={"created_at"}):
        raise ValueError("HOST_AUTHENTICATION_COLLECTION_BINDING_CHANGED")
    from soc_agent.approval import ApprovalRequest
    from soc_agent.continuous.authentication_lifecycle import METADATA
    from soc_agent.execution.binding import validate_binding

    receipt_bytes = read_local(cfg.managed_authentication.approval_file, 32768)
    receipt = ApprovalRequest.model_validate_json(receipt_bytes)
    if hashlib.sha256(receipt.model_dump_json().encode()).hexdigest() != intent["approval_sha256"]:
        raise ValueError("HOST_AUTHENTICATION_COLLECTION_APPROVAL_CHANGED")
    validate_binding(expected, receipt, METADATA)
    if receipt.status.value != "approved" or receipt.decision is None:
        raise ValueError("HOST_AUTHENTICATION_COLLECTION_NOT_APPROVED")
    saved = auth.state()
    if not saved.get("runtime_identity") or saved["runtime_identity"]["uid"] != os.getuid():
        raise ValueError("HOST_AUTHENTICATION_READER_IDENTITY_REQUIRED")
    auth.verify_audit()
    pipeline = open_pipeline(cfg.authentication_runtime, auth.config)
    snapshots = pipeline.store.windows(store.database.store_id)
    with pipeline.store.database.transaction(write=False) as c:
        watermark = pipeline.store._maximum(c, store.database.store_id)
    sources = _sources(store, pipeline)
    output = []
    for snapshot in snapshots:
        # Seal only beyond allowed lateness. A wall clock is never a witness.
        if watermark is None or watermark < snapshot.window.ended_at + timedelta(
            seconds=pipeline.store.lateness
        ):
            continue
        selected = [
            (item, record)
            for item, record in sources
            if item.content_digest in snapshot.source_digests
        ]
        records = tuple(record for _, record in selected)
        windows = AuthenticationWindowExtractor().extract(records)
        if (
            len(windows) != 1
            or windows[0].features.input_fingerprint != snapshot.window.features.input_fingerprint
        ):
            raise ValueError("HOST_AUTHENTICATION_TRAINING_INFERENCE_PARITY_FAILED")
        feature = windows[0].features
        if feature.feature_schema.model_dump(mode="json") != contract["schema"]:
            raise ValueError("HOST_IF_FEATURE_SCHEMA_MISMATCH")
        revision = digest(
            dict(sources=sorted(snapshot.source_digests), feature=feature.input_fingerprint)
        )
        binding = HostAuthenticationBinding(
            runtime_directory=str(store.directory),
            session=store.database.store_id,
            namespace=cfg.namespace,
            scope_sha256=cfg.input_sha256,
            configuration_sha256=digest(cfg.model_dump(mode="json")),
            authentication_configuration_sha256=auth.config.digest,
            source_store_id=pipeline.store.database.store_id,
            source_digests=tuple(sorted(snapshot.source_digests)),
            evidence_revision=revision,
            feature_fingerprint=feature.input_fingerprint,
            implementation_sha256=implementation_digest(),
            collection_approval_sha256=intent["approval_sha256"],
        )
        job = AuthenticationWindowJob(
            kind="authentication_window",
            origin="DECLARED_HOST_JOURNAL",
            records=records,
            packages=cfg.authentication_packages,
            witness=watermark,
            quality="ELIGIBLE",
            source_sha256=digest(binding.model_dump(mode="json")),
            host_binding=binding,
        )
        if validate_window(job) != "ELIGIBLE":
            raise ValueError("HOST_AUTHENTICATION_WINDOW_NOT_ELIGIBLE")
        output.append(job)
    return tuple(output)


def validate_job(job: AuthenticationWindowJob) -> dict:
    if job.origin != "DECLARED_HOST_JOURNAL" or job.host_binding is None:
        raise ValueError("HOST_AUTHENTICATION_JOB_REQUIRED")
    bound = job.host_binding
    parent = Store(Path(bound.runtime_directory))
    # Rebuild from hash-checked source records, not a caller-supplied VERIFIED flag.
    matches = [
        j
        for j in sealed_jobs(parent)
        if j.host_binding.evidence_revision == bound.evidence_revision
    ]
    if len(matches) != 1:
        raise ValueError("HOST_AUTHENTICATION_SEALED_SOURCE_UNAVAILABLE")
    rebuilt = matches[0]
    # Later witnesses cannot mutate an already sealed input. Only the evidence
    # set/feature/binding must match; the original witness is rechecked below.
    if rebuilt.model_dump(mode="json", exclude={"witness"}) != job.model_dump(
        mode="json", exclude={"witness"}
    ):
        raise ValueError("HOST_AUTHENTICATION_SEALED_JOB_CHANGED")
    if validate_window(job) != "ELIGIBLE" or job.witness > rebuilt.witness:
        raise ValueError("HOST_AUTHENTICATION_WITNESS_INVALID")
    return package_contract(job.packages)
