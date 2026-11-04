"""Read existing windows/packages; this projection never dispatches IF inference."""

from pathlib import Path

from soc_agent.linux_runtime.service import open_pipeline
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.research.models import digest


def observation(directory, packages, parent_directory=None):
    store = RuntimeStore(directory)
    pipeline = open_pipeline(directory, store.config)
    windows = pipeline.store.windows(store.config.incident_id)
    latest = max((w.window.ended_at for w in windows), default=None)
    # A wall clock does not attest window completeness. Only later retained
    # events can witness the end; the final window remains incomplete.
    with pipeline.store.database.transaction(write=False) as connection:
        watermark = pipeline.store._maximum(connection, store.config.incident_id)
    complete = [w for w in windows if watermark and w.window.ended_at <= watermark]
    model = None
    if packages:
        from soc_agent.security_ai.packaging.package import load_package

        supplied = packages[0]
        # Check kind before a loader can instantiate any other model kind.
        from soc_agent.security_ai.packaging.files import read_package, strict_json

        values = read_package(Path(supplied.directory))
        if strict_json(values["manifest.json"])["model_kind"] != "authentication_anomaly":
            raise ValueError("AUTHENTICATION_IF_MODEL_KIND_REQUIRED")
        loaded = load_package(
            Path(supplied.directory), expected_manifest_digest=supplied.manifest_sha256
        )
        model = dict(
            manifest_sha256=loaded.manifest_digest,
            model_id=loaded.manifest.model_id,
            feature_names=loaded.manifest.ordered_feature_names,
            threshold=loaded.profile.config.threshold,
            validation="INTERNAL_PACKAGE_BINDING_NOT_NATIVE_TRAINING_ASSURANCE",
        )
    value = dict(
        host_events=sum(pipeline.queue.counts().values()),
        authentication_windows=dict(
            total=len(windows),
            eligible=len(complete),
            incomplete=len(windows) - len(complete),
            latest_end=latest.isoformat() if latest else None,
        ),
        if_admission=dict(
            state="BLOCKED_NO_APPROVED_PACKAGE"
            if model is None
            else "INSUFFICIENT_COMPLETE_WINDOW"
            if not complete
            else "BLOCKED_EXACT_IF_ACTION_AND_NATIVE_TRAINING_CONTRACT_REQUIRED",
            model=model,
            native_training_parity="UNVERIFIED",
            predictions=0,
            authority="COLLECTION_APPROVAL_IS_NOT_MODEL_ACTION",
            window_fingerprints=[digest(w.model_dump(mode="json")) for w in complete][-32:],
        ),
        rule_incidents=store.jobs(),
        source_assurance="DECLARED_UNATTESTED_HOST_JOURNAL_NOT_TCX_CAPTURE",
    )

    if parent_directory is not None and packages:
        from soc_agent.continuous.host_authentication import package_contract, sealed_jobs
        from soc_agent.continuous.store import Store

        parent = Store(parent_directory)
        if (parent.directory / "authentication-start-intent.json").exists():
            jobs = sealed_jobs(parent)
            value["if_admission"].update(
                state="WAITING_EXACT_IF_ACTION_APPROVAL"
                if jobs
                else "INSUFFICIENT_COMPLETE_WINDOW",
                model=package_contract(packages),
                technical_training_parity="VERIFIED_SHARED_EXTRACTOR_SCHEMA_FROZEN_SCALER_AND_PROFILE",
                host_distribution_validation="UNVERIFIED_RESEARCH_MODEL",
                sealed_jobs=[
                    dict(
                        job=digest(j.model_dump(mode="json")),
                        evidence_revision=j.host_binding.evidence_revision,
                        feature_fingerprint=j.host_binding.feature_fingerprint,
                    )
                    for j in jobs
                ],
            )
    return value
