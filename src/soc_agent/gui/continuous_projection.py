"""Presentation of an attached Runtime in the existing dashboard, never authority."""


def project(value: dict) -> dict:
    current = value.get("continuous")
    if not current:
        return value
    metrics = current.get("metrics", {})
    native = current.get("source") == "NATIVE_SERVICE"
    origin = "REAL_NATIVE" if native else "REPLAY"
    queue = current.get("queue", {})
    capture = current.get("capture_window", {}).get("assessment", {})
    pending = sum(queue.get(k, 0) for k in ("PENDING", "CLAIMED"))
    outcomes = list(current.get("recent_results", []))
    selected = value.get("analysis", {}).get("result")
    if (
        selected
        and selected.get("audit") == "VERIFIED"
        and not any(row["incident_id"] == selected["incident_id"] for row in outcomes)
    ):
        outcomes.append(
            dict(
                incident_id=selected["incident_id"],
                origins=selected.get("input_origins", []),
                classification=selected["classification"],
                predictions=selected.get("predictions", []),
                investigation=selected.get("investigation_status", "UNKNOWN"),
                output=value["analysis"].get("output"),
                audit="VERIFIED",
                retained_selection=True,
            )
        )
    records = []
    models = {}
    for outcome in outcomes[-32:]:
        for prediction in outcome.get("predictions", []):
            model = prediction["model"]
            profile = (
                "quality"
                if model.endswith("quality_rf")
                else "edge"
                if model.endswith("edge_lr")
                else model
            )
            model_state = models.setdefault(
                profile, dict(state="VERIFIED_RETAINED_RESULT", successful=0)
            )
            model_state["successful"] += 1
            # A GUI view is explicitly not a replacement for the original model receipt.
            receipt = dict(
                contract="soc-gui-continuous-prediction-view:v1",
                model_id=model,
                profile=profile,
                origin=", ".join(outcome.get("origins", [])),
                prediction=prediction["prediction"],
                score=prediction.get("score"),
                inferred_at="UNKNOWN",
                model_artifact_sha256=prediction.get("model_artifact_sha256"),
                feature_fingerprint=prediction.get("feature_fingerprint"),
                flow_id=prediction.get("flow_id"),
                evidence_references=prediction.get("evidence_references", []),
            )
            records.append(
                dict(
                    receipt=receipt,
                    status="COMPLETE",
                    advisory_current="RETAINED_ADVISORY_NOT_CONFIRMED_ATTACK",
                    investigation=dict(status=outcome.get("investigation", "UNKNOWN")),
                    analysis_output=outcome.get("output"),
                    incident_id=outcome["incident_id"],
                )
            )
    resources = current.get("resources", {})
    return value | dict(
        state=current.get("state", "UNKNOWN"),
        collection_live=current.get("collection_live", False),
        session_id=current.get("clock_epoch"),
        input_origin=origin,
        last_error=current.get("last_error")
        or ("CONTINUOUS_CONTROLLER_FAILURE" if current.get("controller_error") else None),
        collectors={
            "network": current.get("collector", "UNKNOWN"),
            "dns": "NOT_COLLECTED_IN_THIS_SCOPE"
            if native
            else current.get("dns", {}).get("diagnostic_status", "UNKNOWN"),
            "dns9_ai": "BLOCKED_TRAINING_EXTRACTION_CONTRACT",
        },
        network=dict(
            packets_collected=metrics.get("packets"),
            sent_packets=metrics.get("packets"),
            transport_delivered_packets=metrics.get("native_events")
            if native
            else metrics.get("received"),
            inference_count=metrics.get("predictions"),
            capture_uptime_seconds=current.get("uptime_seconds"),
            capture_integrity=capture.get("status", "UNKNOWN"),
            integrity_state=capture.get("status", "UNKNOWN"),
            queue_backlog=pending,
            runtime_rss_bytes=resources.get("peak_rss_bytes"),
            runtime_cpu_seconds=resources.get("cpu_seconds"),
            packet_accounting=dict(
                # Supported TCX metadata counts are not system-wide raw frame counts.
                normalized_packets_sent=metrics.get("packets"),
                transport_delivered_packets=metrics.get("native_events")
                if native
                else metrics.get("received"),
                capture_drops=metrics.get("queue_dropped"),
                capture_gaps=metrics.get("source_gaps"),
            ),
        ),
        research=dict(
            records=records,
            model_metrics=models,
            worker_running=current.get("analysis", {}).get("worker_running", False),
        ),
        runtime_audit_integrity=current.get("audit", "UNKNOWN"),
    )
