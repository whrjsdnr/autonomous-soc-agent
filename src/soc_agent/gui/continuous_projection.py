"""Presentation of an attached Runtime in the existing dashboard, never authority."""


def availability(current: dict, records: list) -> dict:
    """Explain absent measurements without inventing results or execution authority."""
    counts = current.get("metrics", {})
    native = current.get("source") == "NATIVE_SERVICE"
    measured = any(
        row.get("receipt", {}).get("inference_latency_ms") is not None for row in records
    )
    if counts.get("model_errors", 0):
        inference = "ERROR_MODEL_FAILURE"
    elif measured or counts.get("predictions", 0):
        inference = "MEASURED_RESULTS_AVAILABLE"
    elif native and current.get("native_model") == "EXACT_RETAINED_WINDOW_ACTION_APPROVAL_REQUIRED":
        inference = (
            "BLOCKED_SEALED_JOB_ACTION_APPROVAL"
            if counts.get("eligible", 0)
            else "WAITING_ELIGIBLE_WINDOW_THEN_ACTION_APPROVAL"
        )
    else:
        inference = "WAITING_MODEL_RESULT"
    assessment = current.get("capture_window", {}).get("assessment", {})
    dns = current.get("dns", {})
    transport = current.get("dns_transport", {})
    return dict(
        runtime_error=current.get("last_error"),
        capture=assessment.get("status", "UNKNOWN"),
        capture_reasons=assessment.get("reasons", []),
        inference=inference,
        latency="MEASURED_RECEIPT_LATENCY" if measured else inference,
        investigation="RECORDED_RESULTS_AVAILABLE"
        if records
        else "NO_INCIDENT_NO_INVESTIGATION_RESULT",
        assessment="RECORDED_RESULTS_AVAILABLE"
        if records
        else "NO_INCIDENT_NO_RESEARCH_ASSESSMENT",
        authentication=current.get("authentication", {}).get("state", "NOT_ATTACHED"),
        dns=dict(
            state=transport.get("state", "NOT_ATTACHED"),
            queries=dns.get("counts", {}).get("QUERY", 0),
            transactions=dns.get("counts", {}).get("MATCHED_RESPONSE", 0),
            diagnostic=dns.get("diagnostic_status", "UNKNOWN"),
            semantic_parse_failures=dns.get("counts", {}).get("PARSE_FAILURE", 0),
            transport_control=dns.get("counts", {}).get("TRANSPORT_CONTROL", 0),
            raw_helper_parse_failures=transport.get("dns_parse_failures"),
            raw_helper_counter_scope=(
                "INCLUDES_TCP_CONTROL_WITHOUT_DNS_PAYLOAD; DISTINCT_FROM_TRANSACTION_PARSE_FAILURES"
            ),
            helper_authenticated=transport.get("origin") == "REAL_NATIVE_DNS_METADATA",
            listener_scope="ACCEPT_LISTENER_CLOSED_AFTER_SINGLE_AUTHENTICATED_HELPER_CONNECTS",
            dns9="BLOCKED_TRAINING_EXTRACTION_CONTRACT",
        ),
        cleanup=current.get("cleanup", "UNKNOWN"),
        remote_cleanup=current.get("collector_cleanup", "UNKNOWN"),
    )


def measurement_reason(snapshot: dict, metric: str) -> str:
    states = snapshot.get("runtime_observability", {})
    if not states:
        return "NOT OBSERVED · no measured values"
    name = {
        "severity": "assessment",
        "progress": "investigation",
        "quality": "inference",
        "edge": "inference",
    }.get(metric, metric)
    return str(states.get(name, "NO_MEASURED_RESULT"))


def project(value: dict) -> dict:
    current = value.get("continuous")
    if not current:
        return value
    metrics = current.get("metrics", {})
    native = current.get("source") == "NATIVE_SERVICE"
    origin = (
        "REAL_NATIVE"
        if native
        else ("OFFLINE_PCAP" if current.get("source") == "PCAP_REPLAY" else "REPLAY")
    )
    queue = current.get("queue", {})
    capture = current.get("capture_window", {}).get("assessment", {})
    window = capture.get("window_evidence", {})
    cpus = window.get("cpus", [])
    losses = [row.get("counters", {}).get("ring_reservation_failures") for row in cpus]
    ring_loss = (
        sum(losses)
        if losses and all(type(value) is int and value >= 0 for value in losses)
        else None
    )
    quality = dict(
        status=capture.get("status", "UNKNOWN"),
        window_id=current.get("capture_window", {}).get("id"),
        scope="LAST_SEALED_WINDOW_OWNED_HOOK_NOT_SYSTEM_WIDE",
        active_generation=current.get("producer", {}).get("generation"),
        sealed_generation=window.get("clock", {}).get("epoch"),
        clock=window.get("clock", {}).get("status", "UNKNOWN"),
        same_epoch=capture.get("same_epoch", "UNKNOWN"),
        counter_reconciliation=capture.get("counter_reconciliation", "UNKNOWN"),
        owned_ring_loss=ring_loss,
        queue_drops=metrics.get("queue_dropped"),
        source_gaps=metrics.get("source_gaps"),
        kernel_wide_drops="UNKNOWN",
        reasons=capture.get("reasons", []),
        per_cpu=cpus,
    )
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
                investigation_detail=selected.get("investigation_detail", {}),
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
                profile,
                dict(
                    state="VERIFIED_RETAINED_RESULT"
                    if outcome.get("retained_selection")
                    else "VERIFIED_CONTINUOUS_RESULT",
                    successful=0,
                ),
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
                inferred_at=prediction.get("inferred_at", "UNKNOWN"),
                inference_latency_ms=prediction.get("inference_latency_ms"),
                model_artifact_sha256=prediction.get("model_artifact_sha256"),
                feature_fingerprint=prediction.get("feature_fingerprint"),
                flow_id=prediction.get("flow_id"),
                evidence_references=prediction.get("evidence_references", []),
            )
            records.append(
                dict(
                    receipt=receipt,
                    status="COMPLETE",
                    advisory_current="RETAINED_ADVISORY_NOT_CONFIRMED_ATTACK"
                    if outcome.get("retained_selection")
                    else "CONTINUOUS_ADVISORY_NOT_CONFIRMED_ATTACK",
                    investigation=outcome.get("investigation_detail")
                    or dict(status=outcome.get("investigation", "UNKNOWN")),
                    analysis_output=outcome.get("output"),
                    incident_id=outcome["incident_id"],
                )
            )
    observability = availability(current, records)
    for name in ("quality", "edge"):
        models.setdefault(
            name,
            dict(state=observability["inference"], successful=0, reason=observability["inference"]),
        )
    resources = current.get("resources", {})
    error = current.get("last_error")
    if error == "TimeoutError:":
        # Historical reports used an empty exception message. Keep the raw value
        # in continuous details; expose the known category in the safe status banner.
        error = "CONTINUOUS_SOURCE_TIMEOUT"
    elif isinstance(error, str) and error.startswith("ValueError:"):
        error = error.removeprefix("ValueError:")
    producer = current.get("producer", {})
    authenticated = (
        native
        and current.get("source_assurance") == "ROOT_INSTALLED_PASSIVE_TCX"
        and bool(producer.get("policy_sha256"))
        and producer.get("policy_sha256")
        == capture.get("source_provenance", {}).get("approval_digest")
    )
    attached = value.get("authentication", {})
    authentication = dict(
        attached if attached.get("runtime_state") else current.get("authentication", {})
    )
    transport = current.get("authentication_transport", {})
    if authentication.get("state") == "NOT_ATTACHED":
        authentication.update(
            runtime_state="NOT_ATTACHED",
            reason="HOST_AUTHENTICATION_COLLECTION_NOT_IN_TCP_TRIAL_SCOPE"
            if native
            else "NO_AUTHENTICATION_RUNTIME_OR_JOURNAL_REPLAY_CONFIGURED",
            input_origin="NO_DATA",
        )
    else:
        authentication.setdefault("runtime_state", authentication.get("state", "UNKNOWN"))
    authentication["transport"] = transport
    authentication["processed_inputs"] = metrics.get("authentication_inputs")
    return value | dict(
        capture_quality=quality,
        runtime_observability=observability,
        service_scope=dict(
            status="AUTHENTICATED_SERVICE_SCOPE_OBSERVED" if authenticated else "UNVERIFIED",
            policy_sha256=producer.get("policy_sha256"),
            namespace=producer.get("namespace"),
            interface=capture.get("source_provenance", {}).get("interface"),
            authority="DISPLAY_ONLY_NOT_A_NEW_EXECUTION_OR_MODEL_GRANT",
        ),
        authentication=authentication,
        dns=current.get("dns", {}) | dict(transport=current.get("dns_transport", {})),
        dns_observation=(
            str(current.get("dns", {}).get("counts", {}))
            if metrics.get("dns_inputs", 0)
            else "NO_DNS_OBSERVATIONS"
        ),
        state=current.get("state", "UNKNOWN"),
        collection_live=current.get("collection_live", False),
        session_id=current.get("clock_epoch"),
        input_origin=origin,
        last_error=error
        or ("CONTINUOUS_CONTROLLER_FAILURE" if current.get("controller_error") else None),
        collectors={
            "network": current.get("collector", "UNKNOWN"),
            "dns": current.get("dns_transport", {}).get("state", "NOT_COLLECTED_IN_THIS_SCOPE")
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
            capture_drops=ring_loss,
            gap_count=metrics.get("source_gaps"),
            capture_drop_scope="LAST_SEALED_WINDOW_OWNED_RING_ONLY",
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
