"""Read-only formatting of existing DTOs. These labels do not grant authority."""

import json
import re


def short(value):
    value = str(value) if value is not None else "UNKNOWN"
    return value if len(value) <= 28 else value[:16] + "…" + value[-8:]


def screen_data(value):
    """Presentation-only masking; backend DTOs and their bound digests stay unchanged."""
    if isinstance(value, dict):
        return {
            k: "[REDACTED]"
            if str(k).lower()
            in {"username", "user_name", "hostname", "operator_identity", "subject_id"}
            else screen_data(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [screen_data(v) for v in value[:512]]
    if isinstance(value, str):
        return re.sub(r"/home/[^/\s\"']+", "$HOME", value)
    return value


def research_sections(value):
    record = value.get("research_record")
    if not record:
        return [
            ("No advisory selected", "Run an explicit demo, then select a result."),
            ("Operational boundary", "RESEARCH_ONLY · no operational promotion or security WRITE"),
        ]
    receipt = record.get("receipt") or {}
    inv = record.get("investigation") or {}
    if value.get("research_view") == "audit":
        return [
            ("Audit integrity", str(value.get("audit_integrity", "UNKNOWN"))),
            ("Model invocation · UTC", str(receipt.get("inferred_at", "UNKNOWN"))),
            (
                "Source / receipt type",
                str(receipt.get("origin", "UNKNOWN"))
                + "\n"
                + str(receipt.get("contract", "UNKNOWN")),
            ),
            ("Model identity", str(receipt.get("model_id", "UNKNOWN"))),
            (
                "Artifact / input binding",
                short(receipt.get("artifact_digest"))
                + "\n"
                + short(receipt.get("feature_digest", receipt.get("input_digest"))),
            ),
            (
                "Stored outcome",
                str(record.get("status", "UNKNOWN"))
                + " · "
                + str(record.get("error") or "No recorded error"),
            ),
            (
                "Checkpoint / provenance",
                "Restored "
                + str(inv.get("checkpoint_restored", "UNKNOWN"))
                + "\nContext "
                + short(inv.get("context", {}).get("receipt_digest")),
            ),
        ]
    assessment = inv.get("assessment", {})
    draft = assessment.get("threat_assessment", assessment.get("assessment", {}))
    validation = receipt.get("validation_level", "UNKNOWN")
    if (
        receipt.get("contract") == "soc-network-research-receipt:v1"
        and receipt.get("origin") == "OFFLINE_PCAP"
        and receipt.get("producer_version") == "1.1.0"
        and record.get("status") == "COMPLETE"
    ):
        validation = "OFFLINE_VERIFIED_FLOW"
    return [
        (
            "Incident · READ-only",
            short(inv.get("incident_id")) + "\n" + str(inv.get("status", "UNKNOWN")),
        ),
        (
            "Input / validation",
            str(receipt.get("origin", "UNKNOWN")) + "\n" + str(validation),
        ),
        (
            "Model advisory · uncalibrated",
            str(receipt.get("profile", "UNKNOWN")).title()
            + " · score "
            + str(receipt.get("score", "UNKNOWN"))
            + "\nThreshold "
            + str(receipt.get("threshold", "UNKNOWN"))
            + " · "
            + str(receipt.get("prediction", "UNKNOWN")),
        ),
        (
            "Verified source references",
            "\n".join(short(x) for x in inv.get("evidence_references", [])) or "UNKNOWN",
        ),
        (
            "Assessment · not observed fact",
            str(draft.get("summary", "No stored assessment summary")),
        ),
        (
            "Recommended action / boundary",
            str(draft.get("recommended_action", "No stored response recommendation"))
            + "\n"
            + str(inv.get("action_policy", "UNKNOWN")),
        ),
    ]


def sections(page, value):
    if not isinstance(value, dict):
        return [("No selection", "Select a record to review its source and outcome.")]
    if value.get("ok") is False:
        return [
            ("Request blocked / uncertain", str(value.get("error", value.get("status", "UNKNOWN"))))
        ]
    data = value.get("result", value)
    if not isinstance(data, dict):
        return [
            (
                "Stored records",
                f"{len(data) if isinstance(data, list) else 'UNKNOWN'} records • select a row",
            )
        ]
    if "research_view" in data:
        return research_sections(data)
    if "models" in data and "context_digest" in data:
        panels = []
        for model in data["models"]:
            output = model["output"]
            label = output.get("predicted_class", output.get("label", "UNKNOWN"))
            score = output.get("confidence", output.get("probability", "UNKNOWN"))
            panels.append(
                (
                    model["binding_id"] + " • " + model["status"],
                    str(label)
                    + " | uncalibrated output: "
                    + str(score)
                    + "\n"
                    + model["model_version"],
                )
            )
        return panels + [
            ("Advisory Context", short(data["context_digest"]) + " • 3 models / 2 observations"),
            (
                "Fixture only / SCRIPTED investigation",
                "NOT_INFERABLE • 실제 네트워크 원본 데이터 분석은 아직 검증되지 않았습니다.",
            ),
            (
                "Measured total execution",
                str(round(data["elapsed_seconds"], 3)) + " seconds • WRITE_DENIED",
            ),
        ]
    if "packages" in data:
        return [
            ("Fixture validation history", str(data.get("last_validation_check", "UNKNOWN"))),
            ("Operational input", "NOT_INFERABLE • training producer parity not verified"),
            ("Context reference", short((data.get("last_validation") or {}).get("context_digest"))),
            (
                "Advisory boundary",
                "Model outputs are not observed security facts or execution authority",
            ),
        ]
    if "record" in data:
        record = data["record"]
        request = record.get("request", {})
        action = record.get("action", request.get("action", {}))
        payload = action.get("tool_input", "{}")
        try:
            payload = json.loads(payload) if isinstance(payload, str) else payload
        except (ValueError, TypeError):
            payload = {}
        approval = record.get("approval", {})
        return [
            ("Requested action", str(action.get("tool_name", "UNKNOWN"))),
            (
                "Decision / expiry",
                str(data.get("status", record.get("status", "UNKNOWN")))
                + " • "
                + str(approval.get("expires_at", "UNKNOWN")),
            ),
            ("Bound target", str(payload.get("resource_id", payload.get("account_id", "UNKNOWN")))),
            (
                "Evidence binding",
                short(payload.get("evidence_digest", request.get("evidence_digest"))),
            ),
            ("Policy binding", short(payload.get("policy_digest", record.get("policy_digest")))),
            (
                "Execution scope",
                "Registered TEST MARKER only"
                if "action" in record
                else "RESPONSE_SIMULATION • no resource changes",
            ),
        ]
    if "rule_id" in data:
        observed = data.get("observations", {})
        assessment = data.get("advisory_assessment", {})
        # AssessmentResult nests the model's assessment; READ_ONLY may have none.
        assessment = assessment.get("threat_assessment", assessment.get("assessment", assessment))
        steps = data.get("tool_steps", [])
        progress = " • ".join(
            str(s.get("tool_name", "READ")) + ": " + str(s.get("status", "UNKNOWN")) for s in steps
        )
        return [
            (
                data["rule_id"].replace("_", " ").title(),
                str(data.get("status", "UNKNOWN")) + " • " + data.get("assessment_mode", "UNKNOWN"),
            ),
            (
                "Verified source references",
                str(len(data.get("evidence_references", [])))
                + " source digest references • "
                + short(data.get("incident_id")),
            ),
            (
                "Event timeline (UTC)",
                str(observed.get("first_seen", "UNKNOWN"))
                + "\n"
                + str(observed.get("last_seen", "UNKNOWN")),
            ),
            ("READ tool progress", progress or "UNKNOWN • no stored tool progress"),
            (
                "Advisory assessment • not an observed fact",
                str(assessment.get("summary", "No stored model assessment")),
            ),
            ("Audit / result", short(data.get("result_digest"))),
        ]
    if "scenario_id" in data:
        stages = data.get("stages", {})
        return [
            (
                data["scenario_id"] + " • " + data.get("overall_status", "NOT_RUN"),
                "FIXTURE / REPLAY • " + data.get("assessment_mode", "SCRIPTED"),
            ),
            (
                "Reported stages",
                " • ".join(k + ": " + v["status"] for k, v in stages.items()) or "NOT_RUN",
            ),
            ("Findings", ", ".join(data.get("detections", [])) or "No detection reported"),
            ("Audit receipt", short(data.get("audit_receipt"))),
        ]
    if "evaluation_id" in data:
        return [
            ("Offline evaluation", str(data.get("verdict", "UNKNOWN"))),
            (
                "Regression gate",
                str(data.get("regression_result", data.get("regression_gate", "UNKNOWN"))),
            ),
            ("Data assurance", str(data.get("ground_truth_assurance", "UNKNOWN"))),
            ("Promotion", str(data.get("promotion", "UNKNOWN"))),
        ]
    return [
        ("Stored backend result", "No attack fact or execution authority inferred from this view."),
        ("Status", str(data.get("status", data.get("overall_status", "UNKNOWN")))),
    ]
