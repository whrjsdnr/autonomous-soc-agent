"""Read-only formatting of existing DTOs. These labels do not grant authority."""

import json


def short(value):
    value = str(value) if value is not None else "UNKNOWN"
    return value if len(value) <= 28 else value[:16] + "…" + value[-8:]


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
