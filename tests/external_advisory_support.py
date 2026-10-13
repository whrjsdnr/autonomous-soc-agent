"""Scripted responses for advisory diagnostics; not inference or authority."""


def responses(context):
    evidence = str(
        context.results[0].observation.association.source_evidence_references[0].evidence_id
    )
    return [
        {
            "goal": "Read-only source verification",
            "steps": [
                {
                    "tool_name": "source_lookup",
                    "tool_input": {"indicator": "synthetic-source"},
                    "purpose": "Verify source evidence",
                }
            ],
        },
        {
            "observations": [],
            "hypotheses": [],
            "assessment": {
                "severity": "high",
                "confidence": 0.2,
                "summary": "Model-derived signal requires verification; no authorization",
                "supporting_evidence_ids": [evidence],
            },
        },
    ]
