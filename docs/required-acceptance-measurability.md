# Required acceptance measurability — Phase 7-5A.2

Phase 7-5A.1 established CASE B: legacy feedback could identify required coverage
and overall defects, but not which paths were unnecessary. That conclusion remains
correct for every snapshot without the new explicit human adjudication.

## One trusted human source

`FeedbackRequest.coverage_expectation` remains the single source of required
permissions. It now optionally carries `InvestigationPathAdjudication`:

```json
{
  "required_permissions": ["network_read"],
  "path_adjudication": {
    "adjudication_version": "human-investigation-path-adjudication:v1",
    "unnecessary_permissions": [],
    "review_completeness": "COMPLETE"
  }
}
```

The existing coverage contract still requires nonempty required permissions.
Adjudication covers the finite SYSTEM_READ / NETWORK_READ / FILE_READ permission
classes, not individual tool calls, tool inputs, or all production planner behavior.
All tuples are canonical, sorted and unique; noncanonical duplicates/order, WRITE,
arbitrary values, overlapping required/unnecessary permissions, extra fields and
mutation are rejected. COMPLETE and PARTIAL are explicit human declarations.

Required permissions are not treated as an exhaustive allowlist.
An overall UNNECESSARY_INVESTIGATION label does not identify an unnecessary path.
Selected paths alone do not establish necessity. Labels and adjudication are not
automatically synchronized; existing verdict/label validation remains intact.

An empty unnecessary set is a measured zero only after an analyst explicitly marks the adjudication complete.

PARTIAL alone, missing adjudication, or any HOLDOUT case lacking COMPLETE evidence
leaves the aggregate metric NOT_MEASURABLE with value null. Compatible PARTIAL
facts can coexist with an explicitly COMPLETE judgment; PARTIAL never supplies
completeness. All COMPLETE judgments must agree. Any asserted unnecessary path
conflicting with another contributing required path, contradictory COMPLETE sets,
or PARTIAL facts outside a COMPLETE set preserves analyst disagreement as normal
Dataset exclusion. No reviewer is automatically preferred or overwritten.

## Authentication and immutable provenance

Submission uses the existing Analyst Feedback permission, authenticated principal,
session-bound request-specific durable confirmation and immutable feedback record.
The entire adjudication is part of the confirmed request digest. A caller cannot
claim a trusted role in the body. No new authority infrastructure is introduced.

The Dataset is reference-first: every ImprovementSample pins all contributing
Feedback IDs/digests, including explicit adjudication. The builder verifies these
records and preserves references, without copying or inferring raw human payloads.
Offline ground-truth loading verifies the exact incident, Experience, Evaluation,
Feedback digest and sample bindings. Frozen HOLDOUT cases retain each individual
`PinnedPathAdjudication`, including its exact feedback reference and completeness.
Missing facts are not replaced with annotations or overall diagnostic labels.

Historical feedback is never backfilled by inference.

A new fact requires explicit new Feedback, Dataset rebuild, new candidate/spec/plan
binding, new evaluation/comparison, and new ReviewRequest. Old Dataset membership,
results, comparisons and terminal ReviewRecords remain unchanged. Feedback without
the optional field and legacy ground-truth/trace payloads omit new absent fields
when serialized, preserving old content identities. Schema stays v13: existing
JSON payload/digest persistence supports this additive contract without migration.

## Measurement and acceptance

The adapter selects a canonical tuple of permission paths. For each frozen case
with consistent COMPLETE adjudication, count:

`len(selected_permissions ∩ explicitly_unnecessary_permissions)`

Unselected unnecessary permissions are not counted. Explicit COMPLETE empty sets
and empty intersections produce measured zero; missing/PARTIAL evidence never does.
An aggregate count is measured only when every evaluated HOLDOUT case has COMPLETE
evidence. This is one count per selected permission class per case, not a claim
about actual investigation steps or Tool invocations.

Baseline and candidate use the same frozen cases, order, human facts, metric
definitions and sandbox. The existing NOT_GREATER_THAN_BASELINE criterion computes
PASS for candidate <= baseline, FAIL for candidate > baseline, and UNKNOWN for
unmeasurable evidence. The evaluator does not hard-code any acceptance outcome.
The current candidate operation only adds required coverage; it cannot remove an
existing path. A count decrease can be tested as measurement semantics without
inventing a remove-path executable candidate operation.

## Human Review and promotion boundary

New COMPLETE evidence can yield an all-PASS comparison and a reviewable request.
There is still no automatic APPROVE. An explicit trusted human review with its own
permission/confirmation is required. Synthetic integration fixtures demonstrate
PROMOTABLE only after this real governance service commits an APPROVE; this is test
proof, not a production review or promotion. Missing/PARTIAL facts, acceptance FAIL,
missing review, REJECT and DEFER remain NON_PROMOTABLE; corrupted source bindings
raise integrity errors. Policy/Approval evidence remains scoped to the existing
local gate probes, not exhaustive production safety or production LLM quality.

Promotion eligibility does not perform promotion.

Adjudication has no Policy override, Tool Approval, confirmation-reuse, executor,
protected state mutation, Response or promotion capability. There is no
PromotionRequest, registry, active pointer, rollback, runtime activation or live
LLM/API. Version registry, bootstrap and independent promotion/rollback governance
remain the separate Phase 7-5B responsibility.
