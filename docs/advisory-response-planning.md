# Phase 4-5 — Advisory Response Planning

## Purpose and non-goals

A proposed action is not an authorized action.
Policy preflight is not execution authorization.

This phase structures options for human consideration using an existing incident,
IncidentDecision, authenticated recorded incident review, and registered tools.
It does not decide whether to execute. It does not invoke tools, create approvals,
issue state authorizations, change state, register capabilities, alter policy,
train models, infer again or generate another IncidentDecision.

The older `soc_agent.response.ResponsePlanner` and ResponseCoordinator already
produce and consume executable step lifecycle models. They remain unchanged for
compatibility. Phase 4-5 is explicitly imported from
`soc_agent.response.advisory`; its ResponsePlan and ActionProposal have different
shapes and cannot be passed to the existing Executor or Coordinator. There is no
conversion or promotion API. The legacy workflow is not silently upgraded to this
new review binding contract.

## Architecture and entry points

```text
Explicit CandidateIntent drafts + IncidentState + IncidentDecision + HumanReviewRecord
  → read-only authoritative source validation
  → versioned conservative planning rules
  → Registry resolution and exact input schema validation
  → existing PolicyEngine preflight
  → immutable ResponsePlan + advisory ActionProposals
  → human review required (stop)
```

```python
from soc_agent.response.advisory import (
    CandidateIntent,
    PersistentPlanningSource,
    ResponsePlanner,
)

# store is an explicitly opened Phase 4-4 SQLiteGovernanceStore.
# registry contains only capabilities installed by trusted application setup.
planner = ResponsePlanner(registry=registry, source=PersistentPlanningSource(store))
plan = planner.create_plan(
    incident_state=state,
    decision=decision,
    review=review,
    objective="Consider evidence-grounded next steps",
    candidates=(),  # Supply explicit CandidateIntent objects when exact inputs are known.
)
```

No additional LLM is necessary. CandidateIntent is an **untrusted explicit draft**
from the calling analyst/application, with candidate tool, proposed input, purpose,
rationale and Evidence IDs. It cannot specify risk, permission, reversibility or
policy outcome. The planner filters these alternatives by deterministic rules;
it does not invent targets from raw logs, infer capabilities from tool names, or
manufacture missing inputs. Empty intents produce an explicit gap, not a guessed
action. Descriptions are retained from actual tool metadata. A future candidate
LLM must feed this same untrusted draft boundary and cannot supply authority.

PersistentPlanningSource validates current state, store identity, revision and
full fingerprint against the registered Decision and Review in one read
transaction. It uses Phase 4-4's existing validated ledger restoration and checks
exact record equality; a syntactically valid reviewer string or forged review is
not sufficient. Alternative PlanningSource implementations would be trusted
composition dependencies and must enforce the documented provenance contract.
No authentication provider is installed by planning.

## ResponsePlan contract

`ResponsePlan` contains a stable plan ID, PlanContent, proposed actions and a
creation timestamp. PlanContent contains:

- PlanningBasis: incident ID, full StateAnchor, original Decision and Review,
  and actual incident Evidence records.
- Objective, retained decision rationale and uncertainty/limitations.
- Evidence references, canonical candidate alternatives, proposed action details.
- Investigation gaps, review requirements, residual risk without action and
  structured disposition codes.
- Literal planning version `response-planning:v1`.

Creation time is excluded from semantic identity. The original source clocks and
full review digest are retained because they are part of the exact reviewed
snapshot. The basis preserves Evidence, observations, hypotheses, assessment,
model-derived context and human disposition as different existing typed fields.
No prose is promoted to a verified fact.

## ActionProposal contract

The advisory proposal contains its own hash identity, incident ID, parent plan ID
and ActionDetails. Details bind the CandidateIntent's canonical exact input to
ToolMetadata, serialized input JSON schema, tool binding digest, the unchanged
PolicyResult, a policy-derived approval requirement, category, intended security
effect, possible operational impact, blocking reasons and uncertainties.

The contract intentionally lacks the legacy Executor's `action_id`, `tool_name`
and `tool_input` fields. The executor's existing strict validation rejects it
before execution or approval creation. Copying fields into a different executable
object would be a new trusted operation; no such operation exists in this phase.
Python domain objects are not a sandbox against malicious application code.

Candidate purpose and rationale are labeled `unverified_candidate_intent`.
Security efficacy and target relevance are unknown until examined by a human.
Operational impact is separate from ToolRiskLevel: reads may expose sensitive data
or consume resources; writes may disrupt users, traffic or services. These are
possible impacts, not a verified prediction or a new numerical score.
Tool metadata has no reversibility contract, so only `unknown` is emitted. Future
capability metadata must supply an auditable basis before another value is used.

## Evidence grounding

The planner reuses Phase 4-3 decision validation, including Assessment reference
checks and Fusion revalidation. Each candidate Evidence ID must exist in the
current validated incident. Unknown IDs, another incident's evidence and actual
Fusion/AISignal IDs are rejected. Human review does not convert model predictions
into Evidence, establish cross-domain correlation or confirm compromise.

A candidate without Evidence may be an investigation option, with a blocking
reason explicitly requiring factual and target grounding. Reference membership
does **not** establish that a target/input is entailed by source records; the
planner does not attempt semantic proof. All proposals require future human
review and explicit promotion before anything could execute.

The existing ThreatAssessor requires Evidence even when only models raise an
alert. Therefore the real-package model-only scenario retains source telemetry
and an INFO assessment; the model provides the suspicious indication. It is not
a zero-Evidence ThreatAssessment and does not bypass that existing contract.

## Planning rules and Policy preflight

| Situation | v1 planning behavior |
| --- | --- |
| Evidence-linked suspicious Decision | Consider supplied registered response candidates; no claim of attack success |
| Suspicion with investigation gaps | Preserve gaps and block response promotion pending resolution |
| Only models raise concern / insufficient basis | Defer WRITE candidates; retain investigation alternatives and model uncertainty |
| BENIGN/anomaly or assessment/model disagreement | Preserve original contributions and explicit review disposition |
| Review requests investigation | Suppress WRITE candidates, including destructive ones |
| Review outcome REJECTED | Emit no proposals; preserve conservative stop disposition |
| CLOSED incident | Reject new planning pending a separate reconsideration workflow |
| No response capability in Registry | `appropriate_response_tool_unavailable`; no invented tool |
| No candidate intents | `no_candidate_intents_supplied`; no inferred inputs |
| Policy DENY | Retain denied candidate as a blocked option with the original reason |
| Policy REQUIRE_APPROVAL | Preserve requirement; create no approval |
| Policy ALLOW | Preserve result; planning still does not execute or authorize |

The real ReviewOutcome.REJECTED value means `state_change_rejected`, not an
analytical truth verdict. v1 intentionally stops planning conservatively for this
outcome rather than claiming the human disproved the Decision. ACKNOWLEDGED and
CHANGE_ELIGIBLE permit consideration only. Neither approves a response action.

Categories are deliberately minimal: `additional_investigation` for read
permissions and `response_consideration` for write permissions. This avoids
labeling observation as containment or inventing remediation/recovery capabilities
that existing metadata does not describe. Category is not policy authorization:
HIGH-risk reads still require approval, and destructive actions remain denied.
The fixed PolicyEngine is reused unchanged, including WRITE+READ_ONLY contradiction
and WRITE+LOW approval handling. No new policy outcome enum is introduced.

## Identity, tampering and staleness

Canonical JSON and SHA-256 reuse the review identity implementation. A plan ID
hashes complete PlanContent, including source bindings, canonical alternatives,
exact normalized input, purpose/rationale, Evidence, metadata/schema and Policy
results. Proposals hash their details plus incident and parent plan ID. This
avoids a circular plan/action hash. Object key order, Evidence reference order and
candidate alternative order are normalized; these are not execution sequences.
Pydantic round trips revalidate nested values, IDs and bindings, including models
constructed through validation-bypassing copy methods.

Hash validation detects payload changes under an existing identity, not malicious
rewriting with a newly calculated hash. `planner.validate_current(plan,
incident_state=state)` additionally rereads authoritative provenance and regenerates
the deterministic advisory content to reject stale or inconsistent plans. Changes
to Registry metadata/schema require revalidation. This is still only a read-time
check; it grants no TOCTOU safety at a later execution time and reserves nothing.
Metadata/schema hashes do not attest handler implementation or real behavior.
Any future promotion/execution must revalidate current state, tool metadata,
policy and exact action-specific approval; an earlier preflight never substitutes
for those checks.

## Persistence decision

**ResponsePlan/ActionProposal persistence is not implemented in Phase 4-5.**
Advisory plans are currently in-memory artifacts; restart recovery is not provided.
Phase 4-4 schema remains version 1; no migration, initialization, plan table or
plan write occurs. Existing incident/review records are read through the durable
store. This deliberately keeps the planner a read-only advisory layer while
avoiding silently placing new artifacts in Phase 4-4's approval issuance ledger.
A dedicated durable proposal lifecycle, retention policy and explicit migration
remain follow-up work. Canonical serializable models support review/export, but
no durable save/load, restart recovery or audit history for plans is claimed.
The models contain source evidence and may contain sensitive raw telemetry;
callers must control access and must not log the complete artifact indiscriminately.

## Governance and operational limitations

The following remain distinct: IncidentDecision review, state-change authorization,
ResponsePlan review, and Tool execution approval. ResponsePlan human review is
represented as requirements only, with no new approval system or UI. The existing
external human-authentication boundary is still default deny unless explicitly
configured by trusted composition. Test human confirmations are not production
authentication.

No production response tools are added. Synthetic tests install fixture wrappers
for metadata/preflight inspection only, with execution prohibited. Policy preflight
does not prove operational safety, target ownership, reversibility, model accuracy
or absence of compromise. There is no cross-domain attribution, new confidence,
impact score, external SOC/SIEM/SOAR integration or execution promotion.

## Validation and next phase

Unit tests cover immutable contracts, identities/tampering, exact input validation,
source/evidence binding, all real review outcomes, stale state/tool bindings,
policy outcomes and forbidden calls. Real saved-package synthetic scenarios use
Mock LLM assessment and separate test-only human confirmation, preserve actual
model outputs and stop at preflight. Full regression includes the existing
Phase 4-4 restart and independent-process CAS tests without modifying them.

Next steps require explicit design: durable plan lifecycle and v1 migration,
verified capability/impact/reversibility metadata, target-grounding review,
ResponsePlan-specific human review, and a separately governed promotion boundary.
None of these grants execution authority in this phase.

## Final verification — 2026-09-28

- Advisory unit suite: **48 passed**, exit **0** (previously 47; one additional
  test directly checks that the legacy ResponseCoordinator rejects an advisory
  plan without forwarding it to execution).
- Saved-model integration scenarios: **9 passed**, exit **0**. ML inference uses
  actual saved packages; assessment uses Mock LLM, and human confirmation uses
  a separate test-only adapter.
- Full regression: **1,597 passed in 295.46s**, exit **0**; Phase 4-4 baseline was
  1,540. No prior tests were removed or weakened.
- Ruff check, Ruff format check and `git diff --check`: exit **0**.
- Full log: `/tmp/soc-phase45-full-final.log`; captured process exit code:
  `/tmp/soc-phase45-full-final.exit`.

The earlier log recorded 1,596 passed, but its process exit code was unavailable,
so the full suite was rerun. Phase 4-4 schema/authorization/CAS and the existing
executable implementation remain unchanged. No commit or push was performed.
