# Self-Improvement Audit and Runtime Outcome Projection

Baseline `7421fae974ffdcb438f06a10cc9131adc6a1c8b1`, 2026-10-14, WSL2 Ubuntu only.

## Verdict and scope

PARTIAL for a continuous-runtime self-improving lifecycle. Existing offline governed components are implemented and tested; they are not a general autonomous learning or self-modifying system. This change adds a validated read-only runtime outcome projection and connects it to the authenticated operator query. No automatic proposal generation, promotion, policy/threshold/tool permission change, code modification, model replacement or ground-truth relabeling is connected to Continuous Runtime.

AGENTS.md describes reflection/learning as future Foundation work. Actual repository code contains later, explicit offline `experience`, `feedback`, `improvement_dataset`, `improvement_candidates`, `offline_evaluation`, `offline_comparison`, `improvement_review` and `improvement_promotion` packages. The audit follows actual code/tests and preserves their narrow trust boundaries; it does not delete them or reimplement them as a new platform.

## Existing inventory

TESTED below means automated isolated SQLite/fixture/provider tests, not an actual operating learning loop or verified performance improvement. Exact test counts appear in completion evidence.

| Capability | Status | Source / callable | Tests and limits |
|---|---|---|---|
| Experience persistence | TESTED | `experience/capture.py::ExperienceCaptureService.capture`, `experience/store.py` | `tests/integration/experience/`; explicit historical core workflow capture; no automatic continuous-runtime experience migration |
| Investigation outcome | TESTED | `experience/models.py::ExperienceContent`, `evaluation/service.py::ExperienceEvaluator` | experience/feedback/evaluation integration; anchors, trace references, outcomes, no inferred attack truth |
| Tool failure | PARTIAL | investigation trace + `evaluation/service.py`, `linux_runtime/store.py::finish` | historical outcomes and workflow failures recorded; this projection exports references/status, not a complete per-tool diagnostic taxonomy |
| LLM failure | TESTED | `linux_runtime/service.py::BudgetClient`, `store.py::invocation_event` | `tests/integration/linux_runtime/test_invocation_recovery.py`, `tests/unit/llm/`; sanitized categories/unknown invocation handling; this phase performs no live API call |
| Human feedback persistence | TESTED | `feedback/service.py::AnalystFeedbackService`, `feedback/models.py` | `tests/integration/feedback/`; provider authentication, permission, bound one-use confirmation; a local action approval is not diagnostic feedback |
| FP/FN human adjudication | TESTED | `feedback/models.py::DiagnosticLabel`, `FeedbackRequest`; independent evaluation GroundTruth | feedback/evaluation tests; no engine-output-generated labels; operating corpus unavailable |
| Reflection | PARTIAL | `improvement_candidates/analysis.py::analyze` | deterministic patterns with minimum support and UNKNOWN causality; no LLM reflection engine or memory/RAG package |
| Improvement proposals | TESTED | `improvement_candidates/service.py::ImprovementCandidateService`, `generation.py::generate`, `models.py` | candidate tests; bounded REVIEW proposals and separate explicit structured coverage declarations |
| Offline planning | TESTED | `offline_evaluation/service.py::OfflineEvaluationPlanner.plan` | planning tests; SPECIFY→PLAN→STOP is not itself execution |
| Offline paired validation | TESTED | `offline_comparison/service.py::OfflineEvaluationRunner.evaluate`, `execution.py::execute_pair` | offline comparison tests: frozen baseline, same cases, independent human coverage truth, holdout/measurement/invariant checks; supported read-only coverage only |
| Regression/acceptance gate | TESTED | `offline_comparison/evaluation.py`, `improvement_review/models.py::require_decision`, `improvement_promotion/eligibility.py` | missing/unmeasurable/unsafe/regressed results cannot be claimed eligible; project-wide Scenario regression remains a separately run gate |
| Human review | TESTED | `improvement_review/service.py::ImprovementReviewService.submit` | provider principal/session, exact binding, durable one-use confirmation, terminal decision and audit |
| Controlled promotion | TESTED | `improvement_promotion/service.py::ImprovementActivationService.promote` | explicit administrative action after review; CAS against expected pointer, bounded strategy family only; not model/code/policy replacement |
| Rollback | TESTED | same service `rollback`, `store.py::create_rollback_request` | registered historical version and separate authentication/confirmation required; no arbitrary payload |
| Improvement audit | TESTED | per-package stores and existing governance ledger | integrity/tampering/transaction/restart tests; no rewrite of past audit events |
| Continuous-runtime feedback export | TESTED | NEW `linux_runtime/feedback_projection.py::project_feedback` | new runtime projection tests; original source/receipt/incident/result/audit validated; no table or migration |
| Continuous-runtime auto learn/promote | NOT_IMPLEMENTED | no call from LinuxMonitor to candidate or activation services | intentional boundary: no autonomous application |
| Knowledge/vector memory | NOT_IMPLEMENTED | no `memory/` or `reflection/` package found | historical experience is not a knowledge database or RAG |

## Proposal contract and reuse

Existing `CandidateContent`/`ImprovementCandidate` bind deterministic proposal identity, dataset manifest, supporting sample/pattern references, bounded trigger/focus, target component, rationale, proposed review, expected effect and read-only authority. `OfflineEvaluationPlanner` supplies validation specification/test plan. `ImprovementReviewRequest`/`ImprovementReviewRecord` supply authenticated human review status, frozen source snapshot and audit reference. These linked objects together represent the proposal workflow; not every field is in a single new object. No second proposal engine was added.

Prompt/Rule/Tool Selection REVIEW prose cannot be interpreted as an executable patch. `improvement_candidates/strategy.py::compile_candidate_strategy` accepts only explicit `CoverageProposal` fields; the executable family is `INVESTIGATION_STRATEGY_DEFAULT`. `planning/strategy.py::InvestigationStrategy` specifies required **existing read-only permission coverage**; it does not create Tools, expand executable Tool permissions or loosen approvals. Prompt text, rule strings and annotations cannot change operating policy.

`improvement_promotion/provider.py::RegistryBackedInvestigationStrategyProvider` is explicit opt-in composition. Core-runtime tests demonstrate governed selection/rollback. Continuous Linux Runtime does not inject this registry provider automatically.

## New read-only feedback connection

`operator feedback` executes `project_feedback()` inside the existing Runtime process after OS peer authentication. Direct projection tests show zero data writes: queue, source and monitor logical dumps remain identical.

Projection includes opaque Finding ID/digest, Incident ID, result digest, original Evidence/Provenance references, input origin, processing status, trust category and immutable projection/item digests. Native events and Fixture origins remain distinct. Scripted results are `VERIFIED_TEST_RESULT`; real-LLM assessment references are `MODEL_INFERENCE`; native read-only observations are `OBSERVED_EVENT`. OS-peer action decisions may be `HUMAN_FEEDBACK` **only as consent to a simulation**, never as diagnostic truth. Explicit test actors remain `VERIFIED_TEST_RESULT`.

The native-shaped parser fixtures used by existing Runtime tests are not real OS evidence merely because the parser emits NATIVE_OS tags. Test execution environment is recorded separately from source contract tags. Digest validation proves consistency, not origin authenticity outside the trusted collector boundary.

All diagnostic labels remain `UNLABELED`, authority NONE. Untrusted annotations/LLM prose are not copied, prompted, executed or interpreted. IDs are derived deterministically from reference content; projection is reconstructed after restart from original stores. No separate feedback persistence engine, duplicate proposal record or schema migration was added. The projection explicitly reports candidate generation/promotion NOT_CONNECTED and ground-truth generation/automatic changes DISABLED.

Projection validates audit hash chain, finding/state/result binding, current source/incident/provenance and reviewed simulation Window. Unknown/missing/changed sources fail closed. A bound of 512 findings rejects a larger projection rather than silently hiding data. CLI operator audit returns at most the latest 100 **receipt references**, not sensitive raw payloads.

## Offline validation evidence and limits

Existing paired evaluation is verified for its supported read-only permission-coverage fixture family. It is not arbitrary candidate code execution or a DNS/Network model replacement gate. Existing independent Authentication GroundTruth/Runner remain unchanged: 11 Fixture cases, 60 Window×Rule units, TP 7 / FP 2 / TN 49 / FN 2. These historical Fixture metrics are not newly measured operating performance and do not establish that an improvement has occurred.

No new candidate was promoted or strategy applied. Existing Scenario S01–S12 and Detection Evaluation regressions are run alongside approval/transport/security tests in Track A, separately from Track B offline audit tests. No candidate-specific operational effect was VERIFIED. Native labeled data and prospective/held-out validation are required before claiming better FP/FN, quality or latency.

## Trust-boundary checks

- Untrusted model output and plain-text human notes remain data, never authority.
- Feedback authentication/authorization, source binding, confirmation consumption and inconsistent reviewer judgments are preserved.
- Ground Truth comes from independent labels/human coverage declarations, never a Finding, LLM score or operator action approval.
- Forged incident/evidence/digest/reference and altered audit records are rejected.
- Generic JSON cannot supply policy/model/code/approval/Tool-permission patches to the new projection.
- Existing activation uses `mutation_guard`, separate admin permission/purpose, required human review, one-use confirmation, expected-pointer CAS and append-oriented history. No activation callable is exposed by the operator Socket.
- Sources, Synthetic v2, Operational Provenance v3, Network/DNS NOT_INFERABLE, investigation WRITE_DENIED and actual OS handlers=0 remain unchanged.

## Tests and development findings

New `tests/integration/runtime_feedback/test_projection.py` verifies read-only dumps, deterministic restart reconstruction, result/reference/audit tampering rejection, absent sources, malicious annotation exclusion, test-vs-OS actor distinction and no labels/authority from supplied JSON. Initial projection test incorrectly equated the existing native-shaped parser fixture origin tag with Fixture origin; the test now checks actual trust classification and does not claim real OS execution. Scripted outcome classification was made explicit.

Legacy tests reused: experience, feedback, improvement dataset/candidates/review, offline evaluation/comparison, promotion/rollback; their authentication mocks are test providers, not live operating-user verification. New local OS-peer approval is verified separately in Track A.

## Remaining work

1. Explicitly map validated Runtime outcomes into existing historical dataset contracts only after acquiring genuine independent human diagnostic feedback. No fabricated StateAnchor/experience or diagnostic label should bridge incompatible schemas.
2. Independent labeled operating corpus, review disagreement handling and prospective candidate validation; current single native event cannot determine operating precision/recall.
3. Optional operator-authenticated diagnostic feedback endpoint requires a separate explicit adjudication contract; this task's socket reviews only simulation actions.
4. Any future strategy activation remains an explicit administrative workflow; operating thresholds/policy/approvals/Tool permissions/models/code must not auto change.
5. Same-UID trust/process isolation, physical Linux and load testing remain future work. Windows/AWS not verified or developed.

Final test counts and static-check results are recorded below after execution. Commit/Push are not performed.

## Completion evidence

- Existing experience/feedback/dataset/candidates/review/offline evaluation/comparison/promotion/rollback plus initial projection suite: **291 passed, 0 failed**, 537.67 seconds (`/tmp/soc-live-track-b.log`). This included the initial 13 projection cases; it is not a separate operating improvement experiment.
- Final projection suite after explicitly separating OS-peer review consent from simulation outcome trust: **14 passed, 0 failed**, 11.45 seconds (`/tmp/soc-live-track-b-projection-final.log`). Consent remains HUMAN_FEEDBACK; a successful pure simulation remains VERIFIED_TEST_RESULT and uncertainty remains UNKNOWN. Diagnostic labels stay UNLABELED throughout. The new count overlaps prior projection cases and must not be summed with 291.
- Track A relevant Scenario/evaluation/transport/guard/runtime suite: **479 passed**, separately reported in `live-operator-approval.md`.
- Ruff / format / diff PASS; no existing self-improvement source or test was modified. Task-specific changes are only the new runtime projection, authenticated query connection, projection tests and this audit report.
- No new candidate/strategy/model/policy/threshold was applied. No true operational improvement effect was measured. The overall continuous self-improvement lifecycle remains PARTIAL even though its tested offline components and read-only projection are verified.

The final-code native operator Feedback query also passed against the retained real WSL event and OS-peer-reviewed simulation. It returned three reference items with distinct trust: native read-only observation, OS-peer action consent, pure test simulation result. All diagnostic labels remained UNLABELED; automatic changes were DISABLED. `/tmp/soc-live-native-final-code.json` records this evidence. This validates the query/lineage connection, not an operational self-improvement effect.
