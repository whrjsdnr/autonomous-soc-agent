# Analyst Feedback — Phase 6-3

Evaluation records facts; Analyst Feedback records human judgment.

Analyst Feedback is not execution or governance authority.
Past feedback does not authorize future action.
Human-labeled ground truth may contain disagreement or error.
No consensus or correctness is inferred automatically.

## Architecture and scope

`Experience → Evaluation → authenticated analyst → FeedbackRequest → confirmation → AnalystFeedback`

`AnalystFeedbackService.submit` reads and validates the immutable Experience,
Evaluation and necessary original source records, authenticates through the existing
`AuthenticationProvider`, checks incident-scoped RBAC, and consumes a request-specific
confirmation. Confirmation consumption, feedback insert and submission audit share
one SQLite write transaction. There are no calls to execution, reconciliation,
review issuance, Policy mutation or Incident mutation services.

The only supported scope is `overall`: the analyst judges the referenced evaluation
and incident handling as a whole. Labels do not identify a component or fabricate
an artifact annotation. There is no new HTTP endpoint, provider, authority token,
learning process or background worker. Core service and read queries are sufficient.

## Verdicts and diagnostic labels

Verdicts are `correct`, `incorrect`, and `inconclusive`. The latter means the analyst
cannot decide from available information; it is not an execution outcome.

Diagnostic labels are explicit human judgments:

- `false_positive`: the system treated something as a threat or responded, but the analyst judges it was not a real threat.
- `false_negative`: the analyst judges a real threat was missed or necessary judgment/response was omitted.
- `unnecessary_investigation`: the analyst judges an investigation step or path was unnecessary.
- `missed_investigation`: the analyst judges necessary investigation was omitted.

All four labels assert a definite defect in the overall scope, so they require
`incorrect`. `correct` and `inconclusive` cannot carry these labels. False positive
and false negative together are rejected in the same scope. False positive plus
unnecessary investigation is valid. Duplicate or non-canonical label order is
rejected; clients supply labels sorted by their string values.

Evaluation does not calculate these labels. Neither Policy DENY, human rejection,
execution failure nor uncertainty automatically assigns a verdict.

## Trusted identity and confirmation

`SUBMIT_ANALYST_FEEDBACK` is a separate permission and confirmation purpose in the
existing identity boundary. Trusted incident-scoped ANALYST and ADMIN roles receive
this permission; RESPONDER and APPROVER alone do not. ADMIN still has no Policy bypass.
Caller fields such as analyst, role, approved or trusted are not accepted.

Production composition must explicitly supply a trusted provider and permission
verifier. Tests use the existing test-only provider. There is no production IdP.
`HumanActionContext.decision_id` may be null only for this feedback purpose, because
historical records can exist before a Decision. Existing governance purposes still
require a Decision reference. No existing serialized context fields are added.

Confirmation binds subject, provider, session, feedback purpose, exact request digest
and expiry. The request digest includes submission ID, incident, Experience and
Evaluation IDs/digests, scope, verdict, labels and note. No other purpose can authorize
feedback. No feedback confirmation can authorize a Tool or State change.

## Immutability, retries and disagreement

Each request has a caller-retained `submission_id`. Immutable feedback identity
binds the complete request and authenticated provider/subject/session. Creation time
is not an identity input. SQL uniqueness on provider/subject/submission ID rejects
changed payload or session for an existing submission.

A retry first reauthenticates and reauthorizes, validates the sources, then returns
an exactly matching committed record. This is a read of an existing submission, not
another use of the confirmation. The same session is required. Changed/new requests
require fresh confirmation. A new judgment uses a new submission ID and confirmation.

Independent processes serialize writes with SQLite BEGIN IMMEDIATE; competing
identical submissions return one canonical record. Lost commit response raises the
existing uncertain-commit error. Reopen/query or an authenticated exact retry can
resolve what was committed. There is no automatic retry. A rollback may still leave
a confirmation consumed by an external provider: obtain fresh human confirmation
rather than assuming it is reusable.

Different analysts' opposing verdicts remain independent records. There is no
majority vote, overwrite, deletion, correctness inference or analyst ranking.

## Persistence, provenance and queries

Apply existing migrations through v6, then explicitly call `migrate_feedback` for
v6 → v7. It adds `analyst_feedback`, `feedback_audit` and query indexes, preserving
Experience, Evaluation, confirmation, governance and execution data. DDL and version
update are atomic; errors roll back. Unsupported future schemas are rejected.

Feedback carries source IDs/digests and the existing non-secret verification receipt:
subject, provider, session, authorized permission, exact context, confirmation
reference and times. The audit binds feedback digest and creation time. Queries
validate source binding, indexed fields, consumed receipt and audit digest.
Submission additionally validates original historical sources using the existing
Evaluation source validator. Source retention is required; missing or superseded
unrecoverable references fail closed.

Queries: `get`, `list_for_evaluation`, `list_for_experience`, `list_for_incident`.
These are trusted application reads, not authentication or action authorization APIs.
Feedback records never become Evidence for another Incident.

## Privacy and limitations

Only references, human labels, non-secret provenance and an optional 1,000-character
plain-text note are stored. No credentials, raw events, Evidence payloads, prompts or
hidden reasoning are copied. Common credential-assignment, bearer-token and private
key markers in notes are rejected. This is not a general secret detector: analysts
must not enter sensitive information or encoded secrets. Notes remain untrusted
annotations and are never executed or automatically inserted into prompts.

SQLite provides same-host local-filesystem transaction isolation, not distributed
coordination or tamper-proof audit. A database writer can alter data and recompute
digests; digests detect inconsistency, not establish cryptographic human authenticity.
Historical approvals confer no future authority. Authentication provider correctness,
source retention and operational access controls remain deployment responsibilities.

Phase 6-4 may consume analyst judgments alongside objective facts. This phase adds
no recommendations, learning, prompt/rule/model changes or quality/accuracy metrics.

## Validation

Focused tests cover verdict/label semantics, authentication/authorization, exact
source and confirmation bindings, replay, idempotency, disagreement, restart,
independent-process race, atomic commit/response loss, corruption, migration and
unchanged authoritative records.

Validation results:

- Focused feedback tests: 44 passed, exit 0.
- Related regression: 540 passed, exit 0.
- Full pytest (one execution): 2,015 passed, exit 0, in 507.40 seconds.

The baseline was 1,971 tests. No existing test assertions were weakened.
