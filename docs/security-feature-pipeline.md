# Phase 3-1: Versioned security feature pipeline

## Semantic boundaries

```text
Evidence / Dataset Row / Streaming Event
    → Source Adapter → SecurityRecord
    → versioned FeatureExtractor → FeatureSchema validation → FeatureSet
    → future SecurityAI → SecurityAIResult → AISignal
```

- **Evidence** is an observed source record in IncidentState. Its raw_data is text,
  not necessarily JSON or a model input.
- **SecurityRecord** is a structured immutable JSON source with record type/schema,
  observation time and source identity. It also supports offline rows and stream
  events that have no incident; Evidence cannot represent those without inventing
  an incident or promoting them into Agent evidence.
- **FeatureSet** is a validated derived model-input snapshot. Rates and other
  transformations are not new observations, predictions, or AISignals.

Extraction never changes IncidentState or creates Evidence/AISignals. No LLM,
Tool, Policy, Approval, response, or SecurityAI inference is called. FeatureSet is
independent of runtime: a future agent-triggered call and a streaming inference
runtime can consume the same feature contract.

## Schemas, ordering, and validation

`FeatureSchema(schema_name, schema_version, features)` retains an ordered tuple of
`FeatureDefinition(name, data_type, nullable, description)`. Empty schemas,
duplicate names, and extra fields are rejected. Every feature is required.
Explicit null is permitted only with `nullable=True`; missing values never silently
become null or zero. There is no imputation, categorical encoding, or normalization.

Feature scalar types are strict Python/JSON int, float, bool, and str. In particular,
`True` is not an int, an int is not a float, and a numeric string is not a number.
NaN/Infinity and nested objects/arrays are invalid feature values. Unknown features
are rejected. Record payloads may contain nested JSON, but concrete extractors must
validate their own supported source schema before computing features.

`feature_names` and `feature_values` follow the schema tuple, independent of source
or dictionary insertion order. `input_payload()` returns a fresh dictionary in
schema order. FeatureSet stores the complete schema for standalone validation,
canonical immutable JSON values, provenance, application UUID and UTC timestamp.
Its JSON representation uses canonical text for payloads, as other project models
do. It round-trips through `FeatureSet.model_validate_json`.

All versions in this package are strict numeric strings of one to three components
(e.g. `1`, `1.0`, `1.0.0`). These are distinct identities, not version ranges. No
implicit version normalization or routing occurs. Trusted application code owns
schema and extractor versions. A feature addition/order/type/meaning change needs
a schema version change; calculation changes need an extractor version change.
There is no registry enforcing historical version immutability in this phase.

## Source provenance

`SourceReference` describes a logical source using `source_type`, `source_name`,
optional `source_version`, and required external `record_id`:

| Type | Example logical identity | Additional binding |
| --- | --- | --- |
| EVIDENCE | auth.log / Evidence UUID | incident + current Evidence |
| DATASET | fixture_network@1 / row-42 | DatasetRecordReference + DatasetSchema |
| STREAM | network_flow_events@1 / event-42 | trusted source adapter assertion |

The SecurityRecord's own UUID identifies the structured snapshot; the external
record/event ID identifies its origin. `observed_at` captures source/event time,
while FeatureSet `created_at` captures extraction time. Both require timezone and
normalize to UTC. No topic, queue offset, socket, consumer group, or connection is
part of these contracts; extra transport fields are rejected.

`DatasetSchema` is minimal metadata: dataset name/version, record schema version,
and optional label_field. It is not a dataset manager. Dataset references must
agree with generic source identity and record schema version. STREAM requires no
dataset metadata or incident. Incident-associated stream records are allowed when
a matching state is provided. A single extraction may use multiple distinct
records, but mixed incident bindings (including incident-bound plus unbound
records) are rejected rather than guessing how to assign an incident.

Each `FeatureSourceReference` retains logical source identity, internal record UUID,
record type/schema, source, observation time, optional Evidence/dataset references,
and a SHA-256 digest of the canonical source fields. FeatureSet does not retain raw
source fields or label values. Duplicate record IDs, Evidence IDs, or logical
source identities within an extraction are rejected.

`record_from_evidence` resolves an Evidence ID from validated current state, parses
raw_data as a JSON object, and creates a detached record. The extraction factory
revalidates records/state and checks incident, Evidence existence, canonical raw
content, source name, and observation time. Altered fields behind a valid Evidence
ID therefore fail. This is stronger than merely asserting related Evidence IDs.

Offline/stream source identity is supplied by trusted application adapters; no
external store, event authentication, or dataset catalog is consulted. Digests
permit later content comparison, not proof of authenticity or anonymization.

## Extractor and result API

`FeatureExtractor` is a synchronous structural Protocol:
`extract(record, *, state=None) -> FeatureSet`. FeatureSet already owns validated
values and FeatureExtractionProvenance, so an additional FeatureExtractionResult
wrapper would duplicate the same information and is intentionally omitted.

`create_feature_set` is the reusable factory for trusted extractors. It validates
schema, values, provenance, and Evidence binding; it cannot prove that arbitrary
caller-supplied values were calculated correctly. Concrete versioned extractor
implementations and their tests own that guarantee. Direct model construction
validates shape, not origin authenticity; Pydantic validation-bypass APIs are not
safe ingestion paths. The factory revalidates serialized input snapshots.

`AuthenticationSummaryExtractor` is a small fixture implementation, not an
operational detection model. It accepts record_type `authentication_summary` and
record_schema_version `1.0.0`, with strict nonnegative integer counts:

```text
failed_login_count, successful_login_count, unique_accounts
window_seconds: positive integer
```

Output schema `auth_features@1.0.0`, extractor `auth_summary@1.0.0`:

```text
failed_login_count
unique_accounts
failure_rate = failed / (failed + successful)
login_velocity = (failed + successful) / window_seconds
```

Zero total attempts are rejected because failure_rate is undefined. A zero/negative
window, numeric overflow, missing/extra fields, and invalid types fail. Rates use
Python float division without implicit rounding. Declared dataset labels are removed
before source schema validation. Undeclared extra label fields fail validation.

```python
from soc_agent.security_ai.features import AuthenticationSummaryExtractor, record_from_evidence

record = record_from_evidence(
    state=state,
    evidence_id=evidence_id,
    record_type="authentication_summary",
    record_schema_version="1.0.0",
)
features = AuthenticationSummaryExtractor().extract(record, state=state)
model_input = features.input_payload()  # No inference is invoked.
fingerprint = features.input_fingerprint
```

Public extraction errors use generic messages without raw record values.
FeatureProvenanceError is a FeatureExtractionError subclass. Direct contract
violations use Pydantic ValidationError with input values hidden in rendered errors.
This is not a general-purpose traceback/log redaction system: do not expose
exception internals or serialize ValidationError.errors() indiscriminately.

## Fingerprint versus source identity

`input_fingerprint` is computed using SHA-256 of the existing canonical JSON utility
applied to schema name/version, extractor name/version, ordered feature names and
values. It is a computed property, not a caller-supplied or serialized field; it is
recomputed after deserialization. FeatureSet IDs, timestamps, source IDs, transport,
raw fields, and labels are excluded.

Same values/contracts from two Evidence records or two source kinds have the same
input fingerprint but different provenance. Order, feature value, schema identity,
or extractor identity/version changes alter the fingerprint. Source content changes
are separately detectable through content_digest. Fingerprints do not prove semantic
equality between differently versioned schemas, model compatibility, or authenticity.

## Label leakage

Labels are targets for future training, not inference features. A FeatureSet rejects
feature names matching a source dataset's declared label_field, and the fixture
extractor explicitly excludes that field before validating inputs. TargetLabel and
training-example abstractions are deferred. This cannot detect labels disguised as
other fields or a malicious extractor computing label-derived values. Adapter/schema
review and future evaluation remain necessary. Never treat the name check as a
complete statistical leakage detector.

## Future offline and runtime paths

```text
Offline:
CIC-IDS2017 → Dataset Adapter → FeatureExtractor → FeatureSet → SecurityAI

Runtime:
eBPF / Logs / Network Telemetry → Security Data Bus → Source Adapter
    → FeatureExtractor → FeatureSet → Lightweight SecurityAI → AISignal → SOC Agent
```

Adapters own CSV parsing, transport metadata and ingestion. Extractors own only local
validated transformations. Kernel/eBPF collection may filter or aggregate telemetry;
ML inference is planned for a userspace SecurityAI runtime. Neither kernel inference
nor a streaming runtime is implemented here. On-demand Agent inference and future
bus-triggered inference can share contracts; incident assignment for unsolicited
stream signals remains a future runtime responsibility.

Phase 3-2 can define a dataset-specific record adapter and ordered feature schema
once the actual network dataset is inspected. A classifier must check its expected
schema/extractor versions and consume `feature_values` in schema order. Phase 3-6
will bind feature_set_id/input_fingerprint to actual SecurityAI execution/result
provenance. Existing SecurityAIResult/AISignal APIs remain unchanged in this phase.

No CSV I/O, data bus, eBPF sensor, async consumer, ML dependency, training, splitting,
evaluation, persistence, model adapter, fusion, or self-improvement is implemented.
Tests use only fixture data and verify Evidence/dataset/stream contracts, no external
execution, determinism, source binding, numeric rejection, and label separation.
