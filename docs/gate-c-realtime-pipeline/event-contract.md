# Common event contract

`soc-common-event:v1` is additive; it does not redefine Fusion v1, Event ingestion v1,
External Context v2, existing Selection Digests or Decision payload/ID.

| Field | Contract |
|---|---|
| event_id | UUID5 of canonical source identity; source record ID is also retained |
| platform / collector_id | windows, linux or explicitly validated_fixture; bounded collector label |
| event_type | os_record or validated_model_input; inference never masquerades as OS observation |
| event_timestamp | timezone-aware UTC normalization; no timestamp replacement |
| ingestion_timestamp | first committed receipt time retained across duplicates |
| source | namespace + generation/device + original record/cursor; all required |
| metadata | channel, provider, code and original timestamp text |
| normalized_fields | bounded immutable key/value pairs, no duplicate names |
| schema_version / provenance / validation_status | explicit version; native_read_only or explicit_precomputed_fixture; source-record validation only |
| soc_event | optional existing typed Event with original ID/time unchanged |
| feature_payload | optional existing FeatureRow / SourceFeatureObservation, original ID binding, no assigned incident |

Windows original TimeCreated is kept as ISO text including 100 ns digits; Python datetime
has microsecond precision, so the raw source timestamp must not be discarded. Journal
microseconds/cursor/machine are retained. Message, EventData, command line and credentials
are not serialized by the collectors. Observation identifiers are not attack findings.

Source digest covers all semantic fields except ingestion_timestamp. Same source identity
with changed content is rejected; changed source identity is a distinct event. First receipt
is not overwritten by a duplicate. Event payload is capped at 256 KiB. Strict extra-field
rejection and serialization revalidation apply at queue and worker boundaries.

For model inputs, official ordered feature identity must match the reviewed binding and
all named finite numeric features must exist. No filling, label mapping or schema coercion.
Existing official loaders verify package/code/artifact identities; their limits are unchanged.
The original SOC event ID stays in official Envelope provenance; the common event ID and
source identity stay in separately retained source Evidence. Advisory context is not observed fact.
