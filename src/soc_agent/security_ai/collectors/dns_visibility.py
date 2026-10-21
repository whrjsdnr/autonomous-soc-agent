"""Allowlisted stage counters; absence of an event is not proof of parser failure."""

from pydantic import Field, model_validator

from soc_agent.security_ai.research.models import Frozen


class DNSStages(Frozen):
    contract: str = Field(pattern=r"^soc-zeek-dns-stages:v1$")
    candidate_udp: int = Field(ge=0, le=4096, strict=True)
    candidate_tcp: int = Field(ge=0, le=4096, strict=True)
    header_validated: int = Field(ge=0, le=65536, strict=True)
    header_invalid: int = Field(ge=0, le=65536, strict=True)
    analyzer_dispatch: int = Field(ge=0, le=65536, strict=True)
    query_parsed: int = Field(ge=0, le=65536, strict=True)
    response_parsed: int = Field(ge=0, le=65536, strict=True)
    transaction_matched: int = Field(ge=0, le=8192, strict=True)
    event_emitted: int = Field(ge=0, le=8192, strict=True)
    parse_failed: int = Field(ge=0, le=65536, strict=True)
    response_missing_metadata: int = Field(ge=0, le=8192, strict=True)
    transaction_ambiguous: int | None = Field(default=None, ge=0, le=65536, strict=True)
    non_dns_confirmed: int | None = Field(default=None, ge=0, le=4096, strict=True)
    analyzer_attached: bool | None = Field(default=None, strict=True)
    question_matched: int | None = Field(default=None, ge=0, le=65536, strict=True)
    question_mismatched: int | None = Field(default=None, ge=0, le=65536, strict=True)
    duplicate_queries: int | None = Field(default=None, ge=0, le=65536, strict=True)
    multiple_responses: int | None = Field(default=None, ge=0, le=65536, strict=True)
    response_without_query: int | None = Field(default=None, ge=0, le=65536, strict=True)
    transport_checksum_rejected: int | None = Field(default=None, ge=0, le=65536, strict=True)
    diagnostic_truncated: bool = Field(strict=True)

    @model_validator(mode="after")
    def consistent(self):
        if (
            self.header_validated != self.analyzer_dispatch
            or self.transaction_matched > self.event_emitted
            or self.response_missing_metadata > self.event_emitted
            or self.response_parsed > self.header_validated
        ):
            raise ValueError("ZEEK_DNS_STAGE_ACCOUNTING_MISMATCH")
        return self


def closed_data(data: dict) -> tuple[dict, DNSStages | None]:
    value = dict(data)
    # Omitted legacy field means NOT_OBSERVED, never an all-zero counter record.
    diagnostics = value.pop("dns_diagnostics", None)
    return value, DNSStages.model_validate(diagnostics) if diagnostics is not None else None


def diagnose(
    stages: DNSStages | None,
    *,
    candidates: int | None,
    accepted: int,
    rejected: int,
    missing_response: int = 0,
    capture_gap: bool = False,
    encrypted_only: bool = False,
) -> dict:
    classification = "DNS_VISIBILITY_UNKNOWN"
    if rejected:
        classification = "DNS_ADAPTER_REJECTED"
    elif stages is not None and not stages.diagnostic_truncated:
        if stages.non_dns_confirmed:
            classification = "PORT53_NON_DNS"
        elif stages.header_invalid:
            classification = "DNS_HEADER_INVALID"
        elif stages.transport_checksum_rejected:
            classification = "DNS_TRANSPORT_CHECKSUM_REJECTED"
        elif stages.parse_failed:
            classification = "DNS_PARSE_FAILED"
        elif stages.transaction_ambiguous or stages.multiple_responses:
            classification = "DNS_TRANSACTION_AMBIGUOUS"
        elif stages.analyzer_attached is False and candidates:
            classification = "DNS_ANALYZER_NOT_ATTACHED"
        elif stages.response_missing_metadata or stages.response_without_query or missing_response:
            classification = "DNS_RESPONSE_MISSING"
        elif stages.query_parsed and not stages.event_emitted:
            classification = "DNS_EVENT_NOT_EMITTED"
        elif candidates == 0 and not stages.header_validated and not stages.event_emitted:
            classification = "NO_DNS_TRAFFIC_OBSERVED"
        elif accepted and stages.event_emitted:
            classification = "DNS_METADATA_OBSERVED"
    visibility = (
        "CAPTURE_GAP"
        if capture_gap
        else "PARSE_FAILURE"
        if classification
        in {
            "DNS_PARSE_FAILED",
            "DNS_HEADER_INVALID",
            "DNS_ADAPTER_REJECTED",
            "DNS_TRANSPORT_CHECKSUM_REJECTED",
        }
        else "DNS_TRANSACTION_INCOMPLETE"
        if classification in {"DNS_RESPONSE_MISSING", "DNS_TRANSACTION_AMBIGUOUS"}
        else "DNS_VISIBLE"
        if classification == "DNS_METADATA_OBSERVED"
        else "NO_DNS_OBSERVED"
        if classification == "NO_DNS_TRAFFIC_OBSERVED"
        else "ENCRYPTED_DNS_UNOBSERVABLE"
        if encrypted_only and not accepted
        else "DNS_VISIBILITY_UNKNOWN"
    )
    return dict(
        visibility=visibility,
        classification=classification,
        scope="OBSERVED_PLAINTEXT_DNS_WINDOW_NOT_NETWORK_WIDE",
        encrypted_dns="DOH_DOT_PLAINTEXT_QUERY_NOT_VISIBLE",
        candidate_packets=candidates,
        stage_counters=stages.model_dump(mode="json") if stages else None,
        analyzer_status="DISPATCH_OBSERVED"
        if stages and stages.analyzer_dispatch
        else "ERROR_CALLBACK_OBSERVED"
        if stages and (stages.header_invalid or stages.parse_failed)
        else "UNKNOWN",
        analyzer_dispatch_scope="DNS_MESSAGE_CALLBACK_NOT_ALL_DISPATCH_ATTEMPTS",
        checksum_scope="PORT53_TRANSPORT_WEIRD_CALLBACK_NOT_PROOF_OF_DNS_CONTENT_OR_OFFLOAD",
        adapter_accepted=accepted,
        adapter_rejected=rejected,
        adapter_rejection_reason="ZEEK_RECORD_SCHEMA_REJECTED" if rejected else None,
        dns9_features_generated=0,
        dns9="BLOCKED",
        header_scope="ZEEK_HEADER_EVENT_NOT_FULL_MESSAGE_VALIDATION",
        matching_scope="ZEEK_TRANSACTION_METADATA_PLUS_IN_MEMORY_QUESTION_FINGERPRINT_CALLBACKS"
        if stages and stages.question_matched is not None
        else "EXISTING_ZEEK_TRANSACTION_METADATA",
        qname_plaintext_retained=False,
        qname_comparison="OBSERVED_CALLBACK_MATCH"
        if stages and stages.question_matched
        else "NOT_OBSERVED",
        payload_retained=False,
        fqdn_retained=False,
    )
