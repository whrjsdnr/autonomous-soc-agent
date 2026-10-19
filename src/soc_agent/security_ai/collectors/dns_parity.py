"""DNS header observations cannot substitute for the upstream DNS9 lexical producer."""

from soc_agent.security_ai.collectors.parity import DNS9
from soc_agent.security_ai.research.dns import catalogue

AMBIGUITIES = (
    "FQDN_count unit/aggregation not defined; cannot equate it with query count or name length",
    "Subdomain boundary/public suffix/normalization undefined",
    "Count versus ratio, ASCII population and case handling undefined",
    "Population, case, separators and entropy normalization undefined",
    "Special-character population and count/ratio undefined",
    "Label/root-dot/empty-label policy undefined",
    "Label length units and root/prefix handling undefined",
    "Mean denominator and root-label handling undefined",
    "Wire length versus bytes versus textual characters undefined",
)


def report() -> dict:
    contract = catalogue()
    if tuple(contract["feature_names"]) != DNS9:
        raise ValueError("ZEEK_DNS9_CONTRACT_ORDER_MISMATCH")
    return dict(
        status="BLOCKED",
        feature_values=None,
        feature_contract_digest=contract["model"]["feature_contract_digest"]
        if "feature_contract_digest" in contract["model"]
        else "3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0",
        preprocessing="float32 -> named fitted StandardScaler -> round/clip/int8; unchanged",
        raw_names_retained=False,
        feature_mapping=[
            dict(
                position=i,
                name=n,
                classification="MISSING",
                query_api_candidate="SEMANTIC_MISMATCH",
                reason=reason,
                unit="UNVERIFIED_UPSTREAM_EXTRACTION_UNAVAILABLE",
            )
            for i, (n, reason) in enumerate(zip(DNS9, AMBIGUITIES, strict=True))
        ],
        diagnostic_fields={
            "query_type": "DIRECT",
            "response_code": "DIRECT",
            "TTL": "DIRECT",
            "response_latency": "DIRECT",
        },
        training_producer="UNVERIFIED",
        native_dns9_inference="BLOCKED",
    )
