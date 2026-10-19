"""A missing feature cannot be invented from a connection summary."""

NETWORK14 = (
    (
        "duration_seconds",
        "SEMANTIC_MISMATCH",
        "Zeek connection lifetime differs from 30s/120s packet windows",
    ),
    (
        "forward_packet_count",
        "SEMANTIC_MISMATCH",
        "orig_pkts; Zeek originator is not proven first-seen direction",
    ),
    ("backward_packet_count", "SEMANTIC_MISMATCH", "resp_pkts; window/direction parity unverified"),
    ("forward_ip_bytes", "SEMANTIC_MISMATCH", "orig_ip_bytes; direction/window parity unverified"),
    ("backward_ip_bytes", "SEMANTIC_MISMATCH", "resp_ip_bytes; direction/window parity unverified"),
    ("ip_length_min", "MISSING", "Packet IP lengths absent"),
    ("ip_length_max", "MISSING", "Packet IP lengths absent"),
    (
        "ip_length_mean",
        "DERIVED",
        "IP byte totals / packet count; only if complete same-window counts",
    ),
    ("ip_length_population_std", "MISSING", "Second moment absent"),
    ("tcp_syn_packet_count", "MISSING", "history does not enumerate every SYN packet"),
    ("tcp_fin_packet_count", "MISSING", "history does not enumerate every FIN packet"),
    ("tcp_rst_packet_count", "MISSING", "history does not enumerate every RST packet"),
    (
        "iat_mean_seconds",
        "DERIVED",
        "duration/(packets-1), conditional on identical complete packet window",
    ),
    ("iat_max_seconds", "MISSING", "Per-packet arrival times absent"),
)
DNS9 = (
    "FQDN_count",
    "subdomain_length",
    "numeric",
    "entropy",
    "special",
    "labels",
    "labels_max",
    "labels_average",
    "len",
)


def report() -> dict:
    return dict(
        network14="BLOCKED",
        dns9="BLOCKED",
        quality="BLOCKED",
        edge="BLOCKED",
        feature_producer="ZEEK_CONN_SUMMARY_NOT_NETWORK14_PRODUCER_1_1_0",
        network_mapping=[dict(name=n, classification=c, reason=r) for n, c, r in NETWORK14],
        dns_mapping=[
            dict(
                name=n,
                classification="MISSING",
                reason="FQDN excluded; DNS9 training producer parity unverified",
            )
            for n in DNS9
        ],
        producer_version="1.1.0",
        dtype="float32",
        feature_digest=None,
        investigation="BLOCKED_NO_VERIFIED_AI_RECEIPT",
    )


def require_inference() -> None:
    raise ValueError("ZEEK_NETWORK14_PARITY_BLOCKED_NO_MODEL_INVOCATION")
