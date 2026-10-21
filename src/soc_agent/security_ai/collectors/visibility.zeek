# Aggregate existing analyzer callbacks only; no payload, domain or endpoint output.
module SOCVisibility;
export {
    type Counters: record {
        contract: string;
        candidate_udp: count; candidate_tcp: count;
        header_validated: count; header_invalid: count;
        analyzer_dispatch: count; query_parsed: count; response_parsed: count;
        transaction_matched: count; event_emitted: count; parse_failed: count;
        response_missing_metadata: count; transaction_ambiguous: count &optional;
        question_matched: count &optional;
        question_mismatched: count &optional;
        duplicate_queries: count &optional;
        multiple_responses: count &optional;
        response_without_query: count &optional;
        diagnostic_truncated: bool;
    };
    global counts: Counters = [$contract="soc-zeek-dns-stages:v1",
        $candidate_udp=0, $candidate_tcp=0, $header_validated=0, $header_invalid=0,
        $analyzer_dispatch=0, $query_parsed=0, $response_parsed=0,
        $transaction_matched=0, $event_emitted=0, $parse_failed=0,
        $response_missing_metadata=0, $transaction_ambiguous=0, $duplicate_queries=0,
        $multiple_responses=0, $response_without_query=0, $question_matched=0,
        $question_mismatched=0, $diagnostic_truncated=F];
    global snapshot: function(): string;
}
# Bounded in-memory question identity only. No names/hashes/endpoints are output.
# This detects pending-ID ambiguity; Zeek remains the transaction matcher.
type Pending: record { fingerprint: string; waiting: bool; responses: count; };
global questions: table[string] of Pending;
global raw_records: count = 0;
global observations: count = 0;
function tick(): bool {
    if ( observations >= 65536 ) {
        counts$diagnostic_truncated=T;
        return F;
    }
    ++observations;
    return T;
}
function snapshot(): string { return to_json(counts); }
event raw_packet(p: raw_pkt_hdr) &priority=100 {
    if ( raw_records >= 4096 ) { counts$diagnostic_truncated=T; return; }
    ++raw_records;
    if ( p?$udp && (p$udp$sport == 53/udp || p$udp$dport == 53/udp) )
        ++counts$candidate_udp;
    if ( p?$tcp && (p$tcp$sport == 53/tcp || p$tcp$dport == 53/tcp) )
        ++counts$candidate_tcp;
}
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
    if ( ! tick() ) return;
    ++counts$analyzer_dispatch;
    ++counts$header_validated;
    if ( msg$QR ) {
        ++counts$response_parsed;
        local key = fmt("%s:%d", c$uid, msg$id);
        if ( key in questions ) {
            if ( questions[key]$responses > 0 ) ++counts$multiple_responses;
            ++questions[key]$responses;
            questions[key]$waiting=F;
        }
        else ++counts$response_without_query;
    }
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    if ( ! tick() ) return;
    ++counts$query_parsed;
    local key = fmt("%s:%d", c$uid, msg$id);
    local identity = sha256_hash(fmt("%s|%d|%d", to_lower(query), qtype, qclass));
    if ( key in questions && questions[key]$waiting ) {
        if ( questions[key]$fingerprint == identity ) ++counts$duplicate_queries;
        else ++counts$transaction_ambiguous;
    }
    else {
        if ( key !in questions && |questions| >= 4096 ) {
            counts$diagnostic_truncated=T;
            return;
        }
        questions[key]=[$fingerprint=identity, $waiting=T, $responses=0];
    }
}
function check_question(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( ! tick() ) return;
    local key = fmt("%s:%d", c$uid, msg$id);
    local identity = sha256_hash(fmt("%s|%d|%d", to_lower(query), qtype, qclass));
    if ( key in questions && questions[key]$fingerprint == identity )
        ++counts$question_matched;
    else {
        ++counts$question_mismatched;
        ++counts$transaction_ambiguous;
    }
}
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    check_question(c, msg, query, qtype, qclass);
}
event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    check_question(c, msg, query, qtype, qclass);
}
event conn_weird(name: string, c: connection, addl: string, source: string) {
    if ( name == "DNS_truncated_len_lt_hdr_len" ) {
        if ( tick() ) ++counts$header_invalid;
    }
    else if ( /^DNS_/ in name ) {
        if ( tick() ) ++counts$parse_failed;
    }
}
hook Log::log_stream_policy(rec: any, id: Log::ID) &priority=100 {
    if ( id == DNS::LOG && tick() ) {
        local d = rec as DNS::Info;
        ++counts$event_emitted;
        if ( d?$rtt ) ++counts$transaction_matched;
        else if ( ! d?$rcode ) ++counts$response_missing_metadata;
    }
}
