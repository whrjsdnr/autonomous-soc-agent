# Bounded metadata stdout protocol; no query, answer or payload serialization.
@load ./network14
@load ./visibility
redef SOCNetwork14::graceful_limit = T;
module SOCLive;
export {
    type Endpoint: record {
        orig_h: addr; orig_p: count; resp_h: addr; resp_p: count;
    };
    type Summary: record {
        ts: time; uid: string; id: Endpoint; proto: transport_proto;
        duration: double &optional;
        orig_pkts: count &optional; resp_pkts: count &optional;
        orig_ip_bytes: count &optional; resp_ip_bytes: count &optional;
        missed_bytes: count &optional; conn_state: string &optional;
        trans_id: count &optional; qtype: count &optional; rcode: count &optional;
        rtt: double &optional; TTLs: vector of double &optional; TC: bool &optional;
    };
}
global messages: count = 0;
global output_bytes: count = 0;
global packets: count = 0;
global supported_packets: count = 0;
global unsupported_packets: count = 0;
global networks: count = 0;
global dns_events: count = 0;
global omitted_events: count = 0;
global stop_reason = "ZEEK_DONE";
global closed = F;
function request_stop(reason: string) {
    if ( stop_reason == "ZEEK_DONE" ) stop_reason = reason;
    terminate();
}
function emit(kind: string, data: string) {
    if ( closed ) Reporter::fatal("SOC_ZEEK_POST_CLOSED_EVENT");
    # Reserve COUNTER + CLOSED envelopes, each bounded to 2 KiB.
    local line = fmt("{\"sequence\":%d,\"kind\":\"%s\",\"data\":%s}", messages+1, kind, data);
    if ( messages >= 8190 ) {
        ++omitted_events;
        request_stop("EVENT_LIMIT_REACHED");
        return;
    }
    if ( output_bytes + |line| + 1 > 8388608 - 4096 ) {
        ++omitted_events;
        request_stop("OUTPUT_LIMIT_REACHED");
        return;
    }
    ++messages;
    output_bytes += |line| + 1;
    if ( kind == "packet" || kind == "unsupported" ) ++packets;
    if ( kind == "packet" ) ++supported_packets;
    if ( kind == "unsupported" ) ++unsupported_packets;
    if ( kind == "network" ) ++networks;
    if ( kind == "dns" ) ++dns_events;
    print line;
    if ( messages == 8190 ) request_stop("EVENT_LIMIT_REACHED");
}
event SOCNetwork14::packet_limit_reached() { request_stop("PACKET_LIMIT_REACHED"); }
event zeek_init() &priority=100 { print open("/dev/stderr"), "SOC_ZEEK_INIT"; flush_all(); }
event zeek_init() &priority=-20 { emit("ready", "{}"); flush_all(); }
hook Log::log_stream_policy(rec: any, id: Log::ID) {
    if ( id == SOCNetwork14::PACKETS ) {
        local p = rec as SOCNetwork14::Info;
        local unsupported = p$kind == "UNSUPPORTED" || p$frame_length > 65535 ||
            p$captured_length != p$frame_length;
        if ( p?$ip_length && (p$ip_length > 65535 || p$ip_length + 14 > p$frame_length) )
            unsupported = T;
        emit(unsupported ? "unsupported" : "packet", to_json(p));
    }
    if ( id == Conn::LOG ) {
        local c = rec as Conn::Info;
        local n: Summary = [$ts=c$ts, $uid=c$uid, $id=[$orig_h=c$id$orig_h, $orig_p=port_to_count(c$id$orig_p),
            $resp_h=c$id$resp_h, $resp_p=port_to_count(c$id$resp_p)], $proto=c$proto];
        if ( c?$duration ) n$duration=interval_to_double(c$duration);
        if ( c?$orig_pkts ) n$orig_pkts=c$orig_pkts;
        if ( c?$resp_pkts ) n$resp_pkts=c$resp_pkts;
        if ( c?$orig_ip_bytes ) n$orig_ip_bytes=c$orig_ip_bytes;
        if ( c?$resp_ip_bytes ) n$resp_ip_bytes=c$resp_ip_bytes;
        if ( c?$missed_bytes ) n$missed_bytes=c$missed_bytes;
        if ( c?$conn_state ) n$conn_state=c$conn_state;
        emit("network", to_json(n));
    }
    if ( id == DNS::LOG ) {
        local d = rec as DNS::Info;
        local dns: Summary = [$ts=d$ts, $uid=d$uid, $id=[$orig_h=d$id$orig_h, $orig_p=port_to_count(d$id$orig_p),
            $resp_h=d$id$resp_h, $resp_p=port_to_count(d$id$resp_p)], $proto=d$proto];
        if ( d?$trans_id ) dns$trans_id=d$trans_id;
        if ( d?$qtype ) dns$qtype=d$qtype;
        if ( d?$rcode ) dns$rcode=d$rcode;
        if ( d?$rtt ) dns$rtt=interval_to_double(d$rtt);
        if ( d?$TTLs ) {
            local ttls: vector of double = vector();
            for ( i in d$TTLs ) ttls[|ttls|]=interval_to_double(d$TTLs[i]);
            dns$TTLs=ttls;
        }
        if ( d?$TC ) dns$TC=d$TC;
        emit("dns", to_json(dns));
    }
    # Prevent ALL default log files, including raw DNS names and file extraction logs.
    break;
}
event zeek_done() &priority=-100 {
    # This hook is the only CLOSED producer. Fatal/kill paths produce no certificate.
    local stats = get_net_stats();
    local counter = fmt("{\"packet_records\":%d,\"supported_packet_records\":%d,\"unsupported_packet_records\":%d,\"network_events\":%d,\"dns_events\":%d,\"pkts_recvd\":%d,\"pkts_dropped\":%d,\"pkts_link\":%d,\"bytes_recvd\":%d}",
        packets, supported_packets, unsupported_packets, networks, dns_events,
        stats$pkts_recvd, stats$pkts_dropped, stats$pkts_link, stats$bytes_recvd);
    local counter_line = fmt("{\"sequence\":%d,\"kind\":\"counter\",\"data\":%s}", messages+1, counter);
    if ( |counter_line| + 1 > 2048 ) Reporter::fatal("SOC_ZEEK_COUNTER_BOUND");
    ++messages;
    output_bytes += |counter_line| + 1;
    print counter_line;
    local data = fmt("{\"stop_reason\":\"%s\",\"packet_records\":%d,\"network_events\":%d,\"dns_events\":%d,\"messages_before_closed\":%d,\"bytes_before_closed\":%d,\"omitted_packet_records\":%d,\"omitted_events\":%d,\"pkts_recvd\":%d,\"pkts_dropped\":%d,\"pkts_link\":%d,\"bytes_recvd\":%d}",
        stop_reason, packets, networks, dns_events, messages, output_bytes,
        SOCNetwork14::omitted_packet_records, omitted_events,
        stats$pkts_recvd, stats$pkts_dropped, stats$pkts_link, stats$bytes_recvd);
    data = sub_bytes(data, 0, |data|-1) + fmt(",\"supported_packet_records\":%d,\"unsupported_packet_records\":%d}", supported_packets, unsupported_packets);
    data = sub_bytes(data, 0, |data|-1) + ",\"dns_diagnostics\":" + SOCVisibility::snapshot() + "}";
    local line = fmt("{\"sequence\":%d,\"kind\":\"closed\",\"data\":%s}", messages+1, data);
    if ( |line| + 1 > 2048 ) Reporter::fatal("SOC_ZEEK_CLOSED_BOUND");
    closed = T;
    print line;
    flush_all();
}
