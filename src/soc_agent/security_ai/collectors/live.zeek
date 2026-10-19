# Bounded metadata stdout protocol; no query, answer or payload serialization.
@load ./network14
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
function emit(kind: string, data: string) {
    ++messages;
    if ( messages > 8192 ) Reporter::fatal("SOC_ZEEK_STREAM_MESSAGE_LIMIT");
    print fmt("{\"sequence\":%d,\"kind\":\"%s\",\"data\":%s}", messages, kind, data);
}
event zeek_init() &priority=-20 { emit("ready", "{}"); }
hook Log::log_stream_policy(rec: any, id: Log::ID) {
    if ( id == SOCNetwork14::PACKETS ) emit("packet", to_json(rec));
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
event zeek_done() &priority=-20 { emit("closed", to_json(get_net_stats())); }
