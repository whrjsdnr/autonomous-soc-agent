# Offline-only bounded metadata. No packet payload, names, or answers are logged.
module SOCNetwork14;
export {
    redef enum Log::ID += { PACKETS };
    type Info: record {
        sequence: count &log;
        seconds: count &log;
        microseconds: count &log;
        frame_length: count &log;
        captured_length: count &log;
        kind: string &log;
        source: addr &log &optional;
        destination: addr &log &optional;
        source_port: count &log &optional;
        destination_port: count &log &optional;
        ip_length: count &log &optional;
        tcp_flags: count &log &optional;
    };
}
global sequence: count = 0;
event zeek_init() {
    Log::create_stream(PACKETS, [$columns=Info, $path="network14_packets"]);
}
event raw_packet(p: raw_pkt_hdr) {
    ++sequence;
    if ( sequence > 4096 )
        Reporter::fatal("SOC_ZEEK_PACKET_LIMIT");
    local current = get_current_packet();
    local r: Info = [$sequence=sequence, $seconds=current$ts_sec,
        $microseconds=current$ts_usec, $frame_length=current$len,
        $captured_length=current$caplen, $kind="UNSUPPORTED"];
    if ( p?$ip && ! p$ip$MF && p$ip$offset == 0 ) {
        r$source=p$ip$src; r$destination=p$ip$dst; r$ip_length=p$ip$len;
    }
    else if ( p?$ip6 && |p$ip6$exts| == 0 ) {
        r$source=p$ip6$src; r$destination=p$ip6$dst; r$ip_length=40+p$ip6$len;
    }
    if ( r?$ip_length ) {
        if ( p?$tcp && p$tcp$reserved == 0 ) {
            r$kind="tcp"; r$source_port=port_to_count(p$tcp$sport);
            r$destination_port=port_to_count(p$tcp$dport); r$tcp_flags=p$tcp$flags;
        }
        else if ( p?$udp ) {
            r$kind="udp"; r$source_port=port_to_count(p$udp$sport);
            r$destination_port=port_to_count(p$udp$dport); r$tcp_flags=0;
        }
    }
    Log::write(PACKETS, r);
}
