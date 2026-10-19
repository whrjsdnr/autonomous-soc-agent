# Offline diagnostics only; names/answers/payload never leave the ephemeral container.
redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0secs;
event zeek_init() &priority=-10
    {
    local c = Log::get_filter(Conn::LOG, "default");
    c$include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration", "orig_pkts", "resp_pkts",
                     "orig_ip_bytes", "resp_ip_bytes", "missed_bytes", "conn_state");
    Log::add_filter(Conn::LOG, c);
    local d = Log::get_filter(DNS::LOG, "default");
    d$include = set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "trans_id", "rtt", "qtype", "rcode", "TTLs", "TC");
    Log::add_filter(DNS::LOG, d);
    }
