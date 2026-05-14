module ML;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;

        flow_duration: double &log;
        fwd_pkts: count &log;
        bwd_pkts: count &log;
        fwd_bytes: count &log;
        bwd_bytes: count &log;
    };
}

event zeek_init()
{
    Log::create_stream(ML::LOG, [$columns=Info, $path="ml_features"]);
}

event connection_state_remove(c: connection)
{
    local duration = c$duration / 1sec;

    local fwd_pkts = c$orig$num_pkts;
    local bwd_pkts = c$resp$num_pkts;

    local fwd_bytes = 0;
    local bwd_bytes = 0;

    if ( c$orig?$size )
        fwd_bytes = c$orig$size;

    if ( c$resp?$size )
        bwd_bytes = c$resp$size;

    if ( fwd_pkts == 0 && bwd_pkts == 0 )
        return;

    local rec: Info = [
        $ts = network_time(),
        $uid = c$uid,

        $flow_duration = duration,
        $fwd_pkts = fwd_pkts,
        $bwd_pkts = bwd_pkts,
        $fwd_bytes = fwd_bytes,
        $bwd_bytes = bwd_bytes
    ];

    Log::write(ML::LOG, rec);
}
