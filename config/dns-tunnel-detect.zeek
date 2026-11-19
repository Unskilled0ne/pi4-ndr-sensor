# Lightweight DNS Tunneling & Long Query Detector for Pi4 NDR Sensor
@load base/protocols/dns
@load base/frameworks/notice

module DNS_Tunnel;

export {
    redef enum Notice::Type += {
        DNS_Tunnel_Suspicious_Query,
        DNS_High_Volume_Subdomain
    };

    const max_query_length = 52 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( |query| > max_query_length ) {
        # Exclude standard in-addr.arpa / ip6.arpa reverse lookups
        if ( ! (query in /\.arpa$/) ) {
            NOTICE([
                $note=DNS_Tunnel_Suspicious_Query,
                $msg=fmt("Oversized DNS query detected (%d bytes): %s", |query|, query),
                $conn=c,
                $identifier=cat(c$id$orig_h, query),
                $suppress_for=30sec
            ]);
        }
    }
}
