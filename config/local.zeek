@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice

redef LogAscii::use_json = T;

redef Analyzer::disabled_analyzers += {
    Analyzer::ANALYZER_SMB,
    Analyzer::ANALYZER_KRB,
    Analyzer::ANALYZER_DCE_RPC,
    Analyzer::ANALYZER_RADIUS,
    Analyzer::ANALYZER_RDP,
    Analyzer::ANALYZER_SNMP,
    Analyzer::ANALYZER_SIP
};

redef tcp_inactivity_timeout = 60 secs;
redef udp_inactivity_timeout = 30 secs;
redef table_expire_interval = 30 secs;

@load policy/protocols/conn/community-id-logging
@load ./dns-tunnel-detect.zeek
