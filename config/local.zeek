@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice

redef LogAscii::use_json = T;

redef disable_analyzer += {
    PacketAnalyzer::ANALYZER_SMB,
    PacketAnalyzer::ANALYZER_KERBEROS,
    PacketAnalyzer::ANALYZER_DCE_RPC,
    PacketAnalyzer::ANALYZER_RADIUS,
    PacketAnalyzer::ANALYZER_RDP,
    PacketAnalyzer::ANALYZER_SNMP,
    PacketAnalyzer::ANALYZER_SIP
};

redef tcp_inactivity_timeout = 60 secs;
redef udp_inactivity_timeout = 30 secs;
redef table_expire_interval = 30 secs;

@load policy/protocols/conn/community-id-logging
