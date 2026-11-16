# Zeek local site configuration for Raspberry Pi 4 (4GB RAM)
# Passive network telemetry optimized for low memory footprint

@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice

# Output logs in JSON format for fast, structured parsing by the forwarder
redef LogAscii::use_json = T;

# Disable heavy protocol analyzers to conserve memory (< 1GB RAM)
redef disable_analyzer += {
    PacketAnalyzer::ANALYZER_SMB,
    PacketAnalyzer::ANALYZER_KERBEROS,
    PacketAnalyzer::ANALYZER_DCE_RPC,
    PacketAnalyzer::ANALYZER_RADIUS,
    PacketAnalyzer::ANALYZER_RDP,
    PacketAnalyzer::ANALYZER_SNMP,
    PacketAnalyzer::ANALYZER_SIP
};

# Tune table expiration and connection timeouts for low memory overhead
redef tcp_inactivity_timeout = 60 secs;
redef udp_inactivity_timeout = 30 secs;
redef table_expire_interval = 30 secs;

# Assign community ID to correlate Zeek logs directly with Suricata alerts
@load policy/protocols/conn/community-id-logging
