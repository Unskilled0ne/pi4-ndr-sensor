import json
import pytest
from pathlib import Path
from ndr_sensor.hunter import LogHunter, HuntMatch, HuntReport
from ndr_sensor.cli import main


@pytest.fixture
def mock_log_env(tmp_path: Path):
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir(parents=True)
    suricata_file = tmp_path / "eve.json"

    dns_entries = [
        {"ts": 1700000001.0, "id.orig_h": "192.168.1.50", "id.resp_h": "1.1.1.1", "id.orig_p": 54321, "id.resp_p": 53, "proto": "udp", "query": "malware-c2.example.com", "qtype_name": "A", "answers": ["203.0.113.5"]},
        {"ts": 1700000002.0, "id.orig_h": "192.168.1.60", "id.resp_h": "8.8.8.8", "id.orig_p": 54322, "id.resp_p": 53, "proto": "udp", "query": "legit-search.org", "qtype_name": "A", "answers": ["198.51.100.1"]},
        {"ts": 1700000003.0, "id.orig_h": "192.168.1.50", "id.resp_h": "1.1.1.1", "id.orig_p": 54323, "id.resp_p": 53, "proto": "udp", "query": "suspicious-beacon.net", "qtype_name": "TXT", "answers": ["data=exfil"]},
    ]
    with open(zeek_dir / "dns.log", "w", encoding="utf-8") as f:
        for entry in dns_entries:
            f.write(json.dumps(entry) + "\n")

    http_entries = [
        {"ts": 1700000004.0, "id.orig_h": "192.168.1.50", "id.resp_h": "203.0.113.5", "id.orig_p": 49152, "id.resp_p": 80, "proto": "tcp", "method": "GET", "host": "malware-c2.example.com", "uri": "/beacon?device=sensor1", "user_agent": "curl/7.68.0"},
        {"ts": 1700000005.0, "id.orig_h": "192.168.1.70", "id.resp_h": "198.51.100.1", "id.orig_p": 49153, "id.resp_p": 80, "proto": "tcp", "method": "GET", "host": "legit-search.org", "uri": "/search?q=cybersecurity", "user_agent": "Mozilla/5.0"},
    ]
    with open(zeek_dir / "http.log", "w", encoding="utf-8") as f:
        for entry in http_entries:
            f.write(json.dumps(entry) + "\n")

    ssl_entries = [
        {"ts": 1700000006.0, "id.orig_h": "192.168.1.50", "id.resp_h": "203.0.113.6", "id.orig_p": 49154, "id.resp_p": 443, "proto": "tcp", "server_name": "stealth.c2-network.io", "subject": "CN=stealth.c2-network.io"},
    ]
    with open(zeek_dir / "ssl.log", "w", encoding="utf-8") as f:
        for entry in ssl_entries:
            f.write(json.dumps(entry) + "\n")

    notice_entries = [
        {"ts": 1700000007.0, "id.orig_h": "192.168.1.50", "id.resp_h": "203.0.113.6", "id.orig_p": 49154, "id.resp_p": 443, "note": "Port_Scan", "msg": "Potential port scan detected from 192.168.1.50", "sub": "100 ports scanned"},
    ]
    with open(zeek_dir / "notice.log", "w", encoding="utf-8") as f:
        for entry in notice_entries:
            f.write(json.dumps(entry) + "\n")

    conn_entries = [
        {"ts": 1700000008.0, "id.orig_h": "192.168.1.50", "id.resp_h": "203.0.113.10", "id.orig_p": 50000, "id.resp_p": 22, "proto": "tcp", "service": "ssh"},
    ]
    with open(zeek_dir / "conn.log", "w", encoding="utf-8") as f:
        for entry in conn_entries:
            f.write(json.dumps(entry) + "\n")

    suricata_entries = [
        {
            "timestamp": "2023-11-14T22:13:28.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "dest_ip": "203.0.113.5",
            "src_port": 49152,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET MALWARE Suspicious C2 Beacon Request",
                "signature_id": 2024001,
                "severity": 1,
                "category": "A Network Trojan was detected",
            },
        },
        {
            "timestamp": "2023-11-14T22:13:29.000000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.50",
            "dest_ip": "1.1.1.1",
            "src_port": 54321,
            "dest_port": 53,
            "proto": "UDP",
            "dns": {"rrname": "suricata-tracked-host.com", "rrtype": "A", "rdata": "1.2.3.4"},
        },
    ]
    with open(suricata_file, "w", encoding="utf-8") as f:
        for entry in suricata_entries:
            f.write(json.dumps(entry) + "\n")

    return {"zeek_dir": zeek_dir, "suricata_file": suricata_file}


def test_hunt_by_ip_only(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    report = hunter.hunt(ip="192.168.1.50")

    assert report.total_matches > 0
    assert report.ip_filter == "192.168.1.50"
    for m in report.matches:
        assert m.src_ip == "192.168.1.50" or m.dest_ip == "192.168.1.50"

    queries = [m.target_or_query for m in report.matches]
    assert "malware-c2.example.com" in queries
    assert any("ET MALWARE" in q for q in queries)


def test_hunt_by_keyword_only(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    report = hunter.hunt(query="malware")

    assert report.total_matches >= 2
    matched_targets = [m.target_or_query for m in report.matches]
    assert any("malware-c2.example.com" in t for t in matched_targets)
    assert any("ET MALWARE" in t for t in matched_targets)


def test_hunt_by_ip_and_keyword_combination(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    report_matched = hunter.hunt(ip="192.168.1.50", query="beacon")
    assert report_matched.total_matches > 0
    for m in report_matched.matches:
        assert m.src_ip == "192.168.1.50" or m.dest_ip == "192.168.1.50"
        assert "beacon" in m.target_or_query.lower() or "beacon" in json.dumps(m.details).lower()

    report_nomatch = hunter.hunt(ip="192.168.1.70", query="malware")
    assert report_nomatch.total_matches == 0


def test_hunt_source_filtering(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    dns_report = hunter.hunt(sources=["dns"])
    assert all(m.event_type == "dns" for m in dns_report.matches)

    alert_report = hunter.hunt(sources=["alert"])
    assert all(m.event_type in ("alert", "notice") for m in alert_report.matches)


def test_hunt_limit(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    report = hunter.hunt(limit=2)
    assert len(report.matches) == 2


def test_hunt_case_sensitivity(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    ci_report = hunter.hunt(query="get", case_sensitive=False)
    assert ci_report.total_matches > 0

    cs_report = hunter.hunt(query="get", case_sensitive=True)
    assert cs_report.total_matches == 0

    cs_report_upper = hunter.hunt(query="GET", case_sensitive=True)
    assert cs_report_upper.total_matches > 0


def test_hunt_regex(mock_log_env):
    hunter = LogHunter(
        suricata_path=str(mock_log_env["suricata_file"]),
        zeek_dir=str(mock_log_env["zeek_dir"]),
    )
    report = hunter.hunt(query=r"malware-c2\..*\.com", use_regex=True)
    assert report.total_matches > 0
    assert any("malware-c2.example.com" in m.target_or_query for m in report.matches)


def test_hunt_missing_files(tmp_path: Path):
    non_existent = tmp_path / "does_not_exist"
    hunter = LogHunter(
        suricata_path=str(non_existent / "eve.json"),
        zeek_dir=str(non_existent / "zeek"),
    )
    report = hunter.hunt(query="test")
    assert report.total_matches == 0
    assert report.total_scanned_lines == 0


def test_hunt_corrupt_logs(tmp_path: Path):
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir(parents=True)
    with open(zeek_dir / "dns.log", "w", encoding="utf-8") as f:
        f.write("#separator \\x09\n")
        f.write("corrupt line not json\n")
        f.write("{invalid: json}\n")
        f.write("\n")

    hunter = LogHunter(zeek_dir=str(zeek_dir))
    report = hunter.hunt(query="anything")
    assert report.total_matches == 0


def test_hunt_report_exports(tmp_path: Path):
    match = HuntMatch(
        timestamp="2023-11-14T22:13:28+00:00",
        source="zeek-dns",
        event_type="dns",
        src_ip="192.168.1.100",
        dest_ip="1.1.1.1",
        target_or_query="suspicious.domain.com",
        category="DNS Query (A)",
        severity="medium",
        details={"query": "suspicious.domain.com"},
    )
    report = HuntReport(
        query_filter="suspicious",
        ip_filter="192.168.1.100",
        total_scanned_lines=150,
        total_matches=1,
        top_queries={"suspicious.domain.com": 1},
        top_devices={"192.168.1.100": 1},
        top_sources={"zeek-dns": 1},
        matches=[match],
    )

    json_path = tmp_path / "report.json"
    report.save_json(str(json_path))
    assert json_path.exists()
    loaded_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded_json["total_matches"] == 1
    assert loaded_json["matches"][0]["target_or_query"] == "suspicious.domain.com"

    csv_path = tmp_path / "report.csv"
    report.save_csv(str(csv_path))
    assert csv_path.exists()
    content = csv_path.read_text(encoding="utf-8")
    assert "suspicious.domain.com" in content
    assert "192.168.1.100" in content

    md_path = tmp_path / "report.md"
    report.save_markdown(str(md_path))
    assert md_path.exists()
    md_content = md_path.read_text(encoding="utf-8")
    assert "# NDR Investigation & Log Hunt Report" in md_content
    assert "192.168.1.100" in md_content
    assert "suspicious.domain.com" in md_content


def test_cli_hunt_execution(mock_log_env, tmp_path, monkeypatch, capsys):
    out_file = tmp_path / "cli_report.json"
    test_args = [
        "pi4-ndr",
        "hunt",
        "--ip", "192.168.1.50",
        "-q", "malware",
        "-o", str(out_file),
        "--suricata-file", str(mock_log_env["suricata_file"]),
        "--zeek-dir", str(mock_log_env["zeek_dir"]),
    ]
    monkeypatch.setattr("sys.argv", test_args)

    main()

    captured = capsys.readouterr()
    assert "[+] Scanned" in captured.out
    assert "[+] Found" in captured.out
    assert "[+] Full report saved to:" in captured.out
    assert out_file.exists()
