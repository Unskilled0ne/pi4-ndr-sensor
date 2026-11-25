import sys
import argparse
import logging
from ndr_sensor.config import AppConfig
from ndr_sensor.forwarder import LogForwarder
from ndr_sensor.models import NDREvent


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def cmd_run(args):
    config = AppConfig.load(args.config)
    forwarder = LogForwarder(config)

    from ndr_sensor.health import start_health_server
    start_health_server(forwarder, port=getattr(args, "health_port", 9100))

    forwarder.run_loop(poll_interval=args.poll_interval)


def cmd_test_config(args):
    try:
        config = AppConfig.load(args.config)
        print("[+] Configuration valid:")
        print(f"    Sensor: {config.sensor.id} (interface: {config.sensor.interface})")
        print(f"    Endpoint: {config.forwarding.endpoint_url}")
        print(f"    Mode: {config.forwarding.mode}")
        print(f"    Suricata Path: {config.logs.suricata.path}")
        print(f"    Zeek Directory: {config.logs.zeek.dir}")
        print(f"    State File: {config.state.offset_file}")
    except Exception as e:
        print(f"[-] Config error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_test_send(args):
    config = AppConfig.load(args.config)
    forwarder = LogForwarder(config)

    test_event = NDREvent(
        sensor_id=config.sensor.id,
        source="suricata",
        event_type="alert",
        src_ip="198.51.100.25",
        dest_ip="192.168.1.10",
        src_port=44821,
        dest_port=80,
        proto="tcp",
        severity="high",
        signature="ET EXPLOIT Suspicious Command Injection Probe (Test Alert)",
        raw={
            "alert": {
                "signature": "ET EXPLOIT Suspicious Command Injection Probe (Test Alert)",
                "signature_id": 2000001,
                "severity": 2
            },
            "community_id": "1:abc123test=="
        }
    )

    forwarder.batch_queue.append(test_event)
    success = forwarder.flush()
    if success:
        print("[+] Test alert delivered successfully.")
    else:
        print("[-] Alert delivery failed.", file=sys.stderr)
        sys.exit(1)


def cmd_hunt(args):
    from ndr_sensor.hunter import LogHunter

    suricata_path = args.suricata_file
    zeek_dir = args.zeek_dir

    if not suricata_path or not zeek_dir:
        try:
            config = AppConfig.load(args.config)
            suricata_path = suricata_path or config.logs.suricata.path
            zeek_dir = zeek_dir or config.logs.zeek.dir
        except Exception:
            suricata_path = suricata_path or "/var/log/suricata/eve.json"
            zeek_dir = zeek_dir or "/var/log/zeek/current"

    hunter = LogHunter(suricata_path=suricata_path, zeek_dir=zeek_dir)

    sources = [s.strip() for s in args.source.split(",")] if args.source else ["all"]
    query = args.query

    report = hunter.hunt(
        query=query,
        ip=args.ip,
        sources=sources,
        limit=args.limit,
        case_sensitive=args.case_sensitive,
        use_regex=args.regex,
    )

    print(f"[+] Scanned {report.total_scanned_lines:,} log entries across {len(report.sources_searched)} source file(s).")
    print(f"[+] Found {report.total_matches:,} match(es) (query={query!r}, ip={args.ip!r}).")

    if report.top_queries:
        print("\n[+] Top Targets & Queries:")
        for q, count in list(report.top_queries.items())[:5]:
            print(f"    - {q}: {count} hit(s)")

    if report.top_devices:
        print("\n[+] Top Associated Devices:")
        for dev, count in list(report.top_devices.items())[:5]:
            print(f"    - {dev}: {count} hit(s)")

    if args.output:
        fmt = (args.format or "").lower().strip()
        out_str = str(args.output).lower()
        if fmt == "json" or out_str.endswith(".json"):
            report.save_json(args.output)
        elif fmt == "csv" or out_str.endswith(".csv"):
            report.save_csv(args.output)
        else:
            report.save_markdown(args.output)
        print(f"\n[+] Full report saved to: {args.output}")
    else:
        if report.matches:
            print("\n[+] Recent Matches:")
            for m in report.matches[:20]:
                src_str = f"{m.src_ip}:{m.src_port}" if m.src_port else (m.src_ip or "-")
                dest_str = f"{m.dest_ip}:{m.dest_port}" if m.dest_port else (m.dest_ip or "-")
                print(f"    [{m.timestamp}] ({m.source}) {src_str} -> {dest_str} | {m.target_or_query}")
            if len(report.matches) > 20:
                print(f"    ... and {len(report.matches) - 20} more. Use --output to save complete report.")
        else:
            print("[-] No events matched the criteria.")


def main():
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("-c", "--config", help="Path to forwarder.yaml", default=None)
    common_parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    parser = argparse.ArgumentParser(description="NDR Sensor Forwarder Daemon", parents=[common_parser])
    subparsers = parser.add_subparsers(dest="subcommand")

    run_p = subparsers.add_parser("run", help="Start log forwarder", parents=[common_parser])
    run_p.add_argument("--poll-interval", type=float, default=0.5, help="Polling interval in seconds")
    run_p.add_argument("--health-port", type=int, default=9100, help="Health endpoint port")

    subparsers.add_parser("test-config", help="Validate configuration", parents=[common_parser])
    subparsers.add_parser("test-send", help="Send test alert to endpoint", parents=[common_parser])

    top_p = subparsers.add_parser("top", help="Launch real-time telemetry terminal monitor", parents=[common_parser])
    top_p.add_argument("--port", type=int, default=9100, help="Health endpoint port")
    top_p.add_argument("--interval", type=float, default=1.0, help="Refresh interval in seconds")
    top_p.add_argument("--once", action="store_true", help="Print single snapshot and exit")

    hunt_p = subparsers.add_parser("hunt", help="Search logs for keywords, targets, and device IPs", parents=[common_parser])
    hunt_p.add_argument("-q", "--query", "-k", "--keyword", dest="query", default=None, help="Search keyword or pattern")
    hunt_p.add_argument("--ip", default=None, help="Target device IP address (source or destination)")
    hunt_p.add_argument("-s", "--source", default="all", help="Comma-separated log sources to search (all, dns, http, ssl, alert, conn, notice)")
    hunt_p.add_argument("-o", "--output", default=None, help="File path to save report (.json, .csv, .md)")
    hunt_p.add_argument("--format", choices=["json", "csv", "md", "markdown"], default=None, help="Explicit report output format")
    hunt_p.add_argument("--limit", type=int, default=500, help="Maximum number of matching events to return (default: 500)")
    hunt_p.add_argument("--case-sensitive", action="store_true", help="Perform case-sensitive matching")
    hunt_p.add_argument("--regex", action="store_true", help="Treat query as regular expression")
    hunt_p.add_argument("--suricata-file", default=None, help="Override path to Suricata eve.json")
    hunt_p.add_argument("--zeek-dir", default=None, help="Override path to Zeek logs directory")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.subcommand == "run":
        cmd_run(args)
    elif args.subcommand == "test-config":
        cmd_test_config(args)
    elif args.subcommand == "test-send":
        cmd_test_send(args)
    elif args.subcommand == "top":
        from ndr_sensor.top import run_top
        health_url = f"http://127.0.0.1:{args.port}/health"
        run_top(health_url=health_url, interval=args.interval, once=args.once)
    elif args.subcommand == "hunt":
        cmd_hunt(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
