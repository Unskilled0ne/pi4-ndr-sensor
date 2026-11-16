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
    forwarder.run_loop(poll_interval=args.poll_interval)


def cmd_test_config(args):
    try:
        config = AppConfig.load(args.config)
        print("✔ Configuration file successfully loaded and validated.")
        print(f"  Sensor ID: {config.sensor.id}")
        print(f"  Forwarding Endpoint: {config.forwarding.endpoint_url}")
        print(f"  Mode: {config.forwarding.mode}")
        print(f"  Suricata Log Path: {config.logs.suricata.path}")
        print(f"  Zeek Log Directory: {config.logs.zeek.dir}")
        print(f"  Offset File: {config.state.offset_file}")
    except Exception as e:
        print(f"❌ Configuration error: {e}", file=sys.stderr)
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

    print(f"Dispatching test alert to {config.forwarding.endpoint_url} (mode: {config.forwarding.mode})...")
    forwarder.batch_queue.append(test_event)
    success = forwarder.flush()
    if success:
        print("✔ Test alert dispatched successfully!")
    else:
        print("❌ Test alert dispatch failed. Check endpoint status and logs.", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Raspberry Pi 4 NDR Telemetry Sensor CLI")
    parser.add_argument("-c", "--config", help="Path to forwarder.yaml", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    run_p = subparsers.add_parser("run", help="Start the NDR log forwarder daemon")
    run_p.add_argument("--poll-interval", type=float, default=0.5, help="Polling interval in seconds")

    subparsers.add_parser("test-config", help="Validate configuration file")
    subparsers.add_parser("test-send", help="Send a test alert through the pipeline")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.subcommand == "run":
        cmd_run(args)
    elif args.subcommand == "test-config":
        cmd_test_config(args)
    elif args.subcommand == "test-send":
        cmd_test_send(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
