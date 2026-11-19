#!/usr/bin/env python3
"""pi4-ndr top — Live Terminal Status & Telemetry Dashboard

Connects to the local sensor health endpoint (:9100/health) or queries local state
to display a real-time monitor for the Pi4 NDR Sensor daemon.
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error
import argparse

# ANSI color codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_BLUE = "\033[34m"
CLR_CYAN = "\033[36m"
CLR_GRAY = "\033[90m"
CLR_CLEAR = "\033[2J\033[H"


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable KiB, MiB, GiB."""
    if num_bytes < 0:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_uptime(seconds: float) -> str:
    """Format uptime seconds into Dd Hh Mm Ss."""
    sec = int(seconds)
    days, sec = divmod(sec, 86400)
    hours, sec = divmod(sec, 3600)
    minutes, sec = divmod(sec, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{sec}s")
    return " ".join(parts)


def draw_bar(value: int, max_val: int = 5000, length: int = 24) -> str:
    """Render a visual ASCII bar."""
    if max_val <= 0:
        max_val = 1
    fraction = min(1.0, max(0.0, value / max_val))
    filled = int(fraction * length)
    empty = length - filled
    bar_color = CLR_GREEN if fraction < 0.6 else (CLR_YELLOW if fraction < 0.85 else CLR_RED)
    return f"{bar_color}[{'█' * filled}{'░' * empty}]{CLR_RESET} {fraction * 100:5.1f}%"


def fetch_health_data(url: str = "http://127.0.0.1:9100/health") -> dict:
    """Fetch health and telemetry dictionary from sensor."""
    req = urllib.request.Request(url, headers={"User-Agent": "pi4-ndr-top"})
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass
    return {}


def render_dashboard(data: dict, health_url: str) -> None:
    """Render the dashboard UI to standard output."""
    sys.stdout.write(CLR_CLEAR)

    print(f"{CLR_BOLD}{CLR_CYAN}══════════════════════════════════════════════════════════════════════════════{CLR_RESET}")
    print(f"{CLR_BOLD} 🛡️  Pi4-NDR-Sensor — Real-Time Telemetry Monitor{CLR_RESET}       (Ctrl+C to exit)")
    print(f"{CLR_BOLD}{CLR_CYAN}══════════════════════════════════════════════════════════════════════════════{CLR_RESET}")

    if not data:
        print(f"\n  {CLR_RED}● Sensor Daemon is OFFLINE or Health Server unreachable at:{CLR_RESET} {health_url}")
        print(f"    Check status with: {CLR_YELLOW}systemctl status pi4-ndr-forwarder{CLR_RESET}")
        print(f"    Verify health port: {CLR_YELLOW}--health-port 9100{CLR_RESET}\n")
        print(f"{CLR_GRAY}──────────────────────────────────────────────────────────────────────────────{CLR_RESET}")
        return

    status = data.get("status", "unknown")
    status_str = f"{CLR_GREEN}● RUNNING{CLR_RESET}" if status == "ok" else f"{CLR_RED}● {status.upper()}{CLR_RESET}"
    sensor_id = data.get("sensor_id", "pi4-ndr-01")
    uptime = format_uptime(data.get("uptime_seconds", 0.0))
    queue_depth = data.get("queue_depth", 0)
    failures = data.get("consecutive_failures", 0)
    fail_color = CLR_GREEN if failures == 0 else CLR_RED

    print(f"  Sensor ID    : {CLR_BOLD}{sensor_id}{CLR_RESET}              Status : {status_str}")
    print(f"  Uptime       : {uptime:<24} Failures : {fail_color}{failures} consecutive{CLR_RESET}")
    print(f"  Queue Buffer : {draw_bar(queue_depth, 5000)} ({queue_depth}/5000)")

    print(f"{CLR_GRAY}──────────────────────────────────────────────────────────────────────────────{CLR_RESET}")
    print(f"{CLR_BOLD} 📊 Telemetry Metrics{CLR_RESET}")

    metrics = data.get("metrics", {})
    ev_read = metrics.get("events_read", 0)
    ev_norm = metrics.get("events_normalized", 0)
    ev_fwd = metrics.get("events_forwarded", 0)
    ev_drop = metrics.get("events_dropped", 0)
    batch_sent = metrics.get("batches_sent", 0)
    disp_err = metrics.get("dispatch_errors", 0)

    print(f"  Events Read       : {CLR_BOLD}{ev_read:<12,}{CLR_RESET} Batches Sent     : {CLR_BOLD}{batch_sent:<12,}{CLR_RESET}")
    print(f"  Events Normalized : {CLR_BOLD}{ev_norm:<12,}{CLR_RESET} Forwarded to SOAR: {CLR_GREEN}{ev_fwd:<12,}{CLR_RESET}")
    print(f"  Events Dropped    : {CLR_YELLOW if ev_drop > 0 else CLR_GRAY}{ev_drop:<12,}{CLR_RESET} Dispatch Errors  : {CLR_RED if disp_err > 0 else CLR_GRAY}{disp_err:<12,}{CLR_RESET}")

    print(f"{CLR_GRAY}──────────────────────────────────────────────────────────────────────────────{CLR_RESET}")
    print(f"{CLR_BOLD} 🌐 Network Interface Traffic (Promiscuous SPAN Tap){CLR_RESET}")

    nic = data.get("nic_stats", {})
    rx_bytes = nic.get("rx_bytes", -1)
    rx_pkts = nic.get("rx_packets", -1)
    rx_drop = nic.get("rx_dropped", -1)
    rx_err = nic.get("rx_errors", -1)

    drop_color = CLR_RED if rx_drop > 0 else CLR_GREEN
    err_color = CLR_RED if rx_err > 0 else CLR_GREEN

    print(f"  RX Data Volume    : {CLR_BOLD}{format_bytes(rx_bytes):<12}{CLR_RESET} RX Packets       : {CLR_BOLD}{rx_pkts:<12,}{CLR_RESET}")
    print(f"  Kernel Drops      : {drop_color}{rx_drop:<12,}{CLR_RESET} Packet Errors    : {err_color}{rx_err:<12,}{CLR_RESET}")

    print(f"{CLR_CYAN}══════════════════════════════════════════════════════════════════════════════{CLR_RESET}")
    print(f"{CLR_GRAY}  Live refresh: 1.0s | Press Ctrl+C to return to terminal{CLR_RESET}")


def run_top(health_url: str = "http://127.0.0.1:9100/health", interval: float = 1.0, once: bool = False):
    """Main loop for top monitor."""
    try:
        while True:
            data = fetch_health_data(health_url)
            render_dashboard(data, health_url)
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write(CLR_RESET + "\n")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Live monitor for Pi4 NDR Sensor")
    parser.add_argument("--url", default="http://127.0.0.1:9100/health", help="Health endpoint URL")
    parser.add_argument("--interval", type=float, default=1.0, help="Refresh interval in seconds")
    parser.add_argument("--once", action="store_true", help="Print single snapshot and exit")
    args = parser.parse_args()
    run_top(health_url=args.url, interval=args.interval, once=args.once)


if __name__ == "__main__":
    main()
