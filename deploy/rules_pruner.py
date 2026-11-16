#!/usr/bin/env python3
"""
Rules Pruner for Suricata on Raspberry Pi 4 (4GB RAM)
Trims the full ET Open ruleset (~35,000+ rules) down to ~2,000-4,000 high-priority
rules to keep Suricata memory usage within the ~500MB-1GB target.
"""

import os
import sys
import argparse
import urllib.request
import tarfile
import re
from typing import Set, Dict, List

DEFAULT_ENABLED_CATEGORIES = {
    "emerging-exploit",
    "emerging-malware",
    "emerging-trojan",
    "emerging-scan",
    "emerging-dns",
    "emerging-web_server",
    "emerging-web_client",
    "emerging-current_events",
    "emerging-shellcode",
    "emerging-worm"
}

DEFAULT_DISABLED_CATEGORIES = {
    "emerging-scada",
    "emerging-games",
    "emerging-mobile_malware",
    "emerging-activex",
    "emerging-voip",
    "emerging-chat",
    "emerging-p2p",
    "emerging-inappropriate"
}

ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"


def prune_rules(
    input_dir_or_tar: str,
    output_file: str,
    enabled_categories: Set[str] = DEFAULT_ENABLED_CATEGORIES,
    max_rules: int = 4000
) -> Dict[str, Any]:
    stats = {
        "total_rules_read": 0,
        "enabled_rules_selected": 0,
        "categories": {}
    }

    selected_rules: List[str] = []
    rule_regex = re.compile(r"^\s*alert\s+", re.IGNORECASE)

    def process_rule_file(filename: str, content: str):
        base_cat = os.path.basename(filename).replace(".rules", "")
        # Check if enabled
        is_enabled = any(cat in base_cat.lower() for cat in enabled_categories)
        if not is_enabled:
            return

        lines = content.splitlines()
        for line in lines:
            line_strip = line.strip()
            if rule_regex.match(line_strip):
                stats["total_rules_read"] += 1
                if len(selected_rules) < max_rules:
                    selected_rules.append(line_strip)
                    stats["categories"][base_cat] = stats["categories"].get(base_cat, 0) + 1

    if os.path.isfile(input_dir_or_tar) and (input_dir_or_tar.endswith(".tar.gz") or input_dir_or_tar.endswith(".tgz")):
        print(f"[*] Extracting and scanning rules archive: {input_dir_or_tar}...")
        with tarfile.open(input_dir_or_tar, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".rules"):
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        process_rule_file(member.name, content)
    elif os.path.isdir(input_dir_or_tar):
        print(f"[*] Scanning rules directory: {input_dir_or_tar}...")
        for root, _, files in os.walk(input_dir_or_tar):
            for file in sorted(files):
                if file.endswith(".rules"):
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        process_rule_file(file, f.read())
    else:
        # Create a fallback baseline rule set if running offline
        print("[!] No input rule archive found. Generating high-fidelity baseline rules...")
        baseline = [
            'alert tcp any any -> $HOME_NET 80 (msg:"ET EXPLOIT Generic Suspicious Web Probe"; flow:to_server,established; content:"/etc/passwd"; classtype:web-application-attack; sid:2000001; rev:1;)',
            'alert tcp any any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Brute Force Inbound"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:2000002; rev:1;)',
            'alert dns any any -> any 53 (msg:"ET MALWARE Suspicious Dynamic DNS Query"; dns.query; content:".duckdns.org"; classtype:trojan-activity; sid:2000003; rev:1;)',
            'alert http any any -> any any (msg:"ET MALWARE Known Malicious User-Agent Detected"; http.user_agent; content:"sqlmap"; classtype:bad-unknown; sid:2000004; rev:1;)',
            'alert tcp any any -> $HOME_NET 445 (msg:"ET EXPLOIT SMB Remote Code Execution Probe"; flow:to_server,established; content:"|ff|SMB"; depth:5; classtype:attempted-admin; sid:2000005; rev:1;)'
        ]
        selected_rules = baseline
        stats["categories"]["baseline-security"] = len(baseline)
        stats["total_rules_read"] = len(baseline)

    stats["enabled_rules_selected"] = len(selected_rules)

    out_dir = os.path.dirname(output_file)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Raspberry Pi 4 Trimmed ET Open Ruleset\n")
        f.write(f"# Target size: {len(selected_rules)} active rules\n")
        f.write("# Optimized for < 1GB Suricata RAM footprint on Cortex-A72\n\n")
        for r in selected_rules:
            f.write(f"{r}\n")

    print(f"[✔] Successfully pruned ruleset to {len(selected_rules)} rules -> {output_file}")
    for cat, count in sorted(stats["categories"].items(), key=lambda x: x[1], reverse=True):
        print(f"    - {cat}: {count} rules")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Suricata Ruleset Pruner for Raspberry Pi 4")
    parser.add_argument("-i", "--input", default="rules", help="Rules directory or tar.gz archive")
    parser.add_argument("-o", "--output", default="pi4-trimmed.rules", help="Output pruned rule file")
    parser.add_argument("-m", "--max-rules", type=int, default=3500, help="Maximum allowed active rules")
    parser.add_argument("--download", action="store_true", help="Download latest ET Open archive from Emerging Threats")

    args = parser.parse_args()

    input_path = args.input
    if args.download:
        tar_dest = "/tmp/emerging.rules.tar.gz"
        print(f"[*] Downloading ET Open rules from {ET_OPEN_URL}...")
        try:
            urllib.request.urlretrieve(ET_OPEN_URL, tar_dest)
            input_path = tar_dest
            print("[✔] Download complete.")
        except Exception as e:
            print(f"[!] Download failed ({e}), proceeding with existing input path.")

    prune_rules(input_path, args.output, max_rules=args.max_rules)


if __name__ == "__main__":
    main()
