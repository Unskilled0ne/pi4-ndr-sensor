#!/usr/bin/env python3
import os
import sys
import argparse
import urllib.request
import tarfile
import re
import hashlib
from typing import Set, Dict, List, Any

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

ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"


def is_safe_tar_member(member: tarfile.TarInfo) -> bool:
    name = member.name
    if os.path.isabs(name) or ".." in name.split(os.path.sep):
        return False
    return True


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
    known_vars = {
        "HOME_NET", "EXTERNAL_NET", "HTTP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS",
        "DNS_SERVERS", "TELNET_SERVERS", "AIM_SERVERS", "DC_SERVERS", "DNP3_SERVER",
        "DNP3_CLIENT", "MODBUS_CLIENT", "MODBUS_SERVER", "ENIP_CLIENT", "ENIP_SERVER",
        "HTTP_PORTS", "SHELLCODE_PORTS", "ORACLE_PORTS", "SSH_PORTS", "DNP3_PORTS",
        "MODBUS_PORTS", "FILE_DATA_PORTS", "FTP_PORTS", "GENEVE_PORTS", "VXLAN_PORTS",
        "TEREDO_PORTS", "SIP_PORTS"
    }

    def process_rule_file(filename: str, content: str):
        base_cat = os.path.basename(filename).replace(".rules", "")
        if not any(cat in base_cat.lower() for cat in enabled_categories):
            return

        lines = content.splitlines()
        for line in lines:
            line_strip = line.strip()
            if rule_regex.match(line_strip):
                stats["total_rules_read"] += 1
                header = line_strip.split("(", 1)[0]
                vars_in_header = re.findall(r"\$([A-Za-z0-9_]+)", header)
                if any(v.upper() not in known_vars for v in vars_in_header):
                    continue
                if len(selected_rules) < max_rules:
                    selected_rules.append(line_strip)
                    stats["categories"][base_cat] = stats["categories"].get(base_cat, 0) + 1

    if os.path.isfile(input_dir_or_tar) and (input_dir_or_tar.endswith(".tar.gz") or input_dir_or_tar.endswith(".tgz")):
        with tarfile.open(input_dir_or_tar, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".rules") and is_safe_tar_member(member):
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        process_rule_file(member.name, content)
    elif os.path.isdir(input_dir_or_tar):
        for root, _, files in os.walk(input_dir_or_tar):
            for file in sorted(files):
                if file.endswith(".rules"):
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        process_rule_file(file, f.read())
    else:
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

    out_dir = os.path.dirname(os.path.abspath(output_file))
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, mode=0o755, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        for r in selected_rules:
            f.write(f"{r}\n")

    return stats


def main():
    parser = argparse.ArgumentParser(description="Suricata Ruleset Pruner")
    parser.add_argument("-i", "--input", default="rules", help="Input rules directory or archive")
    parser.add_argument("-o", "--output", default="pi4-trimmed.rules", help="Output pruned rule file")
    parser.add_argument("-m", "--max-rules", type=int, default=3500, help="Maximum allowed active rules")
    parser.add_argument("--download", action="store_true", help="Download latest ET Open archive")

    args = parser.parse_args()
    input_path = args.input

    if args.download:
        tar_dest = "/tmp/emerging.rules.tar.gz"
        try:
            urllib.request.urlretrieve(ET_OPEN_URL, tar_dest)
            # Attempt hash verification
            try:
                sha_url = ET_OPEN_URL + ".sha256"
                sha_dest = "/tmp/emerging.rules.tar.gz.sha256"
                urllib.request.urlretrieve(sha_url, sha_dest)
                with open(sha_dest, "r") as f:
                    expected_hash = f.read().strip().split()[0].lower()
                sha256 = hashlib.sha256()
                with open(tar_dest, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                actual_hash = sha256.hexdigest().lower()
                if actual_hash != expected_hash:
                    print(f"[-] SHA256 mismatch! Expected {expected_hash}, got {actual_hash}", file=sys.stderr)
                    print("[-] Refusing to use potentially tampered ruleset", file=sys.stderr)
                    sys.exit(1)
                print(f"[+] SHA256 verified: {actual_hash}")
            except Exception as e:
                print(f"[!] Could not verify hash (continuing anyway): {e}", file=sys.stderr)
            input_path = tar_dest
        except Exception as e:
            print(f"[-] Download failed: {e}", file=sys.stderr)

    prune_rules(input_path, args.output, max_rules=args.max_rules)


if __name__ == "__main__":
    main()
