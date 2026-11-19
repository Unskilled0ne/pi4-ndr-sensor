#!/usr/bin/env bash
set -euo pipefail

IOC_FILE="/var/lib/pi4-ndr/ioc_blocklist.txt"
TMP_FILE="/tmp/ioc_update_$$"

mkdir -p "$(dirname "${IOC_FILE}")"
echo "# IOC Blocklist - Auto-updated $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${TMP_FILE}"

# Feodo Tracker (banking trojans C2)
curl -sS --max-time 30 "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" 2>/dev/null \
    | grep -v "^#" | grep -v "^$" >> "${TMP_FILE}" || true

# URLhaus (malware URLs — extract domains)
curl -sS --max-time 30 "https://urlhaus.abuse.ch/downloads/text/" 2>/dev/null \
    | grep -v "^#" | grep -v "^$" | sed 's|https\?://||;s|/.*||' | sort -u >> "${TMP_FILE}" || true

sort -u "${TMP_FILE}" -o "${TMP_FILE}"
mv "${TMP_FILE}" "${IOC_FILE}"
chmod 644 "${IOC_FILE}"
echo "[+] Updated IOC blocklist: $(wc -l < "${IOC_FILE}") entries"
