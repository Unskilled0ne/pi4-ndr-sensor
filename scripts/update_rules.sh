#!/usr/bin/env bash
set -euo pipefail

# Automated Suricata Ruleset Updater with Zero-Downtime Hot-Reload
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/pi4-ndr-sensor}"
RULES_DEST="/etc/suricata/rules/pi4-trimmed.rules"
TMP_RULES="/tmp/pi4-trimmed-candidate.rules"
PYTHON_BIN="${INSTALL_PREFIX}/venv/bin/python3"

if [ ! -x "${PYTHON_BIN}" ]; then
    PYTHON_BIN="python3"
fi

echo "[*] [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting NDR ruleset update..."

# 1. Download and prune rules with SHA256 integrity check
"${PYTHON_BIN}" "${INSTALL_PREFIX}/deploy/rules_pruner.py" \
    --download \
    -o "${TMP_RULES}" \
    -m 3500

if [ ! -s "${TMP_RULES}" ]; then
    echo "[-] [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Pruned rules file is empty or missing, aborting." >&2
    exit 1
fi

# 2. Syntax validation if Suricata binary exists
if command -v suricata &>/dev/null && [ -f /etc/suricata/suricata.yaml ]; then
    echo "[*] Validating ruleset syntax with Suricata test mode..."
    if ! suricata -T -c /etc/suricata/suricata.yaml -S "${TMP_RULES}" >/dev/null 2>&1; then
        echo "[-] [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Suricata validation test failed! Preserving current rules." >&2
        rm -f "${TMP_RULES}"
        exit 1
    fi
    echo "[+] Suricata rules syntax valid."
fi

# 3. Atomically replace current ruleset
mkdir -p "$(dirname "${RULES_DEST}")"
chmod 644 "${TMP_RULES}"
mv "${TMP_RULES}" "${RULES_DEST}"
echo "[+] Deployed new rules to ${RULES_DEST} ($(wc -l < "${RULES_DEST}") active rules)"

# 4. Trigger hot-reload without packet capture interruption
RELOADED=false
if command -v suricatasc &>/dev/null && [ -S /var/run/suricata/suricata-command.socket ]; then
    if suricatasc -c reload-rules 2>/dev/null; then
        echo "[+] Successfully hot-reloaded Suricata rules via suricatasc."
        RELOADED=true
    fi
fi

if [ "${RELOADED}" = false ]; then
    if [ -f /var/run/suricata.pid ]; then
        PID=$(cat /var/run/suricata.pid 2>/dev/null || true)
        if [ -n "${PID}" ] && kill -0 "${PID}" 2>/dev/null; then
            kill -HUP "${PID}"
            echo "[+] Sent SIGHUP to Suricata PID ${PID} to trigger rules reload."
            RELOADED=true
        fi
    fi
fi

if [ "${RELOADED}" = false ]; then
    if systemctl is-active --quiet suricata.service; then
        systemctl reload suricata.service 2>/dev/null || true
        echo "[+] Reloaded suricata.service via systemctl."
    fi
fi

echo "[+] [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Ruleset update complete."
