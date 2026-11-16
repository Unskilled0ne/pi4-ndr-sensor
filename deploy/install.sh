#!/usr/bin/env bash
# ==============================================================================
# install.sh - Automated Provisioning for Raspberry Pi 4 NDR Sensor
# Installs Suricata, Zeek, configuration profiles, and systemd daemons.
# ==============================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] This script must be run as root (sudo ./install.sh)" >&2
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_PREFIX="/opt/pi4-ndr-sensor"
CONFIG_DIR="/etc/pi4-ndr"

echo "============================================================"
echo " Raspberry Pi 4 (4GB) — NDR Sensor Installation"
echo "============================================================"

# 1. Install base dependencies
echo "[1/6] Installing system dependencies..."
apt-get update -y
apt-get install -y --no-install-recommends \
    suricata \
    python3 \
    python3-venv \
    python3-pip \
    curl \
    jq \
    ethtool \
    logrotate

# 2. Setup project in /opt
echo "[2/6] Deploying sensor code to ${INSTALL_PREFIX}..."
mkdir -p "${INSTALL_PREFIX}"
cp -r "${PROJECT_DIR}"/* "${INSTALL_PREFIX}/"

# Setup Python Virtual Environment
echo "[3/6] Setting up isolated Python environment..."
python3 -m venv "${INSTALL_PREFIX}/venv"
"${INSTALL_PREFIX}/venv/bin/pip" install --upgrade pip
"${INSTALL_PREFIX}/venv/bin/pip" install -r "${INSTALL_PREFIX}/requirements.txt"

# 3. Setup configurations
echo "[4/6] Installing system configuration files..."
mkdir -p "${CONFIG_DIR}"
mkdir -p /var/run/pi4-ndr /var/log/suricata /var/log/zeek

cp "${INSTALL_PREFIX}/config/forwarder.yaml" "${CONFIG_DIR}/forwarder.yaml"

# Backup default suricata config and copy optimized Pi 4 config
if [ -f /etc/suricata/suricata.yaml ]; then
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
fi
cp "${INSTALL_PREFIX}/config/suricata.yaml" /etc/suricata/suricata.yaml

# 4. Generate trimmed ruleset
echo "[5/6] Building trimmed ET Open ruleset for memory efficiency..."
mkdir -p /etc/suricata/rules
"${INSTALL_PREFIX}/venv/bin/python3" "${INSTALL_PREFIX}/deploy/rules_pruner.py" \
    -o /etc/suricata/rules/pi4-trimmed.rules \
    --download || true

# 5. Install systemd services
echo "[6/6] Installing and enabling systemd services..."
cp "${INSTALL_PREFIX}/deploy/promiscuous-tap.service" /etc/systemd/system/
cp "${INSTALL_PREFIX}/deploy/pi4-ndr-forwarder.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable promiscuous-tap.service
systemctl enable suricata.service
systemctl enable pi4-ndr-forwarder.service

echo "============================================================"
echo "✔ Installation Complete!"
echo "  - Configure SOAR endpoint in: ${CONFIG_DIR}/forwarder.yaml"
echo "  - Start services with: systemctl start suricata pi4-ndr-forwarder"
echo "  - Check logs: journalctl -u pi4-ndr-forwarder -f"
echo "============================================================"
