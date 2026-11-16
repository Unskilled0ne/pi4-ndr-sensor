#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Must be run as root" >&2
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_PREFIX="/opt/pi4-ndr-sensor"
CONFIG_DIR="/etc/pi4-ndr"
STATE_DIR="/var/lib/pi4-ndr"
SERVICE_USER="ndrsensor"
SERVICE_GROUP="ndrsensor"

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    groupadd -r "${SERVICE_GROUP}"
    useradd -r -g "${SERVICE_GROUP}" -d "${INSTALL_PREFIX}" -s /usr/sbin/nologin -c "NDR Sensor Daemon" "${SERVICE_USER}"
fi

# Ensure service user can read logs (add to adm group)
if getent group adm >/dev/null 2>&1; then
    usermod -aG adm "${SERVICE_USER}"
fi

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

mkdir -p "${INSTALL_PREFIX}"
cp -r "${PROJECT_DIR}"/* "${INSTALL_PREFIX}/"

python3 -m venv "${INSTALL_PREFIX}/venv"
"${INSTALL_PREFIX}/venv/bin/pip" install --upgrade pip
"${INSTALL_PREFIX}/venv/bin/pip" install -r "${INSTALL_PREFIX}/requirements.txt"

mkdir -p "${CONFIG_DIR}" "${STATE_DIR}" /var/log/suricata /var/log/zeek
chmod 750 "${CONFIG_DIR}" "${STATE_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}"

cp "${INSTALL_PREFIX}/config/forwarder.yaml" "${CONFIG_DIR}/forwarder.yaml"
chmod 640 "${CONFIG_DIR}/forwarder.yaml"
chown root:"${SERVICE_GROUP}" "${CONFIG_DIR}/forwarder.yaml"

if [ -f /etc/suricata/suricata.yaml ]; then
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
fi
cp "${INSTALL_PREFIX}/config/suricata.yaml" /etc/suricata/suricata.yaml
chmod 644 /etc/suricata/suricata.yaml

mkdir -p /etc/suricata/rules
"${INSTALL_PREFIX}/venv/bin/python3" "${INSTALL_PREFIX}/deploy/rules_pruner.py" \
    -o /etc/suricata/rules/pi4-trimmed.rules \
    --download || true

cp "${INSTALL_PREFIX}/deploy/promiscuous-tap.service" /etc/systemd/system/
cp "${INSTALL_PREFIX}/deploy/pi4-ndr-forwarder.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable promiscuous-tap.service
systemctl enable suricata.service
systemctl enable pi4-ndr-forwarder.service

echo "[+] Installation complete."
