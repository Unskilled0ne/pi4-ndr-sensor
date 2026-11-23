#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

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

# Install Zeek from official repository
if ! command -v zeek &>/dev/null; then
    echo "[*] Installing Zeek..."
    DEBIAN_VER="12"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DEBIAN_VER="${VERSION_ID:-12}"
    fi
    echo "deb [trusted=yes] https://download.opensuse.org/repositories/security:/zeek/Debian_${DEBIAN_VER}/ /" \
        > /etc/apt/sources.list.d/zeek.list
    apt-get update -y
    apt-get install -y --no-install-recommends zeek-lts || apt-get install -y --no-install-recommends zeek || {
        echo "[!] Zeek package install failed. Install manually from https://zeek.org/get-zeek/"
        echo "[!] Continuing without Zeek..."
    }
fi

for b in zeek zeekctl zkg; do
    if [ -x "/opt/zeek/bin/${b}" ] && [ ! -e "/usr/local/bin/${b}" ]; then
        ln -s "/opt/zeek/bin/${b}" "/usr/local/bin/${b}"
    fi
done

mkdir -p "${INSTALL_PREFIX}"
cp -r "${PROJECT_DIR}"/* "${INSTALL_PREFIX}/"

python3 -m venv "${INSTALL_PREFIX}/venv"
"${INSTALL_PREFIX}/venv/bin/pip" install --upgrade pip
"${INSTALL_PREFIX}/venv/bin/pip" install -r "${INSTALL_PREFIX}/requirements.txt"

mkdir -p "${CONFIG_DIR}" "${STATE_DIR}" /var/log/suricata /var/log/zeek
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}"
chown root:"${SERVICE_GROUP}" "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}" "${STATE_DIR}"

if [ -f "${INSTALL_PREFIX}/deploy/setup_ram_storage.sh" ]; then
    bash "${INSTALL_PREFIX}/deploy/setup_ram_storage.sh" "256M" || true
fi

cp "${INSTALL_PREFIX}/config/forwarder.yaml" "${CONFIG_DIR}/forwarder.yaml"
chmod 640 "${CONFIG_DIR}/forwarder.yaml"
chown root:"${SERVICE_GROUP}" "${CONFIG_DIR}/forwarder.yaml"

if [ -f /etc/suricata/suricata.yaml ]; then
    cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
fi
cp "${INSTALL_PREFIX}/config/suricata.yaml" /etc/suricata/suricata.yaml
chmod 644 /etc/suricata/suricata.yaml

# Deploy Zeek site-local policy
ZEEK_SITE_DIR=""
for candidate in /opt/zeek/share/zeek/site /usr/share/zeek/site /usr/local/zeek/share/zeek/site; do
    if [ -d "${candidate}" ]; then
        ZEEK_SITE_DIR="${candidate}"
        break
    fi
done

if [ -n "${ZEEK_SITE_DIR}" ]; then
    if [ -f "${ZEEK_SITE_DIR}/local.zeek" ]; then
        cp "${ZEEK_SITE_DIR}/local.zeek" "${ZEEK_SITE_DIR}/local.zeek.bak"
    fi
    cp "${INSTALL_PREFIX}/config/local.zeek" "${ZEEK_SITE_DIR}/local.zeek"
    cp "${INSTALL_PREFIX}/config/dns-tunnel-detect.zeek" "${ZEEK_SITE_DIR}/dns-tunnel-detect.zeek"
    chmod 644 "${ZEEK_SITE_DIR}/local.zeek" "${ZEEK_SITE_DIR}/dns-tunnel-detect.zeek"
    echo "[+] Zeek site policy and DNS tunnel detector deployed to ${ZEEK_SITE_DIR}/"
else
    echo "[!] Zeek site directory not found. Deploy config/local.zeek manually."
fi

mkdir -p /etc/suricata/rules
"${INSTALL_PREFIX}/venv/bin/python3" "${INSTALL_PREFIX}/deploy/rules_pruner.py" \
    -o /etc/suricata/rules/pi4-trimmed.rules \
    --download || true

# Apply kernel and socket buffer tuning
if [ -f "${INSTALL_PREFIX}/deploy/99-ndr-sensor.conf" ]; then
    cp "${INSTALL_PREFIX}/deploy/99-ndr-sensor.conf" /etc/sysctl.d/99-ndr-sensor.conf
    sysctl --system >/dev/null 2>&1 || true
    echo "[+] Applied network buffer sysctl tuning."
fi

cp "${INSTALL_PREFIX}/deploy/promiscuous-tap.service" /etc/systemd/system/
cp "${INSTALL_PREFIX}/deploy/pi4-ndr-forwarder.service" /etc/systemd/system/
cp "${INSTALL_PREFIX}/deploy/pi4-ndr-rules-update.service" /etc/systemd/system/
cp "${INSTALL_PREFIX}/deploy/pi4-ndr-rules-update.timer" /etc/systemd/system/
if [ -f "${INSTALL_PREFIX}/deploy/zeek.service" ]; then
    cp "${INSTALL_PREFIX}/deploy/zeek.service" /etc/systemd/system/
fi

# Template interface name from config
IFACE=$(grep -oP '(?<=interface: ).*' "${CONFIG_DIR}/forwarder.yaml" 2>/dev/null | tr -d '"' | head -1)
IFACE="${IFACE:-eth0}"
sed -i "s/eth0/${IFACE}/g" /etc/systemd/system/promiscuous-tap.service
if [ -f /etc/systemd/system/zeek.service ]; then
    sed -i "s/eth0/${IFACE}/g" /etc/systemd/system/zeek.service
fi

systemctl daemon-reload
systemctl enable promiscuous-tap.service
systemctl enable suricata.service
systemctl enable zeek.service 2>/dev/null || true
systemctl enable pi4-ndr-forwarder.service
systemctl enable --now pi4-ndr-rules-update.timer 2>/dev/null || true

echo "[+] Installation complete."
