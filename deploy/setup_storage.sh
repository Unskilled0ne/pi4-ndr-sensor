#!/usr/bin/env bash
# ==============================================================================
# setup_storage.sh - External Storage Provisioning for Pi 4 NDR Sensor
# Directs heavy write I/O (Zeek logs, Suricata eve.json) away from MicroSD card
# onto an attached USB3 SSD or external hard drive.
# ==============================================================================

set -euo pipefail

TARGET_LABEL="${1:-LOOT}"
MOUNT_POINT="/mnt/sensor_storage"

echo "[*] Checking for external drive with LABEL=${TARGET_LABEL}..."

if ! blkid -L "${TARGET_LABEL}" >/dev/null 2>&1; then
    echo "[!] Drive with label '${TARGET_LABEL}' not found!"
    echo "    To format a drive for this purpose, run:"
    echo "    sudo mkfs.ext4 -F -L ${TARGET_LABEL} /dev/sdX1"
    exit 1
fi

echo "[✔] Found drive labeled ${TARGET_LABEL}"
mkdir -p "${MOUNT_POINT}"

# Add to fstab if not already present
if ! grep -q "LABEL=${TARGET_LABEL}" /etc/fstab; then
    echo "[*] Adding ${TARGET_LABEL} to /etc/fstab with noatime,nofail..."
    echo "LABEL=${TARGET_LABEL} ${MOUNT_POINT} ext4 defaults,noatime,nofail 0 2" >> /etc/fstab
fi

mount -a || true

# Prepare storage directories
mkdir -p "${MOUNT_POINT}/suricata"
mkdir -p "${MOUNT_POINT}/zeek"
mkdir -p "${MOUNT_POINT}/offsets"

# Re-link log directories
echo "[*] Setting up symlinks for Zeek and Suricata logs..."
mkdir -p /var/log/suricata /var/log/zeek

# Stop services if running before linking
systemctl stop suricata 2>/dev/null || true
systemctl stop zeek 2>/dev/null || true

if [ ! -L /var/log/suricata ]; then
    rm -rf /var/log/suricata
    ln -s "${MOUNT_POINT}/suricata" /var/log/suricata
fi

if [ ! -L /var/log/zeek ]; then
    rm -rf /var/log/zeek
    ln -s "${MOUNT_POINT}/zeek" /var/log/zeek
fi

# Configure Logrotate for Zeek and Suricata to compress logs daily
cat << 'EOF' > /etc/logrotate.d/pi4-ndr-sensor
/var/log/suricata/*.json /var/log/suricata/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}

/var/log/zeek/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
}
EOF

echo "[✔] External storage configuration complete. Logs will be stored on ${MOUNT_POINT}."
