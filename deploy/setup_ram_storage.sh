#!/usr/bin/env bash
set -euo pipefail

# Provision in-memory tmpfs logging buffer to eliminate MicroSD wear
# Recommended for standalone Raspberry Pi 4 nodes without external USB3 SSDs

RAM_MOUNT="/mnt/sensor_ram"
RAM_SIZE="${1:-256M}"
ARCHIVE_DIR="/var/log/sensor_archive"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Must be run as root" >&2
    exit 1
fi

echo "[*] Provisioning ${RAM_SIZE} in-memory tmpfs at ${RAM_MOUNT}..."
mkdir -p "${RAM_MOUNT}" "${ARCHIVE_DIR}"

# 1. Add fstab entry for persistence across reboots
if ! grep -q "${RAM_MOUNT}" /etc/fstab; then
    echo "tmpfs ${RAM_MOUNT} tmpfs defaults,noatime,nosuid,nodev,noexec,mode=0750,size=${RAM_SIZE} 0 0" >> /etc/fstab
    echo "[+] Added tmpfs mount to /etc/fstab"
fi

mount "${RAM_MOUNT}" 2>/dev/null || mount -a || true

# 2. Structure directories inside RAM disk
mkdir -p "${RAM_MOUNT}/suricata" "${RAM_MOUNT}/zeek"
chmod 750 "${RAM_MOUNT}/suricata" "${RAM_MOUNT}/zeek"

if id ndrsensor >/dev/null 2>&1; then
    chown -R ndrsensor:adm "${RAM_MOUNT}/suricata" "${RAM_MOUNT}/zeek"
fi

# 3. Gracefully stop services to switch symlinks
systemctl stop suricata 2>/dev/null || true
systemctl stop zeek 2>/dev/null || true

for svc in suricata zeek; do
    log_dir="/var/log/${svc}"
    target_dir="${RAM_MOUNT}/${svc}"
    if [ -d "${log_dir}" ] && [ ! -L "${log_dir}" ]; then
        mv "${log_dir}"/* "${target_dir}/" 2>/dev/null || true
        rmdir "${log_dir}" 2>/dev/null || rm -rf "${log_dir}"
        ln -s "${target_dir}" "${log_dir}"
    elif [ ! -e "${log_dir}" ]; then
        ln -s "${target_dir}" "${log_dir}"
    fi
    echo "[+] Redirected /var/log/${svc} -> ${target_dir} (tmpfs RAM)"
done

# 4. Aggressive logrotate for RAM disk to prevent OOM
cat << 'EOF' > /etc/logrotate.d/pi4-ndr-ram-storage
/mnt/sensor_ram/suricata/*.json /mnt/sensor_ram/suricata/*.log {
    size 30M
    rotate 4
    compress
    missingok
    notifempty
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}

/mnt/sensor_ram/zeek/*.log {
    size 20M
    rotate 4
    compress
    missingok
    notifempty
}
EOF

chmod 644 /etc/logrotate.d/pi4-ndr-ram-storage
echo "[+] In-memory tmpfs logging buffer active on ${RAM_MOUNT} (MicroSD flash writes eliminated)."
