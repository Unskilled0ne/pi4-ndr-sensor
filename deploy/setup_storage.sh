#!/usr/bin/env bash
set -euo pipefail

TARGET_LABEL="${1:-LOOT}"
MOUNT_POINT="/mnt/sensor_storage"

if [[ ! "$TARGET_LABEL" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "[-] Invalid filesystem label: '${TARGET_LABEL}'" >&2
    exit 1
fi

if ! blkid -L "${TARGET_LABEL}" >/dev/null 2>&1; then
    echo "[-] Partition with LABEL=${TARGET_LABEL} not found" >&2
    exit 1
fi

mkdir -p "${MOUNT_POINT}"

if ! grep -q "LABEL=${TARGET_LABEL}" /etc/fstab; then
    echo "LABEL=${TARGET_LABEL} ${MOUNT_POINT} ext4 defaults,noatime,nofail 0 2" >> /etc/fstab
fi

mount "${MOUNT_POINT}" 2>/dev/null || mount -a || true

mkdir -p "${MOUNT_POINT}/suricata" "${MOUNT_POINT}/zeek" "${MOUNT_POINT}/offsets"
chmod 750 "${MOUNT_POINT}/suricata" "${MOUNT_POINT}/zeek" "${MOUNT_POINT}/offsets"

if id ndrsensor >/dev/null 2>&1; then
    chown -R ndrsensor:adm "${MOUNT_POINT}/suricata" "${MOUNT_POINT}/zeek" "${MOUNT_POINT}/offsets"
fi

systemctl stop suricata 2>/dev/null || true
systemctl stop zeek 2>/dev/null || true

for svc in suricata zeek; do
    log_dir="/var/log/${svc}"
    target_dir="${MOUNT_POINT}/${svc}"
    if [ -d "${log_dir}" ] && [ ! -L "${log_dir}" ]; then
        mv "${log_dir}"/* "${target_dir}/" 2>/dev/null || true
        rmdir "${log_dir}" 2>/dev/null || rm -rf "${log_dir}"
        ln -s "${target_dir}" "${log_dir}"
    elif [ ! -e "${log_dir}" ]; then
        ln -s "${target_dir}" "${log_dir}"
    fi
done

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

chmod 644 /etc/logrotate.d/pi4-ndr-sensor
echo "[+] Storage configuration applied on ${MOUNT_POINT}."
