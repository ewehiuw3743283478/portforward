#!/usr/bin/env bash
# Remove the Port Forward systemd unit. Application files are left in place.
set -euo pipefail

usage() {
    cat <<'EOF'
Remove the Port Forward systemd service.

Usage:
  sudo ./scripts/uninstall-service.sh

This stops and disables the unit and deletes /etc/systemd/system/portforward.service.
It does not delete the app directory, .env, ports.json, or data/auth.json.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

if [[ ! -d /run/systemd/system ]]; then
    echo "systemd is not running on this host." >&2
    exit 1
fi

UNIT_DST="/etc/systemd/system/portforward.service"

if systemctl list-unit-files portforward.service >/dev/null 2>&1; then
    systemctl disable --now portforward.service 2>/dev/null || true
fi

if [[ -f "$UNIT_DST" ]]; then
    rm -f "$UNIT_DST"
    echo "Removed $UNIT_DST"
else
    echo "No unit file at $UNIT_DST"
fi

systemctl daemon-reload
systemctl reset-failed portforward.service 2>/dev/null || true

echo "Service uninstalled. App files were not deleted."
echo "To wipe login state as well: rm -rf data/auth.json"
