#!/usr/bin/env bash
# Install Port Forward as a systemd service for the current checkout.
set -euo pipefail

usage() {
    cat <<'EOF'
Install Port Forward as a systemd service.

Usage:
  sudo ./scripts/install-service.sh [--no-start]

The unit always points at this repository directory (it does not copy files
to /opt). Recommended layout:

  /opt/portforward
EOF
}

NO_START=0
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage; exit 0 ;;
        --no-start) NO_START=1 ;;
        *)
            echo "Unknown option: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo $0 $*" >&2
    exit 1
fi

if [[ ! -d /run/systemd/system ]]; then
    echo "systemd is not running on this host. This installer only supports systemd." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_SRC="$ROOT/deploy/portforward.service"
UNIT_DST="/etc/systemd/system/portforward.service"
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ROOT/app.js" || ! -f "$UNIT_SRC" ]]; then
    echo "Cannot find app.js or deploy/portforward.service under $ROOT" >&2
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "node is not on PATH. Install Node.js 18 or newer." >&2
    exit 1
fi

NODE="$(command -v node)"
if command -v readlink >/dev/null 2>&1; then
    NODE="$(readlink -f "$NODE")"
fi

NODE_MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if [[ "$NODE_MAJOR" -lt 18 ]]; then
    echo "Node.js 18 or newer is required (found $(node -v))." >&2
    exit 1
fi

if [[ ! -x /usr/bin/socat ]]; then
    echo "socat not found at /usr/bin/socat. Install it before starting the service." >&2
    echo "  Debian/Ubuntu: apt-get install -y socat iptables" >&2
    echo "  RHEL/Fedora:   dnf install -y socat iptables" >&2
fi

if [[ ! -d "$ROOT/node_modules" ]]; then
    echo "Installing npm dependencies in $ROOT"
    (cd "$ROOT" && npm install --omit=dev)
fi

if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ROOT/.env.example" "$ENV_FILE"
    echo "Created $ENV_FILE from .env.example — edit it before the first start."
fi
chmod 600 "$ENV_FILE"

env_get() {
    local key="$1"
    local line
    line="$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 || true)"
    [[ -n "$line" ]] || return 0
    printf '%s' "${line#*=}"
}

PANEL_PORT="$(env_get PORT)"
PUBLIC_IP="$(env_get SERVER_PUBLIC_IP)"
BIND_HOST="$(env_get BIND_HOST)"
BIND_HOST="${BIND_HOST:-0.0.0.0}"

PLACEHOLDER=0
if [[ -z "$PUBLIC_IP" || "$PUBLIC_IP" == "your.public.ip.address" || "$PUBLIC_IP" == "203.0.113.10" ]]; then
    PLACEHOLDER=1
fi

tmp="$(mktemp)"
sed \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$ROOT|" \
    -e "s|^ExecStart=.*|ExecStart=$NODE $ROOT/app.js|" \
    "$UNIT_SRC" > "$tmp"
install -m 644 "$tmp" "$UNIT_DST"
rm -f "$tmp"

systemctl daemon-reload
systemctl enable portforward.service

echo
echo "Installed portforward.service"
echo "  App dir : $ROOT"
echo "  Node    : $NODE"
echo "  Unit    : $UNIT_DST"
echo "  Config  : $ENV_FILE"
echo

if [[ $NO_START -eq 1 ]]; then
    echo "Skipped start (--no-start). When .env is ready:"
    echo "  sudo systemctl start portforward"
    exit 0
fi

if [[ $PLACEHOLDER -eq 1 ]]; then
    echo "SERVER_PUBLIC_IP in .env still looks like a placeholder."
    echo "Edit $ENV_FILE, then start the service:"
    echo "  sudo nano $ENV_FILE"
    echo "  sudo systemctl start portforward"
    exit 0
fi

systemctl restart portforward.service
sleep 0.4
if ! systemctl is-active --quiet portforward.service; then
    echo "Service failed to start. Last log lines:" >&2
    journalctl -u portforward.service -n 40 --no-pager >&2 || true
    exit 1
fi

echo "Service is active."
echo "  sudo systemctl status portforward"
echo "  sudo journalctl -u portforward -f"
if [[ "$BIND_HOST" == "0.0.0.0" ]]; then
    echo "  Panel: http://${PUBLIC_IP:-<server-ip>}:${PANEL_PORT:-392}/login"
else
    echo "  Panel: http://${BIND_HOST}:${PANEL_PORT:-392}/login"
fi
echo
echo "First sign-in uses AUTH_USER / AUTH_PASS from .env, then you must set a new password."
echo "Enable an authenticator app under Security."
