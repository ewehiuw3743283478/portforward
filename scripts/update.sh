#!/usr/bin/env bash
# Pull the latest Port Forward from git, refresh dependencies, and restart the service.
set -euo pipefail

usage() {
    cat <<'EOF'
Update this Port Forward checkout from git and restart the systemd service.

Usage:
  sudo ./scripts/update.sh
  sudo ./scripts/update.sh --no-restart
  sudo ./scripts/update.sh --from-panel   # delay restart so the web UI can respond

Keeps .env, data/, and ports.json. Other local edits can make git pull fail.
EOF
}

NO_RESTART=0
FROM_PANEL=0
for arg in "$@"; do
    case "$arg" in
        -h|--help) usage; exit 0 ;;
        --no-restart) NO_RESTART=1 ;;
        --from-panel) FROM_PANEL=1 ;;
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

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .git ]]; then
    echo "Not a git checkout. Clone https://github.com/ewehiuw3743283478/portforward.git to use update." >&2
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    echo "git is not installed." >&2
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "node is not on PATH." >&2
    exit 1
fi

export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=echo

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" == "HEAD" ]]; then
    echo "Detached HEAD. Check out master (or main) before updating." >&2
    exit 1
fi

PORTS_BAK=""
if [[ -f "$ROOT/ports.json" ]]; then
    PORTS_BAK="$(mktemp)"
    cp "$ROOT/ports.json" "$PORTS_BAK"
fi
restore_ports() {
    if [[ -n "$PORTS_BAK" && -f "$PORTS_BAK" ]]; then
        cp "$PORTS_BAK" "$ROOT/ports.json"
        rm -f "$PORTS_BAK"
    fi
}
trap restore_ports EXIT

echo "Fetching origin…"
git fetch --quiet origin

REMOTE_REF=""
if git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1; then
    REMOTE_REF="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}')"
elif git rev-parse --verify "origin/${BRANCH}" >/dev/null 2>&1; then
    REMOTE_REF="origin/${BRANCH}"
elif git rev-parse --verify origin/master >/dev/null 2>&1; then
    REMOTE_REF="origin/master"
elif git rev-parse --verify origin/main >/dev/null 2>&1; then
    REMOTE_REF="origin/main"
fi

if [[ -z "$REMOTE_REF" ]]; then
    echo "No origin branch to pull (tried origin/${BRANCH}, origin/master, origin/main)." >&2
    exit 1
fi

LOCAL="$(git rev-parse --short HEAD)"
REMOTE="$(git rev-parse --short "$REMOTE_REF")"
echo "Local  $LOCAL ($BRANCH)"
echo "Remote $REMOTE ($REMOTE_REF)"

if [[ "$LOCAL" == "$REMOTE" ]]; then
    echo "Already up to date."
else
    echo "Pulling $REMOTE_REF…"
    git merge --ff-only "$REMOTE_REF"
fi

restore_ports
trap - EXIT

echo "Installing npm dependencies…"
npm install --omit=dev

if [[ -x "$ROOT/scripts/install-service.sh" && -d /run/systemd/system ]]; then
    echo "Refreshing systemd unit…"
    bash "$ROOT/scripts/install-service.sh" --no-start
fi

if [[ $NO_RESTART -eq 1 ]]; then
    echo "Skipped restart (--no-restart)."
    echo "Start with: sudo systemctl restart portforward"
    exit 0
fi

if [[ $FROM_PANEL -eq 1 ]]; then
    echo "Waiting 2s so the panel can answer, then restarting…"
    sleep 2
fi

if [[ -d /run/systemd/system ]]; then
    systemctl reset-failed portforward.service 2>/dev/null || true
    echo "Restarting portforward.service…"
    systemctl restart portforward.service
    sleep 0.4
    if systemctl is-active --quiet portforward.service; then
        echo "Update complete. Service is active."
    else
        echo "Service did not come back. Logs:" >&2
        journalctl -u portforward.service -n 40 --no-pager >&2 || true
        exit 1
    fi
else
    echo "systemd is not running; restart the process yourself."
fi
