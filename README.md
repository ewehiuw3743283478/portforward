# portforward

Web UI for forwarding TCP/UDP ports on this machine to internal hosts. Supports **socat** (userland proxy) and **iptables** (kernel DNAT). The panel uses a session login, bcrypt-hashed passwords, and optional authenticator-app (TOTP) two-factor auth.

Recommended install is as a **systemd service**. `systemctl stop` tears down socat processes and iptables rules; they come back from `ports.json` on the next start.

## Quick start (systemd)

On a Linux host with root, Node.js 18+, `socat`, and `iptables`:

```bash
sudo mkdir -p /opt/portforward
sudo git clone https://github.com/ewehiuw3743283478/portforward.git /opt/portforward
cd /opt/portforward
sudo cp .env.example .env
sudo nano .env          # set SERVER_PUBLIC_IP, AUTH_USER, AUTH_PASS
sudo ./scripts/install-service.sh
```

The installer writes `/etc/systemd/system/portforward.service` pointing at **this directory**, enables the unit, and starts it when `.env` looks complete.

```bash
sudo systemctl status portforward
sudo journalctl -u portforward -f
```

Open `http://SERVER_PUBLIC_IP:PORT/login` (default port `392`). Sign in with `AUTH_USER` / `AUTH_PASS`, set a new panel password, then turn on 2FA under **Security**.

Already cloned somewhere else? Run `sudo ./scripts/install-service.sh` from that checkout. The unit will use that path; you do not have to move the files to `/opt`.

## Requirements

- Linux with **systemd**
- **Node.js 18+**
- **socat** at `/usr/bin/socat`
- **iptables** (NAT DNAT, filter `PORTFORWARD` chain, and MASQUERADE)
- **ufw** (optional; used in addition to iptables when the binary is present)
- **root** — the process binds privileged ports and edits firewall / NAT rules

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y nodejs npm socat iptables

# RHEL / Fedora
sudo dnf install -y nodejs npm socat iptables
```

If `node -v` is older than 18, install a current Node from NodeSource or your distro’s current stream before running the installer.

## socat vs iptables

| | socat | iptables |
| --- | --- | --- |
| How | Userspace proxy | Kernel DNAT |
| Destination setup | None | Return path **must** go through this server (usually this box is the default gateway) |
| Client IP seen by destination | This server’s IP | The original client IP |
| When to use | You want it to work | You need the real client IP |

The add form in the UI repeats this in short form.

## Interfaces and firewall

Each forward can pick:

- **Inbound NIC** — where public traffic arrives (`All interfaces`, or a specific card such as `eth0`). Socat binds that card; iptables DNAT matches `-i` on that card.
- **Outbound NIC** — which card is used to reach the destination (`Auto` uses the kernel routing table). Socat binds the connect socket to that card; iptables DNAT also adds `MASQUERADE` on it so replies can return.
- **Open this port in UFW and iptables** — when checked (the default), the panel:
  1. Inserts an `ACCEPT` in a dedicated iptables filter chain named `PORTFORWARD` (INPUT for the listen port; FORWARD as well when the method is iptables DNAT)
  2. If `ufw` is installed, runs the matching `ufw allow` / `ufw route allow` commands

Removing the forward deletes those same rules. `systemctl stop portforward` flushes the `PORTFORWARD` chain. Existing UFW/iptables policy that you created by hand is left alone.

`FORWARD` is often `DROP` on Docker hosts. Opening the port this way is what actually lets DNAT traffic through.

## Configuration

All settings live in `.env` next to `app.js`. The service loads that file by path, so it does not depend on the process working directory.

```bash
sudo cp .env.example .env
sudo chmod 600 .env
sudo nano .env
```

| Variable | Required | Meaning |
| --- | --- | --- |
| `PORT` | yes | Panel listen port (the UI, not a forwarded port) |
| `BIND_HOST` | no | Address to bind. Default `0.0.0.0`. Use `127.0.0.1` behind a reverse proxy |
| `SERVER_PUBLIC_IP` | yes | This server’s public IPv4. Shown in the UI and used in iptables DNAT |
| `AUTH_USER` | first start | Bootstrap username (3–32 chars: letters, numbers, `.` `_` `-`) |
| `AUTH_PASS` | first start | Bootstrap password, min 8 chars. Used **once** to create `data/auth.json` |
| `SESSION_SECRET` | no | Cookie signing key. Generated into `data/auth.json` if omitted |
| `COOKIE_SECURE` | no | `true` when the panel is served over HTTPS |
| `TRUST_PROXY` | no | `true` when TLS is terminated on a reverse proxy |

`AUTH_USER` / `AUTH_PASS` are **not** the live login after the first successful start. The hashed password in `data/auth.json` is. Changing `.env` later will not change the password. Reset instructions are below.

After first sign-in the UI requires a new password (at least 10 characters).

## Using the panel

1. Sign in at `/login`. If 2FA is on, enter the authenticator code or a backup code.
2. **Add a forward:** destination IP, listen port, destination port, inbound/outbound NIC, TCP/UDP, socat or iptables. Leave “Open this port in UFW and iptables” checked unless the hole already exists.
3. The table lists active mappings, NICs, and whether the firewall was opened. Filter, copy `IP:port`, or remove (stops immediately and closes the hole we opened).
4. **Security:** change username/password, enable TOTP, save backup codes.

Mappings are stored in `ports.json` and restored whenever the process starts.

## Run as a service

### Install / update the unit

```bash
cd /opt/portforward          # or your clone
sudo ./scripts/install-service.sh
```

Options:

```bash
sudo ./scripts/install-service.sh --no-start   # enable only; start later yourself
sudo npm run install-service                   # same script; still needs root
```

What the script does:

1. Checks root, systemd, Node 18+, and `app.js`
2. Runs `npm install --omit=dev` if `node_modules` is missing
3. Creates `.env` from `.env.example` if needed (`chmod 600`)
4. Writes `/etc/systemd/system/portforward.service` with this repo path and the real `node` binary
5. `systemctl enable --now portforward` when `SERVER_PUBLIC_IP` is set

### Everyday commands

```bash
sudo systemctl status portforward
sudo systemctl start portforward
sudo systemctl stop portforward      # also drops live socat/iptables forwards
sudo systemctl restart portforward   # reloads ports.json
sudo journalctl -u portforward -f
sudo journalctl -u portforward -n 100 --no-pager
```

`stop` is a real stop: the process handles `SIGTERM`, kills socat children, and deletes its iptables DNAT rules. `start` reapplies whatever is in `ports.json`.

### Upgrade

```bash
cd /opt/portforward
sudo git pull
sudo npm install --omit=dev
sudo systemctl restart portforward
```

If `install-service.sh` already ran, you do not need to run it again unless the unit template in `deploy/portforward.service` changed.

### Uninstall the service

```bash
sudo ./scripts/uninstall-service.sh
```

This only removes the systemd unit. The app directory, `.env`, `ports.json`, and `data/auth.json` stay. Delete those yourself if you want a clean disk.

## Manual run (no systemd)

```bash
cd /opt/portforward
cp .env.example .env
nano .env
npm install
sudo node app.js
```

Ctrl+C sends SIGINT and stops forwards the same way as `systemctl stop`.

## HTTPS / reverse proxy

Do not put this panel on the public internet in cleartext. Prefer a VPN, SSH tunnel, or TLS proxy.

1. Set in `.env`:

   ```env
   BIND_HOST=127.0.0.1
   COOKIE_SECURE=true
   TRUST_PROXY=true
   ```

2. `sudo systemctl restart portforward`
3. Point nginx or Caddy at `127.0.0.1:392`. A full nginx server block is in [`deploy/nginx.example.conf`](deploy/nginx.example.conf).

Caddy equivalent:

```caddy
panel.example.com {
    reverse_proxy 127.0.0.1:392
}
```

## Reset login / lost authenticator

```bash
sudo systemctl stop portforward
sudo rm -f data/auth.json
# set AUTH_USER and AUTH_PASS in .env
sudo systemctl start portforward
```

The next start recreates `data/auth.json` from `.env`. You will be asked to choose a new panel password again.

## Backup

Keep copies of:

- `.env` (bootstrap + bind settings)
- `data/auth.json` (live login, TOTP secret, hashed backup codes)
- `ports.json` (forward list)

`data/` is mode `700` and `data/auth.json` is `600`. Do not commit them.

## Files

| Path | Role |
| --- | --- |
| `app.js` | HTTP panel + forward control |
| `.env` | Config (not in git) |
| `ports.json` | Saved forwards |
| `data/auth.json` | Hashed login / TOTP (created at runtime) |
| `deploy/portforward.service` | systemd unit template |
| `scripts/install-service.sh` | Install / enable / start |
| `scripts/uninstall-service.sh` | Stop and remove the unit |
| `deploy/nginx.example.conf` | TLS reverse-proxy example |

## Security notes

- The service runs as **root** because it must bind low ports and call `iptables`. Treat the panel like a firewall console.
- Use a unique password and enable 2FA. Lockout is 5 failed tries / 15 minutes, plus per-IP rate limits on `/login`.
- Prefer `BIND_HOST=127.0.0.1` plus TLS rather than exposing `PORT` on `0.0.0.0`.
- `COOKIE_SECURE=true` is required for the session cookie to be marked Secure on HTTPS.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `systemctl start` fails | `journalctl -u portforward -n 50 --no-pager` — usually missing `.env` keys or a bad `SERVER_PUBLIC_IP` |
| `Cannot listen on … EADDRINUSE` | Another process (or an old `node app.js`) owns `PORT` |
| Login loops / cookie missing | HTTPS without `COOKIE_SECURE` and `TRUST_PROXY`, or a proxy stripping cookies |
| iptables forward does not connect | Destination must route replies through this server |
| socat forward works, source IP is wrong | Expected: socat hides the client IP. Use iptables if you need it |
| Lost password | Delete `data/auth.json` and restart (see above) |
| Unit points at the wrong directory | Re-run `sudo ./scripts/install-service.sh` from the clone you want |
| Log line about `MemoryStore` | Harmless on a single-process panel. Sessions reset if the service restarts |

## Origin

This repository is based on [ShiSHcat/portforward](https://github.com/ShiSHcat/portforward) (public domain).

## Security contact

Report security issues to [me@shish.cat](mailto:me@shish.cat).
