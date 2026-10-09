# AEZA Hysteria2 VPN watchdog

This repository monitors Hysteria2 from a GitHub-hosted runner, independently of the AEZA VPS. It first verifies actual HTTPS traffic through a local Hysteria2 client proxy. It also checks that AEZA server ID `1983582` still resolves to IP `89.22.238.198` and reports `active` before it will consider a reboot.

## Safety defaults

- `ENABLE_REBOOT` defaults to `false`; initial runs are monitoring-only.
- Hysteria2 is checked with an HTTPS request through a SOCKS5 proxy, not just with a port check.
- Auto-reboot requires two consecutive failed scheduled runs and a successful AEZA read-only identity/status check.
- Cooldown: six hours between accepted reboot requests.
- Hard limit: two reboot requests in a rolling 24-hour window.
- After an accepted reboot request the script makes best-effort recovery checks.
- Optional Telegram notifications are sent only on state changes and reboot/recovery events.
- Do not put API keys or a Hysteria2 URI in repository files. Use GitHub Actions secrets.

GitHub scheduled runs can be delayed or dropped during heavy load. This is a lightweight external monitor, not a guarantee of immediate recovery.

## GitHub configuration

In `Settings → Secrets and variables → Actions`, create repository secrets:

1. `AEZA_API_KEY` — AEZA API key.
2. `HYSTERIA2_URI` — the full Hysteria2 share URI beginning with `hysteria2://` or `hy2://`. Obtain it from the Windows VPN client (copy/share/export profile link) and paste it directly into GitHub; never put it in a commit or public message. The watchdog supports the standard single-port URI format, auth, SNI, `insecure`, Salamander/Gecko obfuscation, `pinSHA256`, and ECH.
3. Optional: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` for notifications. Leave both absent if not wanted.

Create repository variable `ENABLE_REBOOT` with value `false` initially, or leave it unset. Go to `Actions → AEZA Hysteria2 VPN watchdog → Run workflow` to make the first manual check. In the run logs, confirm:

- `AEZA API confirms expected VPS is active`
- `Real HTTPS request through Hysteria2 succeeded`
- `auto-reboot=disabled / monitor-only`

Watch several scheduled runs before enabling reboot. Only after those checks look correct, change `ENABLE_REBOOT` to `true`. If a run says the expected server could not be verified, it blocks reboot.

## AEZA API action

The read-only check uses `GET /api/services/1983582`. A guarded reboot uses `POST /api/services/1983582/ctl` with `{"action":"reboot"}`. AEZA's archived SDK documents `resume`, `suspend`, and `reboot` as `ctl` actions; the actual reboot action must remain disabled until the monitoring phase has been verified.
