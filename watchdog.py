#!/usr/bin/env python3
"""External Hysteria2 reachability monitor with guarded AEZA reboot support.

Secrets are provided only through environment variables. Never print config or URI.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

AEZA_BASE = "https://my.aeza.net/api"
SERVER_ID = 1983582
EXPECTED_IP = "89.22.238.198"
STATE_FILE = Path(".watchdog-state/state.json")
HYSTERIA_BIN = Path("/tmp/hysteria")
SOCKS_ADDR = "127.0.0.1:1080"
CHECK_URL = "https://www.cloudflare.com/cdn-cgi/trace"
COOLDOWN_SECONDS = 6 * 60 * 60
MAX_REBOOTS_PER_24H = 2
FAIL_RUNS_BEFORE_REBOOT = 2


def now_ts() -> int:
    return int(time.time())


def utc_iso(ts: int | None = None) -> str:
    return datetime.fromtimestamp(ts or now_ts(), timezone.utc).isoformat(timespec="seconds")


def log(message: str) -> None:
    print(f"[{utc_iso()}] {message}", flush=True)


def load_state() -> dict:
    default = {
        "last_check_utc": None,
        "last_health": "unknown",
        "consecutive_failed_runs": 0,
        "last_reboot_epoch": 0,
        "reboot_epochs": [],
    }
    try:
        if STATE_FILE.exists():
            saved = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                default.update(saved)
    except Exception as exc:
        log(f"State file unreadable; using safe defaults ({type(exc).__name__}).")
    default["reboot_epochs"] = [
        int(x) for x in default.get("reboot_epochs", [])
        if isinstance(x, (int, float)) and now_ts() - int(x) < 24 * 60 * 60
    ]
    try:
        default["consecutive_failed_runs"] = max(0, int(default["consecutive_failed_runs"]))
        default["last_reboot_epoch"] = max(0, int(default["last_reboot_epoch"]))
    except Exception:
        default["consecutive_failed_runs"] = 0
        default["last_reboot_epoch"] = 0
    return default


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def notify_telegram(message: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        log("Telegram notifications are not configured; details remain in GitHub Actions logs.")
        return
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            if response.status not in (200, 201):
                log(f"Telegram notification returned HTTP {response.status}.")
    except Exception as exc:
        # Don't let a notification outage interfere with monitoring/recovery.
        log(f"Telegram notification failed ({type(exc).__name__}).")


def aeza_request(method: str, path: str, payload: dict | None = None) -> dict:
    token = os.environ.get("AEZA_API_KEY", "").strip()
    if not token:
        raise RuntimeError("AEZA_API_KEY secret is not configured")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        AEZA_BASE + path,
        data=data,
        headers={
            "X-API-Key": token,
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read().decode("utf-8", errors="replace")
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"AEZA returned HTTP {response.status}")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise RuntimeError("Unexpected AEZA API response")
    return result


def check_aeza_server() -> tuple[bool, str]:
    try:
        data = aeza_request("GET", f"/services/{SERVER_ID}")
        root = data.get("data", data)
        items = root.get("items", []) if isinstance(root, dict) else []
        server = next((x for x in items if isinstance(x, dict) and int(x.get("id", -1)) == SERVER_ID), None)
        if server is None and isinstance(root, dict) and root.get("id") == SERVER_ID:
            server = root
        if not server:
            return False, "AEZA API response did not contain the expected server ID"
        ip = server.get("ip")
        status = str(server.get("status", server.get("currentStatus", "unknown"))).lower()
        if ip != EXPECTED_IP:
            return False, f"AEZA server ID resolved to unexpected IP ({ip!r}); reboot blocked"
        if status != "active":
            return False, f"AEZA reports server status {status!r}; reboot blocked"
        return True, "AEZA API confirms expected VPS is active"
    except Exception as exc:
        return False, f"AEZA API check failed ({type(exc).__name__})"


def qscalar(value: str) -> str:
    # JSON strings are valid YAML double-quoted scalars.
    return json.dumps(value, ensure_ascii=False)


def hysteria_config_from_uri(uri_text: str) -> str:
    raw = uri_text.strip()
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme.lower() not in ("hysteria2", "hy2"):
        raise ValueError("HYSTERIA2_URI must start with hysteria2:// or hy2://")
    if not parsed.hostname:
        raise ValueError("HYSTERIA2_URI does not contain a server hostname")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("Port hopping or an invalid port in HYSTERIA2_URI is not supported by this watchdog yet") from exc
    if not parsed.username:
        raise ValueError("HYSTERIA2_URI does not contain authentication data")
    auth = urllib.parse.unquote(parsed.username)
    if parsed.password is not None:
        auth += ":" + urllib.parse.unquote(parsed.password)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)

    def first(key: str, default: str = "") -> str:
        vals = query.get(key)
        return vals[0] if vals else default

    server = f"[{parsed.hostname}]:{port}" if ":" in parsed.hostname else f"{parsed.hostname}:{port}"
    lines = [f"server: {qscalar(server)}", f"auth: {qscalar(auth)}", "socks5:", "  listen: \"127.0.0.1:1080\""]
    lines.extend(["tls:", f"  sni: {qscalar(first('sni', parsed.hostname))}", f"  insecure: {'true' if first('insecure', '0').lower() in ('1', 'true', 'yes') else 'false'}"])
    pin = first("pinSHA256")
    ech = first("ech")
    if pin:
        lines.append(f"  pinSHA256: {qscalar(pin)}")
    if ech:
        lines.append(f"  ech: {qscalar(ech)}")
    obfs = first("obfs")
    obfs_password = first("obfs-password")
    if obfs:
        if obfs not in ("salamander", "gecko"):
            raise ValueError(f"Unsupported Hysteria2 obfs type: {obfs}")
        if not obfs_password:
            raise ValueError("HYSTERIA2_URI specifies obfs but has no obfs-password")
        lines.extend(["obfs:", f"  type: {qscalar(obfs)}", f"  {obfs}:", f"    password: {qscalar(obfs_password)}"])
    return "\n".join(lines) + "\n"


def proxy_request_once() -> tuple[bool, str]:
    uri = os.environ.get("HYSTERIA2_URI", "").strip()
    if not uri:
        return False, "HYSTERIA2_URI secret is not configured"
    if not HYSTERIA_BIN.exists():
        return False, "Hysteria2 client binary was not found on the GitHub runner"

    config_path: Path | None = None
    log_path: Path | None = None
    process: subprocess.Popen | None = None
    try:
        config_text = hysteria_config_from_uri(uri)
        fd, config_name = tempfile.mkstemp(prefix="hy2-watchdog-", suffix=".yaml", dir="/tmp")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(config_text)
        config_path = Path(config_name)
        log_fd, log_name = tempfile.mkstemp(prefix="hy2-watchdog-", suffix=".log", dir="/tmp")
        log_path = Path(log_name)
        log_file = os.fdopen(log_fd, "w", encoding="utf-8")
        process = subprocess.Popen(
            [str(HYSTERIA_BIN), "client", "-c", str(config_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        # Give the local SOCKS proxy time to bind, then probe real HTTPS over it.
        time.sleep(2)
        if process.poll() is not None:
            return False, "Hysteria2 client exited before proxy check"
        for probe in range(1, 4):
            if process.poll() is not None:
                return False, "Hysteria2 client exited during proxy check"
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--fail", "--proxy", "socks5h://127.0.0.1:1080",
                 "--connect-timeout", "8", "--max-time", "16", CHECK_URL],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=18,
                check=False,
            )
            if result.returncode == 0 and "ip=" in result.stdout and "http=" in result.stdout:
                return True, f"Real HTTPS request through Hysteria2 succeeded (probe {probe}/3)"
            if probe < 3:
                time.sleep(4)
        return False, "All 3 HTTPS-through-Hysteria2 probes failed"
    except Exception as exc:
        return False, f"VPN check errored ({type(exc).__name__})"
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        if config_path is not None:
            config_path.unlink(missing_ok=True)
        if log_path is not None:
            log_path.unlink(missing_ok=True)


def post_reboot() -> tuple[bool, str]:
    try:
        result = aeza_request("POST", f"/services/{SERVER_ID}/ctl", {"action": "reboot"})
        # Do not print response body: it is unnecessary and may contain account details.
        return True, "AEZA accepted the reboot request"
    except urllib.error.HTTPError as exc:
        return False, f"AEZA rejected reboot request with HTTP {exc.code}"
    except Exception as exc:
        return False, f"AEZA reboot request failed ({type(exc).__name__})"


def main() -> int:
    state = load_state()
    state["last_check_utc"] = utc_iso()
    enable_reboot = os.environ.get("ENABLE_REBOOT", "false").strip().lower() == "true"
    log(f"Checking Hysteria2 VPN for AEZA VPS ID {SERVER_ID} ({EXPECTED_IP}); auto-reboot={'ENABLED' if enable_reboot else 'disabled / monitor-only'}.")

    # AEZA check is read-only and is also required as a safety guard before any reboot.
    api_ok, api_message = check_aeza_server()
    log(api_message + ("." if not api_message.endswith(".") else ""))

    healthy, health_message = proxy_request_once()
    log(health_message + ("." if not health_message.endswith(".") else ""))

    previous_health = state.get("last_health", "unknown")
    if healthy:
        failed_before = int(state.get("consecutive_failed_runs", 0))
        state["consecutive_failed_runs"] = 0
        state["last_health"] = "healthy"
        if previous_health == "down" or failed_before > 0:
            notify_telegram("✅ VPN AEZA восстановлен: Hysteria2 передаёт HTTPS-трафик. VPS 89.22.238.198.")
        save_state(state)
        return 0

    state["consecutive_failed_runs"] = int(state.get("consecutive_failed_runs", 0)) + 1
    failures = state["consecutive_failed_runs"]
    state["last_health"] = "down"
    log(f"Consecutive failed scheduled runs: {failures}/{FAIL_RUNS_BEFORE_REBOOT} before reboot eligibility.")
    if previous_health != "down":
        notify_telegram(f"⚠️ VPN Hysteria2 не прошёл внешнюю HTTPS-проверку. Проверка {failures}/{FAIL_RUNS_BEFORE_REBOOT}. Автоперезагрузка {'разрешена' if enable_reboot else 'пока выключена'}.")

    if not enable_reboot:
        log("Monitor-only mode: no reboot command will be sent.")
        save_state(state)
        return 0

    if failures < FAIL_RUNS_BEFORE_REBOOT:
        log("Reboot skipped: waiting for another failed scheduled run.")
        save_state(state)
        return 0
    if not api_ok:
        log("Reboot BLOCKED because AEZA read-only server verification failed.")
        save_state(state)
        return 0

    now = now_ts()
    last_reboot = int(state.get("last_reboot_epoch", 0))
    recent_reboots = [int(x) for x in state.get("reboot_epochs", []) if now - int(x) < 24 * 60 * 60]
    if last_reboot and now - last_reboot < COOLDOWN_SECONDS:
        log("Reboot BLOCKED by 6-hour cooldown.")
        save_state(state)
        return 0
    if len(recent_reboots) >= MAX_REBOOTS_PER_24H:
        log("Reboot BLOCKED: maximum of 2 reboot requests in a rolling 24-hour period reached.")
        save_state(state)
        return 0

    log("Safety checks passed. Sending reboot request to AEZA.")
    accepted, reboot_message = post_reboot()
    log(reboot_message + ".")
    if not accepted:
        save_state(state)
        notify_telegram("❌ VPN монитор: AEZA не приняла команду перезагрузки. Проверь GitHub Actions logs.")
        return 0

    state["last_reboot_epoch"] = now
    state["reboot_epochs"] = recent_reboots + [now]
    state["consecutive_failed_runs"] = 0
    save_state(state)
    notify_telegram("🔄 VPN не отвечал после повторных проверок. AEZA приняла запрос на перезагрузку VPS 89.22.238.198. Проверяю восстановление.")

    # Best-effort recovery check; the following scheduled run remains a second safety net.
    for attempt in range(1, 9):
        time.sleep(15)
        recovered, recovery_message = proxy_request_once()
        if recovered:
            state["last_health"] = "healthy"
            state["consecutive_failed_runs"] = 0
            state["last_check_utc"] = utc_iso()
            save_state(state)
            log(f"VPN recovered after reboot (check {attempt}/8).")
            notify_telegram("✅ VPN снова работает после автоматической перезагрузки AEZA.")
            return 0
        log(f"VPN recovery check {attempt}/8 has not passed yet.")

    state["last_health"] = "down"
    state["consecutive_failed_runs"] = 0
    state["last_check_utc"] = utc_iso()
    save_state(state)
    notify_telegram("🚨 AEZA приняла запрос перезагрузки, но VPN не восстановился в течение примерно 2 минут. Автоматические повторы ограничены защитой от циклов; требуется проверка.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # Keep logs useful without echoing environment variables or the connection URI.
        log(f"Fatal watchdog error: {type(exc).__name__}: {exc}")
        sys.exit(1)
