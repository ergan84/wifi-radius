#!/usr/bin/env python3
"""Read-only web dashboard for the custom RADIUS server.

Shows service status, recent journal entries and non-secret config.
No shared secrets, passwords or private keys are ever rendered.
Requires no third-party packages (stdlib http.server only).
"""
import html
import re
import secrets
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
from base64 import b64decode
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

SERVICE_NAME = "custom-radius"
PROD_ENV_PATH = "/etc/custom-radius/radius.env"

# Basic-Auth brute-force limiter: attempts per source address within the
# window. The panel should sit on localhost behind an SSH tunnel, but it
# must not be a free password oracle if anyone ever exposes it.
AUTH_MAX_FAILURES = 10
AUTH_WINDOW_SECONDS = 300

# Keys the /edit form allows changing, with a simple validator each.
# Secrets (passwords, shared secret, private key paths) are deliberately
# excluded — this admin panel never asks for or displays them.
EDITABLE_KEYS = {
    "RADIUS_LISTEN_IP": r"^[0-9a-fA-F.:*]+$",
    "RADIUS_CLIENT_IP": r"^[0-9a-fA-F.:*,/\s]+$",
    "RADIUS_AUTH_PORT": r"^[0-9]{1,5}$",
    "RADIUS_SERVER_NAME": r"^[0-9a-zA-Z.\-]+$",
    "AD_ALLOWED_GROUP": r"^[0-9a-zA-Z._\- ]+$",
    "RADIUS_SESSION_TTL_SECONDS": r"^[0-9]{1,6}$",
    "RADIUS_REQUEST_TIMEOUT_SECONDS": r"^[0-9]{1,4}$",
    "RADIUS_WORKER_THREADS": r"^[0-9]{1,3}$",
}

# Config keys that are safe to display. Anything holding a secret or
# password is intentionally left out of this list.
SAFE_CONFIG_KEYS = [
    "RADIUS_LISTEN_IP",
    "RADIUS_AUTH_PORT",
    "RADIUS_CLIENT_IP",
    "RADIUS_SERVER_NAME",
    "RADIUS_TLS_CERT_FILE",
    "RADIUS_SESSION_TTL_SECONDS",
    "RADIUS_DUPLICATE_WINDOW_SECONDS",
    "RADIUS_REQUEST_TIMEOUT_SECONDS",
    "RADIUS_WORKER_THREADS",
    "RADIUS_STATE_DB",
    "AD_NETBIOS_DOMAIN",
    "AD_ALLOWED_GROUP",
    "WIFI_SSID",
]


def load_env(path):
    result = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key.strip()] = value
    return result


def run(cmd, timeout=5):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout + proc.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"(command failed: {exc})"


def service_status():
    state = run(["systemctl", "is-active", SERVICE_NAME]).strip()
    detail = run(["systemctl", "show", SERVICE_NAME, "-p",
                  "ActiveState,SubState,ExecMainStartTimestamp,MainPID"])
    return state, detail


def recent_journal(lines=1000):
    return run(["journalctl", "-u", SERVICE_NAME, "-n", str(lines), "--no-pager",
                "-o", "short-iso"], timeout=10)


# The trailing "mac=..." group is optional so journal lines written before
# Calling-Station-Id tracking was added still parse (just without a MAC).
# \s+ rather than a literal single space: a client whose MSCHAPv2 name had
# trailing padding produced "user=x  mac=y" (two spaces) in a handful of
# lines logged before the padding was stripped server-side - a fixed single
# space would have missed those retroactively.
ACCEPT_RE = re.compile(r"access accepted user=(\S*)(?:\s+mac=(\S*))?")
AD_REJECT_RE = re.compile(
    r"AD authentication or group policy rejected: user=(\S*)(?:\s+mac=(\S*))?")
CLIENT_REJECT_RE = re.compile(r"request from (\S+) rejected: (.+)$")
TIMEOUT_RE = re.compile(r"ntlm_auth timed out")


def query_events_from_db(db_path, limit=5000):
    """Read login history from the state database custom_radius.py
    writes to, when RADIUS_STATE_DB is configured. This is not subject
    to journald's rolling retention or the last-1000-lines cutoff the
    journal fallback below has, and sidesteps regex parsing of log text
    entirely - the event shape is the same either way, so device_stats()
    and the renderers below don't need to know which source they got.

    mode=ro: the panel only ever reads this file; custom_radius.py is
    the sole writer, in WAL mode, so this is safe to do concurrently
    from a separate process without locking it out.
    """
    try:
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            rows = conn.execute(
                "SELECT ts, user, mac, ok, detail FROM logins "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    events = [{"ts": ts, "user": user, "mac": mac, "ok": bool(ok),
              "detail": detail} for ts, user, mac, ok, detail in rows]
    events.reverse()  # oldest first, matching parse_events()'s journal order
    return events


def parse_events(journal_text):
    """Turn raw journal lines into structured accept/reject events: who
    tried to log in, from which device (MAC, when the AP sent one), and
    whether AD accepted them."""
    events = []
    for line in journal_text.splitlines():
        ts_match = re.match(r"^(\S+)", line)
        ts = ts_match.group(1) if ts_match else ""

        match = ACCEPT_RE.search(line)
        if match:
            events.append({"ts": ts, "user": match.group(1) or "(без имени)",
                           "mac": match.group(2) or "-",
                           "ok": True, "detail": "Access-Accept"})
            continue

        match = AD_REJECT_RE.search(line)
        if match:
            events.append({"ts": ts, "user": match.group(1) or "(без имени)",
                           "mac": match.group(2) or "-",
                           "ok": False, "detail": "AD отклонил (пароль/группа)"})
            continue

        match = CLIENT_REJECT_RE.search(line)
        if match:
            events.append({"ts": ts, "user": match.group(1), "mac": "-",
                           "ok": False, "detail": match.group(2).strip()})
            continue

        if TIMEOUT_RE.search(line):
            events.append({"ts": ts, "user": "—", "mac": "-", "ok": False,
                           "detail": "Таймаут ntlm_auth/AD"})

    return events


def mac_kind(mac):
    """A MAC's second-least-significant bit of the first octet is the
    "locally administered" flag (IEEE 802-2014 8.2.2). iOS 14+ and
    Android 10+ set it when they randomize the MAC per network, which is
    now the common case — so most devices will show as "случайный", and
    that is expected, not a sign anything is wrong."""
    if not mac or mac == "-":
        return ""
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return ""
    return "случайный" if first_octet & 0x02 else "заводской"


def device_stats(events):
    """Group events by (учётная запись, MAC устройства) so the same person
    logging in from two phones shows up as two rows, and the same phone
    reusing a randomized MAC across sessions still collapses into one."""
    devices = {}
    for event in events:
        key = (event["user"], event["mac"])
        info = devices.setdefault(key, {
            "accepted": 0, "rejected": 0, "last_ts": "", "last_ok": None,
        })
        if event["ok"]:
            info["accepted"] += 1
        else:
            info["rejected"] += 1
        # journalctl -o short-iso timestamps sort correctly as strings.
        if event["ts"] >= info["last_ts"]:
            info["last_ts"] = event["ts"]
            info["last_ok"] = event["ok"]
    rows = [{"user": user, "mac": mac, **info}
            for (user, mac), info in devices.items()]
    rows.sort(key=lambda row: row["last_ts"], reverse=True)
    return rows


PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>custom-radius admin</title>
<style>
  :root {{
    --bg: #0f0f0f;
    --surface: #1a1a1a;
    --surface-2: #141414;
    --border: #2a2a2a;
    --text: #e5e7eb;
    --muted: #6b7280;
    --accent: #22d3ee;
    --ok: #34d399;
    --ok-bg: rgba(52, 211, 153, 0.12);
    --bad: #f87171;
    --bad-bg: rgba(248, 113, 113, 0.12);
    --warn: #fbbf24;
    --radius: 8px;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
    background: var(--bg); color: var(--text);
    margin: 0; padding: 0 0 40px;
    -webkit-font-smoothing: antialiased;
  }}
  header {{
    position: sticky; top: 0; z-index: 10;
    background: rgba(15, 15, 15, 0.92); backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
    padding: 16px 20px; display: flex; align-items: baseline;
    justify-content: space-between; flex-wrap: wrap; gap: 8px;
  }}
  h1 {{ font-size: 16px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }}
  h1 .dim {{ color: var(--muted); font-weight: 400; }}
  nav {{ font-size: 13px; color: var(--muted); display: flex; gap: 14px; }}
  nav a {{ color: var(--accent); text-decoration: none; }}
  nav a:hover {{ text-decoration: underline; }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 20px; }}
  section {{ margin-bottom: 28px; }}
  .section-head {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 10px;
  }}
  .section-title {{
    font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--muted); margin: 0;
  }}
  .count {{
    font-size: 11px; color: var(--muted); background: var(--surface-2);
    border: 1px solid var(--border); border-radius: 999px; padding: 1px 8px;
  }}
  .stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
  }}
  .stat {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 14px 16px;
  }}
  .stat .label {{
    font-size: 11px; color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.05em; display: flex; align-items: center; gap: 6px;
  }}
  .stat .value {{ font-size: 30px; font-weight: 300; font-variant-numeric: tabular-nums; margin-top: 6px; }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; display: inline-block; }}
  .dot.ok {{ background: var(--ok); box-shadow: 0 0 8px var(--ok); }}
  .dot.bad {{ background: var(--bad); box-shadow: 0 0 8px var(--bad); }}
  .ok {{ color: var(--ok); }}
  .bad {{ color: var(--bad); }}
  .warn {{ color: var(--warn); }}
  a {{ color: var(--accent); }}
  .panel {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }}
  .scroll {{ max-height: 440px; overflow-y: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{
    text-align: left; padding: 10px 14px; color: var(--muted);
    font-weight: 500; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.04em; background: var(--surface);
    position: sticky; top: 0; border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 9px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover td {{ background: var(--surface-2); }}
  .empty td {{ color: var(--muted); text-align: center; padding: 24px; }}
  .mono {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
  }}
  .mac-kind {{ color: var(--muted); font-size: 11px; }}
  .badge {{
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
  }}
  .badge-ok {{ background: var(--ok-bg); color: var(--ok); }}
  .badge-bad {{ background: var(--bad-bg); color: var(--bad); }}
  .cfg-table td:first-child {{ color: var(--muted); width: 40%; }}
  @media (max-width: 560px) {{
    header {{ padding: 12px 16px; }}
    main {{ padding: 14px; }}
    th, td {{ padding: 8px 10px; }}
  }}
</style>
</head>
<body>
<header>
  <h1>custom-radius <span class="dim">· панель мониторинга</span></h1>
  <nav>
    <span>только просмотр</span>
    <a href="/">обновить</a>
    <a href="/edit">изменить конфигурацию</a>
  </nav>
</header>
<main>

<section>
  <div class="stats">
    <div class="stat">
      <div class="label"><span class="dot {state_class}"></span>Служба</div>
      <div class="value {state_class}">{state}</div>
    </div>
    <div class="stat">
      <div class="label">Access-Accept</div>
      <div class="value ok">{accepted}</div>
    </div>
    <div class="stat">
      <div class="label">Отклонено</div>
      <div class="value {rej_class}">{rejected}</div>
    </div>
  </div>
</section>

<section>
  <div class="section-head">
    <p class="section-title">Устройства — учётная запись и MAC точки доступа</p>
  </div>
  <div class="panel scroll">
  <table>
  <thead><tr><th>Пользователь</th><th>MAC устройства</th><th>Успешно/Отказано</th>
  <th>Последняя попытка</th><th>Результат</th></tr></thead>
  <tbody>
  {device_rows}
  </tbody>
  </table>
  </div>
</section>

<section>
  <div class="section-head">
    <p class="section-title">Конфигурация</p>
  </div>
  <div class="panel">
  <table class="cfg-table">
  <tbody>
  {config_rows}
  </tbody>
  </table>
  </div>
</section>

</main>
</body>
</html>
"""


def render_device_rows(devices):
    if not devices:
        return '<tr class="empty"><td colspan="5">пока нет данных</td></tr>'
    rows = []
    for device in devices[:100]:
        kind = mac_kind(device["mac"])
        mac_cell = html.escape(device["mac"])
        if kind:
            mac_cell += f' <span class="mac-kind">({kind})</span>'
        badge_class = "badge-ok" if device["last_ok"] else "badge-bad"
        badge_text = "ACCEPT" if device["last_ok"] else "REJECT"
        rows.append(
            "<tr>"
            f'<td>{html.escape(device["user"])}</td>'
            f'<td class="mono">{mac_cell}</td>'
            f'<td>{device["accepted"]}/{device["rejected"]}</td>'
            f'<td>{html.escape(device["last_ts"])}</td>'
            f'<td><span class="badge {badge_class}">{badge_text}</span></td>'
            "</tr>"
        )
    return "\n".join(rows)


def render_page(cfg):
    state, _detail = service_status()
    state_class = "ok" if state == "active" else "bad"
    events = None
    db_path = cfg.get("RADIUS_STATE_DB", "")
    if db_path:
        events = query_events_from_db(db_path)
    if events is None:
        events = parse_events(recent_journal())
    accepted = sum(1 for e in events if e["ok"])
    rejected = sum(1 for e in events if not e["ok"])
    rej_class = "warn" if rejected else "ok"
    devices = device_stats(events)

    rows = []
    for key in SAFE_CONFIG_KEYS:
        value = cfg.get(key, "")
        rows.append(f"<tr><td>{html.escape(key)}</td><td>{html.escape(value)}</td></tr>")

    return PAGE.format(
        state=html.escape(state or "unknown"),
        state_class=state_class,
        accepted=accepted,
        rejected=rejected,
        rej_class=rej_class,
        config_rows="\n".join(rows),
        device_rows=render_device_rows(devices),
    )


EDIT_PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>custom-radius admin — изменить конфигурацию</title>
<style>
  :root {{
    --bg: #0f0f0f;
    --surface: #1a1a1a;
    --surface-2: #141414;
    --border: #2a2a2a;
    --text: #e5e7eb;
    --muted: #6b7280;
    --accent: #22d3ee;
    --warn: #fbbf24;
    --warn-bg: rgba(251, 191, 36, 0.1);
    --radius: 8px;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: ui-sans-serif, system-ui, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
    background: var(--bg); color: var(--text);
    margin: 0; padding: 0 0 40px;
    -webkit-font-smoothing: antialiased;
  }}
  header {{
    background: rgba(15, 15, 15, 0.92); border-bottom: 1px solid var(--border);
    padding: 16px 20px;
  }}
  h1 {{ font-size: 16px; font-weight: 600; margin: 0 0 4px; letter-spacing: -0.01em; }}
  header a {{ color: var(--accent); text-decoration: none; font-size: 13px; }}
  header a:hover {{ text-decoration: underline; }}
  main {{ max-width: 640px; margin: 0 auto; padding: 24px 20px; }}
  .panel {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 20px;
  }}
  .field {{ margin-bottom: 16px; }}
  .field:last-child {{ margin-bottom: 0; }}
  label {{
    display: block; font-size: 12px; font-weight: 600; color: var(--muted);
    text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 6px;
  }}
  input {{
    width: 100%; padding: 9px 12px;
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: 7px; color: var(--text); font-size: 14px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    transition: border-color 0.1s;
  }}
  input:focus {{ outline: none; border-color: var(--accent); }}
  button {{
    margin-top: 22px; width: 100%; padding: 11px 18px;
    background: var(--accent); color: #06101f; font-weight: 600;
    border: none; border-radius: 7px; font-size: 14px; cursor: pointer;
  }}
  button:hover {{ filter: brightness(1.08); }}
  pre {{
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px; overflow-x: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-all;
  }}
  .result {{ margin-bottom: 20px; }}
  .result .note {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
  .warn {{
    color: var(--warn); background: var(--warn-bg); border: 1px solid rgba(242, 184, 75, 0.25);
    border-radius: 8px; font-size: 13px; padding: 12px 14px; margin-top: 20px;
    line-height: 1.5;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin: 4px 0 8px; }}
  td, th {{ text-align: left; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; }}
</style>
</head>
<body>
<header>
  <h1>Изменить конфигурацию</h1>
  <a href="/">← назад к панели</a>
</header>
<main>
{result}
<div class="panel">
<form method="post" action="/edit">
{fields}
<button type="submit">Сформировать команды</button>
</form>
</div>
<div class="warn">
  Панель не имеет права сама писать в /etc/custom-radius/radius.env и
  перезапускать службу (осознанное ограничение безопасности). После отправки
  формы здесь появятся готовые команды — выполните их вручную с sudo.
</div>
</main>
</body>
</html>
"""


def render_edit_form(cfg, result_html=""):
    fields = []
    for key in EDITABLE_KEYS:
        value = html.escape(cfg.get(key, ""))
        fields.append(
            '<div class="field">'
            f'<label>{html.escape(key)}</label>'
            f'<input name="{html.escape(key)}" value="{value}">'
            '</div>'
        )
    return EDIT_PAGE.format(fields="\n".join(fields), result=result_html)


def build_apply_commands(changes):
    """Emit copy-pasteable shell commands that apply `changes`.

    A bare `sed -i s/^KEY=.*/.../` exits 0 and changes nothing when KEY is
    not in the file yet, so the admin would believe a setting was applied
    that in fact never was. Each command therefore rewrites the key if it
    exists and appends it if it does not.
    """
    lines = []
    for key, value in changes.items():
        # Escape / and & for the sed s/// expression, then shell-quote the
        # whole argument so it survives copy/paste unchanged.
        escaped = value.replace("\\", "\\\\").replace("/", "\\/").replace("&", "\\&")
        expr = shlex.quote(f"s/^{key}=.*/{key}={escaped}/")
        path = shlex.quote(PROD_ENV_PATH)
        appended = shlex.quote(f"{key}={value}")
        lines.append(
            f"grep -q '^{key}=' {path} "
            f"&& sudo sed -i {expr} {path} "
            f"|| echo {appended} | sudo tee -a {path} > /dev/null"
        )
    lines.append(f"sudo systemctl restart {SERVICE_NAME}")
    return lines


class Handler(BaseHTTPRequestHandler):
    server_version = "custom-radius-admin/1.0"

    def log_message(self, fmt, *args):
        pass  # avoid duplicating access logs into stdout noise

    def _unauthorized(self):
        if self._throttled():
            self.send_response(429)
            self.send_header("Retry-After", str(AUTH_WINDOW_SECONDS))
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write("Слишком много попыток входа".encode("utf-8"))
            return
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="custom-radius admin"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Authorization required")

    def _throttled(self):
        """True when this source address has burned through its attempts."""
        now = time.monotonic()
        source = self.client_address[0]
        with self.server.auth_lock:
            recent = [t for t in self.server.auth_failures[source]
                      if now - t < AUTH_WINDOW_SECONDS]
            self.server.auth_failures[source] = recent
            return len(recent) >= AUTH_MAX_FAILURES

    def _record_failure(self):
        with self.server.auth_lock:
            self.server.auth_failures[self.client_address[0]].append(
                time.monotonic())

    def _check_auth(self):
        if self._throttled():
            return False
        expected_user = self.server.admin_user
        expected_pass = self.server.admin_password
        header = self.headers.get("Authorization", "")
        try:
            decoded = b64decode(header[6:]).decode("utf-8")
            user, _, password = decoded.partition(":")
        except Exception:
            user = password = ""
        # Both comparisons always run, so a wrong username and a wrong
        # password cost the same time.
        ok = (header.startswith("Basic ") &
              secrets.compare_digest(user, expected_user) &
              secrets.compare_digest(password, expected_pass))
        if not ok:
            self._record_failure()
        return ok

    def _send_html(self, body_str, status=200):
        body = body_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _live_cfg(self):
        # Re-read the .env file on every request instead of the value
        # cached at process start, so edits made outside this panel (sed,
        # another admin) show up without having to restart the panel itself.
        try:
            return load_env(self.server.env_path)
        except OSError:
            return self.server.cfg

    def do_GET(self):
        if not self._check_auth():
            self._unauthorized()
            return
        if self.path in ("/", "/index.html"):
            self._send_html(render_page(self._live_cfg()))
            return
        if self.path == "/edit":
            self._send_html(render_edit_form(self._live_cfg()))
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if not self._check_auth():
            self._unauthorized()
            return
        if self.path != "/edit":
            self.send_response(404)
            self.end_headers()
            return

        cfg = self._live_cfg()
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 16384:
            self._send_html(render_edit_form(cfg,
                             '<div class="result"><div class="warn">Слишком большой запрос</div></div>'), 400)
            return
        raw_body = self.rfile.read(length).decode("utf-8", "replace")
        submitted = {k: v[0] for k, v in parse_qs(raw_body).items()}

        errors = []
        changes = {}
        for key, pattern in EDITABLE_KEYS.items():
            if key not in submitted:
                continue
            value = submitted[key].strip()
            current = cfg.get(key, "")
            if value == current:
                continue
            if not re.match(pattern, value):
                errors.append(f"{key}: недопустимое значение «{html.escape(value)}»")
                continue
            changes[key] = value

        if errors:
            result_html = ('<div class="result"><div class="warn">Ошибка:<br>' +
                           "<br>".join(html.escape(e) for e in errors) + "</div></div>")
            self._send_html(render_edit_form(cfg, result_html), 400)
            return

        if not changes:
            self._send_html(render_edit_form(cfg,
                             '<div class="result"><div class="warn">Изменений нет</div></div>'))
            return

        commands = build_apply_commands(changes)
        diff_rows = "".join(
            f"<tr><td>{html.escape(k)}</td>"
            f"<td>{html.escape(cfg.get(k, ''))}</td>"
            f"<td>{html.escape(v)}</td></tr>"
            for k, v in changes.items()
        )
        result_html = (
            '<div class="result">'
            '<div class="note">Изменения не применены. Выполните эти команды '
            'на сервере вручную:</div>'
            f'<pre>{html.escape(chr(10).join(commands))}</pre>'
            '<table><tr><th>Параметр</th><th>Было</th><th>Станет</th></tr>'
            f'{diff_rows}</table>'
            '</div>'
        )
        self._send_html(render_edit_form(cfg, result_html))


def main():
    env_path = sys.argv[1] if len(sys.argv) > 1 else PROD_ENV_PATH
    try:
        cfg = load_env(env_path)
    except OSError as exc:
        sys.exit(f"cannot read config {env_path}: {exc}\n"
                 f"Usage: admin_web.py [/path/to/radius.env]")

    admin_user = cfg.get("RADIUS_ADMIN_WEB_USER")
    admin_password = cfg.get("RADIUS_ADMIN_WEB_PASSWORD")
    if not admin_user or not admin_password:
        sys.exit("RADIUS_ADMIN_WEB_USER / RADIUS_ADMIN_WEB_PASSWORD must be set in " + env_path)

    listen_ip = cfg.get("RADIUS_ADMIN_WEB_LISTEN_IP", "127.0.0.1")
    port = int(cfg.get("RADIUS_ADMIN_WEB_PORT", "8443"))

    httpd = ThreadingHTTPServer((listen_ip, port), Handler)
    httpd.cfg = cfg
    httpd.env_path = env_path
    httpd.admin_user = admin_user
    httpd.admin_password = admin_password
    httpd.auth_failures = defaultdict(list)
    httpd.auth_lock = threading.Lock()
    print(f"custom-radius admin web listening on {listen_ip}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
