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
import subprocess
import sys
from base64 import b64decode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

SERVICE_NAME = "custom-radius"
PROD_ENV_PATH = "/etc/custom-radius/radius.env"

# Keys the /edit form allows changing, with a simple validator each.
# Secrets (passwords, shared secret, private key paths) are deliberately
# excluded — this admin panel never asks for or displays them.
EDITABLE_KEYS = {
    "RADIUS_LISTEN_IP": r"^[0-9a-fA-F.:*]+$",
    "RADIUS_CLIENT_IP": r"^[0-9a-fA-F.:*,/\s]+$",
    "RADIUS_AUTH_PORT": r"^[0-9]{1,5}$",
    "RADIUS_ACCOUNTING_PORT": r"^[0-9]{1,5}$",
    "RADIUS_SERVER_NAME": r"^[0-9a-zA-Z.\-]+$",
    "AD_ALLOWED_GROUP": r"^[0-9a-zA-Z._\- ]+$",
    "RADIUS_SESSION_TTL_SECONDS": r"^[0-9]{1,6}$",
    "RADIUS_REQUEST_TIMEOUT_SECONDS": r"^[0-9]{1,4}$",
}

# Config keys that are safe to display. Anything holding a secret or
# password is intentionally left out of this list.
SAFE_CONFIG_KEYS = [
    "RADIUS_LISTEN_IP",
    "RADIUS_AUTH_PORT",
    "RADIUS_ACCOUNTING_PORT",
    "RADIUS_CLIENT_IP",
    "RADIUS_SERVER_NAME",
    "RADIUS_EAP_METHOD",
    "RADIUS_TLS_MIN_VERSION",
    "RADIUS_SESSION_TTL_SECONDS",
    "RADIUS_REQUEST_TIMEOUT_SECONDS",
    "AD_DOMAIN",
    "AD_NETBIOS_DOMAIN",
    "AD_DC_HOST",
    "AD_ALLOWED_GROUP",
    "AD_AUTH_BACKEND",
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


ACCEPT_RE = re.compile(r"access accepted user=(\S*)")
AD_REJECT_RE = re.compile(r"AD authentication or group policy rejected: user=(\S*)")
CLIENT_REJECT_RE = re.compile(r"request from (\S+) rejected: (.+)$")
TIMEOUT_RE = re.compile(r"ntlm_auth timed out")


def parse_events(journal_text):
    """Turn raw journal lines into structured accept/reject events:
    who tried to log in, whether AD accepted them, and why not."""
    events = []
    for line in journal_text.splitlines():
        ts_match = re.match(r"^(\S+)", line)
        ts = ts_match.group(1) if ts_match else ""

        match = ACCEPT_RE.search(line)
        if match:
            events.append({"ts": ts, "user": match.group(1) or "(без имени)",
                           "ok": True, "detail": "Access-Accept"})
            continue

        match = AD_REJECT_RE.search(line)
        if match:
            events.append({"ts": ts, "user": match.group(1) or "(без имени)",
                           "ok": False, "detail": "AD отклонил (пароль/группа)"})
            continue

        match = CLIENT_REJECT_RE.search(line)
        if match:
            events.append({"ts": ts, "user": match.group(1), "ok": False,
                           "detail": match.group(2).strip()})
            continue

        if TIMEOUT_RE.search(line):
            events.append({"ts": ts, "user": "—", "ok": False,
                           "detail": "Таймаут ntlm_auth/AD"})

    return events


def user_stats(events):
    stats = {}
    for event in events:
        user = event["user"]
        accepted, rejected = stats.get(user, (0, 0))
        if event["ok"]:
            accepted += 1
        else:
            rejected += 1
        stats[user] = (accepted, rejected)
    return sorted(stats.items(), key=lambda item: sum(item[1]), reverse=True)


PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>custom-radius admin</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f1115; color: #e6e6e6;
         margin: 0; padding: 24px; }}
  h1 {{ font-size: 20px; margin-bottom: 4px; }}
  .sub {{ color: #9aa0a6; margin-bottom: 24px; font-size: 13px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
           gap: 12px; margin-bottom: 24px; }}
  .card {{ background: #1a1d23; border: 1px solid #2a2e37; border-radius: 8px;
           padding: 16px; }}
  .card .label {{ font-size: 12px; color: #9aa0a6; text-transform: uppercase; }}
  .card .value {{ font-size: 22px; margin-top: 4px; }}
  .ok {{ color: #4caf50; }}
  .bad {{ color: #f44336; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px; }}
  td, th {{ text-align: left; padding: 4px 10px 4px 0; border-bottom: 1px solid #2a2e37; }}
  th {{ color: #9aa0a6; font-weight: normal; }}
  .warn {{ color: #ffb300; }}
  a {{ color: #64b5f6; }}
  .events {{ max-height: 520px; overflow-y: auto; }}
  .row-ok {{ color: #4caf50; }}
  .row-bad {{ color: #f44336; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 10px;
            font-size: 11px; }}
  .badge-ok {{ background: rgba(76,175,80,0.15); color: #4caf50; }}
  .badge-bad {{ background: rgba(244,67,54,0.15); color: #f44336; }}
  .bar-row {{ display: flex; align-items: center; gap: 8px; margin: 6px 0; font-size: 13px; }}
  .bar-name {{ width: 160px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis;
               white-space: nowrap; }}
  .bar-track {{ flex: 1; height: 14px; background: #1a1d23; border-radius: 4px;
                overflow: hidden; display: flex; }}
  .bar-ok {{ background: #4caf50; height: 100%; }}
  .bar-bad {{ background: #f44336; height: 100%; }}
  .bar-count {{ width: 60px; text-align: right; color: #9aa0a6; flex-shrink: 0; }}
</style>
</head>
<body>
<h1>custom-radius — панель мониторинга</h1>
<div class="sub">только просмотр · обновите страницу вручную · <a href="/">обновить</a> · <a href="/edit">изменить конфигурацию</a></div>

<div class="grid">
  <div class="card">
    <div class="label">Служба</div>
    <div class="value {state_class}">{state}</div>
  </div>
  <div class="card">
    <div class="label">Access-Accept</div>
    <div class="value ok">{accepted}</div>
  </div>
  <div class="card">
    <div class="label">Отклонено</div>
    <div class="value {rej_class}">{rejected}</div>
  </div>
</div>

<div class="sub">Пользователи (accept / reject)</div>
<div class="grid" style="grid-template-columns: 1fr; margin-bottom: 24px;">
  <div class="card">
    {user_bars}
  </div>
</div>

<table>
<tr><th>Параметр</th><th>Значение</th></tr>
{config_rows}
</table>

<div class="sub">Попытки входа — последние сверху</div>
<div class="events">
<table>
<tr><th>Время</th><th>Пользователь / источник</th><th>Результат</th></tr>
{event_rows}
</table>
</div>

</body>
</html>
"""


def render_user_bars(stats):
    if not stats:
        return '<span class="sub">пока нет данных</span>'
    max_total = max(sum(counts) for _, counts in stats) or 1
    rows = []
    for user, (accepted, rejected) in stats[:15]:
        total = accepted + rejected
        width = max(total, 1) / max_total * 100
        ok_share = (accepted / total * 100) if total else 0
        bad_share = 100 - ok_share
        rows.append(
            '<div class="bar-row">'
            f'<div class="bar-name" title="{html.escape(user)}">{html.escape(user)}</div>'
            f'<div class="bar-track" style="width:{width:.0f}%">'
            f'<div class="bar-ok" style="width:{ok_share:.0f}%"></div>'
            f'<div class="bar-bad" style="width:{bad_share:.0f}%"></div>'
            '</div>'
            f'<div class="bar-count">{accepted}/{rejected}</div>'
            '</div>'
        )
    return "\n".join(rows)


def render_event_rows(events):
    if not events:
        return '<tr><td colspan="3" class="sub">пока нет попыток входа</td></tr>'
    rows = []
    for event in reversed(events[-200:]):
        badge_class = "badge-ok" if event["ok"] else "badge-bad"
        badge_text = "ACCEPT" if event["ok"] else "REJECT"
        rows.append(
            "<tr>"
            f'<td>{html.escape(event["ts"])}</td>'
            f'<td>{html.escape(event["user"])}</td>'
            f'<td><span class="badge {badge_class}">{badge_text}</span> '
            f'{html.escape(event["detail"])}</td>'
            "</tr>"
        )
    return "\n".join(rows)


def render_page(cfg):
    state, _detail = service_status()
    state_class = "ok" if state == "active" else "bad"
    journal = recent_journal()
    events = parse_events(journal)
    accepted = sum(1 for e in events if e["ok"])
    rejected = sum(1 for e in events if not e["ok"])
    rej_class = "warn" if rejected else "ok"
    stats = user_stats(events)

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
        user_bars=render_user_bars(stats),
        event_rows=render_event_rows(events),
    )


EDIT_PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>custom-radius admin — изменить конфигурацию</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f1115; color: #e6e6e6;
         margin: 0; padding: 24px; max-width: 720px; }}
  h1 {{ font-size: 20px; margin-bottom: 4px; }}
  .sub {{ color: #9aa0a6; margin-bottom: 24px; font-size: 13px; }}
  label {{ display: block; margin-top: 14px; font-size: 13px; color: #9aa0a6; }}
  input {{ width: 100%; box-sizing: border-box; margin-top: 4px; padding: 8px 10px;
           background: #1a1d23; border: 1px solid #2a2e37; border-radius: 6px;
           color: #e6e6e6; font-size: 14px; }}
  button {{ margin-top: 20px; padding: 10px 18px; background: #2a6fdb; color: #fff;
            border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }}
  pre {{ background: #1a1d23; border: 1px solid #2a2e37; border-radius: 8px;
         padding: 12px; overflow-x: auto; font-size: 12px; line-height: 1.6;
         white-space: pre-wrap; word-break: break-all; }}
  .warn {{ color: #ffb300; font-size: 13px; margin-top: 16px; }}
  a {{ color: #64b5f6; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin: 12px 0; }}
  td, th {{ text-align: left; padding: 4px 10px 4px 0; border-bottom: 1px solid #2a2e37; }}
  th {{ color: #9aa0a6; font-weight: normal; }}
  .sub {{ color: #9aa0a6; margin-bottom: 8px; font-size: 13px; }}
</style>
</head>
<body>
<h1>Изменить конфигурацию</h1>
<div class="sub"><a href="/">← назад к панели</a></div>
{result}
<form method="post" action="/edit">
{fields}
<button type="submit">Сформировать команды</button>
</form>
<div class="warn">
  Панель не имеет права сама писать в /etc/custom-radius/radius.env и
  перезапускать службу (осознанное ограничение безопасности). После отправки
  формы здесь появятся готовые команды — выполните их вручную с sudo.
</div>
</body>
</html>
"""


def render_edit_form(cfg, result_html=""):
    fields = []
    for key in EDITABLE_KEYS:
        value = html.escape(cfg.get(key, ""))
        fields.append(
            f'<label>{html.escape(key)}</label>'
            f'<input name="{html.escape(key)}" value="{value}">'
        )
    return EDIT_PAGE.format(fields="\n".join(fields), result=result_html)


def build_apply_commands(changes):
    lines = []
    for key, value in changes.items():
        # sed replacement: escape / and & for the sed s/// expression,
        # then shell-quote the whole argument for safe copy/paste.
        escaped = value.replace("\\", "\\\\").replace("/", "\\/").replace("&", "\\&")
        expr = f"s/^{key}=.*/{key}={escaped}/"
        lines.append("sudo sed -i " + shlex.quote(expr) + " " + PROD_ENV_PATH)
    lines.append(f"sudo systemctl restart {SERVICE_NAME}")
    return lines


class Handler(BaseHTTPRequestHandler):
    server_version = "custom-radius-admin/1.0"

    def log_message(self, fmt, *args):
        pass  # avoid duplicating access logs into stdout noise

    def _unauthorized(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="custom-radius admin"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Authorization required")

    def _check_auth(self):
        expected_user = self.server.admin_user
        expected_pass = self.server.admin_password
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = b64decode(header[6:]).decode("utf-8")
            user, _, password = decoded.partition(":")
        except Exception:
            return False
        return (secrets.compare_digest(user, expected_user) and
                secrets.compare_digest(password, expected_pass))

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
                             '<div class="warn">Слишком большой запрос</div>'), 400)
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
            result_html = ('<div class="warn">Ошибка:<br>' +
                           "<br>".join(html.escape(e) for e in errors) + "</div>")
            self._send_html(render_edit_form(cfg, result_html), 400)
            return

        if not changes:
            self._send_html(render_edit_form(cfg,
                             '<div class="warn">Изменений нет</div>'))
            return

        commands = build_apply_commands(changes)
        diff_rows = "".join(
            f"<tr><td>{html.escape(k)}</td>"
            f"<td>{html.escape(cfg.get(k, ''))}</td>"
            f"<td>{html.escape(v)}</td></tr>"
            for k, v in changes.items()
        )
        result_html = (
            '<div class="sub">Изменения не применены. Выполните эти команды '
            'на сервере вручную:</div>'
            f'<pre>{html.escape(chr(10).join(commands))}</pre>'
            '<table><tr><th>Параметр</th><th>Было</th><th>Станет</th></tr>'
            f'{diff_rows}</table>'
        )
        self._send_html(render_edit_form(cfg, result_html))


def main():
    env_path = sys.argv[1] if len(sys.argv) > 1 else "/home/dev/radius-lab/.env"
    cfg = load_env(env_path)

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
    print(f"custom-radius admin web listening on {listen_ip}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
