#!/usr/bin/env python3
"""slack_listener.py - Certinel Slack interactivity over Socket Mode.

Outbound-only: dials OUT to Slack over a WebSocket, so it needs NO public
exposure (no Request URL / tunnel). It activates only when the admin selects
"Socket Mode" in the dashboard (Integrations -> Slack interactivity) and stores
an app-level token (xapp-...). Otherwise it idles.

Run as a systemd service under the venv python (certinel-slack-listener.service).
Requires slack_sdk in the venv (`pip install slack_sdk`); if absent it logs and
idles so the rest of the app is unaffected. Homelab-only: air-gapped prod has
no outbound path to Slack, so leave this disabled there.
"""
import json
import os
import db as dbx
import re
import sqlite3
import sys
import time
import urllib.request

JOB_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def _db_path():
    val = os.environ.get("CSR_DB_PATH")
    if not val:
        env = os.environ.get("CERTINEL_ENV",
                             "/etc/certinel/certinel.env")
        try:
            with open(env) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("CSR_DB_PATH="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
        except OSError:
            pass
    return val or "/var/lib/certinel/jobs.db"


DB_PATH = _db_path()


def log(msg):
    sys.stderr.write(f"[slack-listener] {msg}\n")
    sys.stderr.flush()


def get_setting(key):
    try:
        conn = dbx.connect()
        try:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()
    except Exception:
        return None


def assign(job_id, group_id, slack_user):
    if not JOB_ID_RE.match(job_id or ""):
        return False, "invalid job id"
    try:
        gid = int(group_id)
    except (TypeError, ValueError):
        return False, "invalid group"
    try:
        conn = dbx.connect()
        try:
            grp = conn.execute(
                "SELECT name FROM groups WHERE id = ?", (gid,)).fetchone()
            if not grp:
                return False, "group not found"
            cur = conn.execute(
                "UPDATE jobs SET group_id = ? WHERE id = ?", (gid, job_id))
            conn.commit()
            if cur.rowcount == 0:
                return False, f"job {job_id} not found"
            return True, (f":white_check_mark: Job `{job_id}` assigned to "
                          f"*{grp[0]}* by {slack_user}")
        finally:
            conn.close()
    except Exception as e:
        return False, f"db error: {e}"


def respond(response_url, text):
    if not response_url:
        return
    try:
        req = urllib.request.Request(
            response_url,
            data=json.dumps({"replace_original": False, "text": text}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        log(f"respond failed: {e}")


def handle(payload):
    if payload.get("type") != "block_actions":
        return
    act = (payload.get("actions") or [{}])[0]
    block_id = act.get("block_id", "") or ""
    job_id = block_id[4:] if block_id.startswith("job_") else None
    group_id = (act.get("selected_option") or {}).get("value")
    user = ((payload.get("user") or {}).get("username")
            or (payload.get("user") or {}).get("name") or "slack-user")
    if act.get("action_id") == "assign_group" and job_id and group_id:
        ok, msg = assign(job_id, group_id, user)
        log(f"assign job={job_id} group={group_id} user={user} -> {ok}")
        respond(payload.get("response_url"), msg)


def run_socket(app_token):
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse

    client = SocketModeClient(app_token=app_token)

    def _listener(c, req):
        try:
            c.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
            if req.type == "interactive":
                handle(req.payload)
        except Exception as e:
            log(f"handler error: {e}")

    client.socket_mode_request_listeners.append(_listener)
    client.connect()
    log("connected to Slack (socket mode)")
    # Stay connected until the admin turns socket mode off or rotates the token.
    while True:
        time.sleep(10)
        if get_setting("slack_interactive") != "1" \
                or (get_setting("slack_interactive_mode") or "http") != "socket":
            log("socket mode disabled in config; disconnecting")
            break
        if (get_setting("slack_app_token") or "") != app_token:
            log("app token changed; reconnecting")
            break
    try:
        client.disconnect()
    except Exception:
        pass


def main():
    log(f"started; db={DB_PATH}")
    try:
        import slack_sdk  # noqa: F401
    except ImportError:
        log("slack_sdk not installed; socket mode unavailable - idling "
            "(pip install slack_sdk, then restart this service).")
        while True:
            time.sleep(3600)
    while True:
        try:
            enabled = get_setting("slack_interactive") == "1"
            mode = get_setting("slack_interactive_mode") or "http"
            token = get_setting("slack_app_token") or ""
            if enabled and mode == "socket" and token:
                run_socket(token)
            else:
                time.sleep(15)
        except Exception as e:
            log(f"loop error: {e}; retry in 15s")
            time.sleep(15)


if __name__ == "__main__":
    main()
