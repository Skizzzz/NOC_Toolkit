"""
Config blueprint routes.

Provides routes for configuration search, global config management,
change windows, and interface/global configuration actions.
"""

import json
import re
import csv as csv_module
from io import StringIO
from datetime import datetime, timedelta
from typing import Optional

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    Response,
    session,
)
from zoneinfo import ZoneInfo

from src.core.security import (
    require_login,
    require_page_enabled,
)
from src.core.helpers import get_app_timezone, get_app_timezone_info

config_bp = Blueprint(
    "config",
    __name__,
    template_folder="templates",
    url_prefix="",
)

# Timezone for scheduling
_UTC_TZ = ZoneInfo("UTC")


# ====================== Helper Functions ======================


def _solar_node_options(nodes: Optional[list] = None) -> list:
    """Get SolarWinds node options for host selection dropdown."""
    from tools.db_jobs import fetch_solarwinds_nodes

    nodes = nodes if nodes is not None else fetch_solarwinds_nodes()
    options: list = []
    seen: set = set()
    for node in nodes or []:
        ip = (node.get("ip_address") or "").strip()
        if not ip:
            continue
        key = ip.lower()
        if key in seen:
            continue
        seen.add(key)
        caption = (node.get("caption") or "").strip()
        label = caption or ip
        if caption and caption.lower() != key:
            label = f"{caption} ({ip})"
        option: dict = {
            "value": ip,
            "caption": caption or ip,
            "label": label,
        }
        organization = (node.get("organization") or "").strip()
        if organization:
            option["organization"] = organization
        model = (node.get("model") or "").strip()
        if model:
            option["model"] = model
        vendor = (node.get("vendor") or "").strip()
        if vendor:
            option["vendor"] = vendor
        options.append(option)
    options.sort(key=lambda item: (item.get("caption") or item.get("value") or "").lower())
    return options


def _parse_hosts_field(value: Optional[str]) -> list:
    """Parse hosts from comma or newline separated input."""
    hosts = []
    seen = set()
    for chunk in (value or "").splitlines():
        for part in chunk.split(","):
            h = part.strip()
            if h and h not in seen:
                hosts.append(h)
                seen.add(h)
    return hosts


def _format_cst(ts: Optional[str]) -> Optional[str]:
    """Format timestamp in the configured application timezone."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except Exception:
        return ts
    app_tz = get_app_timezone_info()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=app_tz)
    local_dt = dt.astimezone(app_tz)
    tz_abbr = local_dt.strftime("%Z")
    return local_dt.strftime(f"%Y-%m-%d %I:%M %p {tz_abbr}")


def _parse_cst_datetime(value: str) -> datetime:
    """Parse datetime string in the configured application timezone."""
    app_tz = get_app_timezone_info()
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=app_tz)
    else:
        dt = dt.astimezone(app_tz)
    return dt


def _new_job_id() -> str:
    """Return a reasonably unique job identifier."""
    app_tz = get_app_timezone_info()
    return datetime.now(app_tz).strftime("%Y%m%d%H%M%S%f")


def _filter_cli_map(cli_map: dict) -> dict:
    """Remove hosts without CLI lines so we avoid empty pushes."""
    return {host: lines for host, lines in (cli_map or {}).items() if lines}


def _run_cli_job_sync(cli_map, username, password, secret, tool, *, capture_diffs=False):
    """Execute CLI pushes concurrently and return render-friendly results."""
    import threading
    import difflib
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from tools.push_config import push_config_lines, show_run_full

    def _apply_host_config(host, lines, username, password, secret, *, capture_diffs=False, ensure_saved=True):
        """Push config to a single host and optionally return a diff."""
        before = ""
        if capture_diffs:
            try:
                before = show_run_full(host, username, password, secret)
            except Exception as exc:
                before = f"<failed to read before: {exc}>"

        msg = push_config_lines(host, lines, username, password, secret, ensure_saved=ensure_saved)

        diff_text = None
        if capture_diffs:
            try:
                after = show_run_full(host, username, password, secret)
                diff_text = "\n".join(
                    difflib.unified_diff(
                        (before or "").splitlines(),
                        (after or "").splitlines(),
                        fromfile=f"{host} (before)",
                        tofile=f"{host} (after)",
                        lineterminator="",
                    )
                )
            except Exception as exc:
                diff_text = f"<failed to read after: {exc}>"

        return msg, diff_text

    task_map = _filter_cli_map(cli_map)
    if not task_map:
        return {"successes": [], "errors": [], "logs": [], "diffs": {}}

    job_id = _new_job_id()
    successes, errors, logs = [], [], []
    diffs = {}

    max_workers = min(10, max(1, len(task_map)))

    def worker(host, lines):
        return _apply_host_config(host, lines, username, password, secret, capture_diffs=capture_diffs, ensure_saved=True)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(worker, host, lines): host for host, lines in task_map.items()}
        for fut in as_completed(future_map):
            host = future_map[fut]
            lines = task_map.get(host, [])
            try:
                msg, diff_text = fut.result()
                successes.append(f"{host}: {msg}")
                logs.append(f"[{host}] OK - {msg}")
                if diff_text is not None:
                    diffs[host] = diff_text
            except Exception as exc:
                err_msg = f"[{host}] FAIL - {exc}"
                errors.append(err_msg)
                logs.append(err_msg)

    return {"successes": successes, "errors": errors, "logs": logs, "diffs": diffs}


def _start_background_cli_job(cli_map, username, password, secret, tool):
    """Kick off a background job that persists progress in SQLite."""
    import threading
    from tools.db_jobs import insert_job, append_event, mark_done
    from tools.push_config import push_config_lines

    def _apply_host_config(host, lines, username, password, secret, *, capture_diffs=False, ensure_saved=True):
        """Push config to a single host."""
        msg = push_config_lines(host, lines, username, password, secret, ensure_saved=ensure_saved)
        return msg, None

    task_map = _filter_cli_map(cli_map)
    job_id = _new_job_id()
    app_tz = get_app_timezone_info()
    created_ts = datetime.now(app_tz).isoformat(timespec="seconds")

    params_blob = {
        "hosts": list(task_map.keys()),
        "line_counts": {h: len(lines) for h, lines in task_map.items()},
        "tool": tool,
        "username": username,
    }
    insert_job(job_id=job_id, tool=tool, created=created_ts, params=params_blob)

    if not task_map:
        append_event(job_id, "log", {"message": "No CLI lines to apply."}, ts=created_ts)
        mark_done(job_id)
        return job_id

    append_event(
        job_id,
        "log",
        {"message": f"Job {job_id} started", "hosts": list(task_map.keys())},
        ts=created_ts,
    )

    def runner():
        for host, lines in task_map.items():
            try:
                msg, _ = _apply_host_config(host, lines, username, password, secret, capture_diffs=False, ensure_saved=True)
                payload = {
                    "host": host,
                    "message": msg,
                    "lines": len(lines),
                }
                append_event(job_id, "success", payload)
            except Exception as exc:
                payload = {
                    "host": host,
                    "message": str(exc),
                    "lines": len(lines),
                }
                append_event(job_id, "error", payload)

        append_event(job_id, "log", {"message": "Job complete."})
        mark_done(job_id)

    threading.Thread(target=runner, daemon=True).start()
    return job_id


def _get_cli_job_state(job_id):
    """Get the current state of a CLI job."""
    from tools.db_jobs import load_job as db_load_job

    meta, events = db_load_job(job_id)
    if not meta:
        return None

    logs, errors, successes = [], [], []
    for ev in events:
        etype = ev.get("type")
        payload = ev.get("payload", {})
        host = payload.get("host")
        message = payload.get("message")

        if etype == "success":
            success_msg = f"{host}: {message}" if host else (message or "")
            log_msg = f"[{host}] OK - {message}" if host else success_msg
            if success_msg:
                successes.append(success_msg)
            if log_msg:
                logs.append(log_msg)
        elif etype == "error":
            body = message or ""
            err_msg = f"[{host}] FAIL - {body}" if host else (f"FAIL - {body}" if body else "FAIL")
            errors.append(err_msg)
            logs.append(err_msg)
        elif etype == "log":
            msg_text = payload.get("message") if isinstance(payload, dict) else str(payload)
            if msg_text:
                logs.append(msg_text)

    params = meta.get("params") or {}
    total = len(params.get("hosts") or [])
    done_count = len(successes) + len(errors)
    progress_pct = int((done_count / total) * 100) if total else 100
    is_done = bool(meta.get("done"))
    cancelled = bool(meta.get("cancelled"))

    return {
        "job_id": job_id,
        "done": is_done,
        "cancelled": cancelled,
        "progress": progress_pct,
        "total": total,
        "completed": done_count,
        "successes": successes,
        "errors": errors,
        "logs": logs,
    }


def _job_outcome(job_id: str):
    """Check if a job is complete and return its outcome."""
    from tools.db_jobs import load_job as db_load_job

    if not job_id:
        return None
    meta, events = db_load_job(job_id)
    if not meta:
        return None
    errors = []
    for ev in events:
        if ev.get("type") == "error":
            payload = ev.get("payload") or {}
            msg = payload.get("message") or payload or "error"
            errors.append(str(msg))
    job_complete = any(
        ev.get("type") == "log" and isinstance(ev.get("payload"), dict) and ev["payload"].get("message") == "Job complete."
        for ev in events
    )
    done = bool(meta.get("done"))
    cancelled = bool(meta.get("cancelled"))
    if not done and not cancelled:
        if any(ev.get("type") == "cancelled" for ev in events):
            cancelled = True
        elif any(ev.get("type") == "done" for ev in events) or job_complete:
            done = True
    if not done and not cancelled:
        return None
    success = done and not cancelled and not errors
    return {
        "done": done,
        "cancelled": cancelled,
        "success": success,
        "errors": errors,
    }


def _start_change_execution(change: dict):
    """Start executing a scheduled change."""
    from tools.db_jobs import update_change_window, append_change_event

    change_id = change.get("change_id")
    payload = change.get("payload") or {}
    cli_map = payload.get("cli_map") or {}
    username = payload.get("username") or ""
    password = payload.get("password") or ""
    secret = payload.get("secret")

    if not cli_map:
        update_change_window(change_id, status="failed", message="No CLI commands to apply.")
        append_change_event(change_id, "error", "No CLI commands to apply.")
        return

    now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
    update_change_window(change_id, status="running", started=now_iso, message="Change execution started.")
    append_change_event(change_id, "started", "Change execution started.")

    tool = change.get("tool") or "interface-config"
    job_id = _start_background_cli_job(cli_map, username, password, secret, tool)
    update_change_window(change_id, apply_job_id=job_id)


def _start_change_rollback(change: dict) -> bool:
    """Start rolling back a completed change."""
    from tools.db_jobs import update_change_window, append_change_event

    change_id = change.get("change_id")
    rollback_payload = change.get("rollback_payload") or {}
    cli_map = rollback_payload.get("cli_map") or {}
    username = rollback_payload.get("username") or ""
    password = rollback_payload.get("password") or ""
    secret = rollback_payload.get("secret")

    if not cli_map:
        return False

    now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
    update_change_window(change_id, status="rollback-running", rollback_started=now_iso, message="Rollback started.")
    append_change_event(change_id, "rollback-started", "Rollback started.")

    tool = change.get("tool") or "interface-config"
    job_id = _start_background_cli_job(cli_map, username, password, secret, tool)
    update_change_window(change_id, rollback_job_id=job_id)
    return True


# Global event for change window wake
_CHANGE_WAKE = None

def _get_change_wake():
    """Get or create the change wake event."""
    global _CHANGE_WAKE
    import threading
    if _CHANGE_WAKE is None:
        _CHANGE_WAKE = threading.Event()
    return _CHANGE_WAKE


# ====================== Phrase Search (Interface Config) ======================


@config_bp.get("/tools/phrase-search")
@require_login
@require_page_enabled("tool_phrase_search")
def tool_phrase_search():
    """Interface configuration search page."""
    node_options = _solar_node_options()
    return render_template("config/phrase_search.html", node_options=node_options)


@config_bp.post("/search")
@require_login
def search():
    """Execute interface configuration search."""
    from tools.phrase_search import (
        run_show_run_many,
        parse_interfaces_with_descriptions,
        filter_by_phrase,
    )

    hosts = _parse_hosts_field(request.form.get("hosts"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    secret = request.form.get("secret") or None
    phrase = request.form.get("phrase", "").strip()
    case_sensitive = request.form.get("case_sensitive") == "1"
    exact = request.form.get("exact") == "1"
    full_block = request.form.get("full_block") == "1"

    if not (hosts and username and password and phrase):
        flash("All fields except enable are required.")
        return redirect(url_for("config.tool_phrase_search"))

    raw_map, errors = run_show_run_many(hosts, username, password, secret, max_workers=10)

    combined = []
    for host, run_cfg in raw_map.items():
        rows = parse_interfaces_with_descriptions(run_cfg)
        matched = filter_by_phrase(rows, phrase, case_sensitive, exact, full_block)
        for r in matched:
            rr = dict(r)
            rr["switch_ip"] = host
            combined.append(rr)

    if errors:
        for msg in errors:
            flash(f"Failed on {msg}")

    snippet = "\n".join(next(iter(raw_map.values()), "").splitlines()[:200])
    raw_map_json = json.dumps(raw_map)
    hosts_str = ", ".join(hosts)

    return render_template(
        "results.html",
        hosts=hosts,
        hosts_str=hosts_str,
        phrase=phrase,
        case_sensitive=case_sensitive,
        exact=exact,
        full_block=full_block,
        results=combined,
        raw_map_json=raw_map_json,
        snippet=snippet,
    )


@config_bp.post("/download-csv")
@require_login
def download_csv():
    """Download search results as CSV."""
    from tools.phrase_search import (
        parse_interfaces_with_descriptions,
        filter_by_phrase,
        make_csv,
    )

    hosts_str = request.form.get("hosts", "")
    phrase = request.form.get("phrase", "")
    case_sensitive = request.form.get("case_sensitive") == "1"
    exact = request.form.get("exact") == "1"
    full_block = request.form.get("full_block") == "1"
    raw_map_json = request.form.get("raw_map_json", "{}")

    try:
        raw_map = json.loads(raw_map_json)
    except Exception:
        raw_map = {}

    combined = []
    for host, run_cfg in raw_map.items():
        rows = parse_interfaces_with_descriptions(run_cfg)
        matched = filter_by_phrase(rows, phrase, case_sensitive, exact, full_block)
        for r in matched:
            rr = dict(r)
            rr["switch_ip"] = host
            combined.append(rr)

    csv_text = make_csv(combined)
    filename = f"multi_desc_search_{re.sub(r'[^A-Za-z0-9_.-]+', '_', phrase)}.csv"
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ====================== Interface Actions: Preview / Apply ======================


@config_bp.post("/actions/prepare")
@require_login
def actions_prepare():
    """Prepare interface configuration actions for preview."""
    from tools.phrase_search import build_cli_for_action
    from tools.security import log_audit

    selected = request.form.getlist("selected[]")
    action = request.form.get("action")
    new_description = request.form.get("new_description")
    custom_config = request.form.get("custom_config")

    apply_username = request.form.get("apply_username")
    apply_password = request.form.get("apply_password")
    apply_secret = request.form.get("apply_secret")

    pairs = []
    for item in selected:
        host, iface = item.split("||", 1)
        pairs.append((host, iface))

    cli_map = build_cli_for_action(pairs, action, new_description, custom_config)

    if not any(cli_map.values()):
        flash("Nothing to apply. Select interfaces and provide action inputs (description or custom config).")
        return redirect(url_for("config.tool_phrase_search"))

    payload = {
        "cli_map": cli_map,
        "username": apply_username,
        "password": apply_password,
        "secret": apply_secret,
        "tool": "interface-config",
        "pairs": [(h, i) for h, i in pairs],
    }
    return render_template("action_preview.html", cli_map=cli_map, payload=payload)


@config_bp.post("/actions/apply")
@require_login
def actions_apply():
    """Apply interface configuration changes synchronously."""
    from tools.security import log_audit

    payload_json = request.form.get("payload_json", "{}")
    capture_diffs = request.form.get("capture_diffs") == "1"

    try:
        payload = json.loads(payload_json)
    except Exception:
        payload = {}

    cli_map = payload.get("cli_map", {})
    username = payload.get("username")
    password = payload.get("password")
    secret = payload.get("secret")
    tool = payload.get("tool", "interface-config")

    # Log to audit trail
    current_user = session.get("username", "unknown")
    host_count = len(cli_map)
    total_lines = sum(len(lines) for lines in cli_map.values())
    log_audit(
        current_user,
        "config_apply",
        resource=f"{host_count} devices, {total_lines} config lines",
        details=f"Tool: {tool} | Mode: sync | Hosts: {', '.join(list(cli_map.keys())[:5])}{'...' if host_count > 5 else ''}",
        user_id=session.get("user_id")
    )

    result = _run_cli_job_sync(
        cli_map,
        username,
        password,
        secret,
        tool,
        capture_diffs=capture_diffs,
    )

    return render_template("action_result.html", **result)


@config_bp.post("/actions/apply/start")
@require_login
def actions_apply_start():
    """Start interface configuration changes in background."""
    from tools.security import log_audit

    payload_json = request.form.get("payload_json", "{}")
    try:
        payload = json.loads(payload_json)
    except Exception:
        return jsonify({"error": "invalid payload_json"}), 400

    cli_map = payload.get("cli_map", {})
    username = payload.get("username")
    password = payload.get("password")
    secret = payload.get("secret")
    tool = payload.get("tool", "interface-config")

    job_id = _start_background_cli_job(cli_map, username, password, secret, tool)

    # Log to audit trail
    current_user = session.get("username", "unknown")
    host_count = len(cli_map)
    total_lines = sum(len(lines) for lines in cli_map.values())
    log_audit(
        current_user,
        "config_apply",
        resource=f"{host_count} devices, {total_lines} config lines",
        details=f"Tool: {tool} | Mode: background | Job ID: {job_id}",
        user_id=session.get("user_id")
    )

    return jsonify({"job_id": job_id})


@config_bp.post("/actions/schedule")
@require_login
def actions_schedule():
    """Schedule interface configuration changes."""
    from tools.phrase_search import build_cli_for_action
    from tools.db_jobs import schedule_change_window

    payload_json = request.form.get("payload_json", "{}")
    schedule_start = (request.form.get("schedule_start") or "").strip()
    change_number = (request.form.get("change_number") or "").strip()
    rollback_custom = request.form.get("rollback_custom") or ""

    if not schedule_start:
        return jsonify({"error": "schedule_start required"}), 400

    try:
        payload = json.loads(payload_json)
    except Exception:
        return jsonify({"error": "invalid payload_json"}), 400

    tool = payload.get("tool", "interface-config")
    cli_map = payload.get("cli_map") or {}
    username = payload.get("username") or ""
    password = payload.get("password") or ""
    secret = payload.get("secret") or None

    if not (cli_map and username and password):
        return jsonify({"error": "Missing CLI map or credentials."}), 400

    try:
        local_dt = _parse_cst_datetime(schedule_start)
    except Exception:
        return jsonify({"error": "Invalid schedule_start"}), 400

    scheduled_utc = local_dt.astimezone(_UTC_TZ)
    now_utc = datetime.now(_UTC_TZ)
    if scheduled_utc <= now_utc:
        scheduled_utc = now_utc + timedelta(seconds=5)

    change_id = _new_job_id()

    base_payload = {
        "cli_map": cli_map,
        "username": username,
        "password": password,
        "secret": secret,
        "tool": tool,
    }

    rollback_payload = {}
    if rollback_custom.strip():
        if tool == "interface-config":
            pairs = payload.get("pairs") or []
            tuples = [tuple(p) for p in pairs if isinstance(p, (list, tuple)) and len(p) == 2]
            if tuples:
                rollback_map = build_cli_for_action(tuples, "custom-config", None, rollback_custom)
            else:
                lines = [ln.strip() for ln in rollback_custom.splitlines() if ln.strip()]
                rollback_map = {host: list(lines) for host in cli_map.keys()}
        else:
            lines = [ln.strip() for ln in rollback_custom.splitlines() if ln.strip()]
            rollback_map = {host: list(lines) for host in cli_map.keys()}
        rollback_payload = {
            "cli_map": rollback_map,
            "username": username,
            "password": password,
            "secret": secret,
            "tool": tool,
        }

    schedule_change_window(
        change_id=change_id,
        tool=tool,
        change_number=change_number,
        scheduled=scheduled_utc.isoformat(timespec="seconds"),
        payload=base_payload,
        rollback_payload=rollback_payload if rollback_payload else None,
        message="Scheduled change window.",
    )

    _get_change_wake().set()

    app_tz = get_app_timezone_info()
    tz_abbr = local_dt.strftime("%Z") if local_dt.tzinfo else "CST"
    return jsonify({
        "change_id": change_id,
        "scheduled_local": local_dt.strftime(f"%Y-%m-%d %I:%M %p {tz_abbr}"),
    })


@config_bp.get("/actions/status/<job_id>")
@require_login
def actions_status(job_id):
    """Get status of a running interface configuration job."""
    state = _get_cli_job_state(job_id)
    if not state:
        return jsonify({"error": "unknown job id"}), 404
    return jsonify(state)


# ====================== Change Windows ======================


@config_bp.get("/changes")
@require_login
@require_page_enabled("changes_list")
def changes_list():
    """List all scheduled change windows."""
    from tools.db_jobs import list_change_windows

    raw_changes = list_change_windows(limit=200)
    records = []
    for item in raw_changes:
        records.append({
            "change_id": item.get("change_id"),
            "change_number": item.get("change_number"),
            "tool": item.get("tool"),
            "status": item.get("status"),
            "message": item.get("message"),
            "scheduled_cst": _format_cst(item.get("scheduled")),
        })
    app_tz = get_app_timezone()
    return render_template("config/changes.html", changes=records, app_timezone=app_tz)


@config_bp.get("/changes/<change_id>")
@require_login
def change_detail(change_id):
    """View details of a specific change window."""
    from tools.db_jobs import load_change_window, update_change_window, append_change_event

    raw_change, events = load_change_window(change_id)
    if not raw_change:
        flash("Change not found.")
        return redirect(url_for("config.changes_list"))

    if raw_change.get("status") == "running":
        outcome = _job_outcome(raw_change.get("apply_job_id"))
        if outcome:
            now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
            if outcome["success"]:
                update_change_window(
                    raw_change["change_id"],
                    status="completed",
                    completed=now_iso,
                    message="Change completed successfully.",
                )
                append_change_event(raw_change["change_id"], "completed", "Change completed successfully.")
            else:
                msg = "; ".join(outcome["errors"]) or "Change failed."
                update_change_window(
                    raw_change["change_id"],
                    status="failed",
                    completed=now_iso,
                    message=msg,
                )
                append_change_event(raw_change["change_id"], "error", msg)
            raw_change, events = load_change_window(change_id)

    elif raw_change.get("status") == "rollback-running":
        outcome = _job_outcome(raw_change.get("rollback_job_id"))
        if outcome:
            now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
            if outcome["success"]:
                update_change_window(
                    raw_change["change_id"],
                    status="rolled-back",
                    rollback_completed=now_iso,
                    message="Rollback completed successfully.",
                )
                append_change_event(raw_change["change_id"], "rollback-complete", "Rollback completed successfully.")
            else:
                msg = "; ".join(outcome["errors"]) or "Rollback failed."
                update_change_window(
                    raw_change["change_id"],
                    status="rollback-failed",
                    rollback_completed=now_iso,
                    message=msg,
                )
                append_change_event(raw_change["change_id"], "error", msg)
            raw_change, events = load_change_window(change_id)

    change = {
        "change_id": raw_change.get("change_id"),
        "change_number": raw_change.get("change_number"),
        "tool": raw_change.get("tool"),
        "status": raw_change.get("status"),
        "message": raw_change.get("message"),
        "apply_job_id": raw_change.get("apply_job_id"),
        "rollback_job_id": raw_change.get("rollback_job_id"),
        "scheduled_cst": _format_cst(raw_change.get("scheduled")),
        "created_cst": _format_cst(raw_change.get("created")),
        "started_cst": _format_cst(raw_change.get("started")),
        "completed_cst": _format_cst(raw_change.get("completed")),
        "rollback_started_cst": _format_cst(raw_change.get("rollback_started")),
        "rollback_completed_cst": _format_cst(raw_change.get("rollback_completed")),
        "target_count": len((raw_change.get("payload") or {}).get("cli_map") or {}),
    }

    apply_state = _get_cli_job_state(change.get("apply_job_id")) if change.get("apply_job_id") else None
    rollback_state = _get_cli_job_state(change.get("rollback_job_id")) if change.get("rollback_job_id") else None

    prepared_events = []
    for ev in events:
        prepared_events.append({
            "ts": ev.get("ts"),
            "ts_cst": _format_cst(ev.get("ts")),
            "type": ev.get("type"),
            "message": ev.get("message"),
        })

    rollback_available = bool((raw_change.get("rollback_payload") or {}).get("cli_map"))

    return render_template(
        "change_detail.html",
        change=change,
        events=prepared_events,
        apply_state=apply_state,
        rollback_state=rollback_state,
        rollback_available=rollback_available,
    )


@config_bp.post("/changes/<change_id>/start")
@require_login
def change_start_now(change_id):
    """Start a scheduled change immediately."""
    from tools.db_jobs import load_change_window

    raw_change, _ = load_change_window(change_id)
    if not raw_change:
        flash("Change not found.")
        return redirect(url_for("config.changes_list"))
    if raw_change.get("status") != "scheduled":
        flash("Change is not in a scheduled state.")
        return redirect(url_for("config.change_detail", change_id=change_id))

    _start_change_execution(raw_change)
    _get_change_wake().set()
    flash("Change execution started.")
    return redirect(url_for("config.change_detail", change_id=change_id))


@config_bp.post("/changes/<change_id>/rollback")
@require_login
def change_trigger_rollback(change_id):
    """Trigger rollback for a completed change."""
    from tools.db_jobs import load_change_window

    raw_change, _ = load_change_window(change_id)
    if not raw_change:
        flash("Change not found.")
        return redirect(url_for("config.changes_list"))

    if raw_change.get("status") in {"scheduled", "running", "rollback-running"}:
        flash("Change must complete before triggering rollback.")
        return redirect(url_for("config.change_detail", change_id=change_id))

    if _start_change_rollback(raw_change):
        _get_change_wake().set()
        flash("Rollback started.")
    else:
        flash("Rollback unavailable for this change.")
    return redirect(url_for("config.change_detail", change_id=change_id))


# ====================== Global Config Search/Apply ======================


@config_bp.get("/tools/global-config")
@require_login
@require_page_enabled("tool_global_config")
def tool_global_config():
    """Global configuration search page."""
    node_options = _solar_node_options()
    return render_template("config/global_config.html", node_options=node_options)


@config_bp.post("/global/search")
@require_login
def global_config_search():
    """Execute global configuration search."""
    from tools.global_config import run_show_run_many_global

    hosts = _parse_hosts_field(request.form.get("hosts"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    secret = request.form.get("secret") or None
    phrase = request.form.get("phrase", "").strip()
    case_sensitive = request.form.get("case_sensitive") == "1"

    if not (hosts and username and password and phrase):
        flash("All fields are required.")
        return redirect(url_for("config.tool_global_config"))

    raw_map, errors = run_show_run_many_global(hosts, username, password, secret, max_workers=10)

    matches = []
    for h, cfg in raw_map.items():
        hay = cfg if case_sensitive else cfg.lower()
        needle = phrase if case_sensitive else phrase.lower()
        if needle in hay:
            matches.append({"host": h})

    hosts_str = ", ".join(hosts)
    return render_template("global_config_results.html",
                           hosts=hosts,
                           hosts_str=hosts_str,
                           phrase=phrase,
                           matches=matches,
                           errors=errors)


@config_bp.post("/global/download-csv")
@require_login
def global_config_download_csv():
    """Download global config search results as CSV."""
    matches_json = request.form.get("matches_json", "[]")
    try:
        matches = json.loads(matches_json)
    except Exception:
        matches = []
    buf = StringIO()
    w = csv_module.DictWriter(buf, fieldnames=["host"], lineterminator="\n")
    w.writeheader()
    for m in matches:
        w.writerow({"host": m.get("host", "")})
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=global_matches.csv"}
    )


@config_bp.post("/global/actions/prepare")
@require_login
def global_config_actions_prepare():
    """Prepare global configuration actions for preview."""
    from tools.global_config import build_cli_for_global_action

    selected_hosts = request.form.getlist("selected_hosts[]")
    custom_config = request.form.get("custom_config", "")
    apply_username = request.form.get("apply_username")
    apply_password = request.form.get("apply_password")
    apply_secret = request.form.get("apply_secret")

    cli_map = build_cli_for_global_action(selected_hosts, custom_config)

    if not any(cli_map.values()):
        flash("Nothing to apply. Provide global CLI lines and select at least one switch.")
        return redirect(url_for("config.tool_global_config"))

    payload = {
        "cli_map": cli_map,
        "username": apply_username,
        "password": apply_password,
        "secret": apply_secret,
        "tool": "global-config",
    }
    return render_template("action_preview_global.html", cli_map=cli_map, payload=payload)


@config_bp.post("/global/actions/apply")
@require_login
def global_config_actions_apply():
    """Apply global configuration changes synchronously."""
    from tools.security import log_audit

    payload_json = request.form.get("payload_json", "{}")
    capture_diffs = request.form.get("capture_diffs") == "1"

    try:
        payload = json.loads(payload_json)
    except Exception:
        payload = {}

    cli_map = payload.get("cli_map", {})
    username = payload.get("username")
    password = payload.get("password")
    secret = payload.get("secret")
    tool = payload.get("tool", "global-config")

    # Log to audit trail
    current_user = session.get("username", "unknown")
    host_count = len(cli_map)
    total_lines = sum(len(lines) for lines in cli_map.values())
    log_audit(
        current_user,
        "config_apply",
        resource=f"{host_count} devices, {total_lines} config lines",
        details=f"Tool: {tool} | Mode: sync | Hosts: {', '.join(list(cli_map.keys())[:5])}{'...' if host_count > 5 else ''}",
        user_id=session.get("user_id")
    )

    result = _run_cli_job_sync(
        cli_map,
        username,
        password,
        secret,
        tool,
        capture_diffs=capture_diffs,
    )

    return render_template("action_result.html", **result)


@config_bp.post("/global/actions/apply/start")
@require_login
def global_config_actions_apply_start():
    """Start global configuration changes in background."""
    from tools.security import log_audit

    payload_json = request.form.get("payload_json", "{}")
    try:
        payload = json.loads(payload_json)
    except Exception:
        return jsonify({"error": "invalid payload_json"}), 400

    cli_map = payload.get("cli_map", {})
    username = payload.get("username")
    password = payload.get("password")
    secret = payload.get("secret")
    tool = payload.get("tool", "global-config")

    job_id = _start_background_cli_job(cli_map, username, password, secret, tool)

    # Log to audit trail
    current_user = session.get("username", "unknown")
    host_count = len(cli_map)
    total_lines = sum(len(lines) for lines in cli_map.values())
    log_audit(
        current_user,
        "config_apply",
        resource=f"{host_count} devices, {total_lines} config lines",
        details=f"Tool: {tool} | Mode: background | Job ID: {job_id}",
        user_id=session.get("user_id")
    )

    return jsonify({"job_id": job_id})


@config_bp.get("/global/actions/status/<job_id>")
@require_login
def global_config_actions_status(job_id):
    """Get status of a running global configuration job."""
    state = _get_cli_job_state(job_id)
    if not state:
        return jsonify({"error": "unknown job id"}), 404
    return jsonify(state)
