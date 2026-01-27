from flask import Flask, request, redirect, url_for, render_template, flash, Response, jsonify, send_file, session, make_response
import json, csv, os, re, threading, difflib, uuid, time, ipaddress
from io import StringIO
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional, Tuple, List

TMP_WLC_CSV_DIR = os.path.join("tmp", "wlc_csv")
os.makedirs(TMP_WLC_CSV_DIR, exist_ok=True)

TMP_WLC_RF_DIR = os.path.join("tmp", "wlc_rf_csv")
os.makedirs(TMP_WLC_RF_DIR, exist_ok=True)

# ---- Tool helpers (modularized) ----
from tools.phrase_search import (
    run_show_run_many,
    parse_interfaces_with_descriptions,
    filter_by_phrase,
    make_csv,
    build_cli_for_action,
)
from tools.global_config import (
    run_show_run_many_global,
    build_cli_for_global_action,
)
from tools.push_config import push_config_lines, show_run_full, show_run_interfaces

from tools.wlc_inventory import get_ap_inventory_many, get_ap_inventory, make_ap_csv
from tools.aruba_controller import get_aruba_ap_inventory_many
from tools.device_inventory import collect_device_inventory_many, make_inventory_csv

from tools.wlc_rf import get_rf_summary_many, collect_rf_samples
from tools.wlc_clients import RE_TOTAL
from tools.wlc_summer_guest import collect_summer_guest_status, set_wlan_state
from tools.solarwinds import fetch_nodes as fetch_solarwinds_nodes_api, SolarWindsError
from tools.topology import build_topology_report, TopologyError
from tools.bulk_ssh import BulkSSHJob
from tools.template_engine import extract_variables, substitute_variables, validate_template, get_common_templates
from tools.schedule_worker import start_schedule_worker

from tools.netmiko_helpers import ios_xe_connection

from tools.security import (
    init_security_db,
    require_login,
    require_superadmin,
    verify_user,
    update_last_login,
    log_audit,
    get_current_user,
    encrypt_password,
    decrypt_password,
    migrate_existing_passwords,
    change_password,
    create_user,
    get_kb_access_level,
    can_user_create_kb,
    can_view_kb_article,
    require_kb_create,
    require_page_enabled,
)

from tools.db_jobs import (
    init_db,
    insert_job,
    append_event,
    mark_done,
    list_jobs as db_list_jobs,
    load_job as db_load_job,
    job_status,
    has_event,
    load_wlc_dashboard_settings,
    save_wlc_dashboard_settings,
    update_wlc_dashboard_poll_status,
    insert_wlc_dashboard_samples,
    fetch_wlc_dashboard_series,
    fetch_wlc_dashboard_latest_totals,
    fetch_wlc_dashboard_latest_details,
    fetch_upcoming_changes_for_hosts,
    load_wlc_summer_settings,
    save_wlc_summer_settings,
    update_wlc_summer_poll_status,
    insert_wlc_summer_samples,
    fetch_wlc_summer_latest_details,
    fetch_wlc_summer_recent_runs,
    schedule_change_window,
    update_change_window,
    list_change_windows,
    load_change_window,
    append_change_event,
    fetch_due_change_windows,
    load_solarwinds_settings,
    save_solarwinds_settings,
    update_solarwinds_poll_status,
    replace_solarwinds_nodes,
    fetch_solarwinds_nodes,
    insert_bulk_ssh_job,
    load_bulk_ssh_job,
    load_bulk_ssh_results,
    list_bulk_ssh_jobs,
    create_bulk_ssh_template,
    update_bulk_ssh_template,
    delete_bulk_ssh_template,
    load_bulk_ssh_template,
    list_bulk_ssh_templates,
    create_bulk_ssh_schedule,
    update_bulk_ssh_schedule_run,
    toggle_bulk_ssh_schedule,
    delete_bulk_ssh_schedule,
    load_bulk_ssh_schedule,
    list_bulk_ssh_schedules,
    fetch_due_bulk_ssh_schedules,
    # Certificate tracker functions
    insert_certificate,
    update_certificate,
    delete_certificate,
    get_certificate,
    list_certificates,
    get_certificate_stats,
    certificate_exists,
    insert_ise_node,
    update_ise_node,
    update_ise_node_sync_status,
    update_ise_node_version,
    delete_ise_node,
    get_ise_node,
    list_ise_nodes,
    get_enabled_ise_nodes,
    load_cert_sync_settings,
    save_cert_sync_settings,
    update_cert_sync_status,
    # Device inventory functions
    upsert_device_inventory,
    list_device_inventory,
    get_device_inventory,
    delete_device_inventory,
    get_device_inventory_stats,
    # Customer dashboard functions
    get_organizations_from_nodes,
    fetch_customer_dashboard_metrics,
    # Page visibility functions
    get_page_settings,
    get_enabled_pages,
    bulk_update_page_settings,
    # App settings functions
    load_app_settings,
    save_app_settings,
    get_app_timezone,
    get_app_timezone_info,
    US_TIMEZONES,
    # AP Inventory functions
    upsert_ap_inventory_bulk,
    cleanup_stale_ap_inventory,
    list_ap_inventory,
    get_ap_inventory_stats,
)

from tools.cert_tracker import (
    extract_cn_and_expiration,
    extract_full_cert_details,
    extract_cert_chain_details,
    pull_ise_certs,
    get_days_until_expiry,
    get_expiry_class,
    format_expiry_date,
    get_ise_version,
)

from tools.cert_converter import (
    CertConversionError,
    pfx_to_crt_key,
    crt_key_to_pfx,
    pem_to_crt_key,
    crt_key_to_pem,
    der_to_pem,
    pem_to_der,
    create_zip_bundle,
)

app = Flask(__name__)
init_db()
init_security_db()
migrate_existing_passwords()
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-in-prod-use-env-var")


@app.context_processor
def inject_enabled_pages():
    """Inject enabled_pages into all templates for navigation filtering."""
    return {"enabled_pages": get_enabled_pages()}


_DASHBOARD_SETTINGS_LOCK = threading.Lock()
_DASHBOARD_WAKE = threading.Event()
_DASHBOARD_SETTINGS = load_wlc_dashboard_settings()
_DASHBOARD_THREAD = None

_SUMMER_SETTINGS_LOCK = threading.Lock()
_SUMMER_WAKE = threading.Event()
_SUMMER_SETTINGS = load_wlc_summer_settings()
_SUMMER_THREAD = None

_SOLAR_SETTINGS_LOCK = threading.Lock()
_SOLAR_SETTINGS = load_solarwinds_settings()

_CHANGE_WAKE = threading.Event()
_CHANGE_THREAD = None

_DASHBOARD_RANGE_OPTIONS = [
    ("24h", "Last 24h"),
    ("3d", "Last 3 days"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
]
_DASHBOARD_RANGE_TO_HOURS = {
    "24h": 24,
    "3d": 72,
    "7d": 168,
    "30d": 720,
}

_CST_TZ = ZoneInfo("America/Chicago")
_UTC_TZ = ZoneInfo("UTC")


def _collect_wlc_snapshot(host, username, password, secret):
    result = {"host": host, "total_clients": None, "ap_count": None, "ap_details": []}
    errors = []
    try:
        with ios_xe_connection(
            host,
            username,
            password,
            secret,
            fast_cli=False,
            timeout=120,
            auto_enable=bool(secret),
        ) as conn:
            try:
                summary_out = conn.send_command("show wireless summary", read_timeout=180)
                client_match = re.search(r"(?i)total\s+(?:number\s+of\s+)?clients\s*:\s*(\d+)", summary_out or "")
                if client_match:
                    result["total_clients"] = int(client_match.group(1))
                else:
                    errors.append(f"{host}: Total Clients not found in summary")
            except Exception as exc:
                errors.append(f"{host}: wireless summary failed ({exc})")

            try:
                ap_out = conn.send_command("show ap summary", read_timeout=180)
                ap_match = re.search(r"Number of APs:\s*(\d+)", ap_out or "", re.I)
                if ap_match:
                    result["ap_count"] = int(ap_match.group(1))
                else:
                    errors.append(f"{host}: AP count not found in summary")

                # Parse AP details from the same output
                if ap_out:
                    ap_details = _parse_cisco_ap_summary(ap_out)
                    result["ap_details"] = ap_details
            except Exception as exc:
                errors.append(f"{host}: ap summary failed ({exc})")
    except Exception as exc:
        errors.append(f"{host}: {exc}")
    return result, errors


def _parse_cisco_ap_summary(output: str) -> List[Dict]:
    """
    Parse 'show ap summary' output from Cisco 9800 WLC.
    Returns list of dicts with: ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state, slots, country
    """
    rows: List[Dict] = []
    lines = [line.rstrip() for line in output.splitlines() if line.strip()]

    # Find header line containing "AP Name"
    header_idx = -1
    for i, line in enumerate(lines):
        if "AP Name" in line and ("IP Address" in line or "IP" in line):
            header_idx = i
            break
    if header_idx == -1:
        for i, line in enumerate(lines):
            if "AP Name" in line and "AP Model" in line:
                header_idx = i
                break
    if header_idx == -1:
        return rows

    header_line = lines[header_idx]
    cols = re.split(r"\s{2,}", header_line.strip())
    col_index = {c.strip(): idx for idx, c in enumerate(cols)}

    def pick(row_tokens: List[str], names: Tuple[str, ...]) -> str:
        for n in names:
            if n in col_index and col_index[n] < len(row_tokens):
                return row_tokens[col_index[n]].strip()
        return ""

    # Data lines after header
    data_start = header_idx + 1
    if data_start < len(lines) and set(lines[data_start].replace(" ", "")) in (set("-"), set("=")):
        data_start += 1

    for line in lines[data_start:]:
        if not re.search(r"\S", line):
            continue
        # Stop at summary line
        if "Number of APs" in line:
            break
        toks = re.split(r"\s{2,}", line.strip())
        if len(toks) < 2:
            continue

        ap_name = pick(toks, ("AP Name",))
        if not ap_name:
            ap_name = toks[0].strip()

        row = {
            "ap_name": ap_name,
            "ap_ip": pick(toks, ("IP Address", "IP")),
            "ap_model": pick(toks, ("AP Model", "Model")),
            "ap_mac": pick(toks, ("Ethernet MAC", "Ether MAC")),
            "ap_location": pick(toks, ("Location", "Site", "Tag")),
            "ap_state": pick(toks, ("State", "Status")),
            "slots": pick(toks, ("Slots",)),
            "country": pick(toks, ("Country",)),
        }
        rows.append(row)

    return rows


def _collect_aruba_snapshot(host, username, password, secret):
    """Collect client and AP count from an Aruba controller."""
    from tools.aruba_controller import get_aruba_snapshot
    return get_aruba_snapshot(host, username, password, secret)


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
    # Get timezone abbreviation (e.g., CST, EST, PST)
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


def _next_aligned_run(interval_sec: int, base_ts: Optional[float] = None) -> float:
    """Return the next run epoch aligned to the interval grid."""
    if interval_sec <= 0:
        interval_sec = 60
    if base_ts is None:
        base_ts = time.time()
    interval = float(interval_sec)
    remainder = base_ts % interval
    if remainder <= 1e-6:
        return base_ts + interval
    return base_ts + (interval - remainder)


def _job_outcome(job_id: str):
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
    change_id = change.get("change_id")
    payload = change.get("payload") or {}
    cli_map = payload.get("cli_map") or {}
    username = payload.get("username") or ""
    password = payload.get("password") or ""
    secret = payload.get("secret") or None
    tool = change.get("tool") or payload.get("tool") or "interface-config"
    now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")

    if not cli_map or not username or not password:
        update_change_window(
            change_id,
            status="failed",
            message="Missing CLI lines or credentials.",
            completed=now_iso,
        )
        append_change_event(change_id, "error", "Missing CLI lines or credentials for execution.")
        return

    try:
        job_id = _start_background_cli_job(cli_map, username, password, secret, tool)
    except Exception as exc:
        update_change_window(
            change_id,
            status="failed",
            message=f"Failed to start change: {exc}",
            completed=now_iso,
        )
        append_change_event(change_id, "error", f"Failed to start change: {exc}")
        return

    update_change_window(
        change_id,
        status="running",
        started=now_iso,
        apply_job_id=job_id,
        message=f"Change running (job {job_id})",
    )
    append_change_event(change_id, "started", f"Change started with job {job_id}")


def _start_change_rollback(change: dict):
    change_id = change.get("change_id")
    rollback_payload = change.get("rollback_payload") or {}
    cli_map = rollback_payload.get("cli_map") or {}
    if not cli_map:
        append_change_event(change_id, "note", "Rollback requested but no rollback CLI provided.")
        update_change_window(change_id, message="Rollback unavailable (no CLI provided).")
        return False

    username = rollback_payload.get("username") or (change.get("payload") or {}).get("username") or ""
    password = rollback_payload.get("password") or (change.get("payload") or {}).get("password") or ""
    secret = rollback_payload.get("secret") or (change.get("payload") or {}).get("secret")
    tool = rollback_payload.get("tool") or change.get("tool") or "interface-config"

    if not username or not password:
        append_change_event(change_id, "error", "Rollback missing credentials.")
        update_change_window(change_id, message="Rollback missing credentials.")
        return False

    try:
        job_id = _start_background_cli_job(cli_map, username, password, secret, tool)
    except Exception as exc:
        append_change_event(change_id, "error", f"Failed to start rollback: {exc}")
        update_change_window(change_id, message=f"Failed to start rollback: {exc}")
        return False

    now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
    update_change_window(
        change_id,
        status="rollback-running",
        rollback_started=now_iso,
        rollback_job_id=job_id,
        message=f"Rollback running (job {job_id})",
    )
    append_change_event(change_id, "rollback-start", f"Rollback started with job {job_id}")
    return True


def _change_scheduler_loop():
    while True:
        now_utc = datetime.now(_UTC_TZ)
        due = fetch_due_change_windows(now_utc.isoformat(timespec="seconds"))
        for change in due:
            if change.get("status") == "scheduled":
                _start_change_execution(change)

        active = [c for c in list_change_windows(limit=500) if c.get("status") in {"running", "rollback-running"}]
        for change in active:
            if change.get("status") == "running":
                outcome = _job_outcome(change.get("apply_job_id"))
                if not outcome:
                    continue
                now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
                if outcome["success"]:
                    update_change_window(
                        change["change_id"],
                        status="completed",
                        completed=now_iso,
                        message="Change completed successfully.",
                    )
                    append_change_event(change["change_id"], "completed", "Change completed successfully.")
                else:
                    msg = "; ".join(outcome["errors"]) or "Change failed."
                    update_change_window(
                        change["change_id"],
                        status="failed",
                        completed=now_iso,
                        message=msg,
                    )
                    append_change_event(change["change_id"], "error", msg)
            elif change.get("status") == "rollback-running":
                outcome = _job_outcome(change.get("rollback_job_id"))
                if not outcome:
                    continue
                now_iso = datetime.now(_UTC_TZ).isoformat(timespec="seconds")
                if outcome["success"]:
                    update_change_window(
                        change["change_id"],
                        status="rolled-back",
                        rollback_completed=now_iso,
                        message="Rollback completed successfully.",
                    )
                    append_change_event(change["change_id"], "rollback-complete", "Rollback completed successfully.")
                else:
                    msg = "; ".join(outcome["errors"]) or "Rollback failed."
                    update_change_window(
                        change["change_id"],
                        status="rollback-failed",
                        rollback_completed=now_iso,
                        message=msg,
                    )
                    append_change_event(change["change_id"], "error", msg)

        triggered = _CHANGE_WAKE.wait(timeout=30)
        if triggered:
            _CHANGE_WAKE.clear()

# ====================== GLOBALS / JOB STORE ======================
LOG_FILE = "logs/changes.csv"
LOG_HEADERS = ["timestamp", "username", "tool", "job_id", "switch_ip", "result", "message", "config_lines"]

# ====================== LOGGING HELPERS ======================
def _log_row(username, tool, job_id, switch_ip, result, message, config_lines):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    new_file = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LOG_HEADERS, lineterminator="\n")
        if new_file:
            w.writeheader()
        w.writerow({
            "timestamp": datetime.now(_CST_TZ).isoformat(sep=" ", timespec="seconds"),
            "username": username,
            "tool": tool,
            "job_id": job_id,
            "switch_ip": switch_ip,
            "result": result,
            "message": message,
            "config_lines": " | ".join(config_lines) if config_lines else "",
        })

def _log_success(username, tool, job_id, switch_ip, message, config_lines):
    _log_row(username, tool, job_id, switch_ip, "success", message, config_lines)

def _log_error(username, tool, job_id, switch_ip, error, config_lines):
    _log_row(username, tool, job_id, switch_ip, "error", str(error), config_lines)


def _parse_hosts_field(value: Optional[str]) -> list[str]:
    hosts = []
    seen = set()
    for chunk in (value or "").splitlines():
        for part in chunk.split(","):
            h = part.strip()
            if h and h not in seen:
                hosts.append(h)
                seen.add(h)
    return hosts


def _parse_string_list_field(value: Optional[str]) -> list[str]:
    items: list[str] = []
    seen = set()
    for chunk in (value or "").splitlines():
        for part in chunk.split(","):
            text = part.strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append(text)
    return items


def _parse_int_list_field(value: Optional[str]) -> list[int]:
    items: list[int] = []
    seen = set()
    for chunk in (value or "").replace(",", " ").split():
        try:
            number = int(chunk)
        except Exception:
            continue
        if number < 0 or number in seen:
            continue
        seen.add(number)
        items.append(number)
    return items


def _build_summer_toggle_cli(profile_name: str, wlan_id: int, *, enable: bool, psk: Optional[str] = None) -> list[str]:
    lines = [f"wlan {profile_name} {wlan_id}"]
    if enable and psk:
        lines.append(f'security wpa psk set-key ascii "{psk}"')
    lines.extend(["no shutdown" if enable else "shutdown", "exit"])
    return lines


def _sanitize_psk(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = value.strip()
    if len(cleaned) < 8 or len(cleaned) > 63:
        return None
    cleaned = cleaned.replace('"', '')
    return cleaned


def _format_cst_short(ts: Optional[str]) -> str:
    full = _format_cst(ts)
    if not full:
        return "—"
    return full.replace(" CST", "")


def _build_change_indicator(info: Optional[dict]) -> Optional[dict]:
    if not info:
        return None
    change_id = info.get("change_id")
    if not change_id:
        return None
    if (info.get("status") or "scheduled").lower() != "scheduled":
        return None
    scheduled_iso = info.get("scheduled_iso")
    change_number = info.get("change_number") or ""
    message = info.get("message") or ""
    tooltip_parts = []
    if change_number:
        tooltip_parts.append(f"Change #: {change_number}")
    formatted = _format_cst(scheduled_iso)
    if formatted:
        tooltip_parts.append(formatted)
    if message:
        tooltip_parts.append(message)
    return {
        "change_id": change_id,
        "scheduled_iso": scheduled_iso,
        "scheduled_short": _format_cst_short(scheduled_iso),
        "tooltip": " | ".join(tooltip_parts) if tooltip_parts else "Scheduled change",
    }


def _get_solar_settings() -> dict:
    with _SOLAR_SETTINGS_LOCK:
        return dict(_SOLAR_SETTINGS)


def _set_solar_settings(settings: dict):
    with _SOLAR_SETTINGS_LOCK:
        _SOLAR_SETTINGS.clear()
        _SOLAR_SETTINGS.update(settings)
    save_solarwinds_settings(_SOLAR_SETTINGS)


def _derive_wlc_hosts_from_solarwinds(nodes: Optional[list[dict]] = None) -> list[str]:
    """Derive Cisco 9800 WLC hosts from SolarWinds nodes."""
    if nodes is None:
        nodes = fetch_solarwinds_nodes()
    hosts: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        caption = (node.get("caption") or "").lower()
        vendor = (node.get("vendor") or "").lower()
        model = (node.get("model") or "").lower()
        ip_address = (node.get("ip_address") or "").strip()
        if not ip_address:
            continue
        if "wc01" in caption and "cisco" in vendor and "9800" in model:
            if ip_address not in seen:
                seen.add(ip_address)
                hosts.append(ip_address)
    return hosts


def _derive_aruba_hosts_from_solarwinds(nodes: Optional[list[dict]] = None) -> list[str]:
    """Derive Aruba controller hosts from SolarWinds nodes (hostname starts with wc0, vendor starts with Aruba)."""
    if nodes is None:
        nodes = fetch_solarwinds_nodes()
    hosts: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        caption = (node.get("caption") or "").lower()
        vendor = (node.get("vendor") or "").lower()
        ip_address = (node.get("ip_address") or "").strip()
        if not ip_address:
            continue
        # Match: hostname starts with "wc0" and vendor starts with "aruba"
        if caption.startswith("wc0") and vendor.startswith("aruba"):
            if ip_address not in seen:
                seen.add(ip_address)
                hosts.append(ip_address)
    return hosts


def _update_aruba_hosts_from_solarwinds(nodes: Optional[list[dict]] = None) -> list[str]:
    """Update Aruba hosts in dashboard settings from SolarWinds."""
    auto_hosts = _derive_aruba_hosts_from_solarwinds(nodes)
    with _DASHBOARD_SETTINGS_LOCK:
        current_hosts = _DASHBOARD_SETTINGS.get("aruba_hosts") or []
        if auto_hosts != current_hosts:
            _DASHBOARD_SETTINGS["aruba_hosts"] = auto_hosts
            save_wlc_dashboard_settings(_DASHBOARD_SETTINGS)
    return auto_hosts


def _update_wlc_hosts_from_solarwinds(nodes: Optional[list[dict]] = None) -> list[str]:
    auto_hosts = _derive_wlc_hosts_from_solarwinds(nodes)
    with _DASHBOARD_SETTINGS_LOCK:
        current_hosts = _DASHBOARD_SETTINGS.get("hosts") or []
        if auto_hosts != current_hosts:
            _DASHBOARD_SETTINGS["hosts"] = auto_hosts
            save_wlc_dashboard_settings(_DASHBOARD_SETTINGS)
    return auto_hosts


def _update_summer_hosts_from_solarwinds(nodes: Optional[list[dict]] = None) -> list[str]:
    auto_hosts = _derive_wlc_hosts_from_solarwinds(nodes)
    with _SUMMER_SETTINGS_LOCK:
        current_hosts = _SUMMER_SETTINGS.get("hosts") or []
        if auto_hosts != current_hosts:
            _SUMMER_SETTINGS["hosts"] = auto_hosts
            save_wlc_summer_settings(_SUMMER_SETTINGS)
    return auto_hosts


def _label_wlc_hosts(hosts: Optional[list[str]], nodes: Optional[list[dict]] = None) -> list[str]:
    if not hosts:
        return []

    node_by_ip: dict[str, str] = {}
    node_by_caption: dict[str, str] = {}
    for node in nodes or []:
        ip = (node.get("ip_address") or "").strip()
        caption = (node.get("caption") or "").strip()
        if ip:
            node_by_ip[ip.lower()] = caption
        if caption:
            node_by_caption[caption.lower()] = caption

    labels: list[str] = []
    seen: set[str] = set()
    for raw in hosts:
        host = (raw or "").strip()
        if not host:
            continue
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)

        caption = node_by_ip.get(key) or node_by_caption.get(key)
        if caption and caption.lower() != key:
            labels.append(f"{caption} ({host})")
        else:
            labels.append(caption or host)
    return labels


def _solar_node_options(nodes: Optional[list[dict]] = None) -> list[dict[str, str]]:
    nodes = nodes if nodes is not None else fetch_solarwinds_nodes()
    options: list[dict[str, str]] = []
    seen: set[str] = set()
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
        option: dict[str, str] = {
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


def _solar_org_options(nodes: Optional[list[dict]] = None) -> list[dict[str, object]]:
    nodes = nodes if nodes is not None else fetch_solarwinds_nodes()
    counts: Dict[str, int] = {}
    for node in nodes or []:
        org = (node.get("organization") or "").strip()
        if not org:
            continue
        counts[org] = counts.get(org, 0) + 1
    options: List[dict[str, object]] = []
    for org, count in counts.items():
        options.append({"name": org, "count": count})
    options.sort(key=lambda item: item["name"].lower())
    return options


def _resolve_target_node(raw_value: Optional[str], nodes: Optional[list[dict]] = None) -> tuple[Optional[str], Optional[dict]]:
    """Return (ip, node) for the provided text, falling back to captions."""
    text = (raw_value or "").strip()
    if not text:
        return None, None
    nodes = nodes or fetch_solarwinds_nodes()

    ip_candidate: Optional[str] = None
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
    if match:
        ip_candidate = match.group(1)
    else:
        try:
            ipaddress.ip_address(text)
            ip_candidate = text
        except ValueError:
            ip_candidate = None

    matched_node: Optional[dict] = None
    if ip_candidate:
        for node in nodes or []:
            ip_value = (node.get("ip_address") or "").strip()
            if ip_value and ip_value == ip_candidate:
                matched_node = node
                break
        return ip_candidate, matched_node

    lowered = text.lower()
    for node in nodes or []:
        caption = (node.get("caption") or "").strip().lower()
        if caption == lowered:
            ip_value = (node.get("ip_address") or "").strip() or None
            matched_node = node
            return ip_value, matched_node

    return None, None


def _clamp_workers(requested: Optional[str], hosts_count: int, *, default: int = 10, upper: int = 50) -> int:
    try:
        workers = int((requested or "").strip()) if requested else default
    except Exception:
        workers = default
    if workers < 1:
        workers = default
    workers = min(workers, upper)
    if hosts_count:
        workers = min(workers, hosts_count)
    return max(workers, 1)


def _new_job_id() -> str:
    """Return a reasonably unique job identifier."""
    return datetime.now(_CST_TZ).strftime("%Y%m%d%H%M%S%f")


def _filter_cli_map(cli_map):
    """Remove hosts without CLI lines so we avoid empty pushes."""
    return {host: lines for host, lines in (cli_map or {}).items() if lines}


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


def _run_cli_job_sync(cli_map, username, password, secret, tool, *, capture_diffs=False):
    """Execute CLI pushes concurrently and return render-friendly results."""
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
                _log_success(username, tool, job_id, host, msg, lines)
            except Exception as exc:
                err_msg = f"[{host}] FAIL - {exc}"
                errors.append(err_msg)
                logs.append(err_msg)
                _log_error(username, tool, job_id, host, exc, lines)

    return {"successes": successes, "errors": errors, "logs": logs, "diffs": diffs}


def _start_background_cli_job(cli_map, username, password, secret, tool):
    """Kick off a background job that persists progress in SQLite."""
    task_map = _filter_cli_map(cli_map)
    job_id = _new_job_id()
    created_ts = datetime.now(_CST_TZ).isoformat(timespec="seconds")

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
                _log_success(username, tool, job_id, host, msg, lines)
            except Exception as exc:
                payload = {
                    "host": host,
                    "message": str(exc),
                    "lines": len(lines),
                }
                append_event(job_id, "error", payload)
                _log_error(username, tool, job_id, host, exc, lines)

        append_event(job_id, "log", {"message": "Job complete."})
        mark_done(job_id)
        _CHANGE_WAKE.set()

    threading.Thread(target=runner, daemon=True).start()
    return job_id


def _get_cli_job_state(job_id):
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
            if message:
                logs.append(message)
        elif etype == "done":
            logs.append("Done.")
        elif etype == "cancelled":
            logs.append("Cancelled.")
            errors.append("Job cancelled")

    return {
        "logs": logs,
        "errors": errors,
        "successes": successes,
        "done": bool(meta.get("done")),
    }


def _get_dashboard_settings() -> dict:
    with _DASHBOARD_SETTINGS_LOCK:
        return dict(_DASHBOARD_SETTINGS)


def _set_dashboard_settings(settings: dict):
    has_summary = "poll_summary" in settings
    has_validation = "validation" in settings
    with _DASHBOARD_SETTINGS_LOCK:
        existing_summary = _DASHBOARD_SETTINGS.get("poll_summary")
        existing_validation = _DASHBOARD_SETTINGS.get("validation", [])
        _DASHBOARD_SETTINGS.clear()
        _DASHBOARD_SETTINGS.update(settings)
        if not has_summary and existing_summary is not None:
            _DASHBOARD_SETTINGS["poll_summary"] = existing_summary
        if not has_validation and existing_validation:
            _DASHBOARD_SETTINGS["validation"] = existing_validation
        _DASHBOARD_SETTINGS.setdefault("poll_summary", None)
        _DASHBOARD_SETTINGS.setdefault("validation", [])
        _DASHBOARD_SETTINGS.setdefault("last_poll_status", "pending")
        _DASHBOARD_SETTINGS.setdefault("last_poll_message", "Awaiting next poll.")
        _DASHBOARD_SETTINGS.setdefault("last_poll_ts", None)
        if _DASHBOARD_SETTINGS.get("enabled") and not has_summary:
            _DASHBOARD_SETTINGS["last_poll_status"] = "pending"
            _DASHBOARD_SETTINGS["last_poll_message"] = "Awaiting next poll."
            _DASHBOARD_SETTINGS["last_poll_ts"] = None
    if not has_summary:
        _DASHBOARD_WAKE.set()
    save_wlc_dashboard_settings(_DASHBOARD_SETTINGS)


def _record_dashboard_poll_status(ts_iso: Optional[str], status: str, message: str = ""):
    update_wlc_dashboard_poll_status(ts=ts_iso, status=status, message=message)
    with _DASHBOARD_SETTINGS_LOCK:
        _DASHBOARD_SETTINGS["last_poll_ts"] = ts_iso
        _DASHBOARD_SETTINGS["last_poll_status"] = status
        _DASHBOARD_SETTINGS["last_poll_message"] = message


def _get_summer_settings() -> dict:
    with _SUMMER_SETTINGS_LOCK:
        return dict(_SUMMER_SETTINGS)


def _set_summer_settings(settings: dict):
    has_summary = "summary" in settings
    has_validation = "validation" in settings
    with _SUMMER_SETTINGS_LOCK:
        existing_summary = _SUMMER_SETTINGS.get("summary")
        existing_validation = _SUMMER_SETTINGS.get("validation", [])
        _SUMMER_SETTINGS.clear()
        _SUMMER_SETTINGS.update(settings)
        if not has_summary and existing_summary is not None:
            _SUMMER_SETTINGS["summary"] = existing_summary
        if not has_validation and existing_validation:
            _SUMMER_SETTINGS["validation"] = existing_validation
        _SUMMER_SETTINGS.setdefault("summary", None)
        _SUMMER_SETTINGS.setdefault("validation", [])
        _SUMMER_SETTINGS.setdefault("last_poll_status", "pending")
        _SUMMER_SETTINGS.setdefault("last_poll_message", "Awaiting next poll.")
        _SUMMER_SETTINGS.setdefault("last_poll_ts", None)
        _SUMMER_SETTINGS.setdefault("auto_prefix", "Summer")
        hosts_list = _SUMMER_SETTINGS.get("hosts") or []
        summary = _SUMMER_SETTINGS.get("summary")
        if isinstance(summary, dict):
            host_status = summary.get("host_status") or []
            seen_hosts = {entry.get("host") for entry in host_status if entry.get("host")}
            changed = False
            placeholders = []
            for entry in host_status:
                if entry.get("host") not in hosts_list:
                    changed = True
                else:
                    placeholders.append(entry)
            if changed:
                host_status = placeholders
            for host in hosts_list:
                if host not in seen_hosts:
                    host_status.append(
                        {
                            "host": host,
                            "display": host,
                            "ok": False,
                            "message": "Awaiting poll.",
                            "entries": [],
                            "errors": [],
                            "upcoming_change": None,
                        }
                    )
            summary["host_status"] = host_status
            summary["total_hosts"] = len(hosts_list)
        if _SUMMER_SETTINGS.get("enabled") and not has_summary:
            _SUMMER_SETTINGS["last_poll_status"] = "pending"
            _SUMMER_SETTINGS["last_poll_message"] = "Awaiting next poll."
            _SUMMER_SETTINGS["last_poll_ts"] = None
    save_wlc_summer_settings(_SUMMER_SETTINGS)
    _SUMMER_WAKE.set()


def _record_summer_poll_status(ts_iso: Optional[str], status: str, message: str = ""):
    update_wlc_summer_poll_status(ts=ts_iso, status=status, message=message)
    with _SUMMER_SETTINGS_LOCK:
        _SUMMER_SETTINGS["last_poll_ts"] = ts_iso
        _SUMMER_SETTINGS["last_poll_status"] = status
        _SUMMER_SETTINGS["last_poll_message"] = message


def _parse_daily_time_str(value: Optional[str]) -> tuple[int, int]:
    if not value:
        return 7, 0
    try:
        parts = value.split(":")
        hour = max(0, min(int(parts[0]), 23))
        minute = max(0, min(int(parts[1]), 59))
    except Exception:
        return 7, 0
    return hour, minute


def _summer_timezone(settings: dict) -> ZoneInfo:
    """Get timezone for summer guest scheduler, falling back to app timezone."""
    tz_name = settings.get("timezone") or get_app_timezone()
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return get_app_timezone_info()


def _next_summer_run(settings: dict, *, base_dt: Optional[datetime] = None) -> datetime:
    tz = _summer_timezone(settings)
    now = base_dt or datetime.now(tz)
    hour, minute = _parse_daily_time_str(settings.get("daily_time"))
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate = candidate + timedelta(days=1)
    return candidate


def _summer_poll_once(settings: dict, *, manual: bool = False):
    hosts = settings.get("hosts") or []
    username = settings.get("username") or ""
    password = settings.get("password") or ""
    secret = settings.get("secret") or ""
    profile_names = [p for p in (settings.get("profile_names") or []) if p]
    wlan_ids = settings.get("wlan_ids") or []
    auto_prefix = (settings.get("auto_prefix") or "Summer").strip() or "Summer"

    timestamp = datetime.now(_CST_TZ).isoformat(timespec="seconds")

    if not hosts:
        message = "No controllers configured."
        summary = {
            "ts": timestamp,
            "status": "error",
            "message": message,
            "total_hosts": 0,
            "success_hosts": 0,
            "enabled_total": 0,
            "disabled_total": 0,
            "errors": [message],
            "host_status": [],
            "targets": {
                "profile_names": profile_names,
                "wlan_ids": wlan_ids,
                "auto_prefix": auto_prefix,
            },
            "manual": manual,
        }
        _record_summer_poll_status(timestamp, "error", message)
        new_settings = dict(settings)
        new_settings["summary"] = summary
        _set_summer_settings(new_settings)
        return

    workers = min(max(len(hosts), 1), 10)
    samples_all = []
    host_results: dict[str, dict] = {}
    errors: list[str] = []
    enabled_total = 0
    disabled_total = 0
    success_hosts = 0

    upcoming_map = fetch_upcoming_changes_for_hosts("wlc-summer-toggle", hosts)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                collect_summer_guest_status,
                host,
                username,
                password,
                secret,
                profile_names=profile_names,
                wlan_ids=wlan_ids,
                auto_prefix=auto_prefix,
            ): host
            for host in hosts
        }

        for fut in as_completed(futures):
            host = futures[fut]
            host_entry = {"host": host, "display": host, "ok": False, "message": "", "entries": [], "errors": []}
            try:
                samples, host_errors, info = fut.result()
                hostname = None
                if isinstance(info, dict):
                    hostname = info.get("hostname") or None
                if hostname:
                    host_entry["display"] = f"{hostname} - {host}"
            except Exception as exc:
                error_msg = f"{host}: poll failed ({exc})"
                errors.append(error_msg)
                host_entry["message"] = str(exc)
                host_entry["errors"].append(str(exc))
                host_results[host] = host_entry
                continue

            if host_errors:
                for err in host_errors:
                    if err not in errors:
                        errors.append(err)
                host_entry["errors"].extend(host_errors)

            if samples:
                host_ok = True
                for sample in samples:
                    samples_all.append(sample)
                    enabled_value = sample.get("enabled")
                    if enabled_value is True:
                        enabled_total += 1
                    elif enabled_value is False:
                        disabled_total += 1
                        host_ok = False
                    else:
                        host_ok = False
                    host_entry["entries"].append(
                        {
                            "profile_name": sample.get("profile_name"),
                            "ssid": sample.get("ssid"),
                            "wlan_id": sample.get("wlan_id"),
                            "enabled": sample.get("enabled"),
                            "status_text": sample.get("status_text"),
                            "security_text": sample.get("security_text"),
                        }
                    )
                host_entry["ok"] = host_ok and not host_entry["errors"]
                if host_entry["ok"]:
                    host_entry["message"] = "All matching WLANs enabled."
                    success_hosts += 1
                else:
                    host_entry["message"] = "One or more WLANs disabled or unknown."
            else:
                host_entry["message"] = "No matching WLANs found."
                host_entry["ok"] = False

            if not host_entry.get("display"):
                host_entry["display"] = host

            change_indicator = _build_change_indicator(upcoming_map.get(host))
            if change_indicator:
                host_entry["upcoming_change"] = change_indicator

            host_results[host] = host_entry

    ordered_hosts = []
    for host in hosts:
        entry = host_results.get(host)
        if not entry:
            entry = {
                "host": host,
                "display": host,
                "ok": False,
                "message": "No data",
                "entries": [],
                "errors": ["No response"],
            }
        entry.setdefault("display", entry.get("host", host))
        change_indicator = _build_change_indicator(upcoming_map.get(host))
        if change_indicator:
            entry["upcoming_change"] = change_indicator
        ordered_hosts.append(entry)

    unique_errors = list(dict.fromkeys(errors))

    if disabled_total > 0:
        status = "partial"
        message = "Some Summer Guest WLANs are disabled."
    elif unique_errors and success_hosts < len(hosts):
        status = "partial"
        message = "Completed with errors; review details."
    elif unique_errors:
        status = "partial"
        message = "Completed with warnings."
    elif samples_all:
        status = "ok"
        message = "All Summer Guest WLANs enabled."
    else:
        status = "partial"
        message = "No matching WLANs found on configured controllers."

    summary = {
        "ts": timestamp,
        "status": status,
        "message": message,
        "total_hosts": len(hosts),
        "success_hosts": success_hosts,
        "enabled_total": enabled_total,
        "disabled_total": disabled_total,
        "errors": unique_errors,
        "host_status": ordered_hosts,
        "targets": {
            "profile_names": profile_names,
            "wlan_ids": wlan_ids,
            "auto_prefix": auto_prefix,
        },
        "manual": manual,
    }

    insert_wlc_summer_samples(timestamp, samples_all)
    _record_summer_poll_status(timestamp, status, message)
    new_settings = dict(settings)
    new_settings["summary"] = summary
    _set_summer_settings(new_settings)


def _summer_worker_loop():
    next_run: Optional[datetime] = None
    while True:
        settings = _get_summer_settings()
        if not settings.get("enabled"):
            _SUMMER_WAKE.wait(timeout=60)
            _SUMMER_WAKE.clear()
            next_run = None
            continue

        tz = _summer_timezone(settings)
        now = datetime.now(tz)

        if next_run is None:
            next_run = _next_summer_run(settings, base_dt=now)

        remaining = (next_run - now).total_seconds()
        if remaining > 1:
            triggered = _SUMMER_WAKE.wait(timeout=min(remaining, 300))
            if triggered:
                _SUMMER_WAKE.clear()
                next_run = datetime.now(tz)  # run on next iteration
            continue

        try:
            _summer_poll_once(settings)
        except Exception as exc:
            ts_iso = datetime.now(_CST_TZ).isoformat(timespec="seconds")
            _record_summer_poll_status(ts_iso, "error", f"worker exception: {exc}")
        finally:
            next_settings = _get_summer_settings()
            next_run = _next_summer_run(next_settings)


def _ensure_summer_worker():
    global _SUMMER_THREAD
    if _SUMMER_THREAD is None:
        _SUMMER_THREAD = threading.Thread(target=_summer_worker_loop, daemon=True)
        _SUMMER_THREAD.start()


def _run_summer_poll_async():
    settings = _get_summer_settings()
    thread = threading.Thread(target=_summer_poll_once, args=(dict(settings),), kwargs={"manual": True}, daemon=True)
    thread.start()


def _poll_solarwinds_once(settings: dict) -> tuple[list[dict], list[str]]:
    base_url = settings.get("base_url") or ""
    username = settings.get("username") or ""
    password = settings.get("password") or ""
    verify = bool(settings.get("verify_ssl", True))

    if not base_url or not username or not password:
        raise SolarWindsError("SolarWinds base URL and credentials are required")

    nodes = fetch_solarwinds_nodes_api(
        base_url=base_url,
        username=username,
        password=password,
        verify_ssl=verify,
    )

    shaped = []
    for node in nodes:
        shaped.append(
            {
                "node_id": str(node.get("node_id") or ""),
                "caption": node.get("caption") or "",
                "organization": node.get("organization") or "",
                "vendor": node.get("vendor") or "",
                "model": node.get("model") or "",
                "version": node.get("version") or "",
                "hardware_version": node.get("hardware_version") or "",
                "ip_address": node.get("ip_address") or "",
                "status": node.get("status") or "",
                "last_seen": node.get("last_seen") or "",
                "extra": node.get("raw") or {},
            }
        )
    return shaped, []


def _run_solarwinds_poll(manual: bool = False) -> tuple[bool, str]:
    settings = _get_solar_settings()
    try:
        nodes, errors = _poll_solarwinds_once(settings)
        replace_solarwinds_nodes(nodes)
        _update_wlc_hosts_from_solarwinds(nodes)
        _update_summer_hosts_from_solarwinds(nodes)
        status = "ok" if not errors else "partial"
        message = f"Poll complete. Stored {len(nodes)} node(s)."
        if errors:
            message += " " + "; ".join(errors)
        ts_iso = datetime.now(_CST_TZ).isoformat(timespec="seconds")
        update_solarwinds_poll_status(ts=ts_iso, status=status, message=message)
        new_settings = dict(settings)
        new_settings.update({
            "last_poll_ts": ts_iso,
            "last_poll_status": status,
            "last_poll_message": message,
        })
        _set_solar_settings(new_settings)
        return True, message
    except SolarWindsError as exc:
        message = str(exc)
        ts_iso = datetime.now(_CST_TZ).isoformat(timespec="seconds")
        update_solarwinds_poll_status(ts=ts_iso if manual else None, status="error", message=message)
        new_settings = dict(settings)
        new_settings.update({
            "last_poll_ts": ts_iso if manual else settings.get("last_poll_ts"),
            "last_poll_status": "error",
            "last_poll_message": message,
        })
        _set_solar_settings(new_settings)
        return False, message


def _load_rf_job_state(job_id):
    meta, events = db_load_job(job_id)
    if not meta:
        return None

    params = meta.get("params", {})
    samples = []
    logs = []
    errors = []
    seen_errors = set()
    cancelled_event = False

    for ev in events:
        etype = ev.get("type")
        payload = ev.get("payload", {})

        if etype == "sample":
            sample_payload = payload.get("sample") or {}
            samples.append(sample_payload)
            for err in sample_payload.get("errors", []) or []:
                if err and err not in seen_errors:
                    seen_errors.add(err)
                    errors.append(err)
        elif etype == "error":
            msg = payload.get("message")
            if msg and msg not in seen_errors:
                seen_errors.add(msg)
                errors.append(msg)
        elif etype == "log":
            msg = payload.get("message")
            if msg:
                logs.append(msg)
        elif etype == "cancelled":
            logs.append("Cancelled.")
            if "Job cancelled" not in seen_errors:
                seen_errors.add("Job cancelled")
                errors.append("Job cancelled")
            cancelled_event = True

    return {
        "done": bool(meta.get("done")) or cancelled_event,
        "cancelled": bool(meta.get("cancelled")) or cancelled_event,
        "created": meta.get("created"),
        "params": params,
        "samples": samples,
        "errors": errors,
        "logs": logs,
    }


def _load_clients_job_state(job_id):
    meta, events = db_load_job(job_id)
    if not meta:
        return None

    params = meta.get("params", {})
    samples = []
    logs = []
    errors = []
    seen_errors = set()
    cancelled_event = False

    for ev in events:
        etype = ev.get("type")
        payload = ev.get("payload", {})

        if etype == "sample":
            sample_payload = payload.get("sample") or {}
            samples.append(sample_payload)
            for err in sample_payload.get("errors", []) or []:
                if err and err not in seen_errors:
                    seen_errors.add(err)
                    errors.append(err)
        elif etype == "error":
            msg = payload.get("message")
            if msg and msg not in seen_errors:
                seen_errors.add(msg)
                errors.append(msg)
        elif etype == "log":
            msg = payload.get("message")
            if msg:
                logs.append(msg)
        elif etype == "cancelled":
            logs.append("Cancelled.")
            if "Job cancelled" not in seen_errors:
                seen_errors.add("Job cancelled")
                errors.append("Job cancelled")
            cancelled_event = True

    return {
        "done": bool(meta.get("done")) or cancelled_event,
        "cancelled": bool(meta.get("cancelled")) or cancelled_event,
        "created": meta.get("created"),
        "params": params,
        "samples": samples,
        "errors": errors,
        "logs": logs,
    }


def _dashboard_poll_once(settings: dict):
    # Controller credentials (shared between Cisco and Aruba)
    hosts = settings.get("hosts") or []
    username = settings.get("username") or ""
    password = decrypt_password(settings.get("password") or "")
    secret = decrypt_password(settings.get("secret") or "") if settings.get("secret") else None

    # Aruba controller settings (uses same credentials)
    aruba_enabled = settings.get("aruba_enabled", False)
    aruba_hosts = settings.get("aruba_hosts") or []

    # Check if we have any hosts to poll
    has_cisco = hosts and username and password
    has_aruba = aruba_enabled and aruba_hosts and username and password
    all_hosts = list(hosts) + (aruba_hosts if has_aruba else [])

    if not (has_cisco or has_aruba):
        summary = {
            "ts": datetime.now(_CST_TZ).isoformat(timespec="seconds"),
            "status": "error",
            "message": "Missing hosts or credentials",
            "total_hosts": len(all_hosts),
            "success_hosts": 0,
            "errors": ["Missing hosts or credentials"],
            "host_status": [],
        }
        new_settings = dict(settings)
        new_settings["poll_summary"] = summary
        _set_dashboard_settings(new_settings)
        return

    totals_by_host: Dict[str, int] = {h: 0 for h in all_hosts}
    ap_counts: Dict[str, int] = {h: 0 for h in all_hosts}
    ap_details_by_host: Dict[str, List[Dict]] = {h: [] for h in all_hosts}
    controller_types: Dict[str, str] = {}
    errors: list[str] = []
    host_status: Dict[str, Dict] = {}
    timestamp = datetime.now(_CST_TZ).isoformat(timespec="seconds")

    # Mark controller types
    for h in hosts:
        controller_types[h] = "cisco"
    for h in aruba_hosts:
        controller_types[h] = "aruba"

    max_workers = max(min(len(all_hosts), 100), 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        # Submit Cisco controller jobs
        if has_cisco:
            for host in hosts:
                futures[executor.submit(_collect_wlc_snapshot, host, username, password, secret)] = host
        # Submit Aruba controller jobs (using same credentials)
        if has_aruba:
            for host in aruba_hosts:
                futures[executor.submit(_collect_aruba_snapshot, host, username, password, secret)] = host

        for fut in as_completed(futures):
            host = futures[fut]
            ctrl_type = controller_types.get(host, "cisco")
            try:
                snapshot, host_errors = fut.result()
            except Exception as exc:
                errors.append(f"{host}: snapshot failed ({exc})")
                host_status.setdefault(host, {"host": host, "clients": False, "aps": False, "message": str(exc), "controller_type": ctrl_type})
                continue

            total_clients = snapshot.get("total_clients")
            if total_clients is not None:
                totals_by_host[host] = int(total_clients)
                host_status.setdefault(host, {"host": host, "clients": False, "aps": False, "message": "", "controller_type": ctrl_type})
                host_status[host]["clients"] = True
                host_status[host]["message"] = "Clients OK"
            else:
                host_status.setdefault(host, {"host": host, "clients": False, "aps": False, "message": "", "controller_type": ctrl_type})
                if not host_status[host]["message"]:
                    host_status[host]["message"] = "Client poll failed"

            ap_count = snapshot.get("ap_count")
            if ap_count is not None:
                ap_counts[host] = int(ap_count)
                host_status.setdefault(host, {"host": host, "clients": False, "aps": False, "message": "", "controller_type": ctrl_type})
                host_status[host]["aps"] = ap_count > 0
            else:
                host_status.setdefault(host, {"host": host, "clients": False, "aps": False, "message": "", "controller_type": ctrl_type})
                if host_status[host]["message"] == "Clients OK":
                    host_status[host]["message"] = "AP inventory failed"

            # Collect AP details for inventory
            ap_details = snapshot.get("ap_details") or []
            if ap_details:
                ap_details_by_host[host] = ap_details

            for err in host_errors or []:
                errors.append(err)
                if host_status.get(host):
                    host_status[host]["message"] = err

    success_hosts = 0
    statuses_list = []
    for host in all_hosts:
        status = host_status.get(host, {"host": host, "clients": False, "aps": False, "message": "", "controller_type": controller_types.get(host, "cisco")})
        status["aps"] = ap_counts.get(host, 0) > 0
        if status["clients"]:
            success_hosts += 1
        statuses_list.append(status)

    metrics = []
    for host in all_hosts:
        metrics.append({
            "host": host,
            "total_clients": totals_by_host.get(host, 0),
            "ap_count": ap_counts.get(host, 0),
            "ap_details": [],
            "controller_type": controller_types.get(host, "cisco"),
        })

    insert_wlc_dashboard_samples(timestamp, metrics)

    # Update AP inventory with collected details
    for host in all_hosts:
        ap_details = ap_details_by_host.get(host, [])
        if ap_details:
            try:
                upsert_ap_inventory_bulk(ap_details, wlc_host=host)
            except Exception as exc:
                errors.append(f"{host}: AP inventory update failed ({exc})")

    # Cleanup stale APs (not seen for 5+ days) and log removals for audit
    try:
        removed_count, removed_aps = cleanup_stale_ap_inventory(days=5)
        if removed_count > 0:
            # Log removed APs for audit purposes
            for ap in removed_aps:
                log_audit(
                    "system",
                    "ap_inventory_cleanup",
                    resource=f"{ap['ap_name']} ({ap['ap_mac']})",
                    details=f"WLC: {ap['wlc_host']} | Model: {ap['ap_model']} | Last seen: {ap['last_seen']}",
                )
    except Exception as exc:
        errors.append(f"AP inventory cleanup failed ({exc})")

    errors = list(dict.fromkeys(errors))

    if errors:
        status = "partial"
        message = "Partial success; see errors below."
    else:
        status = "ok"
        message = "Poll successful."

    summary = {
        "ts": timestamp,
        "status": status,
        "message": message,
        "total_hosts": len(all_hosts),
        "success_hosts": success_hosts,
        "errors": errors,
        "host_status": statuses_list,
    }

    _record_dashboard_poll_status(timestamp, status, message)
    new_settings = dict(settings)
    new_settings["poll_summary"] = summary
    _set_dashboard_settings(new_settings)
def _dashboard_worker_loop():
    settings = _get_dashboard_settings()
    interval = max(int(settings.get("interval_sec") or 600), 60)
    next_run = _next_aligned_run(interval)
    while True:
        settings = _get_dashboard_settings()
        interval = max(int(settings.get("interval_sec") or 600), 60)
        if not settings.get("enabled"):
            _DASHBOARD_WAKE.wait(timeout=60)
            _DASHBOARD_WAKE.clear()
            next_run = _next_aligned_run(interval)
            continue

        now = time.time()
        if now < next_run:
            remaining = min(30, next_run - now)
            triggered = _DASHBOARD_WAKE.wait(timeout=remaining)
            if triggered:
                _DASHBOARD_WAKE.clear()
                next_run = _next_aligned_run(interval)
            continue

        try:
            _dashboard_poll_once(settings)
        except Exception as exc:
            _record_dashboard_poll_status(
                datetime.now(_CST_TZ).isoformat(timespec="seconds"),
                "error",
                f"worker exception: {exc}",
            )
        finally:
            next_run = _next_aligned_run(interval)


def _ensure_dashboard_worker():
    global _DASHBOARD_THREAD
    if _DASHBOARD_THREAD is None:
        _DASHBOARD_THREAD = threading.Thread(target=_dashboard_worker_loop, daemon=True)
        _DASHBOARD_THREAD.start()


def _ensure_change_scheduler():
    global _CHANGE_THREAD
    if _CHANGE_THREAD is None:
        _CHANGE_THREAD = threading.Thread(target=_change_scheduler_loop, daemon=True)
        _CHANGE_THREAD.start()


_ensure_summer_worker()
_ensure_dashboard_worker()
_ensure_change_scheduler()

# ====================== ERROR HANDLERS ======================
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 Page Not Found errors."""
    return render_template("error.html",
                          error_code=404,
                          error_title="Page Not Found",
                          error_message="The page you're looking for doesn't exist."), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 Internal Server errors."""
    return render_template("error.html",
                          error_code=500,
                          error_title="Server Error",
                          error_message="Something went wrong on our end. Please try again later."), 500

# ====================== AUTHENTICATION ======================
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            update_last_login(user["id"])
            log_audit(username, "login", user_id=user["id"])

            flash(f"Welcome back, {username}!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("index"))
        else:
            log_audit(username or "unknown", "login_failed")
            flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """User logout"""
    username = session.get("username", "unknown")
    log_audit(username, "logout", user_id=session.get("user_id"))
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@require_login
def profile():
    """User profile and password change"""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Verify current password
        user = verify_user(session["username"], current_password)
        if not user:
            flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            flash("Password must be at least 8 characters", "error")
        else:
            if change_password(session["user_id"], new_password):
                log_audit(session["username"], "password_change", user_id=session["user_id"])
                flash("Password changed successfully", "success")
            else:
                flash("Failed to change password", "error")

    return render_template("profile.html", user=get_current_user())


@app.route("/admin/users", methods=["GET", "POST"])
@require_superadmin
def admin_users():
    """User management (superadmin only)"""
    import sqlite3

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "user")
            kb_access_level = request.form.get("kb_access_level", "FSR")
            can_create_kb = 1 if request.form.get("can_create_kb") else 0

            if len(password) < 8:
                flash("Password must be at least 8 characters", "error")
            elif create_user(username, password, role):
                # Update KB permissions for the new user
                conn = sqlite3.connect("noc_toolkit.db")
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET kb_access_level = ?, can_create_kb = ? WHERE username = ?",
                    (kb_access_level, can_create_kb, username)
                )
                conn.commit()
                conn.close()
                log_audit(session["username"], "user_create", resource=username, user_id=session["user_id"])
                flash(f"User '{username}' created successfully", "success")
            else:
                flash(f"Username '{username}' already exists", "error")

        elif action == "update_kb":
            user_id = request.form.get("user_id")
            kb_access_level = request.form.get("kb_access_level", "FSR")
            can_create_kb = 1 if request.form.get("can_create_kb") else 0

            conn = sqlite3.connect("noc_toolkit.db")
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET kb_access_level = ?, can_create_kb = ? WHERE id = ?",
                (kb_access_level, can_create_kb, user_id)
            )
            conn.commit()
            conn.close()
            flash("User KB permissions updated", "success")

    # Fetch all users including KB permissions
    conn = sqlite3.connect("noc_toolkit.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, created_at, last_login, kb_access_level, can_create_kb FROM users ORDER BY id")
    users = [{
        "id": r[0],
        "username": r[1],
        "role": r[2],
        "created_at": r[3],
        "last_login": r[4],
        "kb_access_level": r[5] or "FSR",
        "can_create_kb": r[6] or 0
    } for r in cursor.fetchall()]
    conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/page-settings", methods=["GET", "POST"])
@require_superadmin
def admin_page_settings():
    """Page visibility settings (superadmin only)."""
    if request.method == "POST":
        # Get all page keys from form and update settings
        all_pages = get_page_settings()
        updates = {}
        for page in all_pages:
            key = page["page_key"]
            # If checkbox is checked, it will be in form data
            enabled = request.form.get(f"page_{key}") == "on"
            updates[key] = enabled

        if bulk_update_page_settings(updates):
            log_audit(session["username"], "page_settings_update", user_id=session["user_id"])
            flash("Page visibility settings updated.", "success")
        else:
            flash("Failed to update page settings.", "error")

        return redirect(url_for("admin_page_settings"))

    # Group pages by category
    pages = get_page_settings()
    pages_by_category = {}
    for page in pages:
        cat = page.get("category") or "Other"
        if cat not in pages_by_category:
            pages_by_category[cat] = []
        pages_by_category[cat].append(page)

    return render_template("admin_page_settings.html", pages_by_category=pages_by_category)


@app.route("/admin/settings", methods=["GET", "POST"])
@require_superadmin
def admin_settings():
    """Application-wide settings (superadmin only)."""
    if request.method == "POST":
        new_timezone = request.form.get("timezone", "America/Chicago")

        # Validate timezone is in our allowed list
        valid_timezones = [tz[0] for tz in US_TIMEZONES]
        if new_timezone not in valid_timezones:
            flash("Invalid timezone selected.", "error")
            return redirect(url_for("admin_settings"))

        if save_app_settings(timezone=new_timezone):
            log_audit(session["username"], "app_settings_update", resource=f"timezone={new_timezone}", user_id=session["user_id"])
            flash("Application settings updated successfully.", "success")
        else:
            flash("Failed to update application settings.", "error")

        return redirect(url_for("admin_settings"))

    settings = load_app_settings()
    return render_template("admin_settings.html", settings=settings, timezones=US_TIMEZONES)


# ====================== HOME ======================
@app.get("/")
@require_login
def index():
    # Get counts for dashboard
    total_nodes = len(fetch_solarwinds_nodes())

    # Count upcoming change windows
    now_iso = datetime.now(_CST_TZ).isoformat()
    upcoming_windows = fetch_due_change_windows(now_iso)
    upcoming_changes = len([w for w in upcoming_windows if w.get('status') != 'completed'])
    total_changes = len(list_change_windows())

    return render_template(
        "index.html",
        total_nodes=total_nodes,
        upcoming_changes=upcoming_changes,
        total_changes=total_changes
    )

@app.get("/api/dashboard-stats")
@require_login
def dashboard_stats():
    """API endpoint for real-time dashboard statistics"""
    try:
        # WLC Dashboard stats
        wlc_settings = load_wlc_dashboard_settings()
        latest_totals = fetch_wlc_dashboard_latest_totals()

        wlc_data = {
            'enabled': wlc_settings.get('enabled', False),
            'interval': wlc_settings.get('interval_minutes', 5),
            'clients': latest_totals.get('clients', 0),
            'aps': latest_totals.get('aps', 0),
            'last_poll': _format_cst(wlc_settings.get('last_poll_at')) if wlc_settings.get('last_poll_at') else None
        }

        # Summer Guest stats
        summer_settings = load_wlc_summer_settings()
        summer_data = {
            'enabled': summer_settings.get('enabled', False),
            'schedule': f"Daily at {summer_settings.get('poll_hour', 7)}:00" if summer_settings.get('enabled') else None,
            'last_run': _format_cst(summer_settings.get('last_poll_at')) if summer_settings.get('last_poll_at') else None
        }

        # Job count - count running jobs
        all_jobs = db_list_jobs(limit=500)
        running_jobs = [j for j in all_jobs if not j.get('done') and not j.get('cancelled')]
        jobs_data = len(running_jobs)

        # Change windows
        now_iso = datetime.now(_CST_TZ).isoformat()
        upcoming_windows = fetch_due_change_windows(now_iso)
        upcoming_count = len([w for w in upcoming_windows if w.get('status') != 'completed'])

        return jsonify({
            'wlc': wlc_data,
            'summer_guest': summer_data,
            'jobs': jobs_data,
            'upcoming_changes': upcoming_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====================== JOBS CENTER ======================
@app.get("/jobs")
@require_login
@require_page_enabled("jobs_center")
def jobs_center():
    """Unified jobs center - all background jobs across all tools"""
    all_jobs = db_list_jobs(limit=500)

    jobs = []
    for row in all_jobs:
        job_id = row.get("job_id", "")
        tool = row.get("tool", "")
        created = row.get("created", "")
        done = bool(row.get("done"))
        cancelled = bool(row.get("cancelled"))

        # Determine status
        if cancelled:
            status = "cancelled"
        elif done:
            # Check if it has errors
            _, events = db_load_job(job_id)
            has_errors = any(ev.get("type") == "error" for ev in events)
            status = "failed" if has_errors else "completed"
        else:
            status = "running"

        # Get description from params
        params = row.get("params", {})
        description = params.get("description", tool.replace("-", " ").title())

        # Format created time
        try:
            created_formatted = _format_cst(created) if created else "—"
        except Exception:
            created_formatted = created or "—"

        # Calculate duration if completed
        duration = "—"
        if done and created:
            try:
                # Would need end time from events to calculate actual duration
                duration = "—"
            except Exception:
                pass

        jobs.append({
            'id': job_id,
            'type': tool,
            'description': description,
            'status': status,
            'created_at': created,
            'created_at_formatted': created_formatted,
            'duration': duration,
            'progress': None  # Could calculate from events
        })

    # Also include Bulk SSH jobs
    bulk_ssh_jobs = list_bulk_ssh_jobs(limit=200)
    for row in bulk_ssh_jobs:
        job_id = row.get("job_id", "")
        created = row.get("created", "")
        done = bool(row.get("done"))
        status_raw = row.get("status", "running")

        # Determine status
        if done:
            status = "completed" if status_raw == "completed" else "failed"
        else:
            status = "running"

        # Build description
        device_count = row.get("device_count", 0)
        command = row.get("command", "")[:50]
        description = f"Bulk SSH: {command}{'...' if len(row.get('command', '')) > 50 else ''}"

        # Format created time
        try:
            created_formatted = _format_cst(created) if created else "—"
        except Exception:
            created_formatted = created or "—"

        # Calculate progress
        completed_count = row.get("completed_count", 0)
        progress = int((completed_count / device_count * 100)) if device_count > 0 else None

        jobs.append({
            'id': job_id,
            'type': 'bulk-ssh',
            'description': description,
            'status': status,
            'created_at': created,
            'created_at_formatted': created_formatted,
            'duration': "—",
            'progress': progress
        })

    # Sort all jobs by created_at descending
    jobs.sort(key=lambda j: j.get('created_at', ''), reverse=True)

    return render_template("jobs_center.html", jobs=jobs)

@app.get("/api/jobs")
@require_login
def api_jobs():
    """API endpoint for jobs list (for refresh)"""
    all_jobs = db_list_jobs(limit=500)

    jobs = []
    for row in all_jobs:
        job_id = row.get("job_id", "")
        tool = row.get("tool", "")
        created = row.get("created", "")
        done = bool(row.get("done"))
        cancelled = bool(row.get("cancelled"))

        # Determine status
        if cancelled:
            status = "cancelled"
        elif done:
            _, events = db_load_job(job_id)
            has_errors = any(ev.get("type") == "error" for ev in events)
            status = "failed" if has_errors else "completed"
        else:
            status = "running"

        params = row.get("params", {})
        description = params.get("description", tool.replace("-", " ").title())

        try:
            created_formatted = _format_cst(created) if created else "—"
        except Exception:
            created_formatted = created or "—"

        jobs.append({
            'id': job_id,
            'type': tool,
            'description': description,
            'status': status,
            'created_at': created,
            'created_at_formatted': created_formatted,
            'duration': "—",
            'progress': None
        })

    # Also include Bulk SSH jobs
    bulk_ssh_jobs = list_bulk_ssh_jobs(limit=200)
    for row in bulk_ssh_jobs:
        job_id = row.get("job_id", "")
        created = row.get("created", "")
        done = bool(row.get("done"))
        status_raw = row.get("status", "running")

        # Determine status
        if done:
            status = "completed" if status_raw == "completed" else "failed"
        else:
            status = "running"

        # Build description
        device_count = row.get("device_count", 0)
        command = row.get("command", "")[:50]
        description = f"Bulk SSH: {command}{'...' if len(row.get('command', '')) > 50 else ''}"

        try:
            created_formatted = _format_cst(created) if created else "—"
        except Exception:
            created_formatted = created or "—"

        # Calculate progress
        completed_count = row.get("completed_count", 0)
        progress = int((completed_count / device_count * 100)) if device_count > 0 else None

        jobs.append({
            'id': job_id,
            'type': 'bulk-ssh',
            'description': description,
            'status': status,
            'created_at': created,
            'created_at_formatted': created_formatted,
            'duration': "—",
            'progress': progress
        })

    # Sort all jobs by created_at descending
    jobs.sort(key=lambda j: j.get('created_at', ''), reverse=True)

    return jsonify({'jobs': jobs})

@app.get("/jobs/<job_id>")
@require_login
def job_detail(job_id):
    """View details of a specific job"""
    meta, events = db_load_job(job_id)
    if not meta:
        flash("Job not found")
        return redirect(url_for('jobs_center'))

    # Format events for display
    formatted_events = []
    for ev in events:
        event_type = ev.get('type', 'log')
        timestamp = ev.get('timestamp', '')
        payload = ev.get('payload', {})

        try:
            ts_formatted = _format_cst(timestamp) if timestamp else "—"
        except Exception:
            ts_formatted = timestamp or "—"

        formatted_events.append({
            'type': event_type,
            'timestamp': ts_formatted,
            'payload': payload
        })

    return render_template("job_detail.html", job=meta, events=formatted_events)

@app.post("/api/jobs/<job_id>/cancel")
@require_login
def cancel_job(job_id):
    """Cancel a running job"""
    try:
        # Mark job as cancelled by appending a cancel event
        append_event(job_id, "cancelled", {"message": "Cancelled by user"})
        mark_done(job_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.get("/jobs/<job_id>/progress")
@require_login
def job_progress_page(job_id):
    """Live job progress page with real-time updates - supports both generic jobs and bulk SSH jobs"""
    # First try generic jobs table
    meta, events = db_load_job(job_id)
    if meta:
        params = meta.get("params", {})
        hosts = params.get("hosts", [])
        return render_template(
            "job_progress.html",
            job_id=job_id,
            device_count=len(hosts),
            hosts=hosts,
            tool=meta.get("tool", "config"),
            job_type="generic"
        )

    # Try bulk SSH jobs table
    bulk_job = load_bulk_ssh_job(job_id)
    if bulk_job:
        # Get device list from results (devices that have started/completed)
        results = load_bulk_ssh_results(job_id)
        # We need to know the original device list - parse from command context
        # For now, get devices from results and estimate total from device_count
        device_count = bulk_job.get("device_count", 0)
        completed_devices = [r.get("device") for r in results]

        return render_template(
            "job_progress.html",
            job_id=job_id,
            device_count=device_count,
            hosts=completed_devices,  # Will be populated dynamically via API
            tool="bulk-ssh",
            job_type="bulk_ssh",
            command=bulk_job.get("command", "")
        )

    flash("Job not found")
    return redirect(url_for('jobs_center'))


@app.get("/api/jobs/<job_id>/progress")
@require_login
def api_job_progress(job_id):
    """API endpoint for live job progress data - supports both generic jobs and bulk SSH jobs"""
    # First try generic jobs table
    meta, events = db_load_job(job_id)
    if meta:
        params = meta.get("params", {})
        hosts = params.get("hosts", [])
        done = bool(meta.get("done"))

        # Track per-device status
        device_status = {h: {"status": "pending", "message": "Waiting...", "duration": ""} for h in hosts}
        logs = []
        completed = 0
        success = 0
        failed = 0

        for ev in events:
            etype = ev.get("type")
            payload = ev.get("payload", {})
            host = payload.get("host")
            message = payload.get("message", "")

            if etype == "success" and host:
                device_status[host] = {
                    "status": "success",
                    "message": message[:80] if message else "OK",
                    "duration": ""
                }
                completed += 1
                success += 1
                logs.append(f"[{host}] OK - {message}")
            elif etype == "error" and host:
                device_status[host] = {
                    "status": "error",
                    "message": message[:80] if message else "Failed",
                    "duration": ""
                }
                completed += 1
                failed += 1
                logs.append(f"[{host}] FAIL - {message}")
            elif etype == "log":
                if message:
                    logs.append(message)
            elif etype == "done":
                logs.append("Job complete.")
            elif etype == "cancelled":
                logs.append("Job cancelled.")

        # Build device list for frontend
        devices = []
        for host in hosts:
            status_info = device_status.get(host, {"status": "pending", "message": "Waiting...", "duration": ""})
            devices.append({
                "host": host,
                "status": status_info["status"],
                "message": status_info["message"],
                "duration": status_info["duration"]
            })

        return jsonify({
            "job_id": job_id,
            "done": done,
            "completed": completed,
            "success": success,
            "failed": failed,
            "total": len(hosts),
            "devices": devices,
            "logs": logs
        })

    # Try bulk SSH jobs table
    bulk_job = load_bulk_ssh_job(job_id)
    if bulk_job:
        results = load_bulk_ssh_results(job_id)
        done = bool(bulk_job.get("done"))
        device_count = bulk_job.get("device_count", 0)
        completed = bulk_job.get("completed_count", 0)
        success = bulk_job.get("success_count", 0)
        failed = bulk_job.get("failed_count", 0)

        # Build device list from results
        devices = []
        logs = [f"Job {job_id} started - {device_count} devices"]

        for r in results:
            device = r.get("device", "")
            status = r.get("status", "pending")
            error = r.get("error", "")
            output = r.get("output", "")
            duration_ms = r.get("duration_ms", 0)

            devices.append({
                "host": device,
                "status": status,
                "message": error if status == "failed" else (output[:80] if output else "OK"),
                "duration": f"{duration_ms}ms" if duration_ms else ""
            })

            if status == "success":
                logs.append(f"[{device}] OK - completed in {duration_ms}ms")
            else:
                logs.append(f"[{device}] FAIL - {error}")

        if done:
            logs.append("Job complete.")

        return jsonify({
            "job_id": job_id,
            "done": done,
            "completed": completed,
            "success": success,
            "failed": failed,
            "total": device_count,
            "devices": devices,
            "logs": logs
        })

    return jsonify({"error": "Job not found"}), 404


# ====================== INTERFACE CONFIG SEARCH ======================
@app.get("/tools/phrase-search")
@require_login
@require_page_enabled("tool_phrase_search")
def tool_phrase_search():
    node_options = _solar_node_options()
    return render_template("phrase_search.html", node_options=node_options)

@app.post("/search")
@require_login
def search():
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
        return redirect(url_for("tool_phrase_search"))

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

@app.post("/download-csv")
@require_login
def download_csv():
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
    filename = f"multi_desc_search_{re.sub(r'[^A-Za-z0-9_.-]+','_',phrase)}.csv"
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ====================== TOPOLOGY REPORT ======================
@app.get("/tools/topology")
@require_login
@require_page_enabled("topology_tool")
def topology_tool():
    nodes = fetch_solarwinds_nodes()
    node_options = _solar_node_options(nodes)
    org_options = _solar_org_options(nodes)
    form_data = {
        "target": "",
        "username": "",
        "vendor_mode": "auto",
        "scope": "node",
        "organization": "",
    }
    return render_template(
        "topology_builder.html",
        node_options=node_options,
        org_options=org_options,
        form_data=form_data,
        scope="node",
        results=[],
        result_counts={"total": 0, "success": 0, "errors": 0},
        report_json="",
    )


@app.post("/tools/topology/report")
@require_login
def topology_report():
    scope = (request.form.get("scope") or "node").strip().lower()
    target = (request.form.get("target") or "").strip()
    organization = (request.form.get("organization") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    secret = request.form.get("secret") or ""
    vendor_mode = (request.form.get("vendor_mode") or "auto").strip().lower() or "auto"

    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for("topology_tool"))

    nodes = fetch_solarwinds_nodes()
    node_options = _solar_node_options(nodes)
    org_options = _solar_org_options(nodes)

    # Handle device_list for bulk scope
    device_list_text = (request.form.get("device_list") or "").strip()

    scope = scope if scope in {"node", "organization", "bulk"} else "node"
    form_data = {
        "target": target,
        "username": username,
        "vendor_mode": vendor_mode,
        "scope": scope,
        "organization": organization,
    }

    results: List[dict[str, object]] = []
    export_payload: dict[str, object] = {"scope": scope, "results": []}
    if scope == "organization":
        export_payload["organization"] = organization
    else:
        export_payload["target"] = target

    if scope == "organization":
        if not organization:
            flash("Enter or select an organization to build a topology report.")
            return redirect(url_for("topology_tool"))

        org_key = organization.lower()
        matched_nodes = [
            node for node in nodes or [] if (node.get("organization") or "").strip().lower() == org_key
        ]
        if not matched_nodes:
            flash("No SolarWinds nodes found for the selected organization.")
            return redirect(url_for("topology_tool"))

        for idx, node in enumerate(matched_nodes, start=1):
            host_ip = (node.get("ip_address") or "").strip()
            caption = (node.get("caption") or "").strip() or host_ip or f"Node {idx}"
            root = {
                "ip_address": host_ip,
                "caption": caption,
                "vendor": (node.get("vendor") or "").strip(),
                "model": (node.get("model") or "").strip(),
                "organization": (node.get("organization") or "").strip(),
            }
            if not host_ip:
                results.append({"root": root, "report": None, "error": "Node has no IP address in SolarWinds."})
                export_payload["results"].append({"root": root, "neighbors": [], "error": "missing-ip"})
                continue

            node_vendor_hint = (node.get("vendor") or "").strip() if vendor_mode == "auto" else vendor_mode
            try:
                report = build_topology_report(
                    host=host_ip,
                    username=username,
                    password=password,
                    secret=secret or None,
                    vendor_hint=node_vendor_hint,
                    vendor_mode=None if vendor_mode == "auto" else vendor_mode,
                    nodes=nodes,
                )
                results.append({"root": root, "report": report, "error": None})
                export_payload["results"].append(
                    {"root": root, "neighbors": report.get("neighbors") or [], "error": None}
                )
            except TopologyError as exc:
                err_msg = str(exc)
                results.append({"root": root, "report": None, "error": err_msg})
                export_payload["results"].append({"root": root, "neighbors": [], "error": err_msg})
    elif scope == "bulk":
        if not device_list_text:
            flash("Enter a list of devices (one per line) to build a bulk topology report.")
            return redirect(url_for("topology_tool"))

        # Parse device list
        device_list = [line.strip() for line in device_list_text.split("\n") if line.strip()]
        if not device_list:
            flash("Device list is empty.")
            return redirect(url_for("topology_tool"))

        for device in device_list:
            # Try to match with SolarWinds nodes
            host_ip, node = _resolve_target_node(device, nodes)
            if not host_ip:
                # Use device as-is if not found in SolarWinds
                host_ip = device
                node = None

            root = {
                "ip_address": host_ip,
                "caption": (node.get("caption") if node else "") or device,
                "vendor": (node.get("vendor") if node else "") or "",
                "model": (node.get("model") if node else "") or "",
                "organization": (node.get("organization") if node else "") or "",
            }

            vendor_hint = (node.get("vendor") if node else None) if vendor_mode == "auto" else vendor_mode
            try:
                report = build_topology_report(
                    host=host_ip,
                    username=username,
                    password=password,
                    secret=secret or None,
                    vendor_hint=vendor_hint,
                    vendor_mode=None if vendor_mode == "auto" else vendor_mode,
                    nodes=nodes,
                )
                results.append({"root": root, "report": report, "error": None})
                export_payload["results"].append({"root": root, "neighbors": report.get("neighbors") or [], "error": None})
            except TopologyError as exc:
                err_msg = str(exc)
                results.append({"root": root, "report": None, "error": err_msg})
                export_payload["results"].append({"root": root, "neighbors": [], "error": err_msg})
    else:
        if not target:
            flash("Select a SolarWinds node (hostname or IP) to build a topology report.")
            return redirect(url_for("topology_tool"))

        host_ip, node = _resolve_target_node(target, nodes)
        if not host_ip:
            flash("Unable to resolve the selected node to an IP address from SolarWinds.")
            return redirect(url_for("topology_tool"))

        vendor_hint = (node.get("vendor") if node else None) if vendor_mode == "auto" else vendor_mode
        try:
            report = build_topology_report(
                host=host_ip,
                username=username,
                password=password,
                secret=secret or None,
                vendor_hint=vendor_hint,
                vendor_mode=None if vendor_mode == "auto" else vendor_mode,
                nodes=nodes,
            )
        except TopologyError as exc:
            flash(f"Topology collection failed: {exc}")
            return redirect(url_for("topology_tool"))

        root = {
            "ip_address": host_ip,
            "caption": (node.get("caption") if node else "") or target,
            "vendor": (node.get("vendor") if node else "") or "",
            "model": (node.get("model") if node else "") or "",
            "organization": (node.get("organization") if node else "") or "",
        }

        results.append({"root": root, "report": report, "error": None})
        export_payload["results"].append({"root": root, "neighbors": report.get("neighbors") or [], "error": None})

    report_json = json.dumps(export_payload)
    result_counts = {
        "total": len(results),
        "success": sum(1 for item in results if item.get("report")),
        "errors": sum(1 for item in results if not item.get("report")),
    }

    return render_template(
        "topology_builder.html",
        node_options=node_options,
        org_options=org_options,
        form_data=form_data,
        scope=scope,
        results=results,
        result_counts=result_counts,
        report_json=report_json,
    )


@app.route("/tools/topology/graph", methods=["GET", "POST"])
@require_login
def topology_graph():
    """Interactive graph view for topology discovery"""
    if request.method == "GET":
        # Show empty graph with instructions
        return render_template(
            "topology_graph.html",
            initial_data=None,
            username="",
            password="",
            secret="",
            vendor_mode="auto"
        )

    # POST - Initial discovery from form
    scope = (request.form.get("scope") or "node").strip().lower()
    target = (request.form.get("target") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    secret = request.form.get("secret") or ""
    vendor_mode = (request.form.get("vendor_mode") or "auto").strip().lower()

    if not username or not password or not target:
        flash("Username, password, and target device are required for graph view.")
        return redirect(url_for("topology_tool"))

    nodes = fetch_solarwinds_nodes()
    host_ip, node = _resolve_target_node(target, nodes)
    if not host_ip:
        flash("Unable to resolve the target device.")
        return redirect(url_for("topology_tool"))

    vendor_hint = (node.get("vendor") if node else None) if vendor_mode == "auto" else vendor_mode
    try:
        report = build_topology_report(
            host=host_ip,
            username=username,
            password=password,
            secret=secret or None,
            vendor_hint=vendor_hint,
            vendor_mode=None if vendor_mode == "auto" else vendor_mode,
            nodes=nodes,
        )
    except TopologyError as exc:
        flash(f"Topology discovery failed: {exc}")
        return redirect(url_for("topology_tool"))

    root = {
        "ip_address": host_ip,
        "caption": (node.get("caption") if node else "") or target,
        "vendor": (node.get("vendor") if node else "") or "",
        "model": (node.get("model") if node else "") or "",
        "organization": (node.get("organization") if node else "") or "",
    }

    initial_data = {
        "root": root,
        "neighbors": report.get("neighbors") or []
    }

    return render_template(
        "topology_graph.html",
        initial_data=initial_data,
        username=username,
        password=password,
        secret=secret,
        vendor_mode=vendor_mode
    )


@app.post("/api/topology/discover")
@require_login
def api_topology_discover():
    """JSON API endpoint for discovering topology of a single device"""
    target = request.json.get("target", "").strip()
    username = request.json.get("username", "").strip()
    password = request.json.get("password", "")
    secret = request.json.get("secret", "")
    vendor_mode = request.json.get("vendor_mode", "auto").strip().lower()

    if not target or not username or not password:
        return jsonify({"error": "Missing required parameters"}), 400

    nodes = fetch_solarwinds_nodes()
    host_ip, node = _resolve_target_node(target, nodes)

    if not host_ip:
        # Try using target as-is if not found in SolarWinds
        host_ip = target
        node = None

    vendor_hint = (node.get("vendor") if node else None) if vendor_mode == "auto" else vendor_mode

    try:
        report = build_topology_report(
            host=host_ip,
            username=username,
            password=password,
            secret=secret or None,
            vendor_hint=vendor_hint,
            vendor_mode=None if vendor_mode == "auto" else vendor_mode,
            nodes=nodes,
        )
    except TopologyError as exc:
        return jsonify({"error": str(exc)}), 500

    root = {
        "ip_address": host_ip,
        "caption": (node.get("caption") if node else "") or target,
        "vendor": (node.get("vendor") if node else "") or "",
        "model": (node.get("model") if node else "") or "",
        "organization": (node.get("organization") if node else "") or "",
        "platform": ""
    }

    return jsonify({
        "success": True,
        "root": root,
        "neighbors": report.get("neighbors") or [],
        "device_type": report.get("device_type", ""),
        "command_notes": report.get("command_notes", [])
    })


@app.post("/tools/topology/export")
@require_login
def topology_export():
    report_json = request.form.get("report_json") or ""
    if not report_json:
        flash("No report available to export.")
        return redirect(url_for("topology_tool"))
    try:
        payload = json.loads(report_json)
    except Exception:
        flash("Could not parse the captured topology data.")
        return redirect(url_for("topology_tool"))

    scope = payload.get("scope") or "node"
    results_payload = payload.get("results")
    if not isinstance(results_payload, list):
        fallback_root = payload.get("root") or {}
        fallback_neighbors = payload.get("neighbors") or []
        fallback_error = payload.get("error")
        results_payload = [{"root": fallback_root, "neighbors": fallback_neighbors, "error": fallback_error}]

    buf = StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "Root Caption",
            "Root IP",
            "Local Interface",
            "Neighbor Name",
            "Neighbor IP",
            "Neighbor Port",
            "Protocols",
            "Neighbor Platform",
            "Neighbor Capabilities",
            "Inventory Match",
            "Inventory IP",
            "Inventory Vendor",
            "Inventory Model",
            "Inventory Organization",
        ]
    )

    for result in results_payload:
        root = result.get("root") or {}
        neighbors = result.get("neighbors") or []
        error = result.get("error")
        if neighbors:
            for neighbor in neighbors:
                inventory = neighbor.get("inventory") or {}
                protocols = neighbor.get("protocols") or []
                writer.writerow(
                    [
                        root.get("caption") or "",
                        root.get("ip_address") or "",
                        neighbor.get("local_interface") or "",
                        neighbor.get("remote_name") or "",
                        neighbor.get("remote_ip") or "",
                        neighbor.get("remote_port") or "",
                        "/".join(protocols),
                        neighbor.get("remote_platform") or "",
                        neighbor.get("remote_capabilities") or "",
                        inventory.get("caption") or "",
                        inventory.get("ip_address") or "",
                        inventory.get("vendor") or "",
                        inventory.get("model") or "",
                        inventory.get("organization") or "",
                    ]
                )
        else:
            marker = f"ERROR: {error}" if error else "(no neighbors)"
            writer.writerow(
                [
                    root.get("caption") or "",
                    root.get("ip_address") or "",
                    "",
                    marker,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )

    slug_source = payload.get("organization") if scope == "organization" else payload.get("target")
    if not slug_source and results_payload:
        first_root = (results_payload[0] or {}).get("root") or {}
        slug_source = first_root.get("caption") or first_root.get("ip_address")
    slug_base = slug_source or ("org" if scope == "organization" else "topology")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", slug_base)
    prefix = "topology_org" if scope == "organization" else "topology"
    filename = f"{prefix}_{slug}.csv"

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

# ====================== INTERFACE ACTIONS: PREVIEW / APPLY ======================
@app.post("/actions/prepare")
@require_login
def actions_prepare():
    selected = request.form.getlist("selected[]")  # ["<host>||<iface>", ...]
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
        return redirect(url_for("tool_phrase_search"))

    payload = {
        "cli_map": cli_map,
        "username": apply_username,
        "password": apply_password,
        "secret": apply_secret,
        "tool": "interface-config",
        "pairs": [(h, i) for h, i in pairs],
    }
    return render_template("action_preview.html", cli_map=cli_map, payload=payload)

@app.post("/actions/apply")
@require_login
def actions_apply():
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

# ---------- Background apply for interface actions ----------
@app.post("/actions/apply/start")
@require_login
def actions_apply_start():
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


@app.post("/actions/schedule")
@require_login
def actions_schedule():
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

    _CHANGE_WAKE.set()

    return jsonify({
        "change_id": change_id,
        "scheduled_local": local_dt.strftime("%Y-%m-%d %I:%M %p CST"),
    })

@app.get("/actions/status/<job_id>")
@require_login
def actions_status(job_id):
    state = _get_cli_job_state(job_id)
    if not state:
        return jsonify({"error": "unknown job id"}), 404
    return jsonify(state)

# ====================== CHANGE WINDOWS ======================


@app.get("/changes")
@require_login
@require_page_enabled("changes_list")
def changes_list():
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
    return render_template("changes.html", changes=records, app_timezone=app_tz)


@app.get("/changes/<change_id>")
@require_login
def change_detail(change_id):
    raw_change, events = load_change_window(change_id)
    if not raw_change:
        flash("Change not found.")
        return redirect(url_for("changes_list"))

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


@app.post("/changes/<change_id>/start")
@require_login
def change_start_now(change_id):
    raw_change, _ = load_change_window(change_id)
    if not raw_change:
        flash("Change not found.")
        return redirect(url_for("changes_list"))
    if raw_change.get("status") != "scheduled":
        flash("Change is not in a scheduled state.")
        return redirect(url_for("change_detail", change_id=change_id))

    _start_change_execution(raw_change)
    _CHANGE_WAKE.set()
    flash("Change execution started.")
    return redirect(url_for("change_detail", change_id=change_id))


@app.post("/changes/<change_id>/rollback")
@require_login
def change_trigger_rollback(change_id):
    raw_change, _ = load_change_window(change_id)
    if not raw_change:
        flash("Change not found.")
        return redirect(url_for("changes_list"))

    if raw_change.get("status") in {"scheduled", "running", "rollback-running"}:
        flash("Change must complete before triggering rollback.")
        return redirect(url_for("change_detail", change_id=change_id))

    if _start_change_rollback(raw_change):
        _CHANGE_WAKE.set()
        flash("Rollback started.")
    else:
        flash("Rollback unavailable for this change.")
    return redirect(url_for("change_detail", change_id=change_id))

# ====================== GLOBAL CONFIG SEARCH/APPLY ======================
@app.get("/tools/global-config")
@require_login
@require_page_enabled("tool_global_config")
def tool_global_config():
    node_options = _solar_node_options()
    return render_template("global_config.html", node_options=node_options)

@app.post("/global/search")
@require_login
def global_config_search():
    hosts = _parse_hosts_field(request.form.get("hosts"))
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    secret = request.form.get("secret") or None
    phrase = request.form.get("phrase", "").strip()
    case_sensitive = request.form.get("case_sensitive") == "1"

    if not (hosts and username and password and phrase):
        flash("All fields are required.")
        return redirect(url_for("tool_global_config"))

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

@app.post("/global/download-csv")
@require_login
def global_config_download_csv():
    matches_json = request.form.get("matches_json", "[]")
    try:
        matches = json.loads(matches_json)
    except Exception:
        matches = []
    buf = StringIO()
    w = csv.DictWriter(buf, fieldnames=["host"], lineterminator="\n")
    w.writeheader()
    for m in matches:
        w.writerow({"host": m.get("host", "")})
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=global_matches.csv"}
    )

@app.post("/global/actions/prepare")
@require_login
def global_config_actions_prepare():
    selected_hosts = request.form.getlist("selected_hosts[]")
    custom_config = request.form.get("custom_config", "")
    apply_username = request.form.get("apply_username")
    apply_password = request.form.get("apply_password")
    apply_secret = request.form.get("apply_secret")

    cli_map = build_cli_for_global_action(selected_hosts, custom_config)

    if not any(cli_map.values()):
        flash("Nothing to apply. Provide global CLI lines and select at least one switch.")
        return redirect(url_for("tool_global_config"))

    payload = {
        "cli_map": cli_map,
        "username": apply_username,
        "password": apply_password,
        "secret": apply_secret,
        "tool": "global-config",
    }
    return render_template("action_preview_global.html", cli_map=cli_map, payload=payload)

@app.post("/global/actions/apply")
@require_login
def global_config_actions_apply():
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

@app.post("/global/actions/apply/start")
@require_login
def global_config_actions_apply_start():
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

@app.get("/global/actions/status/<job_id>")
@require_login
def global_config_actions_status(job_id):
    state = _get_cli_job_state(job_id)
    if not state:
        return jsonify({"error": "unknown job id"}), 404
    return jsonify(state)

# ====================== AUDIT LOG VIEWER ======================
def _load_audit_rows():
    rows = []
    if not os.path.exists(LOG_FILE):
        return rows
    with open(LOG_FILE, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            for k in LOG_HEADERS:
                row.setdefault(k, "")
            rows.append(row)
    rows.sort(key=lambda x: x.get("timestamp",""), reverse=True)
    return rows

def _filter_rows(rows, username=None, tool=None, result=None, ip=None, q=None, date_from=None, date_to=None):
    def in_range(ts):
        if not ts: return False
        try:
            dt = datetime.fromisoformat(ts)
        except Exception:
            return False
        if date_from and dt < date_from: return False
        if date_to and dt > date_to: return False
        return True

    out = []
    for r in rows:
        if username and username.lower() not in r["username"].lower(): continue
        if tool and tool != r["tool"]: continue
        if result and result != r["result"]: continue
        if ip and ip not in r["switch_ip"]: continue
        if q:
            blob = " ".join([r.get(k,"") for k in ("message","config_lines","switch_ip","job_id")])
            if q.lower() not in blob.lower(): continue
        if date_from or date_to:
            if not in_range(r.get("timestamp","")): continue
        out.append(r)
    return out

@app.get("/logs")
@require_superadmin
@require_page_enabled("audit_logs")
def audit_logs():
    username = (request.args.get("username") or "").strip() or None
    tool = (request.args.get("tool") or "").strip() or None
    result = (request.args.get("result") or "").strip() or None
    ip = (request.args.get("ip") or "").strip() or None
    q = (request.args.get("q") or "").strip() or None
    df = (request.args.get("date_from") or "").strip() or None
    dt = (request.args.get("date_to") or "").strip() or None
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 25) or 25), 5), 200)

    date_from = None
    date_to = None
    try:
        if df: date_from = datetime.fromisoformat(df)
        if dt:
            dtt = datetime.fromisoformat(dt)
            if len(dt) == 10:
                dtt = dtt.replace(hour=23, minute=59, second=59)
            date_to = dtt
    except Exception:
        date_from = date_to = None

    rows = _load_audit_rows()
    filtered = _filter_rows(rows, username, tool, result, ip, q, date_from, date_to)

    total = len(filtered)
    start = (page-1)*per_page
    end = start+per_page
    page_rows = filtered[start:end]

    tools = sorted({r["tool"] for r in rows if r.get("tool")})

    return render_template(
        "audit_logs.html",
        rows=page_rows,
        total=total,
        page=page,
        per_page=per_page,
        tools=tools,
        filters={
            "username": username or "",
            "tool": tool or "",
            "result": result or "",
            "ip": ip or "",
            "q": q or "",
            "date_from": df or "",
            "date_to": dt or "",
        },
    )

@app.get("/logs/download")
@require_superadmin
def audit_logs_download():
    username = (request.args.get("username") or "").strip() or None
    tool = (request.args.get("tool") or "").strip() or None
    result = (request.args.get("result") or "").strip() or None
    ip = (request.args.get("ip") or "").strip() or None
    q = (request.args.get("q") or "").strip() or None
    df = (request.args.get("date_from") or "").strip() or None
    dt = (request.args.get("date_to") or "").strip() or None

    date_from = None
    date_to = None
    try:
        if df: date_from = datetime.fromisoformat(df)
        if dt:
            dtt = datetime.fromisoformat(dt)
            if len(dt) == 10:
                dtt = dtt.replace(hour=23, minute=59, second=59)
            date_to = dtt
    except Exception:
        date_from = date_to = None

    rows = _filter_rows(_load_audit_rows(), username, tool, result, ip, q, date_from, date_to)

    sio = StringIO()
    w = csv.DictWriter(sio, fieldnames=LOG_HEADERS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k,"") for k in LOG_HEADERS})
    output = sio.getvalue().encode("utf-8")

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs_filtered.csv"}
    )

# ====================== WLC AP INVENTORY ======================

@app.get("/tools/wlc-inventory")
@require_login
@require_page_enabled("wlc_inventory")
def wlc_inventory():
    # Get auto-discovered hosts from dashboard settings
    settings = _get_dashboard_settings()
    cisco_hosts = settings.get("hosts") or []
    aruba_hosts = settings.get("aruba_hosts") or []
    return render_template(
        "wlc_inventory.html",
        cisco_hosts=cisco_hosts,
        aruba_hosts=aruba_hosts,
    )

@app.post("/tools/wlc-inventory/run")
@require_login
def wlc_inventory_run():
    hosts = _parse_hosts_field(request.form.get("hosts"))

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    secret   = (request.form.get("secret") or None)

    max_workers = _clamp_workers(request.form.get("max_workers"), len(hosts), default=10, upper=50)

    # Controller type: cisco (default) or aruba
    controller_type = (request.form.get("controller_type") or "cisco").strip().lower()

    # Optional filters
    f_ap    = (request.form.get("f_ap") or "").strip().lower()
    f_state = (request.form.get("f_state") or "").strip().lower()

    if not (hosts and username and password):
        flash("Hosts, username, and password are required.")
        return redirect(url_for("wlc_inventory"))

    # Build IP-to-hostname mapping from SolarWinds nodes
    solar_nodes = fetch_solarwinds_nodes()
    ip_to_hostname: Dict[str, str] = {}
    for node in solar_nodes:
        node_ip = (node.get("ip_address") or "").strip()
        node_hostname = (node.get("caption") or "").strip()
        if node_ip and node_hostname:
            ip_to_hostname[node_ip] = node_hostname

    # Collect inventory in parallel based on controller type
    if controller_type == "aruba":
        rows, errors = get_aruba_ap_inventory_many(hosts, username, password, secret, max_workers=max_workers)
    else:
        rows, errors = get_ap_inventory_many(hosts, username, password, secret, max_workers=max_workers)

    # Add WLC hostname from SolarWinds to each row
    for row in rows:
        wlc_ip = row.get("wlc", "")
        row["wlc_hostname"] = ip_to_hostname.get(wlc_ip, "")

    # Apply optional filters
    def keep(r):
        if f_ap and f_ap not in (r.get("ap_name", "").lower()):
            return False
        if f_state and f_state not in (r.get("state", "").lower()):
            return False
        return True

    rows = [r for r in rows if keep(r)]

    # Write CSV to a temp file and pass only a token to the template
    csv_text = make_ap_csv(rows)
    token = uuid.uuid4().hex
    file_path = os.path.join(TMP_WLC_CSV_DIR, f"{token}.csv")
    with open(file_path, "w", newline="") as f:
        f.write(csv_text)

    # Per-WLC summary (include hostname)
    from collections import Counter
    per_counts = Counter(r.get("wlc", "") for r in rows)
    per_wlc = [{"wlc": w, "wlc_hostname": ip_to_hostname.get(w, ""), "count": c} for w, c in per_counts.most_common()]
    total_aps = len(rows)

    # Quick summary message
    flash(f"Queried {len(hosts)} WLC(s) with {max_workers} worker(s). "
          f"Found {total_aps} AP(s). Failures: {len(errors)}.")

    return render_template(
        "wlc_results.html",
        token=token,  # pass token for download
        errors=errors,
        meta={"hosts_count": len(hosts), "workers": max_workers, "aps": total_aps},
        per_wlc=per_wlc,
    )

@app.post("/tools/wlc-inventory/download")
@require_login
def wlc_inventory_download():
    token = (request.form.get("token") or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{32}", token):
        return Response("Invalid token", status=400)

    path = os.path.join(TMP_WLC_CSV_DIR, f"{token}.csv")
    if not os.path.exists(path):
        return Response("CSV not found (token expired or invalid).", status=404)

    # Use absolute path for send_file
    abs_path = os.path.abspath(path)
    return send_file(
        abs_path,
        mimetype="text/csv",
        as_attachment=True,
        download_name="wlc_ap_inventory.csv",
    )

# ====================== WLC RF ======================

def _make_rf_csv(rows):
    import csv
    from io import StringIO
    headers = [
        "wlc", "band", "ap_name", "channel",
        "util", "tx_util", "rx_util", "noise", "interference",
        "util_final", "util_src"
    ]
    buf = StringIO()
    w = csv.DictWriter(buf, fieldnames=headers, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in headers})
    return buf.getvalue()

@app.get("/tools/wlc-rf")
@require_login
@require_page_enabled("wlc_rf")
def wlc_rf():
    return render_template("wlc_rf.html")

@app.post("/tools/wlc-rf/run")
@require_login
def wlc_rf_run():
    hosts = _parse_hosts_field(request.form.get("hosts"))

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    secret   = request.form.get("secret") or None
    band     = (request.form.get("band") or "both").strip().lower()

    f_ap = (request.form.get("f_ap") or "").strip().lower()
    min_util_raw = (request.form.get("min_util") or "").strip()
    try:
        min_util = float(min_util_raw) if min_util_raw else None
    except Exception:
        min_util = None

    max_workers = _clamp_workers(request.form.get("max_workers"), len(hosts), default=10, upper=50)

    debug = request.form.get("debug") == "1"

    if not (hosts and username and password):
        flash("Hosts, username, and password are required.")
        return redirect(url_for("wlc_rf"))

    # Run inventory
    rows, errors = get_rf_summary_many(hosts, username, password, secret, band, max_workers=max_workers)

    # Optional debug: capture raw sample from the first host
    samples = None
    if debug and hosts:
        try:
            samples = collect_rf_samples(hosts[0], username, password, secret)
        except Exception as e:
            samples = {"error": str(e)}

    # Filter using util_final numeric
    def keep(r):
        if f_ap and f_ap not in (r.get("ap_name", "").lower()):
            return False
        v = r.get("util_final")
        if v is None:
            v = 0.0
        if min_util is not None and v < min_util:
            return False
        return True

    rows = [r for r in rows if keep(r)]

    # CSV token write
    csv_text = _make_rf_csv(rows)
    token = uuid.uuid4().hex
    path = os.path.join(TMP_WLC_RF_DIR, f"{token}.csv")
    with open(path, "w", newline="") as f:
        f.write(csv_text)

    # Summaries per WLC+Band
    from collections import defaultdict
    sums = defaultdict(float)
    counts_total = defaultdict(int)
    counts_util  = defaultdict(int)
    peaks = defaultdict(float)

    util_rows = 0
    for r in rows:
        key = (r.get("wlc", ""), r.get("band", ""))
        counts_total[key] += 1
        v = r.get("util_final")
        if v is not None:
            util_rows += 1
            counts_util[key] += 1
            sums[key] += v
            if v > peaks[key]:
                peaks[key] = v

    summary = []
    for (wlc, b) in sorted(counts_total.keys(), key=lambda k: (k[0], k[1])):
        total = counts_total[(wlc, b)]
        good  = counts_util[(wlc, b)]
        avg = (sums[(wlc, b)] / good) if good else 0.0
        peak = peaks[(wlc, b)] if good else 0.0
        summary.append({
            "wlc": wlc,
            "band": b,
            "count": total,
            "avg_util": f"{avg:.1f}",
            "peak_util": f"{peak:.1f}",
        })

    flash(
        f"Queried {len(hosts)} WLC(s) with {max_workers} worker(s). "
        f"Rows: {len(rows)}. Radios with utilization parsed: {util_rows}. "
        f"Failures: {len(errors)}."
    )
    return render_template(
        "wlc_rf_results.html",
        token=token,
        summary=summary,
        errors=errors,
        samples=samples,  # <-- for debug display
        meta={
            "hosts_count": len(hosts),
            "workers": max_workers,
            "rows": len(rows),
            "failures": len(errors),
        },
    )

@app.get("/tools/wlc-rf/download/<token>")
@require_login
def wlc_rf_download(token):
    path = os.path.join(TMP_WLC_RF_DIR, f"{token}.csv")
    if not os.path.exists(path):
        return "Token not found", 404
    with open(path, "rb") as f:
        data = f.read()
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=wlc_rf_utilization.csv"}
    )

# ====================== WLC RF TROUBLESHOOT (configurable polls; single WLC) ======================
from collections import defaultdict
from tools.wlc_rf import get_rf_summary_many  # reuses your existing collector

@app.get("/tools/wlc-rf-troubleshoot")
@require_login
def wlc_rf_troubleshoot():
    return render_template("wlc_rf_troubleshoot.html")

def _rf_poll_worker(job_id: str, params: dict):
    """Background worker: polls every interval for N rounds, or until cancelled."""
    hosts = params["hosts"]
    username = params["username"]
    password = params["password"]
    secret = params.get("secret")
    band = params.get("band", "both")
    polls = int(params.get("polls", 1))
    interval = max(120, int(params.get("interval_sec", 300)))

    for i in range(polls):
        if has_event(job_id, "cancelled"):
            append_event(job_id, "log", {"message": "Job cancelled."})
            mark_done(job_id, cancelled=True)
            return

        try:
            rows, errors = get_rf_summary_many(
                hosts, username, password, secret, band, max_workers=1
            )
        except Exception as exc:
            rows, errors = [], [str(exc)]

        sums = defaultdict(float)
        counts = defaultdict(int)
        peaks = defaultdict(float)

        for r in rows:
            key = (r.get("wlc", ""), r.get("band", ""))
            v = r.get("util_final")
            if v is None:
                continue
            sums[key] += v
            counts[key] += 1
            if v > peaks[key]:
                peaks[key] = v

        round_series = []
        keys = set(counts.keys()) | set(peaks.keys())
        for key in sorted(keys, key=lambda k: (k[0], k[1])):
            wlc, band_label = key
            c = counts.get(key, 0)
            avg = (sums[key] / c) if c else 0.0
            peak = peaks.get(key, 0.0)
            round_series.append({
                "label": f"{wlc} {band_label}",
                "avg": round(avg, 2),
                "peak": round(peak, 2),
            })

        sample = {
            "ts": datetime.now(_CST_TZ).isoformat(timespec="seconds"),
            "series": round_series,
            "errors": errors,
            "round": i + 1,
            "total_rounds": polls,
        }

        append_event(job_id, "sample", payload={"sample": sample}, ts=sample["ts"])
        for err in errors:
            append_event(job_id, "error", payload={"message": err})

        append_event(
            job_id,
            "log",
            {
                "message": f"Completed round {i + 1} of {polls}",
                "errors": len(errors),
            },
        )

        if i < polls - 1:
            for _ in range(interval):
                time.sleep(1)
                if has_event(job_id, "cancelled"):
                    append_event(job_id, "log", {"message": "Job cancelled."})
                    mark_done(job_id, cancelled=True)
                    return

    append_event(job_id, "log", {"message": "Job complete."})
    mark_done(job_id)

@app.post("/tools/wlc-rf-troubleshoot/start")
@require_login
def wlc_rf_troubleshoot_start():
    # Single WLC
    host = (request.form.get("host") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    secret   = request.form.get("secret") or None
    band     = (request.form.get("band") or "both").strip().lower()

    # Poll count
    try:
        polls = int(request.form.get("polls") or "3")
    except (ValueError, TypeError):
        polls = 3
    if polls < 1:
        polls = 1
    if polls > 999:
        polls = 999  # soft cap; hard cap is total runtime below

    # Interval (seconds), clamp to >= 120
    try:
        interval_sec = int(request.form.get("interval_sec") or "300")
    except (ValueError, TypeError):
        interval_sec = 300
    if interval_sec < 120:
        interval_sec = 120

    # Enforce total job runtime <= 12 hours
    MAX_TOTAL_SEC = 12 * 3600
    total_runtime = interval_sec * polls
    if total_runtime > MAX_TOTAL_SEC:
        max_polls = MAX_TOTAL_SEC // interval_sec
        if max_polls < 1:
            max_polls = 1
        if max_polls < polls:
            polls = int(max_polls)
            flash(f"Poll count reduced to {polls} to keep total runtime under 12 hours.")

    if not (host and username and password):
        flash("Host, username, and password are required.")
        return redirect(url_for("wlc_rf_troubleshoot"))

    job_id = _new_job_id()
    created_ts = datetime.now(_CST_TZ).isoformat(timespec="seconds")
    params_blob = {
        "hosts": [host],
        "username": username,
        "password": password,
        "secret": secret,
        "band": band,
        "polls": polls,
        "interval_sec": interval_sec,
        "username": username,
    }

    insert_job(job_id=job_id, tool="wlc-rf-troubleshoot", created=created_ts, params=params_blob)
    append_event(
        job_id,
        "log",
        {"message": f"Job {job_id} started", "hosts": params_blob["hosts"]},
        ts=created_ts,
    )

    threading.Thread(target=_rf_poll_worker, args=(job_id, params_blob), daemon=True).start()
    return redirect(url_for("wlc_rf_troubleshoot_job", job_id=job_id))

@app.get("/tools/wlc-rf-troubleshoot/job/<job_id>")
@require_login
def wlc_rf_troubleshoot_job(job_id):
    meta, _ = db_load_job(job_id)
    if not meta:
        flash("Unknown troubleshooting job.")
        return redirect(url_for("wlc_rf_troubleshoot"))
    return render_template("wlc_rf_troubleshoot_job.html", job_id=job_id, params=meta.get("params", {}))

@app.get("/tools/wlc-rf-troubleshoot/status/<job_id>")
@require_login
def wlc_rf_troubleshoot_status(job_id):
    state = _load_rf_job_state(job_id)
    if not state:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(state)

# Cancel a job
@app.post("/tools/wlc-rf-troubleshoot/cancel/<job_id>")
@require_login
def wlc_rf_troubleshoot_cancel(job_id):
    meta, _ = db_load_job(job_id)
    if not meta:
        flash("Unknown job.")
        return redirect(url_for("wlc_jobs_overview"))
    append_event(job_id, "cancelled", payload={"by": "user"})
    mark_done(job_id, cancelled=True)
    flash(f"Job {job_id} cancellation requested.")
    return redirect(url_for("wlc_jobs_overview"))
# =================== /WLC RF TROUBLESHOOT ======================

# ====================== WLC CLIENTS TROUBLESHOOTER ======================

@app.get("/tools/wlc-clients-troubleshoot")
@require_login
def wlc_clients_troubleshoot():
    return render_template("wlc_clients_troubleshoot.html")


@app.post("/tools/wlc-clients-troubleshoot/start")
@require_login
def wlc_clients_troubleshoot_start():
    hosts = _parse_hosts_field(request.form.get("hosts"))

    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    secret   = request.form.get("secret") or None

    # poll count
    try:
        polls = int(request.form.get("max_polls") or request.form.get("polls") or "3")
    except (ValueError, TypeError):
        polls = 3
    if polls < 1: polls = 1
    if polls > 999: polls = 999  # hard cap; we enforce total runtime below

    # interval minutes -> seconds (accept either 'interval' in minutes or 'interval_sec')
    if request.form.get("interval_sec"):
        try:
            interval_sec = int(request.form.get("interval_sec"))
        except (ValueError, TypeError):
            interval_sec = 300
    else:
        try:
            interval_min = int(request.form.get("interval") or "5")
        except (ValueError, TypeError):
            interval_min = 5
        interval_sec = max(120, interval_min * 60)  # min 2 minutes
    if interval_sec < 120:
        interval_sec = 120  # enforce lower bound

    # Enforce 12-hour max runtime
    MAX_TOTAL_SEC = 12 * 3600
    total_runtime = interval_sec * polls
    if total_runtime > MAX_TOTAL_SEC:
        max_polls = MAX_TOTAL_SEC // interval_sec
        if max_polls < 1: max_polls = 1
        if max_polls < polls:
            polls = int(max_polls)
            flash(f"Poll count reduced to {polls} to keep total runtime under 12 hours.")

    if not (hosts and username and password):
        flash("At least one host, username, and password are required.")
        return redirect(url_for("wlc_clients_troubleshoot"))

    job_id = _new_job_id()
    created_ts = datetime.now(_CST_TZ).isoformat(timespec="seconds")
    params_blob = {
        "hosts": hosts,                # 1..N WLCs
        "username": username,
        "password": password,
        "secret": secret,
        "polls": polls,
        "interval_sec": interval_sec,
    }

    insert_job(job_id=job_id, tool="wlc-clients", created=created_ts, params=params_blob)
    append_event(
        job_id,
        "log",
        {"message": f"Job {job_id} started", "hosts": hosts},
        ts=created_ts,
    )

    threading.Thread(target=_clients_poll_worker, args=(job_id, params_blob), daemon=True).start()
    return redirect(url_for("wlc_clients_troubleshoot_job", job_id=job_id))


def _clients_poll_worker(job_id: str, params: dict):
    """
    Worker loop:
      - If multiple WLCs: collect total clients per WLC (fast) + overall total
      - If single WLC: also collect per-WLAN breakdown (SSID lines)
      - Respects cancel flag between polls and before appending a sample
      - Persists samples/errors/done into SQLite
    """
    from tools.wlc_clients import get_client_summary_many_parallel, get_client_summary

    hosts = params["hosts"]
    username, password, secret = params["username"], params["password"], params.get("secret")
    polls = int(params.get("polls", 1))
    interval = max(120, int(params.get("interval_sec", 300)))
    multi = len(hosts) > 1

    try:
        for i in range(polls):
            if has_event(job_id, "cancelled"):
                append_event(job_id, "log", {"message": "Job cancelled."})
                mark_done(job_id, cancelled=True)
                return

            try:
                if multi:
                    rows, errors = get_client_summary_many_parallel(
                        hosts, username, password, secret,
                        include_per_wlan=False,
                        max_workers=min(len(hosts), 20)
                    )
                    totals_by_wlc = {r["wlc"]: int(r.get("total_clients", 0) or 0) for r in rows}
                    total_all = sum(totals_by_wlc.values())
                    wlans = []
                else:
                    r, errors = get_client_summary(hosts[0], username, password, secret, include_per_wlan=True)
                    totals_by_wlc = {r["wlc"]: int(r.get("total_clients", 0) or 0)} if r else {}
                    total_all = sum(totals_by_wlc.values())
                    wlans = r.get("wlans", []) if r else []
            except Exception as exc:
                totals_by_wlc, wlans, errors, total_all = {}, [], [str(exc)], 0

            sample = {
                "ts": datetime.now(_CST_TZ).isoformat(timespec="seconds"),
                "totals_by_wlc": totals_by_wlc,
                "total_all": total_all,
                "wlans": wlans,
                "errors": errors,
                "round": i + 1,
                "total_rounds": polls,
            }

            append_event(job_id, "sample", payload={"sample": sample}, ts=sample["ts"])
            for err in errors or []:
                append_event(job_id, "error", payload={"message": err})

            append_event(
                job_id,
                "log",
                {
                    "message": f"Completed round {i + 1} of {polls}",
                    "total_clients": total_all,
                },
            )

            if i < polls - 1:
                for _ in range(interval):
                    time.sleep(1)
                    if has_event(job_id, "cancelled"):
                        append_event(job_id, "log", {"message": "Job cancelled."})
                        mark_done(job_id, cancelled=True)
                        return

        append_event(job_id, "log", {"message": "Job complete."})
        mark_done(job_id, cancelled=False)
    except Exception as exc:
        append_event(job_id, "error", {"message": f"Worker crashed: {exc}"})
        mark_done(job_id, cancelled=True)


@app.get("/tools/wlc-clients-troubleshoot/job/<job_id>")
@require_login
def wlc_clients_troubleshoot_job(job_id):
    meta, _ = db_load_job(job_id)
    if not meta:
        flash("Job not found")
        return redirect(url_for("wlc_clients_troubleshoot"))
    return render_template("wlc_clients_troubleshoot_job.html", job_id=job_id, params=meta.get("params", {}))



@app.get("/tools/wlc-clients-troubleshoot/status/<job_id>")
@require_login
def wlc_clients_troubleshoot_status(job_id):
    state = _load_clients_job_state(job_id)
    if not state:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(state)

# Jobs list endpoint for WLC CLIENTS TROUBLESHOOTER
@app.get("/tools/wlc-clients-troubleshoot/jobs")
@require_login
def wlc_clients_troubleshoot_jobs():
    jobs = []
    for row in db_list_jobs(limit=200):
        if row.get("tool") != "wlc-clients":
            continue
        params = row.get("params", {})
        jobs.append({
            "job_id": row.get("job_id"),
            "created": row.get("created", ""),
            "hosts": params.get("hosts", []),
            "polls": params.get("polls"),
            "interval_sec": params.get("interval_sec"),
            "rounds": row.get("samples_count", 0),
            "done": bool(row.get("done")),
            "cancelled": bool(row.get("cancelled")),
        })
    return render_template("wlc_clients_troubleshoot_jobs.html", jobs=jobs)


@app.post("/tools/wlc-clients-troubleshoot/cancel/<job_id>")
@require_login
def wlc_clients_troubleshoot_cancel(job_id):
    meta, _ = db_load_job(job_id)
    if not meta:
        flash("Job not found")
        return redirect(url_for("wlc_clients_troubleshoot"))
    append_event(job_id, "cancelled", payload={"by": "user"})
    mark_done(job_id, cancelled=True)
    return redirect(url_for("wlc_clients_troubleshoot_job", job_id=job_id))

# =================== /WLC Tools ======================
@app.get("/tools/wlc")
@require_login
def wlc_tools():
    return render_template("wlc_tools.html")


def _format_timezone_dt(dt: Optional[datetime], settings: dict) -> Tuple[Optional[str], Optional[str]]:
    if not dt:
        return None, None
    tz = _summer_timezone(settings)
    localized = dt.astimezone(tz)
    return localized.isoformat(timespec="seconds"), localized.strftime("%Y-%m-%d %I:%M %p %Z")


@app.get("/tools/wlc/summer-guest")
@require_login
@require_page_enabled("wlc_summer_guest")
def wlc_summer_guest():
    settings = _get_summer_settings()
    summary = settings.get("summary")
    if summary is not None:
        summary = dict(summary)
    else:
        summary = {
            "ts": settings.get("last_poll_ts"),
            "status": settings.get("last_poll_status", "never"),
            "message": settings.get("last_poll_message", "No poll has run yet."),
            "total_hosts": len(settings.get("hosts") or []),
            "success_hosts": 0,
            "enabled_total": 0,
            "disabled_total": 0,
            "errors": [],
            "host_status": [],
            "targets": {},
            "manual": False,
        }
    targets = summary.setdefault("targets", {})
    targets.setdefault("profile_names", settings.get("profile_names") or [])
    targets.setdefault("wlan_ids", settings.get("wlan_ids") or [])
    targets.setdefault("auto_prefix", settings.get("auto_prefix") or "Summer")
    hosts_list = settings.get("hosts") or []
    upcoming_map = fetch_upcoming_changes_for_hosts("wlc-summer-toggle", hosts_list)
    host_status = summary.setdefault("host_status", [])
    existing_hosts = set()
    for entry in host_status:
        host = entry.get("host")
        if not host:
            continue
        existing_hosts.add(host)
        entry.setdefault("display", entry.get("host", host))
        change_indicator = _build_change_indicator(upcoming_map.get(host))
        if change_indicator:
            entry["upcoming_change"] = change_indicator
    for host in hosts_list:
        if host in existing_hosts:
            continue
        placeholder = {
            "host": host,
            "display": host,
            "ok": False,
            "message": "Awaiting poll.",
            "entries": [],
            "errors": [],
        }
        change_indicator = _build_change_indicator(upcoming_map.get(host))
        if change_indicator:
            placeholder["upcoming_change"] = change_indicator
        host_status.append(placeholder)
    summary["total_hosts"] = len(hosts_list)
    latest_details = fetch_wlc_summer_latest_details()
    recent_runs = fetch_wlc_summer_recent_runs(30)
    next_run_dt = _next_summer_run(settings) if settings.get("enabled") else None
    next_run_iso, next_run_display = _format_timezone_dt(next_run_dt, settings)
    last_poll_display = _format_cst(summary.get("ts")) if summary.get("ts") else None
    tz_name = settings.get("timezone") or _summer_timezone(settings).key
    return render_template(
        "wlc_summer_guest.html",
        settings=settings,
        summary=summary,
        latest_details=latest_details,
        recent_runs=recent_runs,
        next_run_iso=next_run_iso,
        next_run_display=next_run_display,
        last_poll_display=last_poll_display,
        tz_name=tz_name,
        format_ts=_format_cst,
    )


@app.get("/api/wlc/summer-guest")
@require_login
def wlc_summer_guest_data():
    settings = _get_summer_settings()
    summary = settings.get("summary")
    if summary is not None:
        summary = dict(summary)
    else:
        summary = {
            "ts": settings.get("last_poll_ts"),
            "status": settings.get("last_poll_status", "never"),
            "message": settings.get("last_poll_message", ""),
            "total_hosts": len(settings.get("hosts") or []),
            "success_hosts": 0,
            "enabled_total": 0,
            "disabled_total": 0,
            "errors": [],
            "host_status": [],
            "targets": {},
            "manual": False,
        }
    targets = summary.setdefault("targets", {})
    targets.setdefault("profile_names", settings.get("profile_names") or [])
    targets.setdefault("wlan_ids", settings.get("wlan_ids") or [])
    targets.setdefault("auto_prefix", settings.get("auto_prefix") or "Summer")
    next_run_dt = _next_summer_run(settings) if settings.get("enabled") else None
    next_run_iso, next_run_display = _format_timezone_dt(next_run_dt, settings)
    safe_settings = {
        "enabled": bool(settings.get("enabled")),
        "hosts": settings.get("hosts") or [],
        "profile_names": settings.get("profile_names") or [],
        "wlan_ids": settings.get("wlan_ids") or [],
        "daily_time": settings.get("daily_time"),
        "timezone": settings.get("timezone"),
        "last_poll_ts": settings.get("last_poll_ts"),
        "last_poll_status": settings.get("last_poll_status", "never"),
        "last_poll_message": settings.get("last_poll_message", ""),
        "auto_prefix": settings.get("auto_prefix") or "Summer",
    }
    payload = {
        "settings": safe_settings,
        "summary": summary,
        "latest_details": fetch_wlc_summer_latest_details(),
        "recent_runs": fetch_wlc_summer_recent_runs(30),
        "next_run": {
            "iso": next_run_iso,
            "display": next_run_display,
        },
    }
    return jsonify(payload)


@app.post("/api/wlc/summer-guest/run")
@require_login
def wlc_summer_guest_run_api():
    _run_summer_poll_async()
    return jsonify({"status": "scheduled"})


@app.post("/tools/wlc/summer-guest/run")
@require_login
def wlc_summer_guest_run_form():
    _run_summer_poll_async()
    flash("Summer Guest poll started in background.")
    return redirect(url_for("wlc_summer_guest"))


@app.post("/tools/wlc/summer-guest/schedule")
@require_login
def wlc_summer_guest_schedule():
    settings = _get_summer_settings()
    host = request.form.get("host") or ""
    profile_name = request.form.get("profile_name") or ""
    action = request.form.get("action") or ""
    scheduled_str = request.form.get("scheduled") or ""
    change_number = (request.form.get("change_number") or "").strip()
    rollback_requested = request.form.get("schedule_rollback") == "1"

    try:
        wlan_id = int(request.form.get("wlan_id") or "")
    except Exception:
        wlan_id = None
    raw_psk = request.form.get("psk")
    psk = _sanitize_psk(raw_psk)

    if not host or wlan_id is None or not profile_name:
        flash("Missing WLAN details for scheduling.", "error")
        return redirect(url_for("wlc_summer_guest"))

    if action not in {"enable", "disable"}:
        flash("Invalid action for scheduling.", "error")
        return redirect(url_for("wlc_summer_guest"))

    if not scheduled_str:
        flash("Schedule time is required.", "error")
        return redirect(url_for("wlc_summer_guest"))

    if action == "enable" and raw_psk and not psk:
        flash("Passphrase must be at least 8 characters.", "error")
        return redirect(url_for("wlc_summer_guest"))

    try:
        scheduled_local = _parse_cst_datetime(scheduled_str)
    except Exception:
        flash("Invalid schedule time format.", "error")
        return redirect(url_for("wlc_summer_guest"))

    scheduled_utc = scheduled_local.astimezone(_UTC_TZ)
    now_utc = datetime.now(_UTC_TZ)
    if scheduled_utc <= now_utc:
        scheduled_utc = now_utc + timedelta(seconds=5)

    hosts = settings.get("hosts") or []
    if host not in hosts:
        flash(f"Host {host} is not configured in Summer Guest settings.", "error")
        return redirect(url_for("wlc_summer_guest"))

    username = settings.get("username") or ""
    password = settings.get("password") or ""
    secret = settings.get("secret") or ""
    if not username or not password:
        flash("Credentials are required for scheduling.", "error")
        return redirect(url_for("wlc_summer_guest"))

    enable = action == "enable"
    cli_map = {host: _build_summer_toggle_cli(profile_name, wlan_id, enable=enable, psk=psk)}

    payload = {
        "cli_map": cli_map,
        "username": username,
        "password": password,
        "secret": secret,
        "tool": "wlc-summer-toggle",
        "metadata": {
            "host": host,
            "profile_name": profile_name,
            "wlan_id": wlan_id,
            "action": action,
        },
    }

    rollback_payload = None
    if rollback_requested:
        rollback_cli_map = {
            host: _build_summer_toggle_cli(
                profile_name,
                wlan_id,
                enable=not enable,
                psk=psk if (psk and not enable) else None,
            )
        }
        rollback_payload = {
            "cli_map": rollback_cli_map,
            "username": username,
            "password": password,
            "secret": secret,
            "tool": "wlc-summer-toggle",
            "metadata": {
                "host": host,
                "profile_name": profile_name,
                "wlan_id": wlan_id,
                "action": "enable" if not enable else "disable",
            },
        }

    change_id = _new_job_id()

    schedule_change_window(
        change_id=change_id,
        tool="wlc-summer-toggle",
        change_number=change_number,
        scheduled=scheduled_utc.isoformat(timespec="seconds"),
        payload=payload,
        rollback_payload=rollback_payload,
        message=f"Scheduled {action} for {profile_name} ({wlan_id}) on {host}.",
    )

    append_change_event(
        change_id,
        "scheduled",
        f"Change scheduled for {scheduled_local.strftime('%Y-%m-%d %I:%M %p CST')} to {action} {profile_name} ({wlan_id}) on {host}.",
    )

    # Log to audit trail
    current_user = session.get("username", "unknown")
    log_audit(
        current_user,
        "wlc_wlan_schedule",
        resource=f"{host}: {profile_name} ({wlan_id})",
        details=f"Action: {action} | Scheduled: {scheduled_local.strftime('%Y-%m-%d %I:%M %p CST')} | Change ID: {change_id}",
        user_id=session.get("user_id")
    )

    _CHANGE_WAKE.set()
    flash(
        f"Scheduled change {change_id} to {action} {profile_name} ({wlan_id}) on {host} at {scheduled_local.strftime('%Y-%m-%d %I:%M %p CST')}.",
        "success",
    )
    return redirect(url_for("wlc_summer_guest"))


@app.post("/tools/wlc/summer-guest/toggle")
@require_login
def wlc_summer_guest_toggle():
    settings = _get_summer_settings()
    host = request.form.get("host") or ""
    profile_name = request.form.get("profile_name") or ""
    action = request.form.get("action") or ""
    try:
        wlan_id = int(request.form.get("wlan_id") or "")
    except Exception:
        wlan_id = None
    raw_psk = request.form.get("psk")
    psk = _sanitize_psk(raw_psk)

    redirect_target = request.form.get("redirect") or "wlc_summer_guest"

    if not host or wlan_id is None or not profile_name:
        flash("Missing WLAN details.", "error")
        return redirect(url_for(redirect_target))

    hosts = settings.get("hosts") or []
    if host not in hosts:
        flash(f"Host {host} is not in Summer Guest settings.", "error")
        return redirect(url_for(redirect_target))

    username = settings.get("username") or ""
    password = settings.get("password") or ""
    secret = settings.get("secret") or ""
    if not username or not password:
        flash("Credentials are not configured for Summer Guest actions.", "error")
        return redirect(url_for(redirect_target))

    enable = action == "enable"
    if enable and raw_psk and not psk:
        flash("Passphrase must be at least 8 characters.", "error")
        return redirect(url_for(redirect_target))
    try:
        set_wlan_state(
            host,
            username,
            password,
            secret,
            profile_name=profile_name,
            wlan_id=wlan_id,
            enable=enable,
            psk=psk,
        )

        # Log to audit trail
        current_user = session.get("username", "unknown")
        log_audit(
            current_user,
            "wlc_wlan_toggle",
            resource=f"{host}: {profile_name} ({wlan_id})",
            details=f"Action: {'enable' if enable else 'disable'} | SSID: {profile_name}",
            user_id=session.get("user_id")
        )

        flash(
            f"WLAN {profile_name} ({wlan_id}) {'enabled' if enable else 'disabled'} on {host}.",
            "success",
        )
        _run_summer_poll_async()
    except Exception as exc:
        flash(f"Failed to update {profile_name} on {host}: {exc}", "error")

    return redirect(url_for(redirect_target))


@app.route("/tools/wlc/summer-guest/settings", methods=["GET", "POST"])
@require_login
def wlc_summer_guest_settings():
    nodes = fetch_solarwinds_nodes()
    auto_hosts = _update_summer_hosts_from_solarwinds(nodes)
    # refresh settings to include any persisted host updates
    settings = _get_summer_settings()
    settings = dict(settings)
    settings["hosts"] = auto_hosts
    auto_host_labels = _label_wlc_hosts(auto_hosts, nodes)
    if request.method == "POST":
        action = request.form.get("action") or "save"
        enabled = request.form.get("enabled") == "1"
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        secret = request.form.get("secret") or ""
        profile_names = _parse_string_list_field(request.form.get("profile_names"))
        wlan_ids = _parse_int_list_field(request.form.get("wlan_ids"))
        hour, minute = _parse_daily_time_str(request.form.get("daily_time"))
        daily_time = f"{hour:02d}:{minute:02d}"
        timezone_value = (request.form.get("timezone") or settings.get("timezone") or "America/Chicago").strip()

        new_settings = dict(settings)
        new_settings.update(
            {
                "enabled": enabled,
                "hosts": auto_hosts,
                "username": username,
                "password": password,
                "secret": secret,
                "profile_names": profile_names,
                "wlan_ids": wlan_ids,
                "daily_time": daily_time,
                "timezone": timezone_value or settings.get("timezone") or "America/Chicago",
                "validation": settings.get("validation", []),
            }
        )

        if action == "validate":
            validation = []
            for host in auto_hosts:
                status = {"host": host, "ok": False, "message": ""}
                try:
                    samples, host_errors, info = collect_summer_guest_status(
                        host,
                        username,
                        password,
                        secret,
                        profile_names=profile_names or settings.get("profile_names") or ["SummerGuest"],
                        wlan_ids=wlan_ids or settings.get("wlan_ids") or [10],
                        auto_prefix=settings.get("auto_prefix") or "Summer",
                    )
                    hostname = info.get("hostname") if isinstance(info, dict) else None
                    if hostname:
                        status["host"] = f"{hostname} - {host}"
                    if host_errors:
                        status["message"] = host_errors[0]
                    elif samples:
                        status["ok"] = True
                        status["message"] = f"Matched {len(samples)} WLAN(s)"
                    else:
                        status["message"] = "No matching WLANs"
                except Exception as exc:
                    status["message"] = str(exc)
                validation.append(status)
            new_settings["validation"] = validation
            _set_summer_settings(new_settings)
            flash("Validation complete.")
            return redirect(url_for("wlc_summer_guest_settings"))

        if action == "run-now":
            _set_summer_settings(new_settings)
            _run_summer_poll_async()
            flash("Settings saved and poll started.")
            return redirect(url_for("wlc_summer_guest"))

        _set_summer_settings(new_settings)
        flash("Summer Guest settings saved.")
        return redirect(url_for("wlc_summer_guest_settings"))

    profile_text = "\n".join(settings.get("profile_names") or [])
    wlan_ids_text = " ".join(str(v) for v in settings.get("wlan_ids") or [])
    return render_template(
        "wlc_summer_guest_settings.html",
        settings=settings,
        auto_hosts=auto_hosts,
        auto_host_labels=auto_host_labels,
        profile_text=profile_text,
        wlan_ids_text=wlan_ids_text,
    )


# ====================== Device Inventory ======================

@app.get("/tools/device-inventory")
@require_login
@require_page_enabled("device_inventory")
def device_inventory():
    """Device inventory page showing hardware and firmware versions from SolarWinds."""
    # Get all SolarWinds nodes as the inventory source
    nodes = fetch_solarwinds_nodes()

    # Get filters from query params
    vendor_filter = request.args.get("vendor", "").strip()
    model_filter = request.args.get("model", "").strip()
    version_filter = request.args.get("version", "").strip()
    org_filter = request.args.get("org", "").strip()
    search_filter = request.args.get("search", "").strip().lower()

    # Apply filters
    filtered = nodes
    if vendor_filter:
        filtered = [n for n in filtered if (n.get("vendor") or "").lower() == vendor_filter.lower()]
    if model_filter:
        filtered = [n for n in filtered if model_filter.lower() in (n.get("model") or "").lower()]
    if version_filter:
        filtered = [n for n in filtered if version_filter.lower() in (n.get("version") or "").lower()]
    if org_filter:
        filtered = [n for n in filtered if (n.get("organization") or "").lower() == org_filter.lower()]
    if search_filter:
        filtered = [n for n in filtered if (
            search_filter in (n.get("caption") or "").lower() or
            search_filter in (n.get("ip_address") or "").lower() or
            search_filter in (n.get("model") or "").lower() or
            search_filter in (n.get("vendor") or "").lower()
        )]

    # Build stats from all nodes (not filtered)
    stats = {
        "total": len(nodes),
        "by_vendor": {},
        "by_org": {},
    }
    for n in nodes:
        vendor = n.get("vendor") or "Unknown"
        org = n.get("organization") or "Unknown"
        stats["by_vendor"][vendor] = stats["by_vendor"].get(vendor, 0) + 1
        stats["by_org"][org] = stats["by_org"].get(org, 0) + 1

    # Get unique values for filter dropdowns
    vendor_options = sorted(set(n.get("vendor") for n in nodes if n.get("vendor")))
    org_options = sorted(set(n.get("organization") for n in nodes if n.get("organization")))
    model_options = sorted(set(n.get("model") for n in nodes if n.get("model")))[:20]  # Limit models

    return render_template(
        "device_inventory.html",
        stats=stats,
        devices=filtered,
        vendor_options=vendor_options,
        org_options=org_options,
        model_options=model_options,
        filters={
            "vendor": vendor_filter,
            "model": model_filter,
            "version": version_filter,
            "org": org_filter,
            "search": search_filter,
        },
    )


@app.post("/tools/device-inventory/scan")
@require_login
def device_inventory_scan():
    """Scan devices and collect inventory information."""
    # Get form data
    hosts_text = request.form.get("hosts", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    secret = request.form.get("secret", "") or None
    device_type = request.form.get("device_type", "cisco_ios").strip()
    max_workers = int(request.form.get("max_workers", "10") or "10")
    max_workers = max(1, min(max_workers, 50))

    # Parse hosts (comma or newline separated)
    hosts = []
    for line in hosts_text.replace(",", "\n").split("\n"):
        host = line.strip()
        if host:
            hosts.append(host)

    if not hosts:
        flash("Please enter at least one device to scan.", "error")
        return redirect(url_for("device_inventory"))

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("device_inventory"))

    # Log the scan action
    log_audit(
        session.get("username", "unknown"),
        "device_inventory_scan",
        resource=f"{len(hosts)} devices",
        details=f"Device type: {device_type}",
        user_id=session.get("user_id"),
    )

    # Collect inventory from devices
    results, errors = collect_device_inventory_many(
        hosts=hosts,
        username=username,
        password=password,
        secret=secret,
        device_type=device_type,
        max_workers=max_workers,
    )

    # Save results to database
    success_count = 0
    failed_count = 0
    for r in results:
        if r.get("error"):
            scan_status = "failed"
            failed_count += 1
        else:
            scan_status = "success"
            success_count += 1

        upsert_device_inventory(
            device=r["device"],
            device_type=r.get("device_type", device_type),
            vendor=r.get("vendor", ""),
            model=r.get("model", ""),
            serial_number=r.get("serial_number", ""),
            firmware_version=r.get("firmware_version", ""),
            hostname=r.get("hostname", ""),
            uptime=r.get("uptime", ""),
            scan_status=scan_status,
            scan_error=r.get("error", ""),
        )

    if failed_count > 0 and success_count > 0:
        flash(f"Scan complete: {success_count} succeeded, {failed_count} failed.", "warning")
    elif failed_count > 0:
        flash(f"Scan failed for all {failed_count} devices.", "error")
    else:
        flash(f"Scan complete: {success_count} devices scanned successfully.", "success")

    return redirect(url_for("device_inventory"))


@app.get("/tools/device-inventory/export")
@require_login
def device_inventory_export():
    """Export device inventory as CSV from SolarWinds data."""
    import io
    import csv as csv_module

    nodes = fetch_solarwinds_nodes()

    # Apply same filters as the main view
    vendor_filter = request.args.get("vendor", "").strip()
    model_filter = request.args.get("model", "").strip()
    version_filter = request.args.get("version", "").strip()
    org_filter = request.args.get("org", "").strip()
    search_filter = request.args.get("search", "").strip().lower()

    if vendor_filter:
        nodes = [n for n in nodes if (n.get("vendor") or "").lower() == vendor_filter.lower()]
    if model_filter:
        nodes = [n for n in nodes if model_filter.lower() in (n.get("model") or "").lower()]
    if version_filter:
        nodes = [n for n in nodes if version_filter.lower() in (n.get("version") or "").lower()]
    if org_filter:
        nodes = [n for n in nodes if (n.get("organization") or "").lower() == org_filter.lower()]
    if search_filter:
        nodes = [n for n in nodes if (
            search_filter in (n.get("caption") or "").lower() or
            search_filter in (n.get("ip_address") or "").lower() or
            search_filter in (n.get("model") or "").lower()
        )]

    # Generate CSV
    buf = io.StringIO()
    fields = ["caption", "ip_address", "organization", "vendor", "model", "version", "status"]
    writer = csv_module.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for n in nodes:
        row = {k: n.get(k) or n.get(k.replace("_", "")) or "" for k in fields}
        writer.writerow(row)

    timestamp = datetime.now(_CST_TZ).strftime("%Y%m%d_%H%M%S")

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=device_inventory_{timestamp}.csv"},
    )


@app.post("/tools/device-inventory/<device>/delete")
@require_login
def device_inventory_delete(device: str):
    """Delete a device from inventory."""
    if session.get("role") != "superadmin":
        flash("Only superadmins can delete devices from inventory.", "error")
        return redirect(url_for("device_inventory"))

    if delete_device_inventory(device):
        flash(f"Device '{device}' removed from inventory.", "success")
    else:
        flash("Failed to delete device.", "error")

    return redirect(url_for("device_inventory"))


@app.get("/api/device-inventory")
@require_login
def api_device_inventory():
    """JSON API for device inventory data from SolarWinds."""
    nodes = fetch_solarwinds_nodes()
    stats = {
        "total": len(nodes),
        "by_vendor": {},
        "by_org": {},
    }
    for n in nodes:
        vendor = n.get("vendor") or "Unknown"
        org = n.get("organization") or "Unknown"
        stats["by_vendor"][vendor] = stats["by_vendor"].get(vendor, 0) + 1
        stats["by_org"][org] = stats["by_org"].get(org, 0) + 1
    return jsonify({"devices": nodes, "stats": stats})


# ====================== /Device Inventory ======================


@app.get("/tools/solarwinds/nodes")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_nodes():
    settings = _get_solar_settings()
    nodes = fetch_solarwinds_nodes()
    return render_template("solarwinds_nodes.html", settings=settings, nodes=nodes)


@app.get("/tools/solarwinds/inventory")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_inventory():
    """SolarWinds Hardware/Software Inventory Dashboard for CVE assessment."""
    nodes = fetch_solarwinds_nodes()
    settings = _get_solar_settings()

    # Get filters from query params
    vendor_filter = request.args.getlist("vendor")  # Multi-select
    model_filter = request.args.getlist("model")  # Multi-select
    version_filter = request.args.getlist("version")  # Multi-select
    search_filter = request.args.get("search", "").strip().lower()
    hw_version_filter = request.args.get("hw_version", "").strip().lower()

    # Build aggregations BEFORE filtering (for charts)
    vendor_counts = {}
    version_counts = {}
    model_counts = {}
    for n in nodes:
        vendor = n.get("vendor") or "Unknown"
        version = n.get("version") or "Unknown"
        model = n.get("model") or "Unknown"
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        version_counts[version] = version_counts.get(version, 0) + 1
        model_counts[model] = model_counts.get(model, 0) + 1

    # Get unique values for multi-select dropdowns (before filtering)
    vendor_options = sorted(vendor_counts.keys())
    model_options = sorted(model_counts.keys())
    version_options = sorted(version_counts.keys())

    # Apply filters
    filtered = nodes
    if vendor_filter:
        vendor_lower = [v.lower() for v in vendor_filter]
        filtered = [n for n in filtered if (n.get("vendor") or "").lower() in vendor_lower]
    if model_filter:
        model_lower = [m.lower() for m in model_filter]
        filtered = [n for n in filtered if (n.get("model") or "").lower() in model_lower]
    if version_filter:
        version_lower = [v.lower() for v in version_filter]
        filtered = [n for n in filtered if (n.get("version") or "").lower() in version_lower]
    if search_filter:
        filtered = [n for n in filtered if (
            search_filter in (n.get("caption") or "").lower() or
            search_filter in (n.get("ip_address") or "").lower() or
            search_filter in (n.get("model") or "").lower() or
            search_filter in (n.get("vendor") or "").lower() or
            search_filter in (n.get("version") or "").lower()
        )]
    if hw_version_filter:
        filtered = [n for n in filtered if hw_version_filter in (n.get("hardware_version") or "").lower()]

    # Build filtered stats for display
    filtered_vendor_counts = {}
    filtered_version_counts = {}
    filtered_model_counts = {}
    for n in filtered:
        vendor = n.get("vendor") or "Unknown"
        version = n.get("version") or "Unknown"
        model = n.get("model") or "Unknown"
        filtered_vendor_counts[vendor] = filtered_vendor_counts.get(vendor, 0) + 1
        filtered_version_counts[version] = filtered_version_counts.get(version, 0) + 1
        filtered_model_counts[model] = filtered_model_counts.get(model, 0) + 1

    # Sort counts by value descending for display
    top_vendors = sorted(filtered_vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_versions = sorted(filtered_version_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    top_models = sorted(filtered_model_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return render_template(
        "solarwinds_inventory.html",
        nodes=filtered,
        total_count=len(nodes),
        filtered_count=len(filtered),
        settings=settings,
        vendor_counts=top_vendors,
        version_counts=top_versions,
        model_counts=top_models,
        vendor_options=vendor_options,
        model_options=model_options,
        version_options=version_options,
        filters={
            "vendor": vendor_filter,
            "model": model_filter,
            "version": version_filter,
            "search": search_filter,
            "hw_version": hw_version_filter,
        },
    )


@app.get("/tools/solarwinds/inventory/export")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_inventory_export():
    """Export SolarWinds inventory as CSV with filters applied."""
    import io
    import csv as csv_module

    nodes = fetch_solarwinds_nodes()

    # Get filters from query params (same as inventory page)
    vendor_filter = request.args.getlist("vendor")
    model_filter = request.args.getlist("model")
    version_filter = request.args.getlist("version")
    search_filter = request.args.get("search", "").strip().lower()
    hw_version_filter = request.args.get("hw_version", "").strip().lower()

    # Apply filters
    filtered = nodes
    if vendor_filter:
        vendor_lower = [v.lower() for v in vendor_filter]
        filtered = [n for n in filtered if (n.get("vendor") or "").lower() in vendor_lower]
    if model_filter:
        model_lower = [m.lower() for m in model_filter]
        filtered = [n for n in filtered if (n.get("model") or "").lower() in model_lower]
    if version_filter:
        version_lower = [v.lower() for v in version_filter]
        filtered = [n for n in filtered if (n.get("version") or "").lower() in version_lower]
    if search_filter:
        filtered = [n for n in filtered if (
            search_filter in (n.get("caption") or "").lower() or
            search_filter in (n.get("ip_address") or "").lower() or
            search_filter in (n.get("model") or "").lower() or
            search_filter in (n.get("vendor") or "").lower() or
            search_filter in (n.get("version") or "").lower()
        )]
    if hw_version_filter:
        filtered = [n for n in filtered if hw_version_filter in (n.get("hardware_version") or "").lower()]

    # Generate CSV
    buf = io.StringIO()
    fields = ["caption", "ip_address", "organization", "vendor", "model", "version", "hardware_version"]
    writer = csv_module.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for n in filtered:
        row = {k: n.get(k) or "" for k in fields}
        writer.writerow(row)

    timestamp = datetime.now(get_app_timezone_info()).strftime("%Y-%m-%d")

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=solarwinds_inventory_{timestamp}.csv"},
    )


@app.get("/api/solarwinds/nodes")
@require_login
def api_solarwinds_nodes():
    """API endpoint for searching SolarWinds nodes (for bulk SSH inventory search)."""
    query = request.args.get("q", "").strip().lower()
    nodes = fetch_solarwinds_nodes()

    # Filter nodes by query if provided
    if query:
        filtered_nodes = []
        for node in nodes:
            caption = (node.get("caption") or "").lower()
            ip = (node.get("ip_address") or node.get("ipaddress") or "").lower()
            if query in caption or query in ip:
                filtered_nodes.append(node)
        nodes = filtered_nodes

    return jsonify({"nodes": nodes[:50]})  # Limit to 50 results


@app.route("/tools/solarwinds/nodes/settings", methods=["GET", "POST"])
@require_superadmin
def solarwinds_nodes_settings():
    settings = _get_solar_settings()
    if request.method == "POST":
        action = request.form.get("action") or "save"
        base_url = (request.form.get("base_url") or "").strip()
        username = (request.form.get("username") or "").strip()
        password_input = request.form.get("password") or ""
        verify_ssl = request.form.get("verify_ssl") == "1"

        new_settings = dict(settings)
        new_settings.update(
            {
                "base_url": base_url,
                "username": username,
                "verify_ssl": verify_ssl,
            }
        )
        if password_input:
            new_settings["password"] = password_input

        _set_solar_settings(new_settings)

        if action == "poll":
            success, message = _run_solarwinds_poll(manual=True)
            flash(("Poll complete." if success else "Poll failed.") + (f" {message}" if message else ""))
            return redirect(url_for("solarwinds_nodes_settings"))

        flash("SolarWinds settings saved.")
        return redirect(url_for("solarwinds_nodes_settings"))

    nodes_count = len(fetch_solarwinds_nodes())
    template_settings = dict(settings)
    template_settings["password"] = ""
    template_settings["verify_ssl"] = bool(template_settings.get("verify_ssl", True))
    return render_template(
        "solarwinds_nodes_settings.html",
        settings=template_settings,
        nodes_count=nodes_count,
    )


@app.get("/tools/wlc/dashboard")
@require_login
@require_page_enabled("wlc_dashboard")
def wlc_dashboard():
    selected = request.args.get("range", "24h")
    if selected not in _DASHBOARD_RANGE_TO_HOURS:
        selected = "24h"
    settings = _get_dashboard_settings()
    latest = fetch_wlc_dashboard_latest_totals()
    host_details = fetch_wlc_dashboard_latest_details()
    interval_minutes = max(int(settings.get("interval_sec") or 300) // 60, 1)
    return render_template(
        "wlc_dashboard.html",
        settings=settings,
        latest=latest,
        range_options=_DASHBOARD_RANGE_OPTIONS,
        selected_range=selected,
        interval_minutes=interval_minutes,
        host_details=host_details,
    )


@app.get("/tools/wlc/ap-inventory")
@require_login
@require_page_enabled("wlc_dashboard")
def wlc_ap_inventory():
    """Display auto-updating AP inventory collected during WLC polling."""
    # Get filter parameters
    wlc_filter = request.args.get("wlc", "").strip()
    name_filter = request.args.get("name", "").strip()
    model_filter = request.args.get("model", "").strip()
    location_filter = request.args.get("location", "").strip()

    # Load AP inventory with filters
    aps = list_ap_inventory(
        wlc_host=wlc_filter if wlc_filter else None,
        ap_name_filter=name_filter if name_filter else None,
        ap_model_filter=model_filter if model_filter else None,
        ap_location_filter=location_filter if location_filter else None,
    )

    # Get stats for summary cards
    stats = get_ap_inventory_stats()

    # Build filter options for dropdowns
    filters = {
        "wlc": wlc_filter,
        "name": name_filter,
        "model": model_filter,
        "location": location_filter,
    }

    return render_template(
        "ap_inventory.html",
        aps=aps,
        stats=stats,
        filters=filters,
        wlc_options=stats.get("wlc_hosts", []),
    )


@app.get("/tools/wlc/ap-inventory/export")
@require_login
@require_page_enabled("wlc_dashboard")
def wlc_ap_inventory_export():
    """Export AP inventory to CSV with current filters applied."""
    import io
    import csv
    from datetime import datetime

    # Get filter parameters (same as display route)
    wlc_filter = request.args.get("wlc", "").strip()
    name_filter = request.args.get("name", "").strip()
    model_filter = request.args.get("model", "").strip()
    location_filter = request.args.get("location", "").strip()

    # Load AP inventory with filters
    aps = list_ap_inventory(
        wlc_host=wlc_filter if wlc_filter else None,
        ap_name_filter=name_filter if name_filter else None,
        ap_model_filter=model_filter if model_filter else None,
        ap_location_filter=location_filter if location_filter else None,
    )

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "AP Name", "IP Address", "Model", "MAC Address", "Location",
        "State", "Slots", "Country", "WLC Host", "First Seen", "Last Seen"
    ])

    for ap in aps:
        writer.writerow([
            ap.get("ap_name", ""),
            ap.get("ap_ip", ""),
            ap.get("ap_model", ""),
            ap.get("ap_mac", ""),
            ap.get("ap_location", ""),
            ap.get("ap_state", ""),
            ap.get("slots", ""),
            ap.get("country", ""),
            ap.get("wlc_host", ""),
            ap.get("first_seen", ""),
            ap.get("last_seen", ""),
        ])

    # Generate filename with date
    filename = f"ap_inventory_{datetime.now().strftime('%Y-%m-%d')}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/wlc/dashboard")
@require_login
def wlc_dashboard_data():
    selected = request.args.get("range", "24h")
    if selected not in _DASHBOARD_RANGE_TO_HOURS:
        selected = "24h"
    hours = _DASHBOARD_RANGE_TO_HOURS[selected]
    series = fetch_wlc_dashboard_series(hours)
    latest = fetch_wlc_dashboard_latest_totals()
    settings = _get_dashboard_settings()
    details = fetch_wlc_dashboard_latest_details()
    fallback_summary = {
        "ts": settings.get("last_poll_ts"),
        "status": settings.get("last_poll_status", "never"),
        "message": settings.get("last_poll_message", ""),
        "total_hosts": len(settings.get("hosts") or []),
        "success_hosts": 0,
        "errors": [],
        "host_status": [],
    }
    summary = settings.get("poll_summary") or fallback_summary
    if summary is not fallback_summary:
        summary.setdefault("total_hosts", len(settings.get("hosts") or []))
        summary.setdefault("success_hosts", 0)
        summary.setdefault("errors", [])
        summary.setdefault("host_status", [])
    poll = {
        "enabled": bool(settings.get("enabled")),
        "status": settings.get("last_poll_status", "never"),
        "message": settings.get("last_poll_message", ""),
        "ts": settings.get("last_poll_ts"),
        "interval_sec": int(settings.get("interval_sec") or 600),
        "total_hosts": summary.get("total_hosts", 0),
        "success_hosts": summary.get("success_hosts", 0),
        "errors": summary.get("errors", []),
    }
    return jsonify({
        "range": selected,
        "series": series,
        "latest": latest,
        "poll": poll,
        "hosts": settings.get("hosts") or [],
        "aruba_hosts": settings.get("aruba_hosts") or [] if settings.get("aruba_enabled") else [],
        "summary": summary,
        "latest_details": details,
    })


@app.route("/tools/wlc/dashboard/settings", methods=["GET", "POST"])
@require_superadmin
def wlc_dashboard_settings():
    settings = _get_dashboard_settings()
    nodes = fetch_solarwinds_nodes()

    # Auto-discover Cisco controllers
    auto_hosts = _update_wlc_hosts_from_solarwinds(nodes)
    if auto_hosts != settings.get("hosts"):
        updated_settings = dict(settings)
        updated_settings["hosts"] = auto_hosts
        _set_dashboard_settings(updated_settings)
        settings = _get_dashboard_settings()

    # Auto-discover Aruba controllers
    auto_aruba_hosts = _update_aruba_hosts_from_solarwinds(nodes)
    if auto_aruba_hosts != settings.get("aruba_hosts"):
        updated_settings = dict(settings)
        updated_settings["aruba_hosts"] = auto_aruba_hosts
        _set_dashboard_settings(updated_settings)
        settings = _get_dashboard_settings()

    settings = dict(settings)
    settings["hosts"] = auto_hosts
    settings["aruba_hosts"] = auto_aruba_hosts
    auto_host_labels = _label_wlc_hosts(auto_hosts, nodes)
    auto_aruba_labels = _label_wlc_hosts(auto_aruba_hosts, nodes)

    if request.method == "POST":
        action = request.form.get("action") or "save"
        enabled = request.form.get("enabled") == "1"
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        secret = request.form.get("secret") or ""
        try:
            interval_min = int(request.form.get("interval") or "10")
        except Exception:
            interval_min = 10
        interval_sec = max(interval_min * 60, 600)

        # Aruba settings - uses same credentials, just enable/disable toggle
        aruba_enabled = request.form.get("aruba_enabled") == "1"

        # Encrypt passwords before storing
        encrypted_password = encrypt_password(password) if password else settings.get("password", "")
        encrypted_secret = encrypt_password(secret) if secret else settings.get("secret", "")

        new_settings = dict(settings)
        new_settings.update({
            "enabled": enabled,
            "hosts": auto_hosts,
            "username": username,
            "password": encrypted_password,
            "secret": encrypted_secret,
            "interval_sec": interval_sec,
            "validation": settings.get("validation", []),
            # Aruba settings - auto-discovered hosts, same credentials
            "aruba_enabled": aruba_enabled,
            "aruba_hosts": auto_aruba_hosts,
        })

        if action == "validate":
            from tools.wlc_clients import get_client_summary
            from tools.aruba_controller import get_aruba_snapshot
            validation = []
            # Validate Cisco controllers
            for host in auto_hosts:
                status = {"host": host, "clients": False, "message": "", "controller_type": "cisco"}
                try:
                    get_client_summary(host, username, password, secret, include_per_wlan=False)
                    status["clients"] = True
                    status["message"] = "Clients: OK"
                except Exception as exc:
                    status["message"] = str(exc)
                validation.append(status)
            # Validate Aruba controllers (using same credentials)
            for host in auto_aruba_hosts:
                status = {"host": host, "clients": False, "message": "", "controller_type": "aruba"}
                try:
                    result, errors = get_aruba_snapshot(host, username, password, secret)
                    if result.get("total_clients") is not None:
                        status["clients"] = True
                        status["message"] = f"Clients: {result['total_clients']}, APs: {result.get('ap_count', 'N/A')}"
                    else:
                        status["message"] = errors[0] if errors else "Failed to get client count"
                except Exception as exc:
                    status["message"] = str(exc)
                validation.append(status)
            new_settings["validation"] = validation
            _set_dashboard_settings(new_settings)
            flash("Validation complete.")
            return redirect(url_for("wlc_dashboard_settings"))

        _set_dashboard_settings(new_settings)
        log_audit(session.get("username", "unknown"), "wlc_settings_update", user_id=session.get("user_id"))
        flash("Dashboard settings saved.")
        return redirect(url_for("wlc_dashboard_settings"))

    # Decrypt passwords for display in form (but show as empty for security)
    display_settings = dict(settings)
    display_settings["password"] = ""  # Don't display encrypted password
    display_settings["secret"] = ""  # Don't display encrypted secret

    return render_template(
        "wlc_dashboard_settings.html",
        settings=display_settings,
        auto_hosts=auto_hosts,
        auto_host_labels=auto_host_labels,
        auto_aruba_hosts=auto_aruba_hosts,
        auto_aruba_labels=auto_aruba_labels,
    )


@app.get("/tools/wlc/jobs")
@require_login
def wlc_jobs_overview():
    records = []
    for row in db_list_jobs(limit=200):
        tool = row.get("tool") or ""
        if tool not in {
            "wlc-clients",
            "wlc-rf-troubleshoot",
            "wlc-inventory",
            "wlc-rf-summary",
            "wlc-clients-troubleshoot",
            "wlc-rf",
            "wlc",
        } and not tool.startswith("wlc-"):
            continue
        params = row.get("params", {})
        record = {
            "job_id": row.get("job_id"),
            "created": row.get("created"),
            "tool": tool,
            "done": bool(row.get("done")),
            "cancelled": bool(row.get("cancelled")),
            "samples_count": row.get("samples_count"),
            "last_ts": row.get("last_ts"),
            "params": params,
            "username": params.get("username") or params.get("user") or "",
        }
        job_id = record["job_id"]
        status = job_status(job_id)
        cancelled_event = has_event(job_id, "cancelled")
        done_event = has_event(job_id, "done")

        if cancelled_event:
            status = "cancelled"
            record["cancelled"] = True
            record["done"] = True
        elif done_event:
            status = "done"
            record["done"] = True

        record["status"] = status
        records.append(record)

    records.sort(key=lambda r: r.get("created"), reverse=True)
    return render_template("wlc_jobs.html", jobs=records)
# =================== /WLC Tools ======================


# =================== Bulk SSH ======================
@app.route("/tools/bulk-ssh")
@require_login
@require_page_enabled("bulk_ssh")
def bulk_ssh():
    """Bulk SSH terminal page."""
    return render_template("bulk_ssh.html")


@app.route("/tools/bulk-ssh/execute", methods=["POST"])
@require_login
def bulk_ssh_execute():
    """Execute bulk SSH job in background thread."""
    # Parse form data
    device_list = request.form.get("device_list", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    secret = request.form.get("secret", "").strip() or None
    command = request.form.get("command", "").strip()
    device_type = request.form.get("device_type", "cisco_ios")
    max_workers = int(request.form.get("max_workers", 10))
    timeout = int(request.form.get("timeout", 60))
    config_mode = request.form.get("config_mode", "0") == "1"

    # Parse device list
    devices = []
    if device_list:
        lines = device_list.split("\n")
        for line in lines:
            device = line.strip()
            if device and device not in devices:
                devices.append(device)

    # Validate inputs
    if not devices:
        flash("Please enter at least one device.", "error")
        return redirect(url_for("bulk_ssh"))

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("bulk_ssh"))

    if not command:
        flash("Command is required.", "error")
        return redirect(url_for("bulk_ssh"))

    # Create and start job in background thread
    job_id = str(uuid.uuid4())

    # Log to audit trail
    current_user = session.get("username", "unknown")
    mode_label = "Config Mode" if config_mode else "Show Commands"
    log_audit(
        current_user,
        "bulk_ssh_execute",
        resource=f"{len(devices)} devices",
        details=f"Command: {command[:100]}{'...' if len(command) > 100 else ''} | Mode: {mode_label} | Job ID: {job_id}",
        user_id=session.get("user_id")
    )

    def run_job():
        job = BulkSSHJob(
            devices=devices,
            command=command,
            username=username,
            password=password,
            secret=secret,
            device_type=device_type,
            max_workers=max_workers,
            timeout=timeout,
            job_id=job_id,
            config_mode=config_mode,
        )
        job.execute()

    thread = threading.Thread(target=run_job, daemon=True)
    thread.start()

    # Redirect to unified progress page
    return redirect(url_for("job_progress_page", job_id=job_id))


@app.route("/tools/bulk-ssh/results/<job_id>")
@require_login
def bulk_ssh_results(job_id: str):
    """Show results for a bulk SSH job."""
    job = load_bulk_ssh_job(job_id)
    if not job:
        flash("Job not found.", "error")
        return redirect(url_for("bulk_ssh"))

    results = load_bulk_ssh_results(job_id)

    return render_template("bulk_ssh_results.html", job=job, results=results)


@app.route("/tools/bulk-ssh/jobs")
@require_login
def bulk_ssh_jobs():
    """List all bulk SSH jobs."""
    jobs = list_bulk_ssh_jobs(limit=100)
    return render_template("bulk_ssh_jobs.html", jobs=jobs)


@app.route("/api/bulk-ssh/status/<job_id>")
@require_login
def bulk_ssh_status(job_id: str):
    """API endpoint to get job status (for live updates)."""
    job = load_bulk_ssh_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    results = load_bulk_ssh_results(job_id)

    return jsonify({
        "job_id": job_id,
        "status": job.get("status", "running"),
        "done": bool(job.get("done", 0)),
        "device_count": job.get("device_count", 0),
        "completed_count": job.get("completed_count", 0),
        "success_count": job.get("success_count", 0),
        "failed_count": job.get("failed_count", 0),
        "results": [
            {
                "device": r.get("device"),
                "status": r.get("status"),
                "duration_ms": r.get("duration_ms"),
                "error": r.get("error", ""),
            }
            for r in results
        ],
    })


@app.route("/api/bulk-ssh/export/<job_id>")
@require_login
def bulk_ssh_export(job_id: str):
    """Export bulk SSH results to CSV."""
    job = load_bulk_ssh_job(job_id)
    if not job:
        flash("Job not found.", "error")
        return redirect(url_for("bulk_ssh"))

    results = load_bulk_ssh_results(job_id)

    # Build CSV
    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(["Device", "Status", "Duration (ms)", "Output", "Error"])

    # Data rows
    for result in results:
        writer.writerow([
            result.get("device", ""),
            result.get("status", ""),
            result.get("duration_ms", 0),
            result.get("output", ""),
            result.get("error", ""),
        ])

    # Create response
    csv_data = output.getvalue()
    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = f"attachment; filename=bulk_ssh_{job_id[:8]}.csv"
    return response


# =================== Bulk SSH Templates ======================
@app.route("/tools/bulk-ssh/templates")
@require_login
def bulk_ssh_templates():
    """Command templates management page."""
    templates = list_bulk_ssh_templates()
    return render_template("bulk_ssh_templates.html", templates=templates)


@app.route("/tools/bulk-ssh/templates/create", methods=["POST"])
@require_login
def bulk_ssh_template_create():
    """Create a new template."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    command = request.form.get("command", "").strip()
    category = request.form.get("category", "general")
    device_type = request.form.get("device_type", "cisco_ios")

    # Extract variables from command
    variables = ",".join(extract_variables(command))

    if not name or not command:
        flash("Template name and command are required.", "error")
        return redirect(url_for("bulk_ssh_templates"))

    template_id = create_bulk_ssh_template(
        name=name,
        command=command,
        description=description,
        variables=variables,
        device_type=device_type,
        category=category,
        created_by=request.form.get("username", ""),
    )

    if template_id:
        flash(f"Template '{name}' created successfully.", "success")
    else:
        flash("Failed to create template. Name might already exist.", "error")

    return redirect(url_for("bulk_ssh_templates"))


@app.route("/tools/bulk-ssh/templates/<int:template_id>/update", methods=["POST"])
@require_login
def bulk_ssh_template_update(template_id: int):
    """Update an existing template."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    command = request.form.get("command", "").strip()
    category = request.form.get("category", "general")
    device_type = request.form.get("device_type", "cisco_ios")

    variables = ",".join(extract_variables(command))

    if not name or not command:
        flash("Template name and command are required.", "error")
        return redirect(url_for("bulk_ssh_templates"))

    success = update_bulk_ssh_template(
        template_id=template_id,
        name=name,
        command=command,
        description=description,
        variables=variables,
        device_type=device_type,
        category=category,
    )

    if success:
        flash(f"Template '{name}' updated successfully.", "success")
    else:
        flash("Failed to update template.", "error")

    return redirect(url_for("bulk_ssh_templates"))


@app.route("/tools/bulk-ssh/templates/<int:template_id>/delete", methods=["POST"])
@require_login
def bulk_ssh_template_delete(template_id: int):
    """Delete a template."""
    template = load_bulk_ssh_template(template_id)
    if template:
        success = delete_bulk_ssh_template(template_id)
        if success:
            flash(f"Template '{template['name']}' deleted successfully.", "success")
        else:
            flash("Failed to delete template.", "error")
    else:
        flash("Template not found.", "error")

    return redirect(url_for("bulk_ssh_templates"))


@app.route("/api/bulk-ssh/templates")
@require_login
def bulk_ssh_templates_api():
    """API endpoint to list all templates."""
    templates = list_bulk_ssh_templates()
    return jsonify(templates)


@app.route("/api/bulk-ssh/templates/<int:template_id>")
@require_login
def bulk_ssh_template_api(template_id: int):
    """API endpoint to get template details."""
    template = load_bulk_ssh_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    return jsonify(template)


@app.route("/tools/bulk-ssh/templates/seed-defaults", methods=["POST"])
@require_login
def bulk_ssh_templates_seed():
    """Seed database with common templates."""
    common = get_common_templates()
    count = 0
    for tmpl in common:
        template_id = create_bulk_ssh_template(
            name=tmpl["name"],
            command=tmpl["command"],
            description=tmpl["description"],
            variables=tmpl["variables"],
            device_type=tmpl["device_type"],
            category=tmpl["category"],
            created_by="system",
        )
        if template_id:
            count += 1

    flash(f"Added {count} default templates.", "success")
    return redirect(url_for("bulk_ssh_templates"))
# =================== /Bulk SSH Templates ======================


# =================== Bulk SSH Schedules ======================
@app.route("/tools/bulk-ssh/schedules")
@require_login
def bulk_ssh_schedules():
    """Scheduled jobs management page."""
    schedules = list_bulk_ssh_schedules()
    templates = list_bulk_ssh_templates()
    return render_template("bulk_ssh_schedules.html", schedules=schedules, templates=templates)


@app.route("/tools/bulk-ssh/schedules/create", methods=["POST"])
@require_login
def bulk_ssh_schedule_create():
    """Create a new scheduled job."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    device_list = request.form.get("device_list", "").strip()
    command = request.form.get("command", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    secret = request.form.get("secret", "").strip()
    device_type = request.form.get("device_type", "cisco_ios")
    schedule_type = request.form.get("schedule_type", "once")
    alert_on_failure = request.form.get("alert_on_failure") == "on"
    alert_email = request.form.get("alert_email", "").strip()

    # Parse device list
    devices = []
    if device_list:
        lines = device_list.split("\n")
        for line in lines:
            device = line.strip()
            if device and device not in devices:
                devices.append(device)

    devices_json = json.dumps(devices)

    # Calculate next run time based on schedule type
    now = datetime.now(_CST_TZ)

    if schedule_type == "once":
        run_date = request.form.get("run_date", "")
        run_time = request.form.get("run_time", "")
        if run_date and run_time:
            next_run = f"{run_date}T{run_time}:00"
        else:
            next_run = (now + timedelta(minutes=5)).isoformat(timespec="seconds")
        schedule_config = json.dumps({"run_at": next_run})
    elif schedule_type == "daily":
        run_time = request.form.get("daily_time", "00:00")
        hour, minute = run_time.split(":")
        next_run_dt = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
        if next_run_dt <= now:
            next_run_dt += timedelta(days=1)
        next_run = next_run_dt.isoformat(timespec="seconds")
        schedule_config = json.dumps({"time": run_time})
    elif schedule_type == "weekly":
        run_time = request.form.get("weekly_time", "00:00")
        day_of_week = int(request.form.get("day_of_week", 0))
        hour, minute = run_time.split(":")
        # Calculate next occurrence
        days_ahead = day_of_week - now.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        next_run_dt = now + timedelta(days=days_ahead)
        next_run_dt = next_run_dt.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
        next_run = next_run_dt.isoformat(timespec="seconds")
        schedule_config = json.dumps({"time": run_time, "day": day_of_week})
    else:
        next_run = ""
        schedule_config = "{}"

    if not name or not devices or not command or not username or not password:
        flash("All required fields must be filled.", "error")
        return redirect(url_for("bulk_ssh_schedules"))

    schedule_id = create_bulk_ssh_schedule(
        name=name,
        description=description,
        devices_json=devices_json,
        command=command,
        username=username,
        password=password,
        secret=secret,
        device_type=device_type,
        schedule_type=schedule_type,
        schedule_config=schedule_config,
        next_run=next_run,
        alert_on_failure=alert_on_failure,
        alert_email=alert_email,
        created_by=request.form.get("created_by", ""),
    )

    if schedule_id:
        flash(f"Schedule '{name}' created successfully.", "success")
    else:
        flash("Failed to create schedule.", "error")

    return redirect(url_for("bulk_ssh_schedules"))


@app.route("/tools/bulk-ssh/schedules/<int:schedule_id>/toggle", methods=["POST"])
@require_login
def bulk_ssh_schedule_toggle(schedule_id: int):
    """Enable or disable a schedule."""
    enabled = request.form.get("enabled") == "true"
    success = toggle_bulk_ssh_schedule(schedule_id, enabled)

    if success:
        status = "enabled" if enabled else "disabled"
        flash(f"Schedule {status} successfully.", "success")
    else:
        flash("Failed to update schedule.", "error")

    return redirect(url_for("bulk_ssh_schedules"))


@app.route("/tools/bulk-ssh/schedules/<int:schedule_id>/delete", methods=["POST"])
@require_login
def bulk_ssh_schedule_delete(schedule_id: int):
    """Delete a schedule."""
    schedule = load_bulk_ssh_schedule(schedule_id)
    if schedule:
        success = delete_bulk_ssh_schedule(schedule_id)
        if success:
            flash(f"Schedule '{schedule['name']}' deleted successfully.", "success")
        else:
            flash("Failed to delete schedule.", "error")
    else:
        flash("Schedule not found.", "error")

    return redirect(url_for("bulk_ssh_schedules"))
# =================== /Bulk SSH Schedules ======================
# =================== /Bulk SSH ======================


# ====================== Certificate Tracker ======================
@app.route("/certs")
@require_login
@require_page_enabled("cert_tracker")
def cert_tracker():
    """Main certificate tracker dashboard."""
    certs = list_certificates()
    stats = get_certificate_stats()

    # Get filter parameters
    cn_filter = request.args.get('cn', '').strip().lower()
    source_filter = request.args.get('source', '').strip()
    status_filter = request.args.get('status', '').strip()
    issued_to_filter = request.args.get('issued_to', '').strip().lower()
    issued_by_filter = request.args.get('issued_by', '').strip().lower()
    devices_filter = request.args.get('devices', '').strip().lower()

    # Get sort parameters
    sort_by = request.args.get('sort', '').strip()
    sort_dir = request.args.get('dir', 'asc').strip()

    # Add expiry class and days_left to each certificate for color coding
    filtered_certs = []
    for cert in certs:
        cert['expiry_class'] = get_expiry_class(cert.get('expires', ''))
        cert['days_left'] = get_days_until_expiry(cert.get('expires', ''))
        cert['expires_formatted'] = format_expiry_date(cert.get('expires', ''))

        # Apply CN filter
        if cn_filter and cn_filter not in (cert.get('cn') or '').lower():
            continue

        # Apply source filter
        if source_filter and cert.get('source_type') != source_filter:
            continue

        # Apply status/expiry filter (exclusive ranges to match stats)
        if status_filter:
            days_left = cert.get('days_left')
            if status_filter == 'expired':
                # Only expired: days < 0
                if days_left is None or days_left >= 0:
                    continue
            elif status_filter == '14':
                # Only 0-14 days (not expired)
                if days_left is None or days_left < 0 or days_left > 14:
                    continue
            elif status_filter == '30':
                # Only 15-30 days
                if days_left is None or days_left <= 14 or days_left > 30:
                    continue
            elif status_filter == '60':
                # Only 31-60 days
                if days_left is None or days_left <= 30 or days_left > 60:
                    continue
            elif status_filter == 'ok':
                # More than 60 days
                if days_left is None or days_left <= 60:
                    continue

        # Apply issued_to filter
        if issued_to_filter and issued_to_filter not in (cert.get('issued_to') or '').lower():
            continue

        # Apply issued_by filter
        if issued_by_filter and issued_by_filter not in (cert.get('issued_by') or '').lower():
            continue

        # Apply devices filter
        devices_str = (cert.get('devices') or '') + ' ' + (cert.get('source_hostname') or '')
        if devices_filter and devices_filter not in devices_str.lower():
            continue

        filtered_certs.append(cert)

    # Apply sorting
    if sort_by == 'days':
        # Sort by days_left, putting None values at the end
        reverse = (sort_dir == 'desc')
        filtered_certs.sort(
            key=lambda c: (c.get('days_left') is None, c.get('days_left') if c.get('days_left') is not None else 9999),
            reverse=reverse
        )

    return render_template("cert_tracker.html", certs=filtered_certs, stats=stats, sort_by=sort_by, sort_dir=sort_dir)


@app.route("/certs/export")
@require_login
def cert_export():
    """Export certificates to CSV."""
    certs = list_certificates()

    # Apply same filters as cert_tracker
    cn_filter = request.args.get('cn', '').strip().lower()
    source_filter = request.args.get('source', '').strip()
    status_filter = request.args.get('status', '').strip()
    issued_to_filter = request.args.get('issued_to', '').strip().lower()
    issued_by_filter = request.args.get('issued_by', '').strip().lower()
    devices_filter = request.args.get('devices', '').strip().lower()

    filtered_certs = []
    for cert in certs:
        cert['days_left'] = get_days_until_expiry(cert.get('expires', ''))
        cert['expires_formatted'] = format_expiry_date(cert.get('expires', ''))

        if cn_filter and cn_filter not in (cert.get('cn') or '').lower():
            continue
        if source_filter and cert.get('source_type') != source_filter:
            continue
        if status_filter:
            days_left = cert.get('days_left')
            if status_filter == 'expired' and (days_left is None or days_left >= 0):
                continue
            elif status_filter == '14' and (days_left is None or days_left < 0 or days_left > 14):
                continue
            elif status_filter == '30' and (days_left is None or days_left <= 14 or days_left > 30):
                continue
            elif status_filter == '60' and (days_left is None or days_left <= 30 or days_left > 60):
                continue
            elif status_filter == 'ok' and (days_left is None or days_left <= 60):
                continue
        if issued_to_filter and issued_to_filter not in (cert.get('issued_to') or '').lower():
            continue
        if issued_by_filter and issued_by_filter not in (cert.get('issued_by') or '').lower():
            continue
        devices_str = (cert.get('devices') or '') + ' ' + (cert.get('source_hostname') or '')
        if devices_filter and devices_filter not in devices_str.lower():
            continue

        filtered_certs.append(cert)

    # Sort by days_left ascending by default
    filtered_certs.sort(
        key=lambda c: (c.get('days_left') is None, c.get('days_left') if c.get('days_left') is not None else 9999)
    )

    # Build CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['CN', 'Expires', 'Days Left', 'Issued To', 'Issued By', 'Source', 'Devices', 'Serial'])

    for cert in filtered_certs:
        days_left = cert.get('days_left')
        if days_left is None:
            days_str = 'Unknown'
        elif days_left < 0:
            days_str = 'Expired'
        else:
            days_str = str(days_left)

        writer.writerow([
            cert.get('cn', ''),
            cert.get('expires_formatted', ''),
            days_str,
            cert.get('issued_to', ''),
            cert.get('issued_by', ''),
            cert.get('source_type', ''),
            cert.get('devices') or cert.get('source_hostname', ''),
            cert.get('serial', ''),
        ])

    output.seek(0)
    timestamp = datetime.now(_CST_TZ).strftime('%Y%m%d_%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=certificates_{timestamp}.csv'}
    )


@app.route("/certs/upload", methods=["GET", "POST"])
@require_login
def cert_upload():
    """Upload a new certificate."""
    if request.method == "POST":
        if 'cert_file' not in request.files:
            flash("No file selected.", "error")
            return redirect(request.url)

        file = request.files['cert_file']
        if file.filename == '':
            flash("No file selected.", "error")
            return redirect(request.url)

        try:
            cert_bytes = file.read()
            details = extract_full_cert_details(cert_bytes)

            # Check if certificate already exists by serial number
            if details.get('serial') and certificate_exists(details['serial']):
                flash("This certificate already exists in the tracker.", "warning")
                return redirect(url_for('cert_tracker'))

            # Insert the certificate
            cn = details.get('cn', 'Unknown')
            insert_certificate(
                cn=cn,
                expires=details.get('expires', 'Unknown'),
                issued_to=details.get('issued_to', ''),
                issued_by=details.get('issued_by', ''),
                used_by=request.form.get('used_by', ''),
                notes=request.form.get('notes', ''),
                devices=request.form.get('devices', ''),
                source_type='upload',
                source_ip=None,
                source_hostname=None,
                serial=details.get('serial', ''),
            )
            flash(f"Certificate '{cn}' uploaded successfully.", "success")
            return redirect(url_for('cert_tracker'))

        except Exception as e:
            flash(f"Error processing certificate: {str(e)}", "error")
            return redirect(request.url)

    return render_template("cert_upload.html")


@app.route("/certs/<int:cert_id>/edit", methods=["GET", "POST"])
@require_login
def cert_edit(cert_id):
    """Edit certificate details."""
    cert = get_certificate(cert_id)
    if not cert:
        flash("Certificate not found.", "error")
        return redirect(url_for('cert_tracker'))

    if request.method == "POST":
        update_certificate(
            cert_id,
            issued_to=request.form.get('issued_to', ''),
            issued_by=request.form.get('issued_by', ''),
            used_by=request.form.get('used_by', ''),
            notes=request.form.get('notes', ''),
            devices=request.form.get('devices', ''),
        )
        flash("Certificate updated successfully.", "success")
        return redirect(url_for('cert_tracker'))

    return render_template("cert_edit.html", cert=cert)


@app.route("/certs/<int:cert_id>/delete", methods=["POST"])
@require_login
def cert_delete(cert_id):
    """Delete a certificate."""
    # Only superadmin can delete
    if session.get('role') != 'superadmin':
        flash("You don't have permission to delete certificates.", "error")
        return redirect(url_for('cert_tracker'))

    cert = get_certificate(cert_id)
    if cert:
        delete_certificate(cert_id)
        flash(f"Certificate '{cert.get('cn', 'Unknown')}' deleted.", "success")
    else:
        flash("Certificate not found.", "error")

    return redirect(url_for('cert_tracker'))


@app.route("/certs/<int:cert_id>/view")
@require_login
def cert_view(cert_id):
    """View certificate details and chain."""
    cert = get_certificate(cert_id)
    if not cert:
        flash("Certificate not found.", "error")
        return redirect(url_for('cert_tracker'))

    # Add computed fields
    cert['expiry_class'] = get_expiry_class(cert.get('expires', ''))
    cert['days_left'] = get_days_until_expiry(cert.get('expires', ''))
    cert['expires_formatted'] = format_expiry_date(cert.get('expires', ''))

    return render_template("cert_view.html", cert=cert)


@app.route("/certs/chain", methods=["POST"])
@require_login
def cert_chain_view():
    """Upload and view certificate chain details."""
    if 'cert_file' not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for('cert_tracker'))

    file = request.files['cert_file']
    if file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('cert_tracker'))

    try:
        cert_bytes = file.read()
        chain = extract_cert_chain_details(cert_bytes)

        if not chain:
            flash("Could not parse certificate file.", "error")
            return redirect(url_for('cert_tracker'))

        # Add computed fields to each cert in chain
        for cert in chain:
            cert['days_left'] = get_days_until_expiry(cert.get('not_after', ''))
            cert['expires_formatted'] = format_expiry_date(cert.get('not_after', ''))
            cert['expiry_class'] = get_expiry_class(cert.get('not_after', ''))

        return render_template("cert_chain.html", chain=chain, filename=file.filename)

    except Exception as e:
        flash(f"Error parsing certificate: {str(e)}", "error")
        return redirect(url_for('cert_tracker'))


@app.route("/certs/converter", methods=["GET", "POST"])
@require_login
@require_page_enabled("cert_converter")
def cert_converter():
    """Certificate format converter."""
    error = None
    success = None

    if request.method == "POST":
        conversion_type = request.form.get('conversion_type')
        passphrase = request.form.get('passphrase', '')

        try:
            if conversion_type == 'pfx_to_crt':
                file1 = request.files.get('file1')
                if not file1:
                    raise CertConversionError("No PFX file provided")

                pfx_data = file1.read()
                crt_data, key_data, cn = pfx_to_crt_key(pfx_data, passphrase)

                # Create a zip bundle with both files
                zip_data = create_zip_bundle({
                    f'{cn}.crt': crt_data,
                    f'{cn}.key': key_data,
                })

                response = make_response(zip_data)
                response.headers['Content-Type'] = 'application/zip'
                response.headers['Content-Disposition'] = f'attachment; filename={cn}_certificate.zip'
                return response

            elif conversion_type == 'crt_key_to_pfx':
                file1 = request.files.get('file1')
                file2 = request.files.get('file2')
                if not file1 or not file2:
                    raise CertConversionError("Both certificate and key files are required")
                if not passphrase:
                    raise CertConversionError("PFX password is required")

                crt_data = file1.read()
                key_data = file2.read()
                pfx_data = crt_key_to_pfx(crt_data, key_data, passphrase)

                response = make_response(pfx_data)
                response.headers['Content-Type'] = 'application/x-pkcs12'
                response.headers['Content-Disposition'] = 'attachment; filename=certificate.pfx'
                return response

            elif conversion_type == 'pem_to_crt_key':
                file1 = request.files.get('file1')
                if not file1:
                    raise CertConversionError("No PEM file provided")

                pem_data = file1.read()
                crt_data, key_data = pem_to_crt_key(pem_data)

                zip_data = create_zip_bundle({
                    'certificate.crt': crt_data,
                    'private.key': key_data,
                })

                response = make_response(zip_data)
                response.headers['Content-Type'] = 'application/zip'
                response.headers['Content-Disposition'] = 'attachment; filename=certificate_files.zip'
                return response

            elif conversion_type == 'crt_key_to_pem':
                file1 = request.files.get('file1')
                file2 = request.files.get('file2')
                if not file1 or not file2:
                    raise CertConversionError("Both certificate and key files are required")

                crt_data = file1.read()
                key_data = file2.read()
                pem_data = crt_key_to_pem(crt_data, key_data)

                response = make_response(pem_data)
                response.headers['Content-Type'] = 'application/x-pem-file'
                response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
                return response

            elif conversion_type == 'der_to_pem':
                file1 = request.files.get('file1')
                if not file1:
                    raise CertConversionError("No DER file provided")

                der_data = file1.read()
                pem_data = der_to_pem(der_data)

                response = make_response(pem_data)
                response.headers['Content-Type'] = 'application/x-pem-file'
                response.headers['Content-Disposition'] = 'attachment; filename=certificate.pem'
                return response

            elif conversion_type == 'pem_to_der':
                file1 = request.files.get('file1')
                if not file1:
                    raise CertConversionError("No PEM file provided")

                pem_data = file1.read()
                der_data = pem_to_der(pem_data)

                response = make_response(der_data)
                response.headers['Content-Type'] = 'application/x-x509-ca-cert'
                response.headers['Content-Disposition'] = 'attachment; filename=certificate.der'
                return response

            else:
                raise CertConversionError("Invalid conversion type")

        except CertConversionError as e:
            error = str(e)
        except Exception as e:
            error = f"Conversion failed: {str(e)}"

    return render_template("cert_converter.html", error=error, success=success)
# =================== /Certificate Tracker ======================


# ====================== ISE Node Management ======================
@app.route("/ise-nodes")
@require_login
@require_page_enabled("ise_nodes")
def ise_nodes():
    """ISE node management page."""
    nodes = list_ise_nodes()
    sync_settings = load_cert_sync_settings()
    return render_template("ise_nodes.html", nodes=nodes, sync_settings=sync_settings)


@app.route("/ise-nodes/add", methods=["POST"])
@require_login
def ise_node_add():
    """Add a new ISE node."""
    hostname = request.form.get('hostname', '').strip()
    ip = request.form.get('ip', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not all([hostname, ip, username, password]):
        flash("All fields are required.", "error")
        return redirect(url_for('ise_nodes'))

    insert_ise_node(
        hostname=hostname,
        ip=ip,
        username=username,
        password=password,
        enabled=True,
    )
    flash(f"ISE node '{hostname}' added successfully.", "success")
    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/<int:node_id>/edit", methods=["GET", "POST"])
@require_login
def ise_node_edit(node_id):
    """Edit an ISE node."""
    node = get_ise_node(node_id)
    if not node:
        flash("ISE node not found.", "error")
        return redirect(url_for('ise_nodes'))

    if request.method == "POST":
        # Only update password if provided
        new_password = request.form.get('password', '')
        update_ise_node(
            node_id,
            hostname=request.form.get('hostname', '').strip(),
            ip=request.form.get('ip', '').strip(),
            username=request.form.get('username', '').strip(),
            enabled=bool(request.form.get('enabled')),
            password=new_password if new_password else None,
        )
        flash("ISE node updated successfully.", "success")
        return redirect(url_for('ise_nodes'))

    return render_template("ise_node_edit.html", node=node)


@app.route("/ise-nodes/<int:node_id>/delete", methods=["POST"])
@require_login
def ise_node_delete(node_id):
    """Delete an ISE node."""
    if session.get('role') != 'superadmin':
        flash("You don't have permission to delete ISE nodes.", "error")
        return redirect(url_for('ise_nodes'))

    node = get_ise_node(node_id)
    if node:
        delete_ise_node(node_id)
        flash(f"ISE node '{node.get('hostname', 'Unknown')}' deleted.", "success")
    else:
        flash("ISE node not found.", "error")

    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/<int:node_id>/toggle", methods=["POST"])
@require_login
def ise_node_toggle(node_id):
    """Toggle an ISE node enabled/disabled."""
    node = get_ise_node(node_id)
    if node:
        new_status = not node.get('enabled')
        update_ise_node(node_id, enabled=new_status)
        status_text = "enabled" if new_status else "disabled"
        flash(f"ISE node '{node.get('hostname', 'Unknown')}' {status_text}.", "success")
    else:
        flash("ISE node not found.", "error")

    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/<int:node_id>/sync", methods=["POST"])
@require_login
def ise_node_sync(node_id):
    """Sync certificates from a single ISE node."""
    node = get_ise_node(node_id)
    if not node:
        flash("ISE node not found.", "error")
        return redirect(url_for('ise_nodes'))

    try:
        # Build node info for the sync function
        node_info = {
            'hostname': node['hostname'],
            'ip': node['ip'],
            'username': node['username'],
            'password': node['password'],  # get_ise_node decrypts to 'password' key
        }

        # Pull certificates from this node
        certs, sync_errors = pull_ise_certs([node_info])

        # Check if there were errors
        if sync_errors:
            error_msg = sync_errors[0]
            update_ise_node_sync_status(node_id, status='error', message=error_msg)
            flash(f"Sync failed for '{node['hostname']}': {error_msg}", "error")
            return redirect(url_for('ise_nodes'))

        added_count = 0

        for cert_data in certs:
            # Check if certificate already exists
            if cert_data.get('serial') and certificate_exists(cert_data['serial']):
                continue

            insert_certificate(
                cn=cert_data.get('cn', 'Unknown'),
                expires=cert_data.get('expires', 'Unknown'),
                issued_to=cert_data.get('issued_to'),
                issued_by=cert_data.get('issued_by'),
                used_by=cert_data.get('used_by'),
                notes=cert_data.get('notes'),
                devices=cert_data.get('devices'),
                source_type=cert_data.get('source_type', 'ise'),
                source_ip=cert_data.get('source_ip'),
                source_hostname=cert_data.get('source_hostname'),
                serial=cert_data.get('serial'),
            )
            added_count += 1

        # Update node sync status
        update_ise_node_sync_status(node_id, status='success', message=f"Synced {added_count} new certificates")
        flash(f"Synced {added_count} new certificates from '{node['hostname']}'.", "success")

    except Exception as e:
        update_ise_node_sync_status(node_id, status='error', message=str(e))
        flash(f"Sync failed: {str(e)}", "error")

    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/sync-all", methods=["POST"])
@require_login
def ise_sync_now():
    """Sync certificates from all enabled ISE nodes."""
    nodes = get_enabled_ise_nodes()

    if not nodes:
        flash("No enabled ISE nodes configured.", "warning")
        return redirect(url_for('ise_nodes'))

    total_added = 0
    node_errors = []

    # Sync each node individually to track per-node status
    for node in nodes:
        try:
            node_info = {
                'hostname': node['hostname'],
                'ip': node['ip'],
                'username': node['username'],
                'password': node['password'],
            }

            # Pull certificates from this node
            certs, sync_errors = pull_ise_certs([node_info])

            # Check if there were errors for this node
            if sync_errors:
                node_errors.append(node['hostname'])
                update_ise_node_sync_status(node['id'], status='error', message=sync_errors[0])
                continue

            added_count = 0
            for cert_data in certs:
                # Check if certificate already exists
                if cert_data.get('serial') and certificate_exists(cert_data['serial']):
                    continue

                insert_certificate(
                    cn=cert_data.get('cn', 'Unknown'),
                    expires=cert_data.get('expires', 'Unknown'),
                    issued_to=cert_data.get('issued_to'),
                    issued_by=cert_data.get('issued_by'),
                    used_by=cert_data.get('used_by'),
                    notes=cert_data.get('notes'),
                    devices=cert_data.get('devices'),
                    source_type=cert_data.get('source_type', 'ise'),
                    source_ip=cert_data.get('source_ip'),
                    source_hostname=cert_data.get('source_hostname'),
                    serial=cert_data.get('serial'),
                )
                added_count += 1

            total_added += added_count
            update_ise_node_sync_status(node['id'], status='success', message=f"Synced {added_count} new certificates")

        except Exception as e:
            node_errors.append(node['hostname'])
            update_ise_node_sync_status(node['id'], status='error', message=str(e))

    # Update global sync status
    if node_errors:
        update_cert_sync_status(status='error', message=f"Errors on: {', '.join(node_errors)}")
        flash(f"Synced {total_added} certificates. Errors on {len(node_errors)} node(s).", "warning")
    else:
        update_cert_sync_status(status='success', message=f"Synced {total_added} new certificates from {len(nodes)} nodes")
        flash(f"Synced {total_added} new certificates from {len(nodes)} ISE nodes.", "success")

    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/settings", methods=["POST"])
@require_login
def ise_nodes_settings():
    """Update ISE auto-sync settings."""
    enabled = 1 if request.form.get('enabled') else 0
    interval_hours = int(request.form.get('interval_hours', 24))

    # Preserve existing sync status info
    current = load_cert_sync_settings()
    save_cert_sync_settings({
        'enabled': enabled,
        'interval_hours': interval_hours,
        'last_sync_ts': current.get('last_sync_ts'),
        'last_sync_status': current.get('last_sync_status'),
        'last_sync_message': current.get('last_sync_message'),
    })

    flash("Auto-sync settings saved.", "success")
    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/<int:node_id>/fetch-version", methods=["POST"])
@require_login
def ise_node_fetch_version(node_id):
    """Fetch version and patch info from an ISE node."""
    node = get_ise_node(node_id)
    if not node:
        flash("ISE node not found.", "error")
        return redirect(url_for('ise_nodes'))

    version_info = get_ise_version(
        ip=node['ip'],
        username=node['username'],
        password=node['password'],
        hostname=node['hostname']
    )

    if version_info:
        update_ise_node_version(
            node_id,
            version=version_info.get('version', ''),
            patch=version_info.get('patch', '')
        )
        flash(f"Version info updated for {node['hostname']}.", "success")
    else:
        flash(f"Could not fetch version info from {node['hostname']}. Check console for details.", "warning")

    return redirect(url_for('ise_nodes'))


@app.route("/ise-nodes/fetch-all-versions", methods=["POST"])
@require_login
def ise_node_fetch_all_versions():
    """Fetch version and patch info from all enabled ISE nodes."""
    nodes = get_enabled_ise_nodes()
    success_count = 0
    error_count = 0

    for node in nodes:
        version_info = get_ise_version(
            ip=node['ip'],
            username=node['username'],
            password=node['password'],
            hostname=node['hostname']
        )

        if version_info:
            update_ise_node_version(
                node['id'],
                version=version_info.get('version', ''),
                patch=version_info.get('patch', '')
            )
            success_count += 1
        else:
            error_count += 1

    if error_count > 0:
        flash(f"Updated {success_count} node(s). Failed to fetch {error_count} node(s).", "warning")
    else:
        flash(f"Updated version info for {success_count} ISE node(s).", "success")

    return redirect(url_for('ise_nodes'))
# =================== /ISE Node Management ======================


# ====================== KNOWLEDGE BASE ======================
import sqlite3 as kb_sqlite

def get_kb_articles_for_user(user_id: int):
    """Get all KB articles visible to a user based on their access level."""
    access_level = get_kb_access_level(user_id) if user_id else 'FSR'

    conn = kb_sqlite.connect("noc_toolkit.db")
    conn.row_factory = kb_sqlite.Row
    cursor = conn.cursor()

    # Get all articles and filter by visibility
    cursor.execute("""
        SELECT a.*, u.username as author_name
        FROM kb_articles a
        LEFT JOIN users u ON a.created_by = u.id
        ORDER BY a.updated_at DESC
    """)

    all_articles = cursor.fetchall()
    conn.close()

    # Filter based on user access level
    visible_articles = []
    for article in all_articles:
        if can_view_kb_article(access_level, article['visibility']):
            visible_articles.append(dict(article))

    return visible_articles


def get_kb_article(article_id: int):
    """Get a single KB article by ID."""
    conn = kb_sqlite.connect("noc_toolkit.db")
    conn.row_factory = kb_sqlite.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, u.username as author_name
        FROM kb_articles a
        LEFT JOIN users u ON a.created_by = u.id
        WHERE a.id = ?
    """, (article_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def create_kb_article(title: str, subject: str, content: str, visibility: str, created_by: int) -> int:
    """Create a new KB article and return its ID."""
    conn = kb_sqlite.connect("noc_toolkit.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO kb_articles (title, subject, content, visibility, created_by)
        VALUES (?, ?, ?, ?, ?)
    """, (title, subject, content, visibility, created_by))
    article_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return article_id


def update_kb_article(article_id: int, title: str, subject: str, content: str, visibility: str):
    """Update an existing KB article."""
    conn = kb_sqlite.connect("noc_toolkit.db")
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE kb_articles
        SET title = ?, subject = ?, content = ?, visibility = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (title, subject, content, visibility, article_id))
    conn.commit()
    conn.close()


def delete_kb_article(article_id: int):
    """Delete a KB article."""
    conn = kb_sqlite.connect("noc_toolkit.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM kb_articles WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()


def get_kb_subjects():
    """Get all unique subjects from KB articles."""
    conn = kb_sqlite.connect("noc_toolkit.db")
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT subject FROM kb_articles ORDER BY subject")
    subjects = [row[0] for row in cursor.fetchall()]
    conn.close()
    return subjects


@app.route("/knowledge-base")
@require_login
@require_page_enabled("knowledge_base")
def knowledge_base():
    """Knowledge Base main page - list all visible articles."""
    user_id = session.get('user_id')
    articles = get_kb_articles_for_user(user_id)
    subjects = get_kb_subjects()
    can_create = can_user_create_kb(user_id)
    user_access_level = get_kb_access_level(user_id)

    # Filter by subject if provided
    subject_filter = request.args.get('subject', '')
    if subject_filter:
        articles = [a for a in articles if a['subject'] == subject_filter]

    # Search by title/content if provided
    search_query = request.args.get('q', '')
    if search_query:
        search_lower = search_query.lower()
        articles = [a for a in articles if search_lower in a['title'].lower() or search_lower in a['content'].lower()]

    return render_template(
        "knowledge_base.html",
        articles=articles,
        subjects=subjects,
        can_create=can_create,
        user_access_level=user_access_level,
        subject_filter=subject_filter,
        search_query=search_query,
    )


@app.route("/knowledge-base/create", methods=["GET", "POST"])
@require_login
@require_kb_create
def knowledge_base_create():
    """Create a new KB article."""
    if request.method == "POST":
        title = request.form.get('title', '').strip()
        subject = request.form.get('subject', '').strip()
        content = request.form.get('content', '').strip()
        visibility = request.form.get('visibility', 'FSR')

        if not title or not subject or not content:
            flash("Title, subject, and content are required.", "error")
            return render_template("knowledge_base_form.html", mode="create", article={
                'title': title, 'subject': subject, 'content': content, 'visibility': visibility
            }, subjects=get_kb_subjects())

        article_id = create_kb_article(title, subject, content, visibility, session['user_id'])
        log_audit(session.get('username', 'unknown'), 'kb_create', f'article:{article_id}', f'Created KB article: {title}')
        flash("Knowledge base article created successfully.", "success")
        return redirect(url_for('knowledge_base_view', article_id=article_id))

    return render_template("knowledge_base_form.html", mode="create", article={}, subjects=get_kb_subjects())


@app.route("/knowledge-base/<int:article_id>")
@require_login
def knowledge_base_view(article_id):
    """View a KB article."""
    article = get_kb_article(article_id)
    if not article:
        flash("Article not found.", "error")
        return redirect(url_for('knowledge_base'))

    # Check if user can view this article
    user_access_level = get_kb_access_level(session.get('user_id'))
    if not can_view_kb_article(user_access_level, article['visibility']):
        flash("You don't have permission to view this article.", "error")
        return redirect(url_for('knowledge_base'))

    can_edit = can_user_create_kb(session.get('user_id'))

    return render_template("knowledge_base_article.html", article=article, can_edit=can_edit)


@app.route("/knowledge-base/<int:article_id>/edit", methods=["GET", "POST"])
@require_login
@require_kb_create
def knowledge_base_edit(article_id):
    """Edit a KB article."""
    article = get_kb_article(article_id)
    if not article:
        flash("Article not found.", "error")
        return redirect(url_for('knowledge_base'))

    if request.method == "POST":
        title = request.form.get('title', '').strip()
        subject = request.form.get('subject', '').strip()
        content = request.form.get('content', '').strip()
        visibility = request.form.get('visibility', 'FSR')

        if not title or not subject or not content:
            flash("Title, subject, and content are required.", "error")
            return render_template("knowledge_base_form.html", mode="edit", article={
                'id': article_id, 'title': title, 'subject': subject, 'content': content, 'visibility': visibility
            }, subjects=get_kb_subjects())

        update_kb_article(article_id, title, subject, content, visibility)
        log_audit(session.get('username', 'unknown'), 'kb_update', f'article:{article_id}', f'Updated KB article: {title}')
        flash("Knowledge base article updated successfully.", "success")
        return redirect(url_for('knowledge_base_view', article_id=article_id))

    return render_template("knowledge_base_form.html", mode="edit", article=article, subjects=get_kb_subjects())


@app.route("/knowledge-base/<int:article_id>/delete", methods=["POST"])
@require_login
@require_kb_create
def knowledge_base_delete(article_id):
    """Delete a KB article."""
    article = get_kb_article(article_id)
    if not article:
        flash("Article not found.", "error")
        return redirect(url_for('knowledge_base'))

    delete_kb_article(article_id)
    log_audit(session.get('username', 'unknown'), 'kb_delete', f'article:{article_id}', f'Deleted KB article: {article["title"]}')
    flash("Knowledge base article deleted.", "success")
    return redirect(url_for('knowledge_base'))


# ====================== /KNOWLEDGE BASE ======================


# ====================== CUSTOMER DASHBOARD ======================

@app.route("/customer/dashboard")
@require_login
@require_page_enabled("customer_dashboard")
def customer_dashboard():
    """Executive customer dashboard - professional printable network health report."""
    nodes = fetch_solarwinds_nodes()
    org_options = get_organizations_from_nodes(nodes)
    selected_org = request.args.get("org", "")

    metrics = None
    if selected_org:
        wlc_details = fetch_wlc_dashboard_latest_details()
        metrics = fetch_customer_dashboard_metrics(selected_org, nodes, wlc_details)

    generated_at = datetime.now(_CST_TZ).strftime("%B %d, %Y at %I:%M %p CST")

    return render_template(
        "customer_dashboard.html",
        org_options=org_options,
        selected_org=selected_org,
        metrics=metrics,
        generated_at=generated_at,
    )


# ====================== /CUSTOMER DASHBOARD ======================


# ====================== MAIN ======================
if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)

    # Start background schedule worker
    start_schedule_worker(check_interval=60)

    app.run(host="0.0.0.0", port=8080, debug=False)
