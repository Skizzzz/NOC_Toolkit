"""
WLC (Wireless LAN Controller) blueprint routes.

Provides routes for WLC dashboard, AP inventory, summer guest,
RF analysis, and troubleshooting tools.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    Response,
)

from src.core.security import (
    require_login,
    require_superadmin,
    require_page_enabled,
    log_audit,
)

wlc_bp = Blueprint(
    "wlc",
    __name__,
    template_folder="templates",
    url_prefix="",
)


# ====================== WLC Tools Menu ======================

@wlc_bp.get("/tools/wlc")
@require_login
def wlc_tools():
    """WLC tools menu page."""
    return render_template("wlc/wlc_tools.html")


# ====================== WLC Dashboard ======================

@wlc_bp.get("/tools/wlc/dashboard")
@require_login
@require_page_enabled("wlc_dashboard")
def wlc_dashboard():
    """WLC dashboard showing client counts and AP status."""
    # Import here to avoid circular dependencies
    from tools.db_jobs import (
        load_wlc_dashboard_settings,
        fetch_wlc_dashboard_latest_totals,
        fetch_wlc_dashboard_latest_details,
    )

    _DASHBOARD_RANGE_TO_HOURS = {
        "1h": 1,
        "6h": 6,
        "12h": 12,
        "24h": 24,
        "7d": 168,
        "30d": 720,
    }
    _DASHBOARD_RANGE_OPTIONS = [
        ("1h", "1 Hour"),
        ("6h", "6 Hours"),
        ("12h", "12 Hours"),
        ("24h", "24 Hours"),
        ("7d", "7 Days"),
        ("30d", "30 Days"),
    ]

    selected = request.args.get("range", "24h")
    if selected not in _DASHBOARD_RANGE_TO_HOURS:
        selected = "24h"

    settings = load_wlc_dashboard_settings()
    latest = fetch_wlc_dashboard_latest_totals()
    host_details = fetch_wlc_dashboard_latest_details()
    interval_minutes = max(int(settings.get("interval_sec") or 300) // 60, 1)

    return render_template(
        "wlc/wlc_dashboard.html",
        settings=settings,
        latest=latest,
        range_options=_DASHBOARD_RANGE_OPTIONS,
        selected_range=selected,
        interval_minutes=interval_minutes,
        host_details=host_details,
    )


# ====================== WLC AP Inventory ======================

@wlc_bp.get("/tools/wlc/ap-inventory")
@require_login
@require_page_enabled("wlc_dashboard")
def wlc_ap_inventory():
    """Display auto-updating AP inventory collected during WLC polling."""
    from tools.db_jobs import list_ap_inventory, get_ap_inventory_stats

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
        "wlc/ap_inventory.html",
        aps=aps,
        stats=stats,
        filters=filters,
        wlc_options=stats.get("wlc_hosts", []),
    )


@wlc_bp.get("/tools/wlc/ap-inventory/export")
@require_login
@require_page_enabled("wlc_dashboard")
def wlc_ap_inventory_export():
    """Export AP inventory to CSV with current filters applied."""
    import io
    import csv
    from datetime import datetime
    from tools.db_jobs import list_ap_inventory

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


# ====================== WLC Summer Guest ======================

@wlc_bp.get("/tools/wlc/summer-guest")
@require_login
@require_page_enabled("wlc_summer_guest")
def wlc_summer_guest():
    """Summer guest WLAN management page."""
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from typing import Optional, Tuple
    from tools.db_jobs import (
        load_wlc_summer_settings,
        fetch_wlc_summer_latest_details,
        fetch_wlc_summer_recent_runs,
        fetch_upcoming_changes_for_hosts,
    )

    _CST_TZ = ZoneInfo("America/Chicago")

    def _summer_timezone(settings: dict) -> ZoneInfo:
        tz_name = settings.get("timezone") or "America/Chicago"
        try:
            return ZoneInfo(tz_name)
        except Exception:
            return _CST_TZ

    def _format_timezone_dt(dt: Optional[datetime], settings: dict) -> Tuple[Optional[str], Optional[str]]:
        if not dt:
            return None, None
        tz = _summer_timezone(settings)
        localized = dt.astimezone(tz)
        return localized.isoformat(timespec="seconds"), localized.strftime("%Y-%m-%d %I:%M %p %Z")

    def _format_cst(ts: Optional[str]) -> Optional[str]:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts)
            return dt.astimezone(_CST_TZ).strftime("%Y-%m-%d %I:%M %p %Z")
        except Exception:
            return ts

    def _next_summer_run(settings: dict, *, base_dt: Optional[datetime] = None) -> datetime:
        tz = _summer_timezone(settings)
        now = base_dt or datetime.now(tz)
        daily_time = settings.get("daily_time") or "08:00"
        hour, minute = map(int, daily_time.split(":"))
        today_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if now >= today_run:
            return today_run + datetime.timedelta(days=1) if hasattr(datetime, 'timedelta') else today_run
        return today_run

    def _build_change_indicator(changes):
        if not changes:
            return None
        return changes[0] if isinstance(changes, list) else changes

    settings = load_wlc_summer_settings()
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

    next_run_dt = None
    if settings.get("enabled"):
        try:
            next_run_dt = _next_summer_run(settings)
        except Exception:
            pass

    next_run_iso, next_run_display = _format_timezone_dt(next_run_dt, settings)
    last_poll_display = _format_cst(summary.get("ts")) if summary.get("ts") else None
    tz_name = settings.get("timezone") or _summer_timezone(settings).key

    return render_template(
        "wlc/wlc_summer_guest.html",
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


# ====================== WLC RF Analysis ======================

@wlc_bp.get("/tools/wlc-rf")
@require_login
@require_page_enabled("wlc_rf")
def wlc_rf():
    """WLC RF utilization analysis page."""
    return render_template("wlc/wlc_rf.html")


# ====================== WLC RF Troubleshoot ======================

@wlc_bp.get("/tools/wlc-rf-troubleshoot")
@require_login
def wlc_rf_troubleshoot():
    """WLC RF troubleshooting page for single WLC polling."""
    return render_template("wlc/wlc_rf_troubleshoot.html")


# ====================== WLC Clients Troubleshoot ======================

@wlc_bp.get("/tools/wlc-clients-troubleshoot")
@require_login
def wlc_clients_troubleshoot():
    """WLC clients troubleshooting page for multi-WLC polling."""
    return render_template("wlc/wlc_clients_troubleshoot.html")
