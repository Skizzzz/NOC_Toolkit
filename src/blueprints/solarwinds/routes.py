"""
SolarWinds blueprint routes.

Provides routes for SolarWinds node inventory, hardware/software inventory
dashboard, and API endpoints for node search.
"""

import io
import re
import csv as csv_module
from datetime import datetime
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
)

from src.core.security import (
    require_login,
    require_superadmin,
    require_page_enabled,
)
from src.core.helpers import get_app_timezone_info

solarwinds_bp = Blueprint(
    "solarwinds",
    __name__,
    template_folder="templates",
    url_prefix="",
)


# ====================== Helper Functions ======================


def _get_solar_settings() -> dict:
    """Load SolarWinds settings from database."""
    from tools.db_jobs import load_solarwinds_settings
    return load_solarwinds_settings()


def _set_solar_settings(settings: dict) -> None:
    """Save SolarWinds settings to database."""
    from tools.db_jobs import save_solarwinds_settings
    save_solarwinds_settings(settings)


def _match_version_pattern(version: str, pattern: str) -> bool:
    """Match version string against pattern with wildcard (*) or regex support.

    Supports:
    - Plain text: exact substring match (case-insensitive)
    - Wildcards: * matches any characters (e.g., "15.*" matches "15.2.3", "15.10.1")
    - Regex: if pattern starts with "re:" it's treated as regex (e.g., "re:^15\\.([2-5])")
    """
    if not version:
        return False
    version_lower = version.lower()
    pattern_lower = pattern.lower()

    # Regex mode
    if pattern_lower.startswith("re:"):
        try:
            regex_pattern = pattern[3:]  # Keep original case for regex
            return bool(re.search(regex_pattern, version, re.IGNORECASE))
        except re.error:
            return False

    # Wildcard mode (convert * to regex .*)
    if "*" in pattern:
        # Escape special regex chars except *, then convert * to .*
        escaped = re.escape(pattern_lower).replace(r"\*", ".*")
        try:
            return bool(re.match(f"^{escaped}$", version_lower))
        except re.error:
            return False

    # Plain substring match
    return pattern_lower in version_lower


def _apply_inventory_filters(nodes: list, request_args) -> list:
    """Apply filter parameters to nodes list."""
    vendor_filter = request_args.getlist("vendor")
    model_filter = request_args.getlist("model")
    version_filter = request_args.getlist("version")
    search_filter = request_args.get("search", "").strip().lower()
    hw_version_filter = request_args.get("hw_version", "").strip().lower()
    version_search = request_args.get("version_search", "").strip()

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
    if version_search:
        filtered = [n for n in filtered if _match_version_pattern(n.get("version") or "", version_search)]
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

    return filtered


# ====================== SolarWinds Nodes ======================


@solarwinds_bp.get("/tools/solarwinds/nodes")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_nodes():
    """SolarWinds nodes listing page."""
    from tools.db_jobs import fetch_solarwinds_nodes

    settings = _get_solar_settings()
    nodes = fetch_solarwinds_nodes()
    return render_template("solarwinds/solarwinds_nodes.html", settings=settings, nodes=nodes)


# ====================== SolarWinds Inventory ======================


@solarwinds_bp.get("/tools/solarwinds/inventory")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_inventory():
    """SolarWinds Hardware/Software Inventory Dashboard for CVE assessment."""
    from tools.db_jobs import fetch_solarwinds_nodes

    nodes = fetch_solarwinds_nodes()
    settings = _get_solar_settings()

    # Get filters from query params
    vendor_filter = request.args.getlist("vendor")
    model_filter = request.args.getlist("model")
    version_filter = request.args.getlist("version")
    search_filter = request.args.get("search", "").strip().lower()
    hw_version_filter = request.args.get("hw_version", "").strip().lower()
    version_search = request.args.get("version_search", "").strip()

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
    filtered = _apply_inventory_filters(nodes, request.args)

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

    # Build vendor -> model -> version hierarchy for filtered results
    hierarchy = {}
    for n in filtered:
        vendor = n.get("vendor") or "Unknown"
        model = n.get("model") or "Unknown"
        version = n.get("version") or "Unknown"
        if vendor not in hierarchy:
            hierarchy[vendor] = {"count": 0, "models": {}}
        hierarchy[vendor]["count"] += 1
        if model not in hierarchy[vendor]["models"]:
            hierarchy[vendor]["models"][model] = {"count": 0, "versions": {}}
        hierarchy[vendor]["models"][model]["count"] += 1
        if version not in hierarchy[vendor]["models"][model]["versions"]:
            hierarchy[vendor]["models"][model]["versions"][version] = 0
        hierarchy[vendor]["models"][model]["versions"][version] += 1

    # Sort hierarchy for display
    sorted_hierarchy = []
    for vendor in sorted(hierarchy.keys(), key=lambda v: hierarchy[v]["count"], reverse=True):
        vendor_data = hierarchy[vendor]
        models_list = []
        for model in sorted(vendor_data["models"].keys(), key=lambda m: vendor_data["models"][m]["count"], reverse=True):
            model_data = vendor_data["models"][model]
            versions_list = sorted(model_data["versions"].items(), key=lambda x: x[1], reverse=True)
            models_list.append({
                "name": model,
                "count": model_data["count"],
                "versions": versions_list
            })
        sorted_hierarchy.append({
            "name": vendor,
            "count": vendor_data["count"],
            "models": models_list
        })

    # Sort counts by value descending for display
    top_vendors = sorted(filtered_vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_versions = sorted(filtered_version_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    top_models = sorted(filtered_model_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return render_template(
        "solarwinds/solarwinds_inventory.html",
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
        hierarchy=sorted_hierarchy,
        filters={
            "vendor": vendor_filter,
            "model": model_filter,
            "version": version_filter,
            "search": search_filter,
            "hw_version": hw_version_filter,
            "version_search": version_search,
        },
    )


@solarwinds_bp.get("/tools/solarwinds/inventory/export")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_inventory_export():
    """Export SolarWinds inventory as CSV with filters applied."""
    from tools.db_jobs import fetch_solarwinds_nodes

    nodes = fetch_solarwinds_nodes()

    # Apply filters
    filtered = _apply_inventory_filters(nodes, request.args)

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


@solarwinds_bp.get("/tools/solarwinds/inventory/export-summary")
@require_login
@require_page_enabled("solarwinds_nodes")
def solarwinds_inventory_export_summary():
    """Export SolarWinds inventory aggregation summary as CSV (counts per version)."""
    from tools.db_jobs import fetch_solarwinds_nodes

    nodes = fetch_solarwinds_nodes()

    # Apply filters
    filtered = _apply_inventory_filters(nodes, request.args)

    # Build vendor -> model -> version hierarchy for aggregation
    hierarchy = {}
    for n in filtered:
        vendor = n.get("vendor") or "Unknown"
        model = n.get("model") or "Unknown"
        version = n.get("version") or "Unknown"
        if vendor not in hierarchy:
            hierarchy[vendor] = {"count": 0, "models": {}}
        hierarchy[vendor]["count"] += 1
        if model not in hierarchy[vendor]["models"]:
            hierarchy[vendor]["models"][model] = {"count": 0, "versions": {}}
        hierarchy[vendor]["models"][model]["count"] += 1
        if version not in hierarchy[vendor]["models"][model]["versions"]:
            hierarchy[vendor]["models"][model]["versions"][version] = 0
        hierarchy[vendor]["models"][model]["versions"][version] += 1

    # Generate CSV with hierarchical aggregation
    buf = io.StringIO()
    fields = ["Vendor", "Vendor_Count", "Model", "Model_Count", "Software_Version", "Version_Count"]
    writer = csv_module.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    writer.writeheader()

    # Sort and write rows
    for vendor in sorted(hierarchy.keys(), key=lambda v: hierarchy[v]["count"], reverse=True):
        vendor_data = hierarchy[vendor]
        for model in sorted(vendor_data["models"].keys(), key=lambda m: vendor_data["models"][m]["count"], reverse=True):
            model_data = vendor_data["models"][model]
            for version, count in sorted(model_data["versions"].items(), key=lambda x: x[1], reverse=True):
                writer.writerow({
                    "Vendor": vendor,
                    "Vendor_Count": vendor_data["count"],
                    "Model": model,
                    "Model_Count": model_data["count"],
                    "Software_Version": version,
                    "Version_Count": count,
                })

    timestamp = datetime.now(get_app_timezone_info()).strftime("%Y-%m-%d")

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=solarwinds_inventory_summary_{timestamp}.csv"},
    )


# ====================== SolarWinds API ======================


@solarwinds_bp.get("/api/solarwinds/nodes")
@require_login
def api_solarwinds_nodes():
    """API endpoint for searching SolarWinds nodes (for bulk SSH inventory search)."""
    from tools.db_jobs import fetch_solarwinds_nodes

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


# ====================== SolarWinds Settings ======================


@solarwinds_bp.route("/tools/solarwinds/nodes/settings", methods=["GET", "POST"])
@require_superadmin
def solarwinds_nodes_settings():
    """SolarWinds configuration settings page."""
    from tools.db_jobs import fetch_solarwinds_nodes
    from tools.solarwinds import fetch_nodes as fetch_solarwinds_nodes_api, SolarWindsError

    settings = _get_solar_settings()

    if request.method == "POST":
        action = request.form.get("action") or "save"
        base_url = (request.form.get("base_url") or "").strip()
        username = (request.form.get("username") or "").strip()
        password_input = request.form.get("password") or ""
        verify_ssl = request.form.get("verify_ssl") == "1"

        new_settings = dict(settings)
        new_settings.update({
            "base_url": base_url,
            "username": username,
            "verify_ssl": verify_ssl,
        })
        if password_input:
            new_settings["password"] = password_input

        _set_solar_settings(new_settings)

        if action == "poll":
            success, message = _run_solarwinds_poll(manual=True)
            flash(("Poll complete." if success else "Poll failed.") + (f" {message}" if message else ""))
            return redirect(url_for("solarwinds.solarwinds_nodes_settings"))

        flash("SolarWinds settings saved.")
        return redirect(url_for("solarwinds.solarwinds_nodes_settings"))

    nodes_count = len(fetch_solarwinds_nodes())
    template_settings = dict(settings)
    template_settings["password"] = ""
    template_settings["verify_ssl"] = bool(template_settings.get("verify_ssl", True))
    return render_template(
        "solarwinds/solarwinds_nodes_settings.html",
        settings=template_settings,
        nodes_count=nodes_count,
    )


def _run_solarwinds_poll(manual: bool = False) -> tuple:
    """Run a SolarWinds poll and update the database."""
    from tools.db_jobs import (
        replace_solarwinds_nodes,
        update_solarwinds_poll_status,
    )
    from tools.solarwinds import fetch_nodes as fetch_solarwinds_nodes_api, SolarWindsError
    from src.core.helpers import now_iso

    settings = _get_solar_settings()

    try:
        base_url = settings.get("base_url", "").strip()
        username = settings.get("username", "").strip()
        password = settings.get("password", "")

        if not base_url or not username:
            raise SolarWindsError("SolarWinds base URL and credentials are required")

        nodes = fetch_solarwinds_nodes_api(
            base_url=base_url,
            username=username,
            password=password,
            verify_ssl=settings.get("verify_ssl", True),
        )

        errors = []
        replace_solarwinds_nodes(nodes)

        ts_iso = now_iso()
        if errors:
            status = "partial"
            message = f"Synced {len(nodes)} nodes with {len(errors)} errors"
        else:
            status = "success"
            message = f"Synced {len(nodes)} nodes"

        update_solarwinds_poll_status(ts=ts_iso, status=status, message=message)

        return True, message

    except SolarWindsError as exc:
        message = str(exc)
        ts_iso = now_iso() if manual else None
        update_solarwinds_poll_status(ts=ts_iso if manual else None, status="error", message=message)
        return False, message
    except Exception as exc:
        message = str(exc)
        ts_iso = now_iso() if manual else None
        update_solarwinds_poll_status(ts=ts_iso if manual else None, status="error", message=message)
        return False, message
