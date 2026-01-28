"""
Bulk SSH Blueprint Routes.

This module provides routes for bulk SSH operations including:
- Main bulk SSH terminal page
- Job execution and results
- Command templates management
- Scheduled jobs management
- API endpoints for status and export
"""

import csv
import json
import threading
import uuid
from datetime import datetime, timedelta
from io import StringIO
from typing import List

from flask import (
    Blueprint,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from src.core.security import require_login, require_page_enabled

# Create blueprint
bulk_ssh_bp = Blueprint(
    "bulk_ssh",
    __name__,
    template_folder="templates",
)

# CST timezone for scheduling
try:
    from zoneinfo import ZoneInfo
    _CST_TZ = ZoneInfo("America/Chicago")
except ImportError:
    import pytz
    _CST_TZ = pytz.timezone("America/Chicago")


# =================== Main Bulk SSH Page ======================
@bulk_ssh_bp.route("/tools/bulk-ssh")
@require_login
@require_page_enabled("bulk_ssh")
def bulk_ssh():
    """Bulk SSH terminal page."""
    return render_template("bulk_ssh/bulk_ssh.html")


@bulk_ssh_bp.route("/tools/bulk-ssh/execute", methods=["POST"])
@require_login
def bulk_ssh_execute():
    """Execute bulk SSH job in background thread."""
    from tools.bulk_ssh import BulkSSHJob
    from tools.db_jobs import log_audit

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
    devices: List[str] = []
    if device_list:
        lines = device_list.split("\n")
        for line in lines:
            device = line.strip()
            if device and device not in devices:
                devices.append(device)

    # Validate inputs
    if not devices:
        flash("Please enter at least one device.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh"))

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh"))

    if not command:
        flash("Command is required.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh"))

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


# =================== Results and Jobs ======================
@bulk_ssh_bp.route("/tools/bulk-ssh/results/<job_id>")
@require_login
def bulk_ssh_results(job_id: str):
    """Show results for a bulk SSH job."""
    from tools.db_jobs import load_bulk_ssh_job, load_bulk_ssh_results

    job = load_bulk_ssh_job(job_id)
    if not job:
        flash("Job not found.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh"))

    results = load_bulk_ssh_results(job_id)

    return render_template("bulk_ssh/bulk_ssh_results.html", job=job, results=results)


@bulk_ssh_bp.route("/tools/bulk-ssh/jobs")
@require_login
def bulk_ssh_jobs():
    """List all bulk SSH jobs."""
    from tools.db_jobs import list_bulk_ssh_jobs

    jobs = list_bulk_ssh_jobs(limit=100)
    return render_template("bulk_ssh/bulk_ssh_jobs.html", jobs=jobs)


# =================== API Endpoints ======================
@bulk_ssh_bp.route("/api/bulk-ssh/status/<job_id>")
@require_login
def bulk_ssh_status(job_id: str):
    """API endpoint to get job status (for live updates)."""
    from tools.db_jobs import load_bulk_ssh_job, load_bulk_ssh_results

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


@bulk_ssh_bp.route("/api/bulk-ssh/export/<job_id>")
@require_login
def bulk_ssh_export(job_id: str):
    """Export bulk SSH results to CSV."""
    from tools.db_jobs import load_bulk_ssh_job, load_bulk_ssh_results

    job = load_bulk_ssh_job(job_id)
    if not job:
        flash("Job not found.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh"))

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
@bulk_ssh_bp.route("/tools/bulk-ssh/templates")
@require_login
def bulk_ssh_templates():
    """Command templates management page."""
    from tools.db_jobs import list_bulk_ssh_templates

    templates = list_bulk_ssh_templates()
    return render_template("bulk_ssh/bulk_ssh_templates.html", templates=templates)


@bulk_ssh_bp.route("/tools/bulk-ssh/templates/create", methods=["POST"])
@require_login
def bulk_ssh_template_create():
    """Create a new template."""
    from tools.db_jobs import create_bulk_ssh_template
    from tools.template_engine import extract_variables

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    command = request.form.get("command", "").strip()
    category = request.form.get("category", "general")
    device_type = request.form.get("device_type", "cisco_ios")

    # Extract variables from command
    variables = ",".join(extract_variables(command))

    if not name or not command:
        flash("Template name and command are required.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh_templates"))

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

    return redirect(url_for("bulk_ssh.bulk_ssh_templates"))


@bulk_ssh_bp.route("/tools/bulk-ssh/templates/<int:template_id>/update", methods=["POST"])
@require_login
def bulk_ssh_template_update(template_id: int):
    """Update an existing template."""
    from tools.db_jobs import update_bulk_ssh_template
    from tools.template_engine import extract_variables

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    command = request.form.get("command", "").strip()
    category = request.form.get("category", "general")
    device_type = request.form.get("device_type", "cisco_ios")

    variables = ",".join(extract_variables(command))

    if not name or not command:
        flash("Template name and command are required.", "error")
        return redirect(url_for("bulk_ssh.bulk_ssh_templates"))

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

    return redirect(url_for("bulk_ssh.bulk_ssh_templates"))


@bulk_ssh_bp.route("/tools/bulk-ssh/templates/<int:template_id>/delete", methods=["POST"])
@require_login
def bulk_ssh_template_delete(template_id: int):
    """Delete a template."""
    from tools.db_jobs import load_bulk_ssh_template, delete_bulk_ssh_template

    template = load_bulk_ssh_template(template_id)
    if template:
        success = delete_bulk_ssh_template(template_id)
        if success:
            flash(f"Template '{template['name']}' deleted successfully.", "success")
        else:
            flash("Failed to delete template.", "error")
    else:
        flash("Template not found.", "error")

    return redirect(url_for("bulk_ssh.bulk_ssh_templates"))


@bulk_ssh_bp.route("/api/bulk-ssh/templates")
@require_login
def bulk_ssh_templates_api():
    """API endpoint to list all templates."""
    from tools.db_jobs import list_bulk_ssh_templates

    templates = list_bulk_ssh_templates()
    return jsonify(templates)


@bulk_ssh_bp.route("/api/bulk-ssh/templates/<int:template_id>")
@require_login
def bulk_ssh_template_api(template_id: int):
    """API endpoint to get template details."""
    from tools.db_jobs import load_bulk_ssh_template

    template = load_bulk_ssh_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    return jsonify(template)


@bulk_ssh_bp.route("/tools/bulk-ssh/templates/seed-defaults", methods=["POST"])
@require_login
def bulk_ssh_templates_seed():
    """Seed database with common templates."""
    from tools.db_jobs import create_bulk_ssh_template
    from tools.template_engine import get_common_templates

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
    return redirect(url_for("bulk_ssh.bulk_ssh_templates"))


# =================== Bulk SSH Schedules ======================
@bulk_ssh_bp.route("/tools/bulk-ssh/schedules")
@require_login
def bulk_ssh_schedules():
    """Scheduled jobs management page."""
    from tools.db_jobs import list_bulk_ssh_schedules, list_bulk_ssh_templates

    schedules = list_bulk_ssh_schedules()
    templates = list_bulk_ssh_templates()
    return render_template("bulk_ssh/bulk_ssh_schedules.html", schedules=schedules, templates=templates)


@bulk_ssh_bp.route("/tools/bulk-ssh/schedules/create", methods=["POST"])
@require_login
def bulk_ssh_schedule_create():
    """Create a new scheduled job."""
    from tools.db_jobs import create_bulk_ssh_schedule

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
    devices: List[str] = []
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
        return redirect(url_for("bulk_ssh.bulk_ssh_schedules"))

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

    return redirect(url_for("bulk_ssh.bulk_ssh_schedules"))


@bulk_ssh_bp.route("/tools/bulk-ssh/schedules/<int:schedule_id>/toggle", methods=["POST"])
@require_login
def bulk_ssh_schedule_toggle(schedule_id: int):
    """Enable or disable a schedule."""
    from tools.db_jobs import toggle_bulk_ssh_schedule

    enabled = request.form.get("enabled") == "true"
    success = toggle_bulk_ssh_schedule(schedule_id, enabled)

    if success:
        status = "enabled" if enabled else "disabled"
        flash(f"Schedule {status} successfully.", "success")
    else:
        flash("Failed to update schedule.", "error")

    return redirect(url_for("bulk_ssh.bulk_ssh_schedules"))


@bulk_ssh_bp.route("/tools/bulk-ssh/schedules/<int:schedule_id>/delete", methods=["POST"])
@require_login
def bulk_ssh_schedule_delete(schedule_id: int):
    """Delete a schedule."""
    from tools.db_jobs import load_bulk_ssh_schedule, delete_bulk_ssh_schedule

    schedule = load_bulk_ssh_schedule(schedule_id)
    if schedule:
        success = delete_bulk_ssh_schedule(schedule_id)
        if success:
            flash(f"Schedule '{schedule['name']}' deleted successfully.", "success")
        else:
            flash("Failed to delete schedule.", "error")
    else:
        flash("Schedule not found.", "error")

    return redirect(url_for("bulk_ssh.bulk_ssh_schedules"))
