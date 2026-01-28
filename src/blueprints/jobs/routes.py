"""
Jobs Blueprint Routes.

Provides routes for the unified jobs center - monitoring and managing
all background jobs across tools including config changes, WLC polls,
bulk SSH, and more.
"""

from datetime import datetime
from typing import Optional

from flask import Blueprint, render_template, redirect, url_for, flash, jsonify

from src.core.security import require_login, require_page_enabled
from src.core.helpers import get_app_timezone_info


# Create blueprint
jobs_bp = Blueprint(
    "jobs",
    __name__,
    template_folder="templates",
)


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


# ====================== JOBS CENTER ======================
@jobs_bp.get("/jobs")
@require_login
@require_page_enabled("jobs_center")
def jobs_center():
    """Unified jobs center - all background jobs across all tools"""
    from tools.db_jobs import list_jobs as db_list_jobs, load_job as db_load_job
    from tools.db_jobs import list_bulk_ssh_jobs

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
    bulk_ssh_jobs_list = list_bulk_ssh_jobs(limit=200)
    for row in bulk_ssh_jobs_list:
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

    return render_template("jobs/jobs_center.html", jobs=jobs)


@jobs_bp.get("/api/jobs")
@require_login
def api_jobs():
    """API endpoint for jobs list (for refresh)"""
    from tools.db_jobs import list_jobs as db_list_jobs, load_job as db_load_job
    from tools.db_jobs import list_bulk_ssh_jobs

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
    bulk_ssh_jobs_list = list_bulk_ssh_jobs(limit=200)
    for row in bulk_ssh_jobs_list:
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


@jobs_bp.get("/jobs/<job_id>")
@require_login
def job_detail(job_id: str):
    """View details of a specific job"""
    from tools.db_jobs import load_job as db_load_job

    meta, events = db_load_job(job_id)
    if not meta:
        flash("Job not found")
        return redirect(url_for('jobs.jobs_center'))

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

    return render_template("jobs/job_detail.html", job=meta, events=formatted_events)


@jobs_bp.post("/api/jobs/<job_id>/cancel")
@require_login
def cancel_job(job_id: str):
    """Cancel a running job"""
    from tools.db_jobs import append_event, mark_done

    try:
        # Mark job as cancelled by appending a cancel event
        append_event(job_id, "cancelled", {"message": "Cancelled by user"})
        mark_done(job_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@jobs_bp.get("/jobs/<job_id>/progress")
@require_login
def job_progress_page(job_id: str):
    """Live job progress page with real-time updates - supports both generic jobs and bulk SSH jobs"""
    from tools.db_jobs import load_job as db_load_job
    from tools.db_jobs import load_bulk_ssh_job, load_bulk_ssh_results

    # First try generic jobs table
    meta, events = db_load_job(job_id)
    if meta:
        params = meta.get("params", {})
        hosts = params.get("hosts", [])
        return render_template(
            "jobs/job_progress.html",
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
            "jobs/job_progress.html",
            job_id=job_id,
            device_count=device_count,
            hosts=completed_devices,  # Will be populated dynamically via API
            tool="bulk-ssh",
            job_type="bulk_ssh",
            command=bulk_job.get("command", "")
        )

    flash("Job not found")
    return redirect(url_for('jobs.jobs_center'))


@jobs_bp.get("/api/jobs/<job_id>/progress")
@require_login
def api_job_progress(job_id: str):
    """API endpoint for live job progress data - supports both generic jobs and bulk SSH jobs"""
    from tools.db_jobs import load_job as db_load_job
    from tools.db_jobs import load_bulk_ssh_job, load_bulk_ssh_results

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
