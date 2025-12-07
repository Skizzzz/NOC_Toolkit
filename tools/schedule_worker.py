"""Background worker for executing scheduled bulk SSH jobs and ISE cert syncs."""
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from tools.bulk_ssh import BulkSSHJob
from tools.db_jobs import (
    fetch_due_bulk_ssh_schedules,
    update_bulk_ssh_schedule_run,
    load_bulk_ssh_template,
    load_cert_sync_settings,
    update_cert_sync_status,
    get_enabled_ise_nodes,
    insert_certificate,
    certificate_exists,
)
from tools.template_engine import substitute_variables
from tools.cert_tracker import pull_ise_certs

logger = logging.getLogger(__name__)


class ScheduleWorker:
    """Background worker that checks for and executes scheduled bulk SSH jobs."""

    def __init__(self, check_interval: int = 60):
        """
        Initialize the schedule worker.

        Args:
            check_interval: How often to check for due schedules (in seconds)
        """
        self.check_interval = check_interval
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start the background worker thread."""
        if self.running:
            logger.warning("Schedule worker is already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("Schedule worker started")

    def stop(self):
        """Stop the background worker thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Schedule worker stopped")

    def _run(self):
        """Main worker loop that checks for due schedules."""
        while self.running:
            try:
                self._check_and_execute_schedules()
            except Exception as e:
                logger.error(f"Error in schedule worker: {e}")

            try:
                self._check_ise_cert_sync()
            except Exception as e:
                logger.error(f"Error in ISE cert sync: {e}")

            # Sleep for check_interval seconds
            time.sleep(self.check_interval)

    def _check_ise_cert_sync(self):
        """Check if ISE cert sync is due and execute if needed."""
        settings = load_cert_sync_settings()

        if not settings.get("enabled"):
            return

        interval_hours = settings.get("interval_hours", 24)
        last_sync_ts = settings.get("last_sync_ts")

        # Check if sync is due
        if last_sync_ts:
            try:
                last_sync = datetime.fromisoformat(last_sync_ts)
                next_sync = last_sync + timedelta(hours=interval_hours)
                if datetime.now() < next_sync:
                    return  # Not due yet
            except (ValueError, TypeError):
                pass  # Invalid timestamp, run sync

        # Execute sync
        self._execute_ise_cert_sync()

    def _execute_ise_cert_sync(self):
        """Execute ISE certificate sync."""
        logger.info("Starting scheduled ISE certificate sync")

        try:
            nodes = get_enabled_ise_nodes()
            if not nodes:
                update_cert_sync_status(status="warning", message="No enabled ISE nodes configured")
                return

            certs, sync_errors = pull_ise_certs(nodes)
            added = 0
            skipped = 0

            for cert in certs:
                serial = cert.get("serial", "")
                if serial and certificate_exists(serial):
                    skipped += 1
                    continue

                insert_certificate(
                    cn=cert.get("cn", "Unknown"),
                    expires=cert.get("expires", "Unknown"),
                    issued_to=cert.get("issued_to", ""),
                    issued_by=cert.get("issued_by", ""),
                    used_by=cert.get("used_by", ""),
                    notes="",
                    devices="",
                    source_type="ise",
                    source_ip=cert.get("source_ip", ""),
                    source_hostname=cert.get("source_hostname", ""),
                    serial=serial,
                )
                added += 1

            if sync_errors:
                error_count = len(sync_errors)
                message = f"Synced {len(nodes)} node(s): {added} added, {skipped} existing, {error_count} error(s)"
                update_cert_sync_status(status="warning", message=message)
                logger.warning(f"ISE cert sync with errors: {message}")
                for err in sync_errors:
                    logger.warning(f"  - {err}")
            else:
                message = f"Synced {len(nodes)} node(s): {added} added, {skipped} existing"
                update_cert_sync_status(status="success", message=message)
                logger.info(f"ISE cert sync complete: {message}")

        except Exception as e:
            error_msg = f"Sync failed: {str(e)}"
            update_cert_sync_status(status="error", message=error_msg)
            logger.error(f"ISE cert sync failed: {e}")

    def _check_and_execute_schedules(self):
        """Check for due schedules and execute them."""
        schedules = fetch_due_bulk_ssh_schedules()

        for schedule in schedules:
            try:
                self._execute_schedule(schedule)
            except Exception as e:
                logger.error(f"Error executing schedule {schedule['id']}: {e}")

    def _execute_schedule(self, schedule: dict):
        """Execute a single scheduled job."""
        schedule_id = schedule["id"]
        name = schedule["name"]

        logger.info(f"Executing scheduled job: {name} (ID: {schedule_id})")

        # Parse devices
        devices = json.loads(schedule.get("devices_json", "[]"))
        if not devices:
            logger.warning(f"Schedule {name} has no devices")
            return

        # Get command (from template or direct)
        command = schedule.get("command", "")
        template_id = schedule.get("template_id")

        if template_id:
            # Load template
            template = load_bulk_ssh_template(template_id)
            if template:
                command = template.get("command", "")
            else:
                logger.warning(f"Template {template_id} not found for schedule {name}")

        if not command:
            logger.warning(f"Schedule {name} has no command")
            return

        # Create and execute job
        job = BulkSSHJob(
            devices=devices,
            command=command,
            username=schedule.get("username", ""),
            password=schedule.get("password", ""),
            secret=schedule.get("secret"),
            device_type=schedule.get("device_type", "cisco_ios"),
            max_workers=10,
            timeout=60,
        )

        results = job.execute()

        # Calculate next run time
        next_run = self._calculate_next_run(schedule)

        # Update schedule
        last_run = datetime.now().isoformat(timespec="seconds")
        update_bulk_ssh_schedule_run(
            schedule_id=schedule_id,
            last_run=last_run,
            last_job_id=job.job_id,
            next_run=next_run,
        )

        # Check for failures and send alerts if configured
        if schedule.get("alert_on_failure") and job.failed > 0:
            self._send_failure_alert(schedule, job, results)

        logger.info(f"Completed scheduled job: {name} (Job ID: {job.job_id})")

    def _calculate_next_run(self, schedule: dict) -> str:
        """Calculate the next run time for a schedule."""
        schedule_type = schedule.get("schedule_type", "once")
        schedule_config = json.loads(schedule.get("schedule_config", "{}"))

        if schedule_type == "once":
            # One-time schedules don't repeat
            return ""

        now = datetime.now()

        if schedule_type == "daily":
            # Run daily at specified time
            run_time = schedule_config.get("time", "00:00")
            hour, minute = run_time.split(":")
            next_run_dt = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)

            # If we've already passed today's time, schedule for tomorrow
            if next_run_dt <= now:
                next_run_dt += timedelta(days=1)

            return next_run_dt.isoformat(timespec="seconds")

        elif schedule_type == "weekly":
            # Run weekly on specified day and time
            run_time = schedule_config.get("time", "00:00")
            day_of_week = schedule_config.get("day", 0)  # 0 = Monday

            hour, minute = run_time.split(":")

            # Calculate days until next occurrence
            days_ahead = day_of_week - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7

            next_run_dt = now + timedelta(days=days_ahead)
            next_run_dt = next_run_dt.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)

            return next_run_dt.isoformat(timespec="seconds")

        return ""

    def _send_failure_alert(self, schedule: dict, job: BulkSSHJob, results: dict):
        """Send email alert for failed devices (placeholder implementation)."""
        alert_email = schedule.get("alert_email", "")
        if not alert_email:
            return

        # TODO: Implement email sending
        # For now, just log the alert
        failed_devices = [device for device, result in results.items() if result["status"] == "failed"]

        logger.warning(
            f"ALERT: Schedule '{schedule['name']}' had {len(failed_devices)} failures. "
            f"Would send email to: {alert_email}. Failed devices: {', '.join(failed_devices)}"
        )


# Global schedule worker instance
_schedule_worker: Optional[ScheduleWorker] = None


def start_schedule_worker(check_interval: int = 60):
    """Start the global schedule worker."""
    global _schedule_worker
    if _schedule_worker is None:
        _schedule_worker = ScheduleWorker(check_interval=check_interval)
        _schedule_worker.start()


def stop_schedule_worker():
    """Stop the global schedule worker."""
    global _schedule_worker
    if _schedule_worker:
        _schedule_worker.stop()
        _schedule_worker = None
