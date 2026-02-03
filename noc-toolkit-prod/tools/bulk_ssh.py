"""Bulk SSH execution engine for running commands on multiple devices in parallel."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional, Callable

from netmiko import ConnectHandler

from tools.db_jobs import (
    insert_bulk_ssh_job,
    insert_bulk_ssh_result,
    update_bulk_ssh_job_progress,
    mark_bulk_ssh_job_done,
)


class BulkSSHJob:
    """Execute SSH commands on multiple devices in parallel."""

    def __init__(
        self,
        devices: List[str],
        command: str,
        username: str,
        password: str,
        secret: Optional[str] = None,
        device_type: str = "cisco_ios",
        max_workers: int = 10,
        timeout: int = 60,
        job_id: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        config_mode: bool = False,
    ):
        """
        Initialize a bulk SSH job.

        Args:
            devices: List of device hostnames/IPs
            command: Command to execute on each device
            username: SSH username
            password: SSH password
            secret: Enable secret (optional)
            device_type: Netmiko device type (default: cisco_ios)
            max_workers: Maximum parallel connections (default: 10)
            timeout: SSH connection timeout in seconds (default: 60)
            job_id: Unique job ID (auto-generated if not provided)
            progress_callback: Optional callback function(completed, success, failed)
            config_mode: If True, run commands in config mode (config t). Default False.
        """
        self.devices = devices
        self.command = command
        self.username = username
        self.password = password
        self.secret = secret
        self.device_type = device_type
        self.max_workers = max_workers
        self.timeout = timeout
        self.job_id = job_id or str(uuid.uuid4())
        self.progress_callback = progress_callback
        self.config_mode = config_mode

        self.results: Dict[str, dict] = {}
        self.completed = 0
        self.success = 0
        self.failed = 0

    def _execute_on_device(self, device: str) -> dict:
        """
        Execute command on a single device.

        Returns:
            dict with keys: device, status, output, error, duration_ms
        """
        start_time = time.time()
        result = {
            "device": device,
            "status": "failed",
            "output": "",
            "error": "",
            "duration_ms": 0,
        }

        try:
            # Build device connection parameters
            device_params = {
                "device_type": self.device_type,
                "host": device,
                "username": self.username,
                "password": self.password,
                "timeout": self.timeout,
                "fast_cli": True,
                "global_delay_factor": 1,
            }
            if self.secret:
                device_params["secret"] = self.secret

            # Connect and execute
            conn = ConnectHandler(**device_params)
            try:
                # Auto-enable if secret provided
                if self.secret:
                    try:
                        conn.enable()
                    except Exception:
                        pass

                # Execute based on config_mode setting
                if self.config_mode:
                    # Config mode: enter config t, run commands, exit
                    commands = [line.strip() for line in self.command.split('\n') if line.strip()]
                    output = conn.send_config_set(commands, read_timeout=self.timeout)
                    result["output"] = output
                    result["status"] = "success"
                else:
                    # Show command mode: run as-is (supports multi-line show commands too)
                    if '\n' in self.command:
                        # Multiple show commands - run each one
                        outputs = []
                        for cmd in self.command.split('\n'):
                            cmd = cmd.strip()
                            if cmd:
                                outputs.append(f">>> {cmd}")
                                outputs.append(conn.send_command(cmd, read_timeout=self.timeout))
                        output = '\n'.join(outputs)
                    else:
                        output = conn.send_command(self.command, read_timeout=self.timeout)
                    result["output"] = output
                    result["status"] = "success"

            finally:
                conn.disconnect()

        except Exception as e:
            result["error"] = str(e)
            result["status"] = "failed"

        finally:
            result["duration_ms"] = int((time.time() - start_time) * 1000)

        return result

    def execute(self) -> Dict[str, dict]:
        """
        Execute the bulk SSH job across all devices in parallel.

        Returns:
            Dict mapping device hostname to result dict
        """
        created = datetime.now().isoformat(timespec="seconds")

        # Insert job record
        insert_bulk_ssh_job(
            job_id=self.job_id,
            created=created,
            username=self.username,
            command=self.command,
            device_count=len(self.devices),
        )

        # Execute in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_device = {executor.submit(self._execute_on_device, device): device for device in self.devices}

            # Collect results as they complete
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    result = future.result()
                except Exception as e:
                    # Shouldn't happen since _execute_on_device catches all exceptions
                    result = {
                        "device": device,
                        "status": "failed",
                        "output": "",
                        "error": f"Unexpected error: {str(e)}",
                        "duration_ms": 0,
                    }

                # Store result
                self.results[device] = result
                self.completed += 1

                if result["status"] == "success":
                    self.success += 1
                else:
                    self.failed += 1

                # Save result to database
                completed_at = datetime.now().isoformat(timespec="seconds")
                insert_bulk_ssh_result(
                    job_id=self.job_id,
                    device=device,
                    status=result["status"],
                    output=result["output"],
                    error=result["error"],
                    duration_ms=result["duration_ms"],
                    completed_at=completed_at,
                )

                # Update job progress
                update_bulk_ssh_job_progress(
                    job_id=self.job_id, completed=self.completed, success=self.success, failed=self.failed
                )

                # Call progress callback if provided
                if self.progress_callback:
                    try:
                        self.progress_callback(self.completed, self.success, self.failed)
                    except Exception:
                        pass

        # Mark job as done
        final_status = "completed" if self.failed == 0 else "completed_with_errors"
        mark_bulk_ssh_job_done(job_id=self.job_id, status=final_status)

        return self.results


def run_bulk_ssh(
    devices: List[str],
    command: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
    device_type: str = "cisco_ios",
    max_workers: int = 10,
    timeout: int = 60,
    config_mode: bool = False,
) -> tuple[str, Dict[str, dict]]:
    """
    Convenience function to run a bulk SSH job.

    Returns:
        Tuple of (job_id, results_dict)
    """
    job = BulkSSHJob(
        devices=devices,
        command=command,
        username=username,
        password=password,
        secret=secret,
        device_type=device_type,
        max_workers=max_workers,
        timeout=timeout,
        config_mode=config_mode,
    )
    results = job.execute()
    return job.job_id, results
