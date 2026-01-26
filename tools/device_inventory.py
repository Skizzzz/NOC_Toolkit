# tools/device_inventory.py
"""Device inventory collection module for gathering hardware/firmware info from network devices."""

from __future__ import annotations

import io
import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from tools.netmiko_helpers import ios_connection, ios_xe_connection, aruba_aos_connection


def parse_cisco_ios_version(output: str) -> Dict:
    """Parse 'show version' output from Cisco IOS devices."""
    result = {
        "vendor": "Cisco",
        "model": "",
        "serial_number": "",
        "firmware_version": "",
        "hostname": "",
        "uptime": "",
    }

    # Hostname - first line usually contains it
    hostname_match = re.search(r"^(\S+)\s+uptime is", output, re.MULTILINE)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)

    # IOS Version - various formats
    # "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10"
    # "Cisco IOS Software [Gibraltar], Version 16.12.5"
    version_match = re.search(r"Version\s+([\d.()A-Za-z]+)", output)
    if version_match:
        result["firmware_version"] = version_match.group(1)

    # Model number
    model_match = re.search(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)", output)
    if model_match:
        result["model"] = model_match.group(1)
    else:
        # Try alternative: "cisco WS-C3750X-48PF-S"
        model_match2 = re.search(r"cisco\s+([\w-]+)\s+\(", output, re.IGNORECASE)
        if model_match2:
            result["model"] = model_match2.group(1)

    # Serial number
    serial_match = re.search(r"[Ss]ystem\s+[Ss]erial\s+[Nn]umber\s*:\s*(\S+)", output)
    if serial_match:
        result["serial_number"] = serial_match.group(1)
    else:
        # Try: "Processor board ID FOC12345678"
        serial_match2 = re.search(r"Processor board ID\s+(\S+)", output)
        if serial_match2:
            result["serial_number"] = serial_match2.group(1)

    # Uptime
    uptime_match = re.search(r"uptime is\s+(.+?)$", output, re.MULTILINE)
    if uptime_match:
        result["uptime"] = uptime_match.group(1).strip()

    return result


def parse_cisco_xe_version(output: str) -> Dict:
    """Parse 'show version' output from Cisco IOS-XE devices (9800 WLC, Cat 9K, etc.)."""
    result = {
        "vendor": "Cisco",
        "model": "",
        "serial_number": "",
        "firmware_version": "",
        "hostname": "",
        "uptime": "",
    }

    # Hostname
    hostname_match = re.search(r"^(\S+)\s+uptime is", output, re.MULTILINE)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)

    # IOS-XE Version: "Cisco IOS XE Software, Version 17.09.04a"
    version_match = re.search(r"IOS XE Software,?\s*Version\s+([\d.A-Za-z]+)", output)
    if version_match:
        result["firmware_version"] = version_match.group(1)
    else:
        # Fallback to generic Version line
        version_match2 = re.search(r"Version\s+([\d.()A-Za-z]+)", output)
        if version_match2:
            result["firmware_version"] = version_match2.group(1)

    # Model Number: "Model Number                       : C9800-L-F-K9"
    model_match = re.search(r"Model Number\s*:\s*(\S+)", output)
    if model_match:
        result["model"] = model_match.group(1)
    else:
        # Fallback: "cisco C9300-48P"
        model_match2 = re.search(r"cisco\s+(C\d+[\w-]+)", output, re.IGNORECASE)
        if model_match2:
            result["model"] = model_match2.group(1)

    # System Serial Number
    serial_match = re.search(r"System Serial Number\s*:\s*(\S+)", output)
    if serial_match:
        result["serial_number"] = serial_match.group(1)
    else:
        serial_match2 = re.search(r"Processor board ID\s+(\S+)", output)
        if serial_match2:
            result["serial_number"] = serial_match2.group(1)

    # Uptime
    uptime_match = re.search(r"uptime is\s+(.+?)$", output, re.MULTILINE)
    if uptime_match:
        result["uptime"] = uptime_match.group(1).strip()

    return result


def parse_cisco_nxos_version(output: str) -> Dict:
    """Parse 'show version' output from Cisco NX-OS devices (Nexus)."""
    result = {
        "vendor": "Cisco",
        "model": "",
        "serial_number": "",
        "firmware_version": "",
        "hostname": "",
        "uptime": "",
    }

    # Hostname
    hostname_match = re.search(r"Device name:\s*(\S+)", output)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)

    # NX-OS Version: "NXOS: version 9.3(8)"
    version_match = re.search(r"NXOS:\s*version\s+([\d.()A-Za-z]+)", output, re.IGNORECASE)
    if version_match:
        result["firmware_version"] = version_match.group(1)
    else:
        # Fallback: "system:    version 9.3(8)"
        version_match2 = re.search(r"system:\s*version\s+([\d.()A-Za-z]+)", output)
        if version_match2:
            result["firmware_version"] = version_match2.group(1)

    # Hardware model: "cisco Nexus9000 C93180YC-FX Chassis"
    model_match = re.search(r"cisco\s+Nexus\d+\s+(\S+)", output, re.IGNORECASE)
    if model_match:
        result["model"] = model_match.group(1)
    else:
        # Try: "Hardware" section
        model_match2 = re.search(r"Hardware\s+cisco\s+(\S+)", output, re.IGNORECASE)
        if model_match2:
            result["model"] = model_match2.group(1)

    # Serial number: "Processor Board ID SAL12345678"
    serial_match = re.search(r"Processor Board ID\s+(\S+)", output)
    if serial_match:
        result["serial_number"] = serial_match.group(1)

    # Uptime
    uptime_match = re.search(r"Kernel uptime is\s+(.+?)$", output, re.MULTILINE)
    if uptime_match:
        result["uptime"] = uptime_match.group(1).strip()

    return result


def parse_aruba_version(output: str) -> Dict:
    """Parse 'show version' output from Aruba AOS devices (7xxx controllers)."""
    result = {
        "vendor": "Aruba",
        "model": "",
        "serial_number": "",
        "firmware_version": "",
        "hostname": "",
        "uptime": "",
    }

    # ArubaOS Version: "ArubaOS (MODEL: 7205), Version 8.10.0.0"
    version_match = re.search(r"Version\s+([\d.]+)", output)
    if version_match:
        result["firmware_version"] = version_match.group(1)

    # Model: "ArubaOS (MODEL: 7205)"
    model_match = re.search(r"MODEL:\s*(\S+)\)", output)
    if model_match:
        result["model"] = model_match.group(1)

    # Serial Number
    serial_match = re.search(r"Serial Number:\s*(\S+)", output)
    if serial_match:
        result["serial_number"] = serial_match.group(1)

    # Hostname - from prompt or system info
    hostname_match = re.search(r"^\(([^)]+)\)", output, re.MULTILINE)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)

    # Uptime: "Uptime: 45 days 12 hours 30 minutes"
    uptime_match = re.search(r"Uptime:\s*(.+?)$", output, re.MULTILINE)
    if uptime_match:
        result["uptime"] = uptime_match.group(1).strip()

    return result


def parse_dell_version(output: str) -> Dict:
    """Parse 'show version' output from Dell OS10 devices."""
    result = {
        "vendor": "Dell",
        "model": "",
        "serial_number": "",
        "firmware_version": "",
        "hostname": "",
        "uptime": "",
    }

    # OS10 Version
    version_match = re.search(r"OS Version:\s*([\d.]+)", output, re.IGNORECASE)
    if version_match:
        result["firmware_version"] = version_match.group(1)
    else:
        version_match2 = re.search(r"Software Version:\s*([\d.]+)", output)
        if version_match2:
            result["firmware_version"] = version_match2.group(1)

    # Model
    model_match = re.search(r"System Type:\s*(\S+)", output)
    if model_match:
        result["model"] = model_match.group(1)

    # Serial
    serial_match = re.search(r"Service Tag:\s*(\S+)", output)
    if serial_match:
        result["serial_number"] = serial_match.group(1)

    # Hostname
    hostname_match = re.search(r"Node Name:\s*(\S+)", output)
    if hostname_match:
        result["hostname"] = hostname_match.group(1)

    # Uptime
    uptime_match = re.search(r"Up Time:\s*(.+?)$", output, re.MULTILINE)
    if uptime_match:
        result["uptime"] = uptime_match.group(1).strip()

    return result


def collect_device_inventory(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
    device_type: str = "cisco_ios",
) -> Dict:
    """
    Collect hardware and firmware information from a single device.

    Args:
        host: Device hostname or IP
        username: SSH username
        password: SSH password
        secret: Enable secret (optional)
        device_type: Netmiko device type (cisco_ios, cisco_xe, cisco_nxos, aruba_os, dell_os10)

    Returns:
        Dict with device info including: device, device_type, vendor, model,
        serial_number, firmware_version, hostname, uptime, error
    """
    result = {
        "device": host,
        "device_type": device_type,
        "vendor": "",
        "model": "",
        "serial_number": "",
        "firmware_version": "",
        "hostname": "",
        "uptime": "",
        "error": None,
        "raw_output": "",
    }

    # Map device type to connection function and parser
    connection_map = {
        "cisco_ios": (ios_connection, parse_cisco_ios_version),
        "cisco_xe": (ios_xe_connection, parse_cisco_xe_version),
        "cisco_nxos": (ios_connection, parse_cisco_nxos_version),  # Uses IOS connection with nxos type
        "aruba_os": (aruba_aos_connection, parse_aruba_version),
        "aruba_osswitch": (ios_connection, parse_aruba_version),  # Aruba switches via SSH
        "dell_os10": (ios_connection, parse_dell_version),
        "dell_force10": (ios_connection, parse_dell_version),
        "dell_powerconnect": (ios_connection, parse_dell_version),
    }

    if device_type not in connection_map:
        result["error"] = f"Unsupported device type: {device_type}"
        result["vendor"] = "Unknown"
        return result

    conn_func, parser = connection_map[device_type]

    try:
        # For NX-OS, we need to use the ios_connection but specify nxos device type
        if device_type == "cisco_nxos":
            from netmiko import ConnectHandler
            device_params = {
                "device_type": "cisco_nxos",
                "host": host,
                "username": username,
                "password": password,
                "timeout": 60,
            }
            if secret:
                device_params["secret"] = secret
            conn = ConnectHandler(**device_params)
            try:
                output = conn.send_command("show version", read_timeout=60)
            finally:
                conn.disconnect()
        elif device_type in ("dell_os10", "dell_force10", "dell_powerconnect"):
            from netmiko import ConnectHandler
            device_params = {
                "device_type": device_type,
                "host": host,
                "username": username,
                "password": password,
                "timeout": 60,
            }
            if secret:
                device_params["secret"] = secret
            conn = ConnectHandler(**device_params)
            try:
                output = conn.send_command("show version", read_timeout=60)
            finally:
                conn.disconnect()
        else:
            with conn_func(host, username, password, secret, timeout=60) as conn:
                output = conn.send_command("show version", read_timeout=60)

        result["raw_output"] = output

        # Parse the output
        parsed = parser(output)
        result.update(parsed)

    except Exception as e:
        result["error"] = str(e)
        # Set vendor based on device type for failed scans
        if device_type.startswith("cisco"):
            result["vendor"] = "Cisco"
        elif device_type.startswith("aruba"):
            result["vendor"] = "Aruba"
        elif device_type.startswith("dell"):
            result["vendor"] = "Dell"

    return result


def collect_device_inventory_many(
    hosts: List[str],
    username: str,
    password: str,
    secret: Optional[str] = None,
    device_type: str = "cisco_ios",
    max_workers: int = 10,
) -> Tuple[List[Dict], List[str]]:
    """
    Collect inventory from multiple devices in parallel.

    Args:
        hosts: List of device hostnames/IPs
        username: SSH username
        password: SSH password
        secret: Enable secret (optional)
        device_type: Netmiko device type
        max_workers: Maximum parallel connections

    Returns:
        Tuple of (results_list, errors_list)
    """
    results = []
    errors = []

    workers = min(max(len(hosts), 1), max_workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                collect_device_inventory, host, username, password, secret, device_type
            ): host
            for host in hosts
        }

        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                results.append(result)
                if result.get("error"):
                    errors.append(f"{host}: {result['error']}")
            except Exception as e:
                errors.append(f"{host}: {e}")
                results.append({
                    "device": host,
                    "device_type": device_type,
                    "vendor": "",
                    "model": "",
                    "serial_number": "",
                    "firmware_version": "",
                    "hostname": "",
                    "uptime": "",
                    "error": str(e),
                })

    return results, errors


def make_inventory_csv(results: List[Dict]) -> str:
    """Generate CSV string from inventory results."""
    fields = [
        "device",
        "hostname",
        "vendor",
        "model",
        "serial_number",
        "firmware_version",
        "uptime",
        "device_type",
        "scan_status",
        "error",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    writer.writeheader()

    for r in results:
        row = {k: r.get(k, "") for k in fields}
        row["scan_status"] = "failed" if r.get("error") else "success"
        writer.writerow(row)

    return buf.getvalue()
