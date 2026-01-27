# tools/aruba_controller.py
"""
Aruba AOS Controller (7200 series) - Client and AP count collection via SSH.

Commands used:
- show user-table summary: Gets connected client count (Total Users)
- show ap database: Gets AP inventory and count
"""
import re
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools.netmiko_helpers import aruba_aos_connection


def get_aruba_snapshot(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
) -> Tuple[Dict, List[str]]:
    """
    Collect client count, AP count, and AP details from an Aruba controller.

    Returns:
        Tuple of (result_dict, errors_list)
        result_dict: {"host": str, "total_clients": int|None, "ap_count": int|None, "ap_details": list}
    """
    result = {"host": host, "total_clients": None, "ap_count": None, "ap_details": []}
    errors = []

    try:
        with aruba_aos_connection(
            host,
            username,
            password,
            secret,
            fast_cli=False,
            timeout=120,
            auto_enable=bool(secret),
        ) as conn:
            # Get client count
            try:
                # "show user-table summary" gives total authenticated users
                # Example output: "Unique Users: 759  Total Users: 805"
                user_out = conn.send_command("show user-table summary", read_timeout=60)
                client_match = re.search(r"Total\s+Users\s*:\s*(\d+)", user_out or "", re.I)
                if client_match:
                    result["total_clients"] = int(client_match.group(1))
                else:
                    errors.append(f"{host}: Client count not found in user-table summary")
            except Exception as exc:
                errors.append(f"{host}: client count failed ({exc})")

            # Get AP count and details
            try:
                # Disable paging first to get full output
                conn.send_command("no paging", read_timeout=10)
                # Try "show ap database long" first for more details including MAC
                ap_out = conn.send_command("show ap database long", read_timeout=120)
                if not ap_out:
                    ap_out = conn.send_command("show ap database", read_timeout=90)
                if ap_out:
                    # Look for "Total APs:XXX" at the bottom of output
                    total_match = re.search(r"Total\s+APs?\s*:\s*(\d+)", ap_out or "", re.I)
                    if total_match:
                        result["ap_count"] = int(total_match.group(1))
                    else:
                        errors.append(f"{host}: Total APs not found in ap database output")

                    # Parse AP details from the output
                    ap_details = _parse_aruba_ap_database(ap_out)
                    result["ap_details"] = ap_details
                else:
                    errors.append(f"{host}: AP database empty")
            except Exception as exc:
                errors.append(f"{host}: AP count failed ({exc})")

    except Exception as exc:
        errors.append(f"{host}: connection failed ({exc})")

    return result, errors


def _parse_aruba_ap_database(output: str) -> List[Dict]:
    """
    Parse 'show ap database long' or 'show ap database' output from Aruba controller.
    Returns list of dicts with: ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state, slots, country
    """
    rows = []
    if not output:
        return rows

    lines = output.splitlines()

    # Find header line
    header_idx = -1
    for i, line in enumerate(lines):
        # Look for header containing Name and IP/Address
        if "Name" in line and ("IP" in line or "Address" in line):
            header_idx = i
            break

    if header_idx < 0:
        return rows

    # Parse header to get column positions
    header_line = lines[header_idx]
    cols = re.split(r"\s{2,}", header_line.strip())
    col_index = {c.strip(): idx for idx, c in enumerate(cols)}

    # MAC address pattern
    mac_pattern = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
    ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    # Parse data lines
    for line in lines[header_idx + 1:]:
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("="):
            continue
        if "Total APs" in line:
            break

        # Split by multiple spaces
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 2:
            continue

        ap_name = parts[0] if parts else ""

        # Skip non-AP lines (Flags legend, repeated headers, etc.)
        if not ap_name:
            continue
        if "Flags:" in ap_name or "=" in ap_name:
            continue
        if ap_name.lower() == "name":
            continue
        # Skip lines that start with single char + " =" (legend entries like "B = Built-in")
        if re.match(r"^[A-Za-z0-9]{1,2}\s*[-=]", ap_name):
            continue

        row = {
            "ap_name": ap_name,
            "ap_ip": "",
            "ap_model": parts[2] if len(parts) > 2 else "",  # Usually "AP Type" column
            "ap_mac": "",
            "ap_location": "",
            "ap_state": "",
            "slots": "",
            "country": "",
        }

        # Try to find IP address in parts
        for p in parts:
            if ip_pattern.match(p):
                row["ap_ip"] = p
                break

        # Try to find MAC address in parts
        for p in parts:
            if mac_pattern.search(p):
                mac_match = mac_pattern.search(p)
                if mac_match:
                    row["ap_mac"] = mac_match.group(0)
                    break

        # If no MAC found, generate a pseudo-MAC from AP name for deduplication
        # This ensures we can still track APs without MAC
        if not row["ap_mac"] and ap_name:
            # Use a hash of AP name as pseudo-MAC for uniqueness
            import hashlib
            hash_val = hashlib.md5(ap_name.encode()).hexdigest()[:12]
            row["ap_mac"] = ":".join(hash_val[i:i+2] for i in range(0, 12, 2))

        # Look for status
        for p in parts:
            if p.lower() in ("up", "down", "active", "standby"):
                row["ap_state"] = p
                break

        rows.append(row)

    return rows


def get_aruba_client_count(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
) -> Tuple[Optional[int], List[str]]:
    """Get just the client count from an Aruba controller."""
    result, errors = get_aruba_snapshot(host, username, password, secret)
    return result.get("total_clients"), errors


def get_aruba_ap_count(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
) -> Tuple[Optional[int], List[str]]:
    """Get just the AP count from an Aruba controller."""
    result, errors = get_aruba_snapshot(host, username, password, secret)
    return result.get("ap_count"), errors


def get_aruba_ap_inventory(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
) -> Tuple[List[Dict], List[str]]:
    """
    Get detailed AP inventory from an Aruba controller.

    Returns:
        Tuple of (ap_list, errors)
        ap_list: [{"wlc": host, "ap_name": str, "ip": str, "model": str, ...}, ...]
    """
    rows = []
    errors = []

    try:
        with aruba_aos_connection(
            host,
            username,
            password,
            secret,
            fast_cli=False,
            timeout=120,
            auto_enable=bool(secret),
        ) as conn:
            # Disable paging first to get full output
            conn.send_command("no paging", read_timeout=10)
            # Get detailed AP info
            ap_out = conn.send_command("show ap database long", read_timeout=120)
            if not ap_out:
                ap_out = conn.send_command("show ap database", read_timeout=90)

            if ap_out:
                lines = ap_out.splitlines()
                # Find header line
                header_idx = -1
                for i, line in enumerate(lines):
                    if "Name" in line and ("IP" in line or "Address" in line):
                        header_idx = i
                        break

                if header_idx >= 0:
                    # Parse tabular data
                    for line in lines[header_idx + 1:]:
                        line = line.strip()
                        if not line or line.startswith("-") or line.startswith("="):
                            continue
                        if "Total APs" in line:
                            break

                        # Split by multiple spaces
                        parts = re.split(r"\s{2,}", line)
                        if len(parts) >= 2:
                            ap_name = parts[0] if parts else ""

                            # Skip non-AP lines (Flags legend, repeated headers, etc.)
                            # These appear mid-output in "show ap database long"
                            if not ap_name:
                                continue
                            if "Flags:" in ap_name or "=" in ap_name:
                                continue
                            if ap_name.lower() == "name":
                                continue
                            # Skip lines that start with single char + " =" (legend entries like "B = Built-in")
                            if re.match(r"^[A-Za-z0-9]{1,2}\s*[-=]", ap_name):
                                continue

                            row = {
                                "wlc": host,
                                "ap_name": ap_name,
                                "group": parts[1] if len(parts) > 1 else "",
                                "model": parts[2] if len(parts) > 2 else "",
                                "ip": "",
                                "state": "",
                                "location": "",
                            }
                            # Try to find IP in the parts
                            ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                            for p in parts:
                                if ip_pattern.match(p):
                                    row["ip"] = p
                                    break
                            # Look for status
                            for p in parts:
                                if p.lower() in ("up", "down", "active", "standby"):
                                    row["state"] = p
                                    break
                            rows.append(row)
    except Exception as exc:
        errors.append(f"{host}: {exc}")

    return rows, errors


def get_aruba_snapshots_parallel(
    hosts: List[str],
    username: str,
    password: str,
    secret: Optional[str] = None,
    max_workers: int = 10,
) -> Tuple[List[Dict], List[str]]:
    """
    Collect snapshots from multiple Aruba controllers in parallel.

    Returns:
        Tuple of (results_list, errors_list)
    """
    results = []
    errors = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_aruba_snapshot, h, username, password, secret): h
            for h in hosts
        }
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                result, host_errors = fut.result()
                results.append(result)
                errors.extend(host_errors)
            except Exception as exc:
                errors.append(f"{host}: {exc}")

    return results, errors


def get_aruba_ap_inventory_many(
    hosts: List[str],
    username: str,
    password: str,
    secret: Optional[str] = None,
    max_workers: int = 10,
) -> Tuple[List[Dict], List[str]]:
    """
    Get AP inventory from multiple Aruba controllers in parallel.

    Returns:
        Tuple of (combined_ap_list, errors_list)
    """
    combined = []
    errors = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(get_aruba_ap_inventory, h, username, password, secret): h
            for h in hosts
        }
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                rows, host_errors = fut.result()
                combined.extend(rows)
                errors.extend(host_errors)
            except Exception as exc:
                errors.append(f"{host}: {exc}")

    return combined, errors
