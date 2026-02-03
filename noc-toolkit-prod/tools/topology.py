# tools/topology.py
"""Helpers for building on-demand topology reports via CDP/LLDP."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from netmiko import ConnectHandler


class TopologyError(RuntimeError):
    """Raised when a topology collection step fails."""


@dataclass
class CommandResult:
    output: str
    error: str = ""


def _build_device_type_candidates(vendor_hint: Optional[str], mode: Optional[str]) -> List[str]:
    """Return a list of Netmiko device_types to attempt."""
    normalized = (vendor_hint or "").lower()
    mode = (mode or "").lower()
    candidates: List[str] = []

    def add_types(types: Iterable[str]) -> None:
        for device_type in types:
            if device_type not in candidates:
                candidates.append(device_type)

    if mode == "cisco" or "cisco" in normalized:
        add_types(("cisco_ios", "cisco_xe"))
    if mode == "dell" or "dell" in normalized or "force10" in normalized or "nseries" in normalized:
        add_types(("dell_os10", "dell_force10", "dell_powerconnect"))

    # Fallback order tries Cisco first, then Dell variants
    add_types(("cisco_ios", "cisco_xe", "dell_os10", "dell_force10", "dell_powerconnect"))
    return candidates


def _connect_device(
    *,
    host: str,
    username: str,
    password: str,
    secret: Optional[str],
    vendor_hint: Optional[str],
    mode: Optional[str],
    timeout: int = 90,
) -> Tuple[object, str, List[str]]:
    """Attempt Netmiko connections until one succeeds."""
    attempts = _build_device_type_candidates(vendor_hint, mode)
    attempt_errors: List[str] = []
    for device_type in attempts:
        params = {
            "device_type": device_type,
            "host": host,
            "username": username,
            "password": password,
            "timeout": timeout,
            "fast_cli": False,
        }
        if secret:
            params["secret"] = secret
        try:
            conn = ConnectHandler(**params)
            # Enter enable mode when appropriate; ignore failures
            if secret and device_type.startswith("cisco"):
                try:
                    conn.enable()
                except Exception:
                    pass
            return conn, device_type, attempt_errors
        except Exception as exc:
            attempt_errors.append(f"{device_type}: {exc}")
    if attempt_errors:
        detail = "; ".join(attempt_errors)
        raise TopologyError(
            "Unable to establish a Netmiko session to the target switch. "
            f"Attempts: {detail}"
        )
    raise TopologyError(
        "Unable to establish a Netmiko session to the target switch. "
        "Verify the credentials and vendor selection."
    )


def _run_command(conn, command: str, read_timeout: int = 60) -> CommandResult:
    """Run a show command, returning output and a hint if the command failed."""
    try:
        output = (conn.send_command(command, read_timeout=read_timeout) or "").strip()
    except Exception as exc:
        return CommandResult(output="", error=str(exc))

    lowered = output.lower()
    if not output:
        return CommandResult(output=output, error="")
    if any(err in lowered for err in ("invalid input", "incomplete command", "unknown command", "syntax error")):
        return CommandResult(output=output, error="unsupported")
    if "% error" in lowered or "error:" in lowered:
        return CommandResult(output=output, error="error")
    return CommandResult(output=output, error="")


def _search(block: str, pattern: str) -> str:
    match = re.search(pattern, block, flags=re.IGNORECASE)
    return (match.group(1).strip() if match else "")


def _extract_ipv4(block: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", block)
    return match.group(1).strip() if match else ""


def parse_cdp_detail(output: str) -> List[Dict[str, str]]:
    """Parse 'show cdp neighbors detail' output into neighbor records."""
    if not output:
        return []
    blocks = re.split(r"\n-{2,}\n", output)
    if len(blocks) == 1:
        # Fallback split on blank lines preceding 'Device ID'
        blocks = re.split(r"\n(?=Device ID)", output)

    records: List[Dict[str, str]] = []
    for raw in blocks:
        block = raw.strip()
        if "device id" not in block.lower():
            continue
        remote_name = _search(block, r"Device ID:\s*([^\n]+)")
        local_interface = _search(block, r"Interface:\s*([^\n,]+)")
        remote_port = _search(block, r"Port ID\s*\(outgoing port\):\s*([^\n]+)")
        if not (remote_name or local_interface):
            continue
        remote_ip = _extract_ipv4(_search(block, r"IP (?:address|Addr)\s*:\s*([^\n]+)") or block)
        platform_line = _search(block, r"Platform:\s*([^\n]+)")
        remote_capabilities = ""
        remote_platform = ""
        if platform_line:
            parts = [p.strip() for p in platform_line.split(",") if p.strip()]
            if parts:
                remote_platform = parts[0]
            if len(parts) > 1:
                remote_capabilities = parts[1]
        capabilities_line = _search(block, r"Capabilities:\s*([^\n]+)")
        if capabilities_line:
            remote_capabilities = capabilities_line

        records.append(
            {
                "protocol": "CDP",
                "local_interface": local_interface,
                "remote_name": remote_name,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "remote_platform": remote_platform,
                "remote_capabilities": remote_capabilities,
                "raw": block,
            }
        )
    return records


def parse_lldp_detail(output: str) -> List[Dict[str, str]]:
    """Parse 'show lldp neighbors detail' style output."""
    if not output:
        return []
    blocks = re.split(r"\n(?=Local\s+Intf)", output)
    records: List[Dict[str, str]] = []
    for raw in blocks:
        block = raw.strip()
        if "local intf" not in block.lower():
            continue
        local_interface = _search(block, r"Local\s+Intf:\s*([^\n]+)")
        remote_name = _search(block, r"System\s+Name:\s*([^\n]+)")
        if not remote_name:
            remote_name = _search(block, r"Port\s+Description:\s*([^\n]+)")
        remote_port = _search(block, r"Port\s+id:\s*([^\n]+)")
        remote_ip = ""
        management_section = re.findall(r"Management Address(?:es)?\s*:\s*([^\n]+)", block, flags=re.IGNORECASE)
        if management_section:
            remote_ip = _extract_ipv4(management_section[0])
        if not remote_ip:
            remote_ip = _extract_ipv4(block)
        if not (local_interface or remote_name):
            continue
        system_desc = _search(block, r"System Description:\s*([\s\S]+?)\n(?:Time|System Capabilities|Enabled Capabilities|$)")
        remote_platform = ""
        if system_desc:
            remote_platform = system_desc.splitlines()[0].strip()
        capabilities_line = _search(block, r"Enabled Capabilities:\s*([^\n]+)") or _search(
            block, r"System Capabilities:\s*([^\n]+)"
        )

        records.append(
            {
                "protocol": "LLDP",
                "local_interface": local_interface,
                "remote_name": remote_name,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "remote_platform": remote_platform,
                "remote_capabilities": capabilities_line,
                "raw": block,
            }
        )
    return records


def _merge_neighbors(records: List[Dict[str, str]]) -> List[Dict[str, object]]:
    """Combine CDP and LLDP findings into a single list."""
    merged: List[Dict[str, object]] = []

    for rec in records:
        local_interface = (rec.get("local_interface") or "").strip()
        remote_name = (rec.get("remote_name") or "").strip()
        remote_ip = (rec.get("remote_ip") or "").strip()
        remote_port = (rec.get("remote_port") or "").strip()
        remote_platform = (rec.get("remote_platform") or "").strip()
        remote_capabilities = (rec.get("remote_capabilities") or "").strip()
        protocol = (rec.get("protocol") or "").strip()
        raw_block = rec.get("raw") or ""

        local_lower = local_interface.lower()
        remote_ip_lower = remote_ip.lower()
        remote_name_lower = remote_name.lower()
        remote_port_lower = remote_port.lower()

        candidate: Optional[Dict[str, object]] = None
        for entry in merged:
            entry_local = (entry.get("local_interface") or "").strip()
            entry_remote_ip = (entry.get("remote_ip") or "").strip()
            entry_remote_name = (entry.get("remote_name") or "").strip()
            entry_remote_port = (entry.get("remote_port") or "").strip()

            entry_local_lower = entry_local.lower()
            entry_ip_lower = entry_remote_ip.lower()
            entry_name_lower = entry_remote_name.lower()
            entry_port_lower = entry_remote_port.lower()

            # Prefer matching on explicit local interface when present.
            if local_lower and entry_local_lower and local_lower == entry_local_lower:
                candidate = entry
                break

            # If one side lacks the local interface, fall back to remote identifiers.
            if not local_lower and entry_local_lower:
                if remote_ip_lower and remote_ip_lower == entry_ip_lower:
                    candidate = entry
                    break
                if remote_name_lower and remote_name_lower == entry_name_lower:
                    candidate = entry
                    break

            if local_lower and not entry_local_lower and remote_ip_lower and remote_ip_lower == entry_ip_lower:
                candidate = entry
                break

            # As a final fallback, match on remote IP and port pairs.
            if remote_ip_lower and remote_ip_lower == entry_ip_lower:
                if remote_port_lower and entry_port_lower and remote_port_lower == entry_port_lower:
                    candidate = entry
                    break
                if not remote_port_lower or not entry_port_lower:
                    candidate = entry
                    break

        if candidate is None:
            entry = {
                "local_interface": local_interface,
                "remote_name": remote_name,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "remote_platform": remote_platform,
                "remote_capabilities": remote_capabilities,
                "protocols": [protocol] if protocol else [],
                "raw_blocks": [raw_block] if raw_block else [],
            }
            merged.append(entry)
            continue

        if local_interface and not candidate.get("local_interface"):
            candidate["local_interface"] = local_interface
        if remote_name and not candidate.get("remote_name"):
            candidate["remote_name"] = remote_name
        if remote_ip and not candidate.get("remote_ip"):
            candidate["remote_ip"] = remote_ip
        if remote_port and not candidate.get("remote_port"):
            candidate["remote_port"] = remote_port
        if remote_platform and not candidate.get("remote_platform"):
            candidate["remote_platform"] = remote_platform
        if remote_capabilities and not candidate.get("remote_capabilities"):
            candidate["remote_capabilities"] = remote_capabilities

        if raw_block:
            candidate.setdefault("raw_blocks", [])
            candidate["raw_blocks"].append(raw_block)

        if protocol:
            proto_list = candidate.setdefault("protocols", [])
            if protocol not in proto_list:
                proto_list.append(protocol)

    def _sort_key(entry: Dict[str, object]) -> Tuple[str, str]:
        local = (entry.get("local_interface") or "").lower()
        remote = (entry.get("remote_name") or entry.get("remote_ip") or "").lower()
        return (local, remote)

    return sorted(merged, key=_sort_key)


def _index_nodes(nodes: Optional[List[Dict]]) -> Tuple[Dict[str, Dict], Dict[str, Dict]]:
    by_ip: Dict[str, Dict] = {}
    by_caption: Dict[str, Dict] = {}
    for node in nodes or []:
        ip = (node.get("ip_address") or "").strip().lower()
        if ip and ip not in by_ip:
            by_ip[ip] = node
        caption = (node.get("caption") or "").strip().lower()
        if caption and caption not in by_caption:
            by_caption[caption] = node
    return by_ip, by_caption


def annotate_with_inventory(neighbors: List[Dict[str, object]], nodes: Optional[List[Dict]]) -> None:
    """Attach SolarWinds metadata when a neighbor can be matched."""
    by_ip, by_caption = _index_nodes(nodes)
    for neighbor in neighbors:
        matched = None
        remote_ip = (neighbor.get("remote_ip") or "").lower()
        remote_name = (neighbor.get("remote_name") or "").lower()
        if remote_ip and remote_ip in by_ip:
            matched = by_ip[remote_ip]
        elif remote_name and remote_name in by_caption:
            matched = by_caption[remote_name]
        if matched:
            inventory = {
                "node_id": matched.get("node_id"),
                "caption": matched.get("caption"),
                "organization": matched.get("organization"),
                "vendor": matched.get("vendor"),
                "model": matched.get("model"),
                "ip_address": matched.get("ip_address"),
            }
            neighbor["inventory"] = inventory
            if not neighbor.get("remote_platform") and matched.get("model"):
                neighbor["remote_platform"] = matched.get("model")
            if matched.get("vendor"):
                neighbor["remote_vendor"] = matched.get("vendor")
            else:
                neighbor.setdefault("remote_vendor", "")
        else:
            neighbor["inventory"] = None
            neighbor.setdefault("remote_vendor", "")


def build_topology_report(
    *,
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
    vendor_hint: Optional[str] = None,
    vendor_mode: Optional[str] = None,
    nodes: Optional[List[Dict]] = None,
) -> Dict[str, object]:
    """Collect CDP/LLDP neighbors for the given device."""
    conn = None
    attempt_errors: List[str] = []
    try:
        conn, device_type, attempt_errors = _connect_device(
            host=host,
            username=username,
            password=password,
            secret=secret,
            vendor_hint=vendor_hint,
            mode=vendor_mode,
        )
    except TopologyError as exc:
        raise TopologyError(str(exc))

    try:
        outputs: Dict[str, CommandResult] = {
            "cdp_detail": _run_command(conn, "show cdp neighbors detail"),
            "lldp_detail": _run_command(conn, "show lldp neighbors detail"),
        }
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

    records: List[Dict[str, str]] = []
    command_notes: List[str] = []
    for key, result in outputs.items():
        label = key.replace("_", " ")
        if result.error == "unsupported":
            command_notes.append(f"{label} not supported on this device.")
        elif result.error:
            command_notes.append(f"{label} failed: {result.error}")
        if key == "cdp_detail":
            records.extend(parse_cdp_detail(result.output))
        elif key == "lldp_detail":
            records.extend(parse_lldp_detail(result.output))

    neighbors = _merge_neighbors(records)
    annotate_with_inventory(neighbors, nodes)
    def _has_neighbor_details(entry: Dict[str, object]) -> bool:
        def _filled(text: Optional[str]) -> bool:
            return bool((text or "").strip())

        return _filled(entry.get("remote_name")) or _filled(entry.get("remote_ip")) or _filled(entry.get("remote_port")) or bool(entry.get("inventory"))

    neighbors = [
        neighbor
        for neighbor in neighbors
        if _has_neighbor_details(neighbor)
    ]

    return {
        "host": host,
        "device_type": device_type,
        "neighbors": neighbors,
        "command_notes": command_notes,
        "attempt_warnings": attempt_errors,
        "raw_outputs": {key: outputs[key].output for key in outputs},
    }
