from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import io
import csv

from tools.netmiko_helpers import ios_connection

def get_port_status(host, username, password, secret=None):
    """Return a list of rows: {interface, name, status, vlan, duplex, speed, type}."""
    with ios_connection(host, username, password, secret, auto_enable=bool(secret)) as conn:

        try:
            text = conn.send_command("show interfaces status", read_timeout=60)
            rows = parse_ios_show_interfaces_status(text)
            if rows:
                return rows
        except Exception:
            pass

        try:
            text = conn.send_command("show interface status", read_timeout=60)
            rows = parse_ios_show_interfaces_status(text)
            if rows:
                return rows
        except Exception:
            pass

        text = conn.send_command("show interfaces description", read_timeout=60)
        rows = parse_ios_show_interfaces_description(text)
        return rows


def get_port_status_many(hosts, username, password, secret=None, max_workers=10):
    """Run get_port_status concurrently across hosts. Returns (rows_map, errors)."""
    rows_map = {}
    errors = []

    def task(h):
        try:
            return h, get_port_status(h, username, password, secret)
        except Exception as e:
            return h, e

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futmap = {ex.submit(task, h): h for h in hosts}
        for fut in as_completed(futmap):
            h = futmap[fut]
            try:
                host, result = fut.result()
                if isinstance(result, Exception):
                    errors.append(f"{host}: {result}")
                else:
                    rows_map[host] = result
            except Exception as e:
                errors.append(f"{h}: {e}")
    return rows_map, errors


def parse_ios_show_interfaces_status(text):
    """Parse 'show interfaces status' output (Catalyst-style)."""
    rows = []
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ("Port" in ln and "Status" in ln and "Vlan" in ln and "Speed" in ln):
            header_idx = i
            break
    if header_idx is None:
        return rows

    for ln in lines[header_idx+1:]:
        if ln.lower().startswith("port") or ln.startswith("---"):
            continue
        parts = re.split(r"\s{2,}", ln.strip())
        if len(parts) < 4:
            continue
        rows.append({
            "interface": parts[0] if len(parts) > 0 else "",
            "name": parts[1] if len(parts) > 1 else "",
            "status": parts[2] if len(parts) > 2 else "",
            "vlan": parts[3] if len(parts) > 3 else "",
            "duplex": parts[4] if len(parts) > 4 else "",
            "speed": parts[5] if len(parts) > 5 else "",
            "type": parts[6] if len(parts) > 6 else "",
        })
    return rows


def parse_ios_show_interfaces_description(text):
    """Parse 'show interfaces description' fallback."""
    rows = []
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ("Interface" in ln and "Status" in ln and "Description" in ln):
            header_idx = i
            break
    if header_idx is None:
        return rows

    for ln in lines[header_idx+1:]:
        if ln.lower().startswith("interface") or ln.startswith("---"):
            continue
        parts = re.split(r"\s{2,}", ln.strip(), maxsplit=3)
        if not parts:
            continue
        rows.append({
            "interface": parts[0] if len(parts) > 0 else "",
            "name": parts[3] if len(parts) > 3 else (parts[2] if len(parts) > 2 else ""),
            "status": parts[1] if len(parts) > 1 else "",
            "vlan": "",
            "duplex": "",
            "speed": "",
            "type": "",
        })
    return rows


def make_port_status_csv(rows):
    """CSV builder for port status overview."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["switch_ip", "interface", "name", "status", "vlan", "duplex", "speed", "type"],
        lineterminator="\n"
    )
    writer.writeheader()
    for r in rows:
        writer.writerow({
            "switch_ip": r.get("switch_ip", ""),
            "interface": r.get("interface", ""),
            "name": r.get("name", ""),
            "status": r.get("status", ""),
            "vlan": r.get("vlan", ""),
            "duplex": r.get("duplex", ""),
            "speed": r.get("speed", ""),
            "type": r.get("type", ""),
        })
    return buf.getvalue()
