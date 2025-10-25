# tools/wlc_inventory.py
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import io, csv, re

from tools.netmiko_helpers import ios_xe_connection

def get_ap_inventory(host: str, username: str, password: str, secret: Optional[str] = None) -> List[Dict]:
    """
    Returns a list of AP rows for a single 9800:
    [
      {"wlc": host, "ap_name": "...", "ip": "...", "model": "...", "state": "...", "location": "...", "ether_mac": "...", "radio_mac": "...", "slots": "...", "country": "...", "protocol": "..."}
    ]
    """
    rows: List[Dict] = []
    with ios_xe_connection(host, username, password, secret, timeout=60) as conn:
        output = conn.send_command("show ap summary", read_timeout=90)

    # Normalize lines and find header
    lines = [l.rstrip() for l in output.splitlines() if l.strip()]
    # Find header line containing "AP Name" and "IP" (or "IP Address")
    header_idx = -1
    for i, line in enumerate(lines):
        if "AP Name" in line and ("IP Address" in line or "IP" in line):
            header_idx = i
            break
    if header_idx == -1:
        # Try another common header variant
        for i, line in enumerate(lines):
            if "AP Name" in line and "AP Model" in line:
                header_idx = i
                break
    if header_idx == -1:
        # No parseable table; return empty
        return rows

    header_line = lines[header_idx]
    # Header columns split by 2+ spaces
    cols = re.split(r"\s{2,}", header_line.strip())
    # Build a name->index map
    col_index = {c.strip(): idx for idx, c in enumerate(cols)}

    # Helper to fetch a column by any of a few known names
    def pick(row_tokens: List[str], names: Tuple[str, ...]) -> str:
        for n in names:
            if n in col_index and col_index[n] < len(row_tokens):
                return row_tokens[col_index[n]].strip()
        return ""

    # Data lines = after header; optionally skip a dashed separator
    data_start = header_idx + 1
    if data_start < len(lines) and set(lines[data_start].replace(" ", "")) in (set("-"), set("=")):
        data_start += 1

    for line in lines[data_start:]:
        # Stop if we hit a non-table block
        if not re.search(r"\S", line):
            continue
        toks = re.split(r"\s{2,}", line.strip())
        if len(toks) < 2:
            continue

        ap_name = pick(toks, ("AP Name",))
        if not ap_name:
            # Sometimes the first col is the name even if header didn't parse perfectly
            ap_name = toks[0].strip()

        row = {
            "wlc": host,
            "ap_name": ap_name,
            "slots": pick(toks, ("Slots",)),
            "model": pick(toks, ("AP Model", "Model")),
            "ether_mac": pick(toks, ("Ethernet MAC", "Ether MAC")),
            "radio_mac": pick(toks, ("Radio MAC",)),
            "location": pick(toks, ("Location", "Site", "Tag")),
            "country": pick(toks, ("Country",)),
            "ip": pick(toks, ("IP Address", "IP")),
            "state": pick(toks, ("State", "Status")),
            "protocol": pick(toks, ("Protocol",)),
        }
        rows.append(row)

    return rows


def get_ap_inventory_many(hosts: List[str], username: str, password: str, secret: Optional[str] = None, max_workers: int = 10):
    """
    Returns (rows, errors) where rows is a single combined list from all WLCs
    and errors is a list of error messages per-host failure.
    """
    combined: List[Dict] = []
    errors: List[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(get_ap_inventory, h, username, password, secret): h for h in hosts}
        for fut in as_completed(futs):
            host = futs[fut]
            try:
                combined.extend(fut.result())
            except Exception as e:
                errors.append(f"{host}: {e}")
    return combined, errors

# --- CSV ---

def make_ap_csv(rows: List[Dict]) -> str:
    fields = ["wlc", "ap_name", "ip", "model", "state", "location", "slots", "ether_mac", "radio_mac", "country", "protocol"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in fields})
    return buf.getvalue()
