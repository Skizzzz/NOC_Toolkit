# tools/phrase_search.py
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import io
import re

from tools.netmiko_helpers import ios_connection
def run_show_run_many(hosts, username, password, secret=None, max_workers=10):
    """
    Returns (raw_map, errors)
      raw_map: { host: "show run (or interface section)" }
      errors:  [ "host: error ..." ]
    """
    raw_map = {}
    errors = []
    def worker(h):
        try:
            with ios_connection(h, username, password, secret) as conn:
                # Prefer interface sections for speed; fall back to full if not supported
                try:
                    out = conn.send_command("show running-config | section ^interface", read_timeout=60)
                    if out and "interface" in out:
                        return h, out
                except Exception:
                    pass
                out = conn.send_command("show running-config", read_timeout=120)
                return h, out
        except Exception as e:
            return h, e

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(worker, h): h for h in hosts}
        for fut in as_completed(futs):
            h, res = fut.result()
            if isinstance(res, Exception):
                errors.append(f"{h}: {res}")
            else:
                raw_map[h] = res

    return raw_map, errors

# -------------------- Parsing & filtering --------------------

def parse_interfaces_with_descriptions(run_config):
    """
    Parse interface blocks and return rows like:
      {"interface": "Gi1/0/1", "description": "foo", "block": "full text block"}
    """
    lines = (run_config or "").splitlines()
    results = []
    current_if = None
    buf = []
    desc = None

    def flush():
        nonlocal current_if, buf, desc
        if current_if:
            block = "\n".join(buf).rstrip()
            results.append({"interface": current_if, "description": desc or "", "block": block})
        current_if, buf, desc = None, [], None

    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith("interface "):
            flush()
            current_if = line.split(" ", 1)[1].strip()
            buf = [line]
            desc = None
        elif current_if is not None:
            buf.append(line)
            st = line.strip()
            if st.startswith("description"):
                parts = st.split(None, 1)
                desc = parts[1].strip() if len(parts) == 2 else ""
            if st == "!":
                flush()
    flush()
    return results

def filter_by_phrase(rows, phrase, case_sensitive=False, exact=False, full_block=True):
    """
    If full_block=True: search within the interface block text.
    Else: search description (exact or substring, case honoring).
    """
    if not phrase:
        return []

    out = []
    if full_block:
        needle = phrase if case_sensitive else phrase.lower()
        for r in rows:
            hay = r.get("block", "")
            hay_cmp = hay if case_sensitive else hay.lower()
            if needle in hay_cmp:
                out.append({"interface": r["interface"], "description": r.get("description","")})
    else:
        for r in rows:
            desc = r.get("description", "")
            if exact:
                if (desc == phrase) if case_sensitive else (desc.lower() == phrase.lower()):
                    out.append({"interface": r["interface"], "description": desc})
            else:
                hay = desc if case_sensitive else desc.lower()
                needle = phrase if case_sensitive else phrase.lower()
                if needle in hay:
                    out.append({"interface": r["interface"], "description": desc})
    return out

def make_csv(rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["switch_ip", "interface", "description"], lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow({
            "switch_ip": r.get("switch_ip", ""),
            "interface": r.get("interface", ""),
            "description": r.get("description", ""),
        })
    return buf.getvalue()

# -------------------- CLI builder for actions --------------------

def _split_nonempty_lines(text):
    lines = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if s:
            lines.append(s)
    return lines

def build_cli_for_action(pairs, action, new_description=None, custom_config=None):
    """
    Build per-host CLI lists.
      pairs: [(host, interface), ...]
      action: "set-description" | "custom-config"
      new_description: str when action == "set-description"
      custom_config: multiline str when action == "custom-config"

    Returns dict: { host: [ "interface Gi1/0/1", "description blah", "exit", ... ] }
    """
    # Group interfaces per host
    per_host = {}
    for host, iface in pairs or []:
        if host and iface:
            per_host.setdefault(host, []).append(iface)

    cli_map = {}
    if action == "set-description":
        if not (new_description and new_description.strip()):
            # No description provided -> nothing to do
            return {h: [] for h in per_host.keys()}
        desc = new_description.strip()
        for host, ifaces in per_host.items():
            lines = []
            for iface in sorted(set(ifaces)):
                lines.append(f"interface {iface}")
                lines.append(f"description {desc}")
                lines.append("exit")
            cli_map[host] = lines

    elif action == "custom-config":
        cfg_lines = _split_nonempty_lines(custom_config or "")
        if not cfg_lines:
            return {h: [] for h in per_host.keys()}
        for host, ifaces in per_host.items():
            lines = []
            for iface in sorted(set(ifaces)):
                lines.append(f"interface {iface}")
                for ln in cfg_lines:
                    # Replace token with the interface name when present
                    lines.append(ln.replace("{INTERFACE}", iface))
                lines.append("exit")
            cli_map[host] = lines

    else:
        # Unknown action -> empty plan
        cli_map = {h: [] for h in per_host.keys()}

    return cli_map
