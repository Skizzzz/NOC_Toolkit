import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools.netmiko_helpers import ios_connection

# Regex to capture "Number of Active Clients"
RE_TOTAL = re.compile(r"Number of Clients\s*:\s*(\d+)", re.I)
RE_ACTIVE = re.compile(r"Number of Active Clients\s*:\s*(\d+)", re.I)

def _connect_and_run(host, username, password, secret, commands):
    """Open SSH session, run commands, return {cmd: output}."""
    out_map = {}
    try:
        with ios_connection(
            host,
            username,
            password,
            secret,
            fast_cli=False,
            timeout=90,
            auto_enable=bool(secret),
        ) as conn:
            for cmd in commands:
                try:
                    out_map[cmd] = conn.send_command(cmd, read_timeout=120)
                except Exception as e:
                    out_map[cmd] = f"<error: {e}>"
    except Exception as e:
        raise RuntimeError(f"{host}: {e}")
    return out_map


def get_client_summary(host, username, password, secret=None, include_per_wlan=True):
    """
    Get total clients (and per WLAN if requested) for one WLC.
    Returns: (result_dict, errors_list)
    result_dict: {
       "wlc": host,
       "total_clients": int,
       "wlans": [{"wlan_id": id, "wlan_name": name, "clients": n}, ...]
    }
    """
    errors = []
    try:
        cmds = ["show wireless client summary"]
        if include_per_wlan:
            # We'll run show wlan summary and show wlan id X for each SSID found
            cmds.append("show wlan summary")

        out_map = _connect_and_run(host, username, password, secret, cmds)
        client_out = out_map.get("show wireless client summary", "")

        # Parse total clients
        m = RE_TOTAL.search(client_out)
        total = int(m.group(1)) if m else 0

        wlans = []
        if include_per_wlan:
            wlan_summary = out_map.get("show wlan summary", "")
            for line in wlan_summary.splitlines():
                line = line.strip()
                if not line or line.startswith("ID") or line.startswith("--"):
                    continue
                parts = line.split()
                if len(parts) < 3:  # Expect ID, Profile Name, SSID...
                    continue
                try:
                    wlan_id = int(parts[0])
                except:
                    continue
                ssid = parts[2]
                # query per-wlan active clients
                cmd = f"show wlan id {wlan_id} | inc Number"
                per_out = _connect_and_run(host, username, password, secret, [cmd])
                per_txt = per_out.get(cmd, "")
                m2 = RE_ACTIVE.search(per_txt)
                clients = int(m2.group(1)) if m2 else 0
                wlans.append({"wlan_id": wlan_id, "wlan_name": ssid, "clients": clients})

        return {"wlc": host, "total_clients": total, "wlans": wlans}, errors

    except Exception as e:
        errors.append(f"{host}: {e}")
        return None, errors


def get_client_summary_many(hosts, username, password, secret=None, include_per_wlan=False):
    """Sequential version: queries each WLC one by one."""
    rows = []
    errors = []
    for h in hosts:
        r, e = get_client_summary(h, username, password, secret, include_per_wlan)
        if r:
            rows.append(r)
        if e:
            errors.extend(e)
    return rows, errors


def get_client_summary_many_parallel(hosts, username, password, secret=None,
                                     include_per_wlan=True, max_workers=30):
    """
    Parallel version: collects many WLCs concurrently.
    Returns (rows, errs) just like the single-host helper.
    """
    rows, errs = [], []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(get_client_summary, h, username, password, secret, include_per_wlan): h
            for h in hosts
        }
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                r, e = fut.result()
            except Exception as ee:
                r, e = None, [f"{h}: {ee}"]
            if r:
                rows.append(r)
            if e:
                errs.extend(e)
    return rows, errs
