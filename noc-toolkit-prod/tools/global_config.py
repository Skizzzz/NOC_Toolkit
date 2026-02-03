# tools/global_config.py
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools.netmiko_helpers import ios_connection

# ---------- Fetch running-config for many devices ----------
def run_show_run_many_global(hosts, username, password, secret=None, max_workers=10):
    """
    Returns (raw_map, errors)
      raw_map: { host: 'show running-config' }
      errors:  [ 'host: error ...' ]
    """
    raw_map, errors = {}, []

    def worker(h):
        try:
            with ios_connection(h, username, password, secret) as conn:
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

# ---------- Build global CLI for selected hosts ----------
def _split_nonempty_lines(text: str):
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]

def build_cli_for_global_action(selected_hosts, custom_config):
    """
    Returns { host: [global CLI lines…] } for the chosen devices.
    Lines are NOT wrapped in 'interface' context.
    """
    cfg_lines = _split_nonempty_lines(custom_config or "")
    if not cfg_lines:
        # empty plan (caller will guard)
        return {h: [] for h in (selected_hosts or [])}
    return {h: list(cfg_lines) for h in (selected_hosts or [])}
