# tools/push_config.py
from typing import Optional

from tools.netmiko_helpers import ios_connection


def _save_config(conn) -> str:
    try:
        output = conn.save_config()
    except AttributeError:
        # Older Netmiko versions: fallback to write memory
        output = conn.send_command_timing("write memory", strip_prompt=False, strip_command=False)
    return output

# --- Read full running-config ---
def show_run_full(host: str, username: str, password: str, secret: Optional[str]) -> str:
    with ios_connection(host, username, password, secret) as conn:
        return conn.send_command("show running-config", read_timeout=120)

# --- Read only interface sections (falls back to full if needed) ---
def show_run_interfaces(host: str, username: str, password: str, secret: Optional[str]) -> str:
    with ios_connection(host, username, password, secret) as conn:
        try:
            out = conn.send_command("show running-config | section ^interface", read_timeout=60)
            if out and "interface" in out:
                return out
        except Exception:
            pass
        return conn.send_command("show running-config", read_timeout=120)

# --- Push a list of config lines (global or in-interface) ---
def push_config_lines(host: str, lines: list[str], username: str, password: str, secret: Optional[str], *, ensure_saved: bool = False) -> str:
    """
    Sends the provided CLI lines to the device.

    lines can contain:
      - global mode commands (e.g., 'ip ssh version 2')
      - interface blocks (e.g., 'interface Gi1/0/10', 'description foo', 'exit')

    Returns a short status string; raises RuntimeError on failure.
    """
    if not lines:
        return "no lines to apply"

    with ios_connection(host, username, password, secret) as conn:
        try:
            # Netmiko will enter config mode and exit as needed
            _ = conn.send_config_set(lines, exit_config_mode=True)
            if ensure_saved:
                save_output = _save_config(conn)
                if isinstance(save_output, str):
                    lowered = save_output.lower()
                    if "error" in lowered and "[ok" not in lowered:
                        raise RuntimeError(f"save_config reported error: {save_output.strip()}")
                else:
                    raise RuntimeError("save_config did not return output")
        except Exception as e:
            raise RuntimeError(f"send_config_set failed: {e}")

    return f"applied {len(lines)} line(s)"
