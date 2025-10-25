from __future__ import annotations
from typing import Dict, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from tools.netmiko_helpers import ios_xe_connection

# ---------------- Parsing helpers ----------------
# Primary split on 2+ spaces; fallback to any whitespace
_SPLIT_STRICT = re.compile(r"\s{2,}")
_SPLIT_LOOSE  = re.compile(r"\s+")

def _split_cols(line: str) -> List[str]:
    toks = _SPLIT_STRICT.split(line.strip())
    if len(toks) <= 2:
        toks = _SPLIT_LOOSE.split(line.strip())
    return toks

def _to_float(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    s = s.strip().replace("%", "").replace(",", "")
    try:
        return float(s)
    except Exception:
        return None

def _find_header_index(headers: List[str], candidates: List[str]) -> Optional[int]:
    lowers = [h.lower() for h in headers]
    for i, name in enumerate(lowers):
        for c in candidates:
            if c in name:
                return i
    return None

def _parse_rf_table(output: str, band_label: str) -> List[Dict]:
    """
    Works with 9800 'show ap dot11 <band> load-info' (preferred) and similar tables.
    We try to find any header that contains 'util' for utilization; otherwise derive
    from Tx/Rx if present.
    """
    lines = [l.rstrip() for l in (output or "").splitlines() if l.strip()]
    if not lines:
        return []

    # Locate header line (contains "AP Name")
    header_idx = -1
    for i, line in enumerate(lines):
        if "AP Name" in line:
            header_idx = i
            break
    if header_idx == -1:
        return []

    headers = _split_cols(lines[header_idx])

    # Skip dashed separator row if present
    start = header_idx + 1
    if start < len(lines):
        sep = lines[start].replace(" ", "")
        if sep and all(ch in "-=_" for ch in set(sep)):
            start += 1

    # Fuzzy column indices
    idx_ap    = _find_header_index(headers, ["ap name"])
    idx_chan  = _find_header_index(headers, ["channel", "current ch", "ch"])
    idx_util  = _find_header_index(headers, ["channel util", "chan util", "ch util", "utilization", "util %", "util(%)", "util%"])
    idx_tx    = _find_header_index(headers, ["tx util", "tx-util", "txutil"])
    idx_rx    = _find_header_index(headers, ["rx util", "rx-util", "rxutil"])
    idx_noise = _find_header_index(headers, ["noise"])
    idx_intf  = _find_header_index(headers, ["interference", "intf", "non-wifi", "cw", "int"])

    # Any columns that contain "util" in the header
    util_cols = [i for i, h in enumerate(headers) if "util" in h.lower()]

    rows: List[Dict] = []
    for line in lines[start:]:
        toks = _split_cols(line)
        if len(toks) < 2:
            continue

        def get(i: Optional[int]) -> str:
            return toks[i].strip() if i is not None and i < len(toks) else ""

        ap_name = get(idx_ap) if idx_ap is not None else toks[0]
        channel = get(idx_chan)

        util_s = get(idx_util)
        tx_s   = get(idx_tx)
        rx_s   = get(idx_rx)

        util_v = _to_float(util_s)
        tx_v   = _to_float(tx_s)
        rx_v   = _to_float(rx_s)

        util_final = None
        util_src = ""
        if util_v is not None:
            util_final = util_v
            util_src = "overall"
        elif tx_v is not None or rx_v is not None:
            util_final = max(tx_v or 0.0, rx_v or 0.0)
            util_src = "txrx"
        else:
            # last resort: any "util" column with a number
            for i in util_cols:
                v = _to_float(get(i))
                if v is not None:
                    util_final = v
                    util_src = "fuzzy"
                    break

        rows.append({
            "ap_name": ap_name,
            "band": band_label,
            "channel": channel,
            "util": util_s,
            "tx_util": tx_s,
            "rx_util": rx_s,
            "noise": get(idx_noise),
            "interference": get(idx_intf),
            "util_final": util_final,
            "util_src": util_src,
        })
    return rows

def _try_cmds(conn, cmds: List[str], band_label: str) -> List[Dict]:
    for cmd in cmds:
        try:
            out = conn.send_command(cmd, read_timeout=180)
        except Exception:
            continue
        rows = _parse_rf_table(out, band_label)
        if rows:
            return rows
    return []

# ---------------- Collectors ----------------
def _rf_for_band(host: str, username: str, password: str, secret: Optional[str], band: str) -> List[Dict]:
    """
    On 9800, preferred bulk commands are:
      - show ap dot11 5ghz load-info
      - show ap dot11 24ghz load-info
    We still try summaries as fallbacks.
    """
    band_label = "5GHz" if band == "a" else "2.4GHz"
    with ios_xe_connection(host, username, password, secret, timeout=90) as conn:
        try:
            conn.send_command_timing("terminal length 0", strip_prompt=False, strip_command=False)
        except Exception:
            pass
        if band == "a":
            variants = [
                # Preferred for 9800
                "show ap dot11 5ghz load-info",
                # Fallbacks that sometimes include util% or tx/rx util
                "show ap dot11 5ghz summary",
                # Per-AP (too heavy to loop here) — leave for future if needed:
                # "show ap name <AP> auto-rf dot11 5ghz"
            ]
        else:
            variants = [
                "show ap dot11 24ghz load-info",
                "show ap dot11 24ghz summary",
                # "show ap name <AP> auto-rf dot11 24ghz"
            ]
        rows = _try_cmds(conn, variants, band_label)

    for r in rows:
        r["wlc"] = host
    return rows

def get_rf_summary(host: str, username: str, password: str, secret: Optional[str], band: str) -> List[Dict]:
    if band == "5":
        return _rf_for_band(host, username, password, secret, "a")
    elif band == "2.4":
        return _rf_for_band(host, username, password, secret, "b")
    else:
        rows: List[Dict] = []
        try: rows.extend(_rf_for_band(host, username, password, secret, "a"))
        except Exception: pass
        try: rows.extend(_rf_for_band(host, username, password, secret, "b"))
        except Exception: pass
        return rows

def get_rf_summary_many(hosts: List[str], username: str, password: str, secret: Optional[str], band: str, max_workers: int = 10):
    combined: List[Dict] = []
    errors: List[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(get_rf_summary, h, username, password, secret, band): h for h in hosts}
        for fut in as_completed(futs):
            host = futs[fut]
            try:
                combined.extend(fut.result())
            except Exception as e:
                errors.append(f"{host}: {e}")
    return combined, errors

# ---------------- Debug sampler ----------------
def collect_rf_samples(host: str, username: str, password: str, secret: Optional[str]) -> dict:
    """
    Collect raw CLI samples (first ~40 lines) for both bands, trying 9800-correct commands.
    Returns:
      {
        "5ghz": {"cmd": "<which produced output>", "sample": "<first lines>"},
        "24ghz": {"cmd": "...", "sample": "..."}
      }
    """
    samples = {"5ghz": {"cmd": "", "sample": ""}, "24ghz": {"cmd": "", "sample": ""}}
    variants_5 = [
        "show ap dot11 5ghz load-info",
        "show ap dot11 5ghz summary",
    ]
    variants_24 = [
        "show ap dot11 24ghz load-info",
        "show ap dot11 24ghz summary",
    ]
    try:
        with ios_xe_connection(host, username, password, secret, timeout=90) as conn:
            try:
                conn.send_command_timing("terminal length 0", strip_prompt=False, strip_command=False)
            except Exception:
                pass
            # 5 GHz
            for cmd in variants_5:
                try:
                    out = conn.send_command(cmd, read_timeout=180) or ""
                    lines = out.splitlines()
                    if len(lines) >= 2:
                        samples["5ghz"]["cmd"] = cmd
                        samples["5ghz"]["sample"] = "\n".join(lines[:40])
                        break
                except Exception:
                    continue
            # 2.4 GHz
            for cmd in variants_24:
                try:
                    out = conn.send_command(cmd, read_timeout=180) or ""
                    lines = out.splitlines()
                    if len(lines) >= 2:
                        samples["24ghz"]["cmd"] = cmd
                        samples["24ghz"]["sample"] = "\n".join(lines[:40])
                        break
                except Exception:
                    continue
    except Exception:
        pass
    return samples
