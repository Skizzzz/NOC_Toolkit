"""Helpers for polling Summer Guest WLAN status from Cisco 9800 controllers."""
from __future__ import annotations

import re
from typing import Iterable, List, Dict, Tuple, Optional

from .netmiko_helpers import ios_xe_connection

_SPLIT_RE = re.compile(r"\s{2,}")
_STATUS_ENABLED = {"enabled", "up", "active"}
_STATUS_DISABLED = {"disabled", "down", "shutdown", "shut", "inactive"}


def _parse_wlan_summary(output: str) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or not line[0].isdigit():
            continue
        parts = _SPLIT_RE.split(line)
        if len(parts) < 3:
            continue

        wlan_id_raw = parts[0].strip()
        wlan_id = None
        match = re.search(r"(\d+)", wlan_id_raw)
        if match:
            try:
                wlan_id = int(match.group(1))
            except Exception:
                wlan_id = None

        if len(parts) >= 4:
            profile_name = parts[1].strip()
            ssid = parts[2].strip()
            status_text = parts[3].strip()
            security_text = " ".join(parts[4:]).strip() if len(parts) > 4 else ""
        else:
            profile_field = parts[1].strip()
            if "/" in profile_field:
                profile_name, ssid = [chunk.strip() for chunk in profile_field.split("/", 1)]
            else:
                profile_name = profile_field
                ssid = profile_field
            status_text = parts[2].strip() if len(parts) > 2 else ""
            security_text = ""

        entries.append(
            {
                "wlan_id": wlan_id,
                "wlan_id_raw": wlan_id_raw,
                "profile_name": profile_name,
                "ssid": ssid,
                "status_text": status_text,
                "security_text": security_text,
                "raw_line": raw_line.rstrip("\n"),
            }
        )
    return entries


def _normalize_profile_map(profile_names: Iterable[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    exact: Dict[str, str] = {}
    compact: Dict[str, str] = {}
    for name in profile_names or []:
        value = (name or "").strip()
        if not value:
            continue
        exact[value.lower()] = value
        compact[re.sub(r"\s+", "", value.lower())] = value
    return exact, compact


def _classify_status(status_text: str) -> Optional[bool]:
    lowered = (status_text or "").strip().lower()
    if not lowered:
        return None
    if any(token in lowered for token in _STATUS_ENABLED):
        return True
    if any(token in lowered for token in _STATUS_DISABLED):
        return False
    return None


def collect_summer_guest_status(
    host: str,
    username: str,
    password: str,
    secret: str,
    *,
    profile_names: Optional[Iterable[str]] = None,
    wlan_ids: Optional[Iterable[int]] = None,
    auto_prefix: Optional[str] = "Summer",
    timeout: int = 180,
) -> Tuple[List[Dict[str, object]], List[str], Dict[str, object]]:
    """
    Poll a controller for matching WLANs and return their enablement status.

    Returns a tuple of (samples, errors, raw_output).
    Each sample includes host, profile_name, ssid, wlan_id, status_text, enabled, raw.
    """
    profiles_exact, profiles_compact = _normalize_profile_map(profile_names or [])
    wlan_id_set = set()
    for value in wlan_ids or []:
        try:
            wlan_id_set.add(int(value))
        except Exception:
            continue

    auto_prefix_clean = (auto_prefix or "").strip()
    auto_prefix_norm = auto_prefix_clean.lower()

    raw_output = ""
    hostname = None
    samples: List[Dict[str, object]] = []
    errors: List[str] = []

    try:
        with ios_xe_connection(
            host,
            username,
            password,
            secret,
            fast_cli=False,
            timeout=timeout,
            auto_enable=bool(secret),
        ) as conn:
            raw_output = conn.send_command("show wlan summary", read_timeout=timeout)
            try:
                hostname_out = conn.send_command("show running-config | include ^hostname ", read_timeout=timeout)
                match = re.search(r"hostname\s+(\S+)", hostname_out or "")
                if match:
                    hostname = match.group(1)
            except Exception:
                hostname = None
    except Exception as exc:
        errors.append(f"{host}: show wlan summary failed ({exc})")
        return samples, errors, {"raw_output": raw_output, "hostname": hostname}

    entries = _parse_wlan_summary(raw_output or "")
    if not entries:
        errors.append(f"{host}: unable to parse WLAN summary output")
        return samples, errors, {"raw_output": raw_output, "hostname": hostname}

    matched: List[Dict[str, object]] = []
    for entry in entries:
        profile_name = str(entry.get("profile_name") or "")
        profile_key = profile_name.lower()
        profile_compact = re.sub(r"\s+", "", profile_key)
        wlan_id = entry.get("wlan_id")

        hit = False
        prefix_hit = bool(auto_prefix_norm and profile_key.startswith(auto_prefix_norm))

        if profiles_exact and profile_key in profiles_exact:
            hit = True
        elif profiles_compact and profile_compact in profiles_compact:
            hit = True
        elif wlan_id_set and wlan_id is not None and int(wlan_id) in wlan_id_set:
            hit = True
        elif prefix_hit:
            hit = True

        if hit:
            matched.append(entry)

    if not matched:
        target_desc = []
        if profiles_exact:
            target_desc.append("profiles: " + ", ".join(sorted(set(profiles_exact.values()))))
        if wlan_id_set:
            target_desc.append("WLAN IDs: " + ", ".join(str(v) for v in sorted(wlan_id_set)))
        if not target_desc:
            target_desc.append("no filters provided")
        if auto_prefix_norm:
            target_desc.append(f"auto prefix: {auto_prefix_clean}*")
        errors.append(f"{host}: no WLANs matched ({'; '.join(target_desc)})")
        return samples, errors, raw_output

    for entry in matched:
        status_text = str(entry.get("status_text") or "")
        enabled = _classify_status(status_text)
        samples.append(
            {
                "host": host,
                "profile_name": entry.get("profile_name"),
                "ssid": entry.get("ssid"),
                "wlan_id": entry.get("wlan_id"),
                "status_text": status_text,
                "security_text": entry.get("security_text", ""),
                "enabled": enabled,
                "raw": entry,
            }
        )

    return samples, errors, {"raw_output": raw_output, "hostname": hostname}


def set_wlan_state(
    host: str,
    username: str,
    password: str,
    secret: str,
    *,
    profile_name: str,
    wlan_id: int,
    enable: bool,
    psk: Optional[str] = None,
    timeout: int = 180,
) -> None:
    if not profile_name:
        raise ValueError("profile_name required")
    if wlan_id is None:
        raise ValueError("wlan_id required")

    with ios_xe_connection(
        host,
        username,
        password,
        secret,
        fast_cli=False,
        timeout=timeout,
        auto_enable=bool(secret),
    ) as conn:
        commands = [f"wlan {profile_name} {wlan_id}"]
        if enable and psk:
            commands.append(f'security wpa psk set-key ascii "{psk}"')
        commands.append("no shutdown" if enable else "shutdown")
        conn.send_config_set(
            commands,
            read_timeout=timeout,
        )
        conn.send_command("write memory", expect_string=r"#", read_timeout=timeout)
