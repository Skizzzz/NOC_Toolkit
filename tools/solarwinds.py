"""SolarWinds helpers for fetching node inventory."""
from __future__ import annotations

import json
from typing import List, Dict, Optional
from urllib.parse import urlparse

import requests


class SolarWindsError(RuntimeError):
    pass


def _build_query_payload() -> Dict[str, str]:
    query = (
        "SELECT n.NodeID, n.Caption, n.Vendor, n.MachineType, n.IOSVersion, n.IPAddress, n.StatusDescription, n.LastSync, "
        "n.CustomProperties.Organization AS Organization "
        "FROM Orion.Nodes n"
    )
    return {"query": query}


def fetch_nodes(
    *,
    base_url: str,
    username: str,
    password: str,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> List[Dict]:
    if not base_url:
        raise SolarWindsError("Base URL is required")
    if not username or not password:
        raise SolarWindsError("SolarWinds credentials are required")

    base = base_url.rstrip("/")
    if not base.lower().startswith("http"):
        base = "https://" + base

    parsed = urlparse(base)
    # Auto-upgrade default HTTPS port to the SWIS HTTPS port (17778) if not provided and URL didn't already include a path.
    if parsed.scheme == "https" and parsed.port in (None, 443) and not parsed.path:
        base = base.replace(f"{parsed.scheme}://{parsed.netloc}", f"https://{parsed.hostname}:17778", 1)
        parsed = urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        raise SolarWindsError("Invalid base URL; include scheme and host (e.g., https://host:17778)")

    root = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}" if parsed.port else f"{parsed.scheme}://{parsed.hostname}"

    candidates = []
    candidates.append(base)

    if "informationservice" not in parsed.path.lower():
        for suffix in [
            "/SolarWinds/InformationService/v3/Json/Query",
            "/Orion/InformationService/v3/Json/Query",
            "/InformationService/v3/Json/Query",
        ]:
            candidate = root + suffix
            if candidate not in candidates:
                candidates.append(candidate)
    else:
        canonical = root + "/SolarWinds/InformationService/v3/Json/Query"
        if canonical not in candidates:
            candidates.append(canonical)
    last_response: Optional[requests.Response] = None

    for endpoint in candidates:
        try:
            response = requests.post(
                endpoint,
                json=_build_query_payload(),
                auth=(username, password),
                timeout=timeout,
                verify=verify_ssl,
            )
        except requests.RequestException as exc:
            raise SolarWindsError(f"Connection failed: {exc}") from exc

        if response.status_code == 404:
            last_response = response
            continue
        if response.status_code >= 400:
            raise SolarWindsError(f"SolarWinds returned {response.status_code}: {response.text[:200]}")
        break
    else:
        snippet = (last_response.text or "").strip().replace('\n', ' ')[:200] if last_response is not None else ""
        raise SolarWindsError(
            "SolarWinds endpoint not found (HTTP 404). "
            "Verify the base URL points to the SWIS service (e.g., https://host:17778). "
            f"Last response snippet: {snippet or '<empty>'}"
        )

    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        snippet = (response.text or "").strip().replace('\n', ' ')[:200]
        if not snippet:
            snippet = "<empty response>"
        elif "<" in snippet and ">" in snippet:
            snippet = f"HTML snippet: {snippet}"
        hint = "Ensure the base URL includes the Orion port (e.g., https://host:17778) and that the account has API access."
        raise SolarWindsError(f"Invalid JSON response from SolarWinds: {snippet}. {hint}") from exc

    items = data.get("results") or data.get("Results") or []
    nodes: List[Dict] = []
    for item in items:
        nodes.append(
            {
                "node_id": item.get("NodeID"),
                "caption": item.get("Caption"),
                "organization": (item.get("Organization") or item.get("CustomProperties.Organization") or "").strip(),
                "vendor": (item.get("Vendor") or "").strip(),
                "model": item.get("MachineType") or "",
                "version": item.get("IOSVersion") or "",
                "ip_address": item.get("IPAddress") or "",
                "status": item.get("StatusDescription") or "",
                "last_seen": item.get("LastSync") or "",
                "raw": item,
            }
        )
    for node in nodes:
        if not node["vendor"]:
            machine = (node.get("model") or "").strip()
            if machine:
                node["vendor"] = machine.split()[0]
        if not node["vendor"]:
            caption = (node.get("caption") or "").strip()
            if caption:
                node["vendor"] = caption.split('.')[0].split()[0]
    return nodes
