"""Shared helpers for creating Netmiko connections consistently."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Optional

from netmiko import ConnectHandler


def _build_device_dict(
    *,
    host: str,
    username: str,
    password: str,
    secret: Optional[str],
    device_type: str,
    fast_cli: bool,
    timeout: int,
    global_delay_factor: int,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    device: Dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": fast_cli,
        "timeout": timeout,
        "global_delay_factor": global_delay_factor,
    }
    if secret:
        device["secret"] = secret
    if extra:
        device.update(extra)
    return device


@contextmanager
def ios_connection(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
    *,
    fast_cli: bool = True,
    timeout: int = 90,
    global_delay_factor: int = 1,
    auto_enable: bool = False,
    extra: Optional[Dict[str, Any]] = None,
):
    """Yield an active Netmiko connection to an IOS device.

    Parameters mirror the common kwargs we previously duplicated across tools.
    """
    device = _build_device_dict(
        host=host,
        username=username,
        password=password,
        secret=secret,
        device_type="cisco_ios",
        fast_cli=fast_cli,
        timeout=timeout,
        global_delay_factor=global_delay_factor,
        extra=extra,
    )
    conn = ConnectHandler(**device)
    if auto_enable and secret:
        try:
            conn.enable()
        except Exception:
            pass
    try:
        yield conn
    finally:
        conn.disconnect()


@contextmanager
def ios_xe_connection(
    host: str,
    username: str,
    password: str,
    secret: Optional[str] = None,
    *,
    fast_cli: bool = True,
    timeout: int = 90,
    global_delay_factor: int = 1,
    auto_enable: bool = True,
    extra: Optional[Dict[str, Any]] = None,
):
    """Yield an IOS-XE Netmiko connection (e.g., Cisco 9800 WLC)."""
    device = _build_device_dict(
        host=host,
        username=username,
        password=password,
        secret=secret,
        device_type="cisco_xe",
        fast_cli=fast_cli,
        timeout=timeout,
        global_delay_factor=global_delay_factor,
        extra=extra,
    )
    conn = ConnectHandler(**device)
    if auto_enable and secret:
        try:
            conn.enable()
        except Exception:
            pass
    try:
        yield conn
    finally:
        conn.disconnect()
