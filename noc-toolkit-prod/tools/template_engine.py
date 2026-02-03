"""Template engine for bulk SSH command templates with variable substitution."""
import re
from typing import Dict, List, Tuple


def extract_variables(command: str) -> List[str]:
    """
    Extract variable names from a command template.

    Variables are in the format {{variable_name}}

    Example:
        "show interface {{interface}}" -> ["interface"]
    """
    pattern = r'\{\{(\w+)\}\}'
    matches = re.findall(pattern, command)
    # Return unique variables in order of appearance
    seen = set()
    variables = []
    for var in matches:
        if var not in seen:
            seen.add(var)
            variables.append(var)
    return variables


def substitute_variables(command: str, values: Dict[str, str]) -> str:
    """
    Substitute variables in a command template with provided values.

    Args:
        command: Template string with {{variable}} placeholders
        values: Dictionary mapping variable names to values

    Returns:
        Command string with variables substituted

    Example:
        command = "show interface {{interface}}"
        values = {"interface": "GigabitEthernet0/1"}
        result = "show interface GigabitEthernet0/1"
    """
    result = command
    for var, value in values.items():
        pattern = r'\{\{' + re.escape(var) + r'\}\}'
        result = re.sub(pattern, value, result)
    return result


def validate_template(command: str, values: Dict[str, str]) -> Tuple[bool, List[str]]:
    """
    Validate that all variables in a template have values.

    Returns:
        Tuple of (is_valid, missing_variables)
    """
    required_vars = extract_variables(command)
    missing = [var for var in required_vars if var not in values or not values[var]]
    return (len(missing) == 0, missing)


def get_common_templates() -> List[Dict]:
    """Return a list of common pre-built templates."""
    return [
        {
            "name": "Interface Status Check",
            "description": "Check status of a specific interface",
            "command": "show interface {{interface}}",
            "variables": "interface",
            "category": "troubleshooting",
            "device_type": "cisco_ios",
        },
        {
            "name": "Find MAC Address",
            "description": "Search for a MAC address across all interfaces",
            "command": "show mac address-table | include {{mac}}",
            "variables": "mac",
            "category": "troubleshooting",
            "device_type": "cisco_ios",
        },
        {
            "name": "VLAN Status",
            "description": "Show status of a specific VLAN",
            "command": "show vlan id {{vlan_id}}",
            "variables": "vlan_id",
            "category": "troubleshooting",
            "device_type": "cisco_ios",
        },
        {
            "name": "Health Check",
            "description": "Basic device health check - version, uptime, memory, CPU",
            "command": "show version | include uptime|Processor|Software",
            "variables": "",
            "category": "monitoring",
            "device_type": "cisco_ios",
        },
        {
            "name": "Interface Brief",
            "description": "Show all interface statuses",
            "command": "show ip interface brief",
            "variables": "",
            "category": "monitoring",
            "device_type": "cisco_ios",
        },
        {
            "name": "BGP Summary",
            "description": "Show BGP neighbor summary",
            "command": "show ip bgp summary",
            "variables": "",
            "category": "routing",
            "device_type": "cisco_ios",
        },
        {
            "name": "OSPF Neighbors",
            "description": "Show OSPF neighbor adjacencies",
            "command": "show ip ospf neighbor",
            "variables": "",
            "category": "routing",
            "device_type": "cisco_ios",
        },
        {
            "name": "Interface Errors",
            "description": "Check for interface errors and drops",
            "command": "show interface {{interface}} | include error|drop|collision",
            "variables": "interface",
            "category": "troubleshooting",
            "device_type": "cisco_ios",
        },
        {
            "name": "ARP Table Search",
            "description": "Search ARP table for an IP address",
            "command": "show ip arp | include {{ip_address}}",
            "variables": "ip_address",
            "category": "troubleshooting",
            "device_type": "cisco_ios",
        },
        {
            "name": "Running Config Backup",
            "description": "Get full running configuration",
            "command": "show running-config",
            "variables": "",
            "category": "backup",
            "device_type": "cisco_ios",
        },
    ]
