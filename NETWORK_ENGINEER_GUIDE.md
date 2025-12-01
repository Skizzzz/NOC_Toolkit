# NOC Toolkit - Network Engineer User Guide

## Table of Contents
- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Core Tools](#core-tools)
  - [Interface Config Search](#interface-config-search)
  - [Global Config Push](#global-config-push)
  - [Bulk SSH Terminal](#bulk-ssh-terminal)
  - [Topology Explorer](#topology-explorer)
- [Wireless LAN Controller (WLC) Tools](#wireless-lan-controller-wlc-tools)
  - [WLC Dashboard](#wlc-dashboard)
  - [AP Inventory](#ap-inventory)
  - [RF Troubleshooting](#rf-troubleshooting)
  - [Client Troubleshooting](#client-troubleshooting)
  - [Summer Guest WLAN Manager](#summer-guest-wlan-manager)
- [Monitoring & Integration](#monitoring--integration)
  - [SolarWinds Integration](#solarwinds-integration)
  - [Change Window Management](#change-window-management)
  - [Jobs Center](#jobs-center)
  - [Audit Logs](#audit-logs)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Introduction

The NOC Toolkit is a comprehensive web-based platform designed to streamline network operations center tasks. Built specifically for network engineers, it provides powerful automation tools for managing Cisco IOS/IOS-XE devices, wireless controllers, and network monitoring systems.

### Key Features
- **Multi-device SSH automation** - Execute commands across hundreds of devices simultaneously
- **Wireless controller management** - Monitor and troubleshoot WLCs, APs, and clients
- **Configuration search and modification** - Find and update specific configurations at scale
- **Topology discovery** - Build network maps using CDP/LLDP
- **Change management** - Track and schedule maintenance windows
- **Audit logging** - Complete history of all configuration changes

---

## Getting Started

### Accessing the Toolkit

1. Open your web browser and navigate to the NOC Toolkit URL (provided by your administrator)
2. Log in with your credentials
3. You'll land on the **Dashboard** which provides an overview of:
   - Total WLC clients and access points
   - Background job status
   - Service monitoring status
   - Quick access to tools

### User Roles

The toolkit supports two user roles:
- **Engineer** - Standard access to all tools and features
- **Superadmin** - Full access plus user management capabilities

### Dashboard Overview

The main dashboard displays:
- **WLC Clients** - Total wireless clients across all controllers
- **Access Points** - Number of active APs
- **Background Jobs** - Currently running tasks
- **Network Nodes** - Total devices in SolarWinds (if configured)
- **Service Status** - Health of monitoring services
- **Quick Access Tools** - One-click access to common operations

---

## Core Tools

### Interface Config Search

**Use Case:** Find interfaces by configuration pattern and perform bulk actions

**When to Use:**
- Locate all interfaces with specific descriptions (e.g., "Camera", "AP", "Printer")
- Find interfaces with particular VLANs
- Identify interfaces with specific security configurations
- Bulk modify interface configurations

**How to Use:**

1. Navigate to **Interface Config Search** from the dashboard
2. **Step 1 - Enter Devices:**
   - Provide a list of switch IP addresses or hostnames (one per line)
   - Or paste a comma-separated list
3. **Step 2 - Enter SSH Credentials:**
   - Username (your network device username)
   - Password (credentials are encrypted and not stored)
4. **Step 3 - Search Phrase:**
   - Enter the text to search for (e.g., "Access Point", "description Camera")
   - Case-sensitive matching
5. Click **Search Interfaces**
6. **Review Results:**
   - Table shows all matching interfaces with their descriptions
   - Export to CSV for documentation
7. **Take Action (Optional):**
   - Select **Add**, **Remove**, or **Replace** action
   - Enter the configuration lines to apply
   - Preview changes before applying
   - Execute changes across all selected devices

**Example Workflows:**

*Finding all AP connections:*
```
Search Phrase: "description AP"
Results: All interfaces with AP descriptions
Action: Add "spanning-tree portfast" to harden AP ports
```

*VLAN changes:*
```
Search Phrase: "switchport access vlan 10"
Action: Replace "switchport access vlan 10" → "switchport access vlan 20"
```

**Safety Features:**
- Preview mode shows exact configuration changes before applying
- All changes are logged in audit logs
- Parallel execution with progress tracking

---

### Global Config Push

**Use Case:** Search and modify global configuration settings across multiple devices

**When to Use:**
- Update SNMP communities
- Modify logging servers
- Change NTP servers
- Update AAA configurations
- Add/remove access lists

**How to Use:**

1. Navigate to **Global Config Push**
2. **Enter Devices:** List of IPs/hostnames
3. **Enter Credentials:** SSH username and password
4. **Search Phrase:** Text to find in running config (e.g., "ntp server", "snmp-server")
5. Click **Search Global Config**
6. **Review Results:**
   - Shows matching configuration lines from each device
   - Export results to CSV
7. **Take Action:**
   - Choose **Add**, **Remove**, or **Replace**
   - Enter configuration commands
   - Preview changes
   - Apply to all devices

**Example Workflows:**

*Adding a new NTP server:*
```
Search: "ntp server"
Action: Add "ntp server 10.1.1.100"
```

*Updating SNMP community:*
```
Search: "snmp-server community"
Action: Replace "snmp-server community public" → "snmp-server community NewComm123"
```

**Important Notes:**
- Global config changes apply to the device's global configuration mode
- Changes are applied using `configure terminal` context
- Always preview before applying to production

---

### Bulk SSH Terminal

**Use Case:** Execute arbitrary SSH commands on multiple devices in parallel

**When to Use:**
- Gather show commands from many devices
- Execute custom scripts
- Run operational commands (clear, reload, etc.)
- Use templates for repetitive tasks

**How to Use:**

#### Basic Execution

1. Navigate to **Bulk SSH Terminal**
2. **Enter Devices:** Paste device list (IPs or hostnames)
3. **Enter Credentials:** SSH username and password
4. **Enter Commands:** One command per line
   ```
   show version
   show ip interface brief
   show inventory
   ```
5. **Select Command Type:**
   - **Show Commands** - Read-only (no `configure terminal`)
   - **Configuration Commands** - Enters config mode
6. **Advanced Options:**
   - **Enable Password** (if different from login)
   - **Timeout** (seconds to wait per device)
   - **Parallel Workers** (concurrent connections, default: 10)
7. Click **Execute**

#### Using Templates

Templates allow you to save command sequences with variables:

1. Go to **Bulk SSH Terminal** → **Templates** tab
2. Click **Create New Template**
3. **Template Name:** Descriptive name (e.g., "Add VLAN")
4. **Commands:** Use `{{variable_name}}` syntax
   ```
   configure terminal
   vlan {{vlan_id}}
   name {{vlan_name}}
   end
   show vlan id {{vlan_id}}
   ```
5. Save template
6. When executing:
   - Select template
   - Fill in variable values
   - Execute across devices

**Example Templates:**

*Interface Shutdown:*
```
configure terminal
interface {{interface_name}}
shutdown
end
show interface {{interface_name}} status
```

*ACL Creation:*
```
configure terminal
ip access-list extended {{acl_name}}
permit ip {{source_network}} {{wildcard}} any
end
show ip access-list {{acl_name}}
```

#### Scheduled Jobs

1. Navigate to **Schedules** tab
2. Click **Create Schedule**
3. Configure:
   - **Name:** Job identifier
   - **Template:** Select saved template
   - **Devices:** Target device list
   - **Schedule:** Cron expression or interval
   - **Credentials:** SSH credentials
4. Save - job runs automatically

**Viewing Results:**

1. Navigate to **Jobs** tab
2. Select a job to view:
   - Per-device success/failure status
   - Command output from each device
   - Export results to CSV
3. Search and filter output

**Best Practices:**
- Start with a small device subset for testing
- Use templates for complex or repetitive tasks
- Review job results before scheduling production runs
- Adjust parallel workers based on network capacity (default 10 is safe)

---

### Topology Explorer

**Use Case:** Discover and visualize network topology using CDP/LLDP

**When to Use:**
- Map network connections between devices
- Trace L2 paths
- Document network topology
- Troubleshoot connectivity issues
- Find all devices downstream from a core switch

**How to Use:**

#### Discovery Mode

1. Navigate to **Topology Explorer**
2. **Enter Seed Devices:** Starting points for discovery (core switches)
3. **Enter Credentials:** SSH username/password
4. **Discovery Settings:**
   - **Max Depth:** How many hops to traverse (default: 3)
   - **Protocol:** CDP, LLDP, or both
5. Click **Start Discovery**
6. **Results:**
   - Table showing all discovered neighbor relationships
   - Device-to-device connections with interface details
   - Export to CSV

#### Topology Graph (Visual)

1. After discovery, click **View Graph**
2. Interactive network diagram showing:
   - Devices as nodes
   - Connections as edges
   - Interface labels on links
3. **Features:**
   - Zoom and pan
   - Click nodes for details
   - Export as image

#### Path Tracing

Use topology data to trace paths between devices:
- Identify all L2 hops between endpoints
- Document cable paths
- Plan maintenance impacts

**Example Workflows:**

*Discovering a campus network:*
```
Seed Devices:
  core-sw-01
  core-sw-02
Max Depth: 4
Protocol: CDP

Results: Complete campus topology with all access switches
```

*Finding all devices in a building:*
```
Seed Device: building-a-idf-01
Max Depth: 2
Results: All switches and APs in Building A
```

**Supported Devices:**
- Cisco IOS/IOS-XE switches and routers
- Cisco Wireless LAN Controllers (via SSH)
- Any device supporting CDP or LLDP

---

## Wireless LAN Controller (WLC) Tools

### WLC Dashboard

**Use Case:** Real-time monitoring of wireless clients and access points

**Features:**
- **Live Client Counts** - Total wireless clients across all WLCs
- **AP Status** - Active, inactive, and total AP counts
- **Historical Graphs** - Time-series charts of clients/APs
- **Per-WLC Breakdown** - Individual controller statistics
- **Alert Thresholds** - Visual warnings for abnormal activity

**How to Use:**

1. Navigate to **WLC Dashboard**
2. **First-time Setup:**
   - Click **Settings**
   - Add WLC IP addresses (one per line)
   - Enter SSH credentials (username/password)
   - Set polling interval (default: 5 minutes)
   - Click **Save & Start Polling**
3. **Monitor Dashboard:**
   - View real-time client/AP counts
   - Analyze historical trends on charts
   - Check per-controller details in table

**Polling Settings:**
- **Interval:** 1-60 minutes (5 min recommended)
- **Auto-polling:** Background task updates data automatically
- **Pause/Resume:** Stop polling without losing historical data

**Understanding the Graphs:**

*Client Count Chart:*
- Shows total clients over time
- Useful for capacity planning
- Identify peak usage hours

*AP Count Chart:*
- Tracks AP availability
- Detect AP failures (sudden drops)
- Monitor AP provisioning

**Troubleshooting:**
- If data stops updating, check:
  - Polling is enabled (Settings page)
  - WLC credentials are valid
  - Network connectivity to WLCs
  - Jobs Center for errors

---

### AP Inventory

**Use Case:** Query and export access point inventory from wireless controllers

**When to Use:**
- Generate AP inventory reports
- Find APs by name, model, or location
- Verify AP software versions
- Track AP serial numbers for RMA
- Capacity planning

**How to Use:**

1. Navigate to **AP Inventory**
2. **Enter WLCs:** List of WLC IPs/hostnames
3. **Enter Credentials:** SSH username/password
4. Click **Fetch AP Inventory**
5. **Results Table:**
   - AP Name
   - Model
   - Serial Number
   - MAC Address
   - IP Address
   - Software Version
   - Controller joined to
   - Uptime
6. **Export:** Click **Export CSV** to download results

**Example Queries:**

*All APs in a building:*
```
WLCs: wlc-building-a
Filter results by AP name pattern
```

*All APs running old firmware:*
```
Query all WLCs
Sort by software version
Identify APs needing upgrade
```

**Pro Tips:**
- Run inventory quarterly for asset management
- Compare against previous exports to track changes
- Use CSV export for importing into asset databases
- Schedule bulk SSH job to gather detailed AP configs

---

### RF Troubleshooting

**Use Case:** Monitor and troubleshoot wireless RF performance

**Features:**
- **Channel Distribution** - View channel utilization per AP
- **TX Power Levels** - Identify power misconfigurations
- **Interference Detection** - Find sources of RF interference
- **Client RSSI Analysis** - Identify poor client connections
- **RRM Monitoring** - Track Radio Resource Management changes

**How to Use:**

1. Navigate to **WLC RF Troubleshooting**
2. **Enter WLCs:** WLC IPs to query
3. **Enter Credentials:** SSH credentials
4. **Select Radio Band:** 2.4GHz, 5GHz, or both
5. Click **Collect RF Data**
6. **Results:**
   - Per-AP radio settings
   - Channel assignments
   - Power levels
   - Interference metrics
   - Export to CSV

**Troubleshooting Workflows:**

*Channel overlap issues:*
```
1. Collect RF data for all WLCs
2. Sort by Channel
3. Identify channel conflicts
4. Review RRM settings
```

*Poor coverage areas:*
```
1. Collect client data (see Client Troubleshooting)
2. Filter by low RSSI (<-70 dBm)
3. Identify APs with weak signal
4. Plan AP additions/relocations
```

**Scheduled Monitoring:**

Use the **RF Dashboard** feature for automated monitoring:
1. Navigate to **Settings**
2. Configure WLCs and credentials
3. Set polling interval
4. Enable scheduled collection
5. Review historical RF trends

---

### Client Troubleshooting

**Use Case:** Troubleshoot wireless client connectivity and performance issues

**Features:**
- **Client Association Status** - Find connected clients
- **RSSI/SNR Values** - Signal strength metrics
- **AP Association** - Which AP each client is connected to
- **VLAN/SSID Information** - Network assignment
- **Auth Status** - Authentication/association state

**How to Use:**

1. Navigate to **WLC Client Troubleshooting**
2. **Enter WLCs:** WLC IPs to query
3. **Enter Credentials:** SSH credentials
4. **Search Criteria (optional):**
   - Client MAC address
   - Client IP address
   - SSID name
5. Click **Search Clients**
6. **Results:**
   - Client MAC/IP
   - Associated AP
   - RSSI/SNR
   - SSID/VLAN
   - Auth status
   - Data rate

**Troubleshooting Workflows:**

*Client can't connect:*
```
1. Search by client MAC
2. Check association status
3. Verify VLAN assignment
4. Check authentication state
5. Review RSSI (should be > -70 dBm)
```

*Slow performance:*
```
1. Find client in results
2. Check data rate (should be ≥ 24 Mbps)
3. Verify RSSI/SNR
4. Look for high retry rates
5. Check AP channel utilization
```

*Roaming issues:*
```
1. Track client over time
2. Identify AP transitions
3. Check RSSI at roam trigger points
4. Review RRM settings
```

**Export and Reporting:**
- Export client lists to CSV
- Track client counts over time
- Generate reports for capacity planning

---

### Summer Guest WLAN Manager

**Use Case:** Automated seasonal management of guest wireless networks

**Purpose:** Automatically enable/disable guest WLANs during specific months (e.g., summer programs)

**How to Use:**

1. Navigate to **Summer Guest WLAN Manager**
2. **Settings:**
   - Enter WLC IPs
   - SSH credentials
   - WLAN ID to manage (e.g., WLAN 8)
   - Schedule: Define on/off months
     - Example: Enable June-August, Disable September-May
   - Polling interval
3. Click **Save & Enable**

**Automated Workflow:**

The system will:
1. Check schedule at configured intervals
2. Query current WLAN state on WLCs
3. If state doesn't match schedule:
   - Enable WLAN during "on" months
   - Disable WLAN during "off" months
4. Log all actions in audit log
5. Send alerts if changes fail

**Monitoring:**

View the **Status** tab to see:
- Current WLAN state on each WLC
- Last check time
- Next scheduled action
- Recent run history

**Use Cases:**
- Seasonal guest WiFi for summer programs
- Event-based WLAN activation
- Automated network segmentation
- Compliance with security policies

---

## Monitoring & Integration

### SolarWinds Integration

**Use Case:** Import device inventory from SolarWinds NPM

**Features:**
- Import managed nodes from SolarWinds
- Filter by device type, vendor, or location
- Use for bulk operations in other tools
- Keep device lists synchronized

**How to Use:**

1. Navigate to **SolarWinds Nodes**
2. **Settings:**
   - SolarWinds API URL (e.g., `https://solarwinds.company.com:17778/SolarWinds/InformationService/v3/Json/Query`)
   - Username (SolarWinds account)
   - Password
   - Polling interval (hours)
3. Click **Save & Sync**
4. **View Nodes:**
   - All imported devices in table
   - Filter by name, IP, vendor
   - Export to CSV
5. **Use in Other Tools:**
   - Copy IP list for bulk SSH operations
   - Import into topology discovery

**Supported Queries:**
- All managed nodes
- Nodes by vendor (Cisco, Juniper, etc.)
- Nodes by type (Router, Switch, Firewall)
- Custom SWQL queries (advanced)

---

### Change Window Management

**Use Case:** Schedule and track network maintenance windows

**Features:**
- Schedule maintenance windows with start/end times
- Assign devices/scope to changes
- Track change status and notes
- Receive alerts for upcoming changes
- Audit trail of all changes

**How to Use:**

#### Creating a Change Window

1. Navigate to **Change Windows**
2. Click **Schedule New Change**
3. **Fill in Details:**
   - **Title:** Brief description (e.g., "Core Switch Upgrade")
   - **Description:** Detailed change plan
   - **Scheduled Start:** Date and time
   - **Scheduled End:** Estimated completion
   - **Affected Hosts:** Device list (IPs/hostnames)
   - **Change Type:** Emergency, Planned, Routine
   - **Assignee:** Engineer responsible
4. Click **Schedule**

#### Tracking Changes

1. View **Changes List** to see:
   - Upcoming changes
   - In-progress changes
   - Completed changes
2. Click a change for details:
   - Full change description
   - Timeline
   - Affected devices
   - Event log
   - Notes

#### During a Change

1. Open the change window
2. Add updates to **Event Log:**
   - "Started router upgrade"
   - "Completed IOS upgrade"
   - "Testing connectivity"
3. Mark change as **Complete** when done

**Best Practices:**
- Schedule changes at least 24 hours in advance
- Include rollback plan in description
- Update event log during the change
- Review completed changes for lessons learned

**Dashboard Integration:**
- Upcoming changes appear on main dashboard
- Alerts for changes starting soon
- Track change history in audit logs

---

### Jobs Center

**Use Case:** Monitor and manage background tasks

**What Are Jobs?**

Jobs are long-running tasks that execute in the background:
- Bulk SSH operations
- Topology discoveries
- AP inventory collections
- WLC data polling
- Scheduled tasks

**How to Use:**

1. Navigate to **Jobs Center**
2. **View All Jobs:**
   - Job ID
   - Type (SSH, Topology, WLC, etc.)
   - Status (Running, Completed, Failed)
   - Start time
   - Duration
3. **Click a Job** to view:
   - Detailed progress
   - Event log
   - Per-device results
   - Error messages

**Job Statuses:**
- **Running:** Currently executing
- **Completed:** Finished successfully
- **Failed:** Encountered errors
- **Canceled:** Manually stopped

**Managing Jobs:**
- **Monitor Progress:** Real-time updates on running jobs
- **View Results:** Click completed jobs for output
- **Retry Failed:** Re-run failed jobs
- **Cancel:** Stop long-running jobs if needed

**Performance Monitoring:**
- Jobs dashboard shows active task count
- Alerts if jobs fail repeatedly
- Historical job data for trend analysis

---

### Audit Logs

**Use Case:** Complete audit trail of all configuration changes and actions

**What's Logged?**
- All configuration changes pushed to devices
- Bulk SSH commands executed
- WLC modifications
- User logins/logouts
- Change window updates
- Settings modifications

**How to Use:**

1. Navigate to **Audit Logs**
2. **View Logs:**
   - Timestamp
   - User who performed action
   - Action type (Config Change, Command Exec, Login, etc.)
   - Target devices
   - Details/output
3. **Filter Logs:**
   - By date range
   - By user
   - By action type
   - By device IP

**Example Queries:**

*All changes by a user:*
```
Filter: User = "jdoe"
Date Range: Last 7 days
```

*All config changes to a device:*
```
Filter: Target Device = "10.1.1.1"
Action Type: Config Change
```

*Failed login attempts:*
```
Action Type: Login
Status: Failed
```

**Compliance:**
- Logs are immutable (cannot be deleted/modified)
- Provides evidence for change control
- Supports compliance audits
- Tracks unauthorized changes

**Export:**
- Export logs to CSV for reporting
- Import into SIEM systems
- Long-term archival

---

## Best Practices

### Security

1. **Credentials:**
   - Never share login credentials
   - Use strong passwords
   - Change credentials if compromised
   - Credentials are encrypted at rest

2. **Change Control:**
   - Always preview changes before applying
   - Test on non-production first
   - Schedule changes during maintenance windows
   - Document all changes in Change Windows

3. **Access Control:**
   - Request appropriate user role (Engineer vs Superadmin)
   - Log out when finished
   - Report suspicious activity

### Operational Best Practices

1. **Bulk Operations:**
   - Start small - test on 2-3 devices first
   - Verify results before scaling up
   - Use parallel workers conservatively (10-20)
   - Monitor Jobs Center during execution

2. **Configuration Changes:**
   - Always use preview mode
   - Save running-config to startup-config separately
   - Keep backups before major changes
   - Test rollback procedures

3. **Monitoring:**
   - Check dashboard daily for anomalies
   - Review failed jobs promptly
   - Set appropriate polling intervals (5-15 min)
   - Don't over-poll devices (increases load)

4. **Documentation:**
   - Export results to CSV for records
   - Use Change Windows for all maintenance
   - Add notes to completed changes
   - Keep topology maps up to date

### Performance Optimization

1. **Parallel Workers:**
   - Default: 10 workers (safe for most networks)
   - Increase to 20-30 for large, robust networks
   - Decrease to 5 if experiencing timeouts
   - Consider network bandwidth limitations

2. **Timeouts:**
   - Default: 30 seconds (usually sufficient)
   - Increase to 60s for slow devices
   - Increase to 120s for complex commands (show tech-support)

3. **Polling Intervals:**
   - WLC Dashboard: 5-10 minutes
   - SolarWinds: 1-4 hours
   - RF Monitoring: 15-30 minutes
   - Balance between freshness and device load

---

## Troubleshooting

### Common Issues

#### "Connection Timeout" Errors

**Symptoms:** Bulk SSH jobs fail with timeout errors

**Causes:**
- Network connectivity issues
- Device under heavy load
- Firewall blocking SSH
- Incorrect IP address

**Solutions:**
1. Verify device is reachable (ping)
2. Test SSH manually from toolkit server
3. Increase timeout setting (60-120s)
4. Reduce parallel workers (5-10)
5. Check device CPU load

---

#### "Authentication Failed" Errors

**Symptoms:** Cannot connect to devices, auth errors in logs

**Causes:**
- Incorrect username/password
- AAA configuration issues
- Privilege level restrictions
- Account locked/expired

**Solutions:**
1. Verify credentials by manual SSH
2. Check if enable password is required
3. Ensure account has privilege 15 or appropriate level
4. Verify AAA configuration on devices

---

#### WLC Polling Stopped

**Symptoms:** Dashboard shows stale data, "Last Poll: X hours ago"

**Causes:**
- Polling paused in settings
- WLC credentials changed
- Network connectivity lost
- Background service crashed

**Solutions:**
1. Go to WLC Dashboard → Settings
2. Verify polling is enabled
3. Re-enter credentials and save
4. Check Jobs Center for errors
5. Click "Start Polling" to resume

---

#### Slow Performance

**Symptoms:** Web UI is slow, jobs take excessive time

**Causes:**
- Too many parallel workers
- Large number of devices
- Database growth
- Network latency

**Solutions:**
1. Reduce parallel workers to 10
2. Break large jobs into smaller batches
3. Increase device timeouts
4. Check toolkit server resources (CPU/RAM)
5. Optimize database (contact admin)

---

#### Changes Not Applied

**Symptoms:** Configuration push completes but changes not on device

**Causes:**
- Command syntax errors
- Device rejected config
- Missing "end" or "write memory" command
- Insufficient privileges

**Solutions:**
1. Check job results for error messages
2. Verify command syntax
3. Test commands manually on one device
4. Check audit logs for detailed output
5. Ensure running-config was saved (add "write memory" to commands)

---

#### Can't See Other Users' Jobs

**Symptoms:** Jobs Center only shows your own jobs

**Expected Behavior:**
- This is normal - users only see their own jobs for security
- Superadmins can see all jobs

**Solution:**
- Request Superadmin role if you need visibility into all jobs

---

### Getting Help

1. **Check Audit Logs:**
   - Most actions are logged with detailed output
   - Review error messages for clues

2. **Jobs Center:**
   - Failed jobs include error details
   - Event logs show step-by-step execution

3. **Export Results:**
   - Export job results to CSV
   - Share with team for collaborative troubleshooting

4. **Contact Administrator:**
   - If issues persist, contact your NOC Toolkit administrator
   - Provide job ID, timestamp, and error messages

---

## Appendix: Command Reference

### Common Cisco IOS Commands for Bulk SSH

#### Show Commands (Read-Only)
```
show version
show ip interface brief
show vlan brief
show spanning-tree summary
show cdp neighbors
show inventory
show running-config
show interfaces status
show mac address-table
show ip route
show logging
```

#### Configuration Commands
```
configure terminal
interface {{interface_name}}
description {{description}}
switchport mode access
switchport access vlan {{vlan_id}}
no shutdown
end
write memory
```

### WLC Commands Reference

#### Show Commands via SSH
```
show wlan summary
show ap summary
show client summary
show rf profile summary
show 802.11a
show 802.11b
show advanced 802.11a summary
show advanced 802.11b summary
```

---

## Glossary

- **AP** - Access Point (wireless)
- **CDP** - Cisco Discovery Protocol
- **LLDP** - Link Layer Discovery Protocol
- **RSSI** - Received Signal Strength Indicator (wireless signal strength)
- **SNR** - Signal-to-Noise Ratio
- **SSID** - Service Set Identifier (wireless network name)
- **VLAN** - Virtual Local Area Network
- **WLC** - Wireless LAN Controller
- **RRM** - Radio Resource Management
- **AAA** - Authentication, Authorization, and Accounting

---

## Quick Start Checklist

For new users, follow this checklist to get started:

- [ ] Log in to NOC Toolkit
- [ ] Familiarize yourself with the Dashboard
- [ ] Review Audit Logs to see recent activity
- [ ] Try Interface Config Search on a test switch
  - [ ] Search for a simple phrase
  - [ ] Export results to CSV
  - [ ] Preview a change (don't apply yet)
- [ ] Execute a simple Bulk SSH command
  - [ ] Use "show version" on 2-3 switches
  - [ ] Review results in Jobs Center
  - [ ] Export output
- [ ] Explore WLC Dashboard (if WLCs are configured)
  - [ ] Check client counts
  - [ ] View AP inventory
- [ ] Create a test Change Window
  - [ ] Schedule for future date
  - [ ] Add notes
  - [ ] Mark as complete after test
- [ ] Review this guide's Best Practices section
- [ ] Bookmark this guide for reference

---

**Document Version:** 1.0
**Last Updated:** 2025
**Platform:** NOC Toolkit

For questions, feature requests, or issues, contact your Network Operations Center administrator.
