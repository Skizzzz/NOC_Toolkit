# NOC Toolkit Production Runbook

**Version:** 1.0
**Last Updated:** January 27, 2026

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Installation and Startup](#installation-and-startup)
3. [Database Configuration](#database-configuration)
4. [Timezone Configuration](#timezone-configuration)
5. [Scheduled Job Systems](#scheduled-job-systems)
6. [New Features](#new-features)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Security Considerations](#security-considerations)
9. [Backup and Recovery](#backup-and-recovery)

---

## System Overview

The NOC Toolkit is a Flask-based web application that provides network operations center engineers with tools for:

- **WLC Dashboard:** Real-time wireless controller monitoring (Cisco 9800, Aruba 72XX)
- **Bulk SSH:** Multi-device command execution with templates and scheduling
- **Change Management:** Scheduled network changes with rollback capability
- **SolarWinds Integration:** Node synchronization and inventory management
- **Certificate Tracker:** SSL certificate monitoring with ISE sync
- **Topology Builder:** CDP/LLDP neighbor discovery and visualization
- **Device Inventory:** Hardware/software inventory tracking
- **Knowledge Base:** Internal documentation with role-based access

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Flask Application                     │
│                       (app.py)                          │
├─────────────────────────────────────────────────────────┤
│   Background Workers (Daemon Threads)                   │
│   ├── WLC Dashboard Poller                              │
│   ├── Bulk SSH Schedule Worker                          │
│   ├── Change Management Scheduler                       │
│   ├── WLC Summer Guest Scheduler                        │
│   └── Certificate Sync Worker                           │
├─────────────────────────────────────────────────────────┤
│   Data Layer                                            │
│   ├── SQLite: ~/.noc_toolkit/noc_toolkit.db (data)      │
│   ├── SQLite: ./noc_toolkit.db (auth)                   │
│   ├── Fernet Encryption Keys                            │
│   └── CSV Audit Logs: ./logs/changes.csv                │
└─────────────────────────────────────────────────────────┘
```

---

## Installation and Startup

### Prerequisites

- Python 3.9+
- pip
- Network access to target devices and SolarWinds server

### Installation

```bash
# Clone repository
git clone <repository-url>
cd noc-toolkit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Start application
python app.py
```

### Default Credentials

- **Username:** admin
- **Password:** admin123

**IMPORTANT:** Change the default password immediately after first login.

### Configuration Files

| File | Purpose |
|------|---------|
| `~/.noc_toolkit/noc_toolkit.db` | Main data database |
| `./noc_toolkit.db` | Authentication database |
| `./wlc_dashboard.key` | Fernet encryption key for passwords |
| `./logs/changes.csv` | Configuration change audit log |

---

## Database Configuration

### Database Locations

The toolkit uses **two separate SQLite databases**:

1. **Data Database:** `~/.noc_toolkit/noc_toolkit.db`
   - WLC dashboard settings and time-series data
   - Bulk SSH templates, jobs, schedules
   - Change windows and events
   - SolarWinds nodes
   - AP inventory
   - Certificate tracking
   - Device inventory

2. **Auth Database:** `./noc_toolkit.db` (project local)
   - User accounts
   - Audit log entries
   - Page settings

### Important Tables

| Table | Purpose |
|-------|---------|
| `app_settings` | Application-wide settings (timezone) |
| `wlc_dashboard_settings` | WLC poller configuration |
| `wlc_time_series` | Historical wireless metrics |
| `ap_inventory` | Auto-updating AP inventory |
| `bulk_ssh_templates` | SSH command templates |
| `bulk_ssh_schedules` | Scheduled SSH jobs |
| `change_windows` | Scheduled network changes |
| `solarwinds_nodes` | Synced SolarWinds inventory |
| `certificates` | Tracked SSL certificates |
| `ise_nodes` | ISE nodes for cert sync |

---

## Timezone Configuration

### Overview

The NOC Toolkit supports configurable timezone for all scheduled operations. The timezone setting affects:

- Change window execution times
- Bulk SSH schedule execution
- WLC Summer Guest automation
- Certificate expiry calculations
- Time display throughout the UI

### Configuration

1. Navigate to **Admin > App Settings**
2. Select the desired timezone from the dropdown
3. Click **Save Settings**

### Available Timezones

| Timezone | UTC Offset | Description |
|----------|------------|-------------|
| America/New_York | UTC-5/-4 | Eastern Time |
| America/Chicago | UTC-6/-5 | Central Time (Default) |
| America/Denver | UTC-7/-6 | Mountain Time |
| America/Phoenix | UTC-7 | Arizona (No DST) |
| America/Los_Angeles | UTC-8/-7 | Pacific Time |
| America/Anchorage | UTC-9/-8 | Alaska Time |
| Pacific/Honolulu | UTC-10 | Hawaii Time |

### How Timezone Affects Scheduling

All scheduled operations use the configured timezone:

```
Schedule: "Run at 2:00 PM daily"
Configured Timezone: America/Chicago (CST/CDT)

Result: Job runs at 2:00 PM Central Time
- During standard time: 20:00 UTC
- During daylight time: 19:00 UTC
```

### Implementation Details

- Use `get_app_timezone()` to get the IANA timezone string
- Use `get_app_timezone_info()` to get a `ZoneInfo` object
- All `datetime.now()` calls in scheduling code should use the timezone:
  ```python
  from tools.db_jobs import get_app_timezone_info
  now = datetime.now(get_app_timezone_info())
  ```

---

## Scheduled Job Systems

### 1. WLC Dashboard Poller

**Purpose:** Polls wireless LAN controllers for statistics and AP data.

**Configuration Location:** `/tools/wlc/dashboard/settings`

| Setting | Description | Default |
|---------|-------------|---------|
| Poll Interval | Minutes between polls | 5 |
| Cisco Hosts | List of 9800 controllers | Auto-detected from SolarWinds |
| Aruba Hosts | List of Aruba controllers | Auto-detected from SolarWinds |

**Timing Behavior:**
- Runs as daemon thread
- Polls all configured hosts at each interval
- Stores time-series data for historical graphs
- Updates AP inventory during each poll (see [AP Inventory](#ap-inventory))

**Wake Events:**
- `_POLL_WAKE.set()` - Triggers immediate poll

### 2. Bulk SSH Schedule Worker

**Purpose:** Executes scheduled SSH jobs at configured times.

**Configuration Location:** `/tools/bulk-ssh/schedules`

**Schedule Types:**
| Type | Description | Example |
|------|-------------|---------|
| once | Single execution at specified time | "Run at 2026-01-28 14:00" |
| daily | Daily at specified time | "Run every day at 08:00" |
| weekly | Weekly on specified days | "Run Mon, Wed, Fri at 06:00" |

**Timing Behavior:**
- Worker checks for due schedules every 60 seconds
- Jobs are considered due when `next_run <= now()`
- After execution, `next_run` is recalculated based on schedule type
- One-time schedules are disabled after execution

**Timezone Considerations:**
- Schedule times are stored and displayed in configured timezone
- Due check uses `datetime.now(get_app_timezone_info())`

### 3. Change Management Scheduler

**Purpose:** Executes network changes at scheduled times with optional rollback.

**Configuration Location:** Changes created via Interface Search, Global Config, or Summer Guest tools

**Status Transitions:**
```
scheduled → running → completed
                   → failed
                        ↓
              rollback-running → rolled-back
                              → rollback-failed
```

**Timing Behavior:**
- Scheduler loop runs every 30 seconds
- Changes are due when `scheduled_for <= now()` and status is `scheduled`
- Supports auto-rollback configuration

**Wake Events:**
- `_CHANGE_WAKE.set()` - Triggers immediate scheduler check

### 4. WLC Summer Guest Scheduler

**Purpose:** Automatically enables/disables Summer Guest WLANs at configured times.

**Configuration Location:** `/tools/wlc/summer-guest/settings`

| Setting | Description |
|---------|-------------|
| Poll Time | Daily time to run (HH:MM) |
| Timezone | IANA timezone for scheduling |
| Enable Scheduler | Master enable/disable |
| Profile Names | WLAN profile names to manage |
| WLAN IDs | WLAN IDs corresponding to profiles |

**Timing Behavior:**
- Worker waits up to 5 minutes between checks
- Checks if current time matches configured poll time
- Uses its own configurable timezone (falls back to app timezone)

**Wake Events:**
- `_SUMMER_WAKE.set()` - Triggers immediate check after settings change

### 5. Certificate Sync Worker

**Purpose:** Syncs SSL certificates from ISE nodes.

**Configuration Location:** `/certificates/ise-nodes`

| Setting | Description |
|---------|-------------|
| Auto Sync Enabled | Enable automatic sync |
| Sync Interval | Hours between syncs |

**Timing Behavior:**
- Worker checks every 60 seconds
- Syncs when `last_sync + interval <= now()`
- Uses REST API to fetch certificates from ISE nodes

---

## New Features

### AP Inventory

**Purpose:** Automatically tracks access points discovered during WLC polling.

**Location:** `/tools/wlc/ap-inventory`

**Features:**
- Automatic population during WLC dashboard polling
- Deduplication by (AP MAC, WLC Host) combination
- 5-day stale removal (APs not seen in 5 days are automatically deleted)
- CSV export with filtering
- Filter by WLC, model, location, name

**Data Fields:**
| Field | Description |
|-------|-------------|
| ap_name | Access point name |
| ap_ip | IP address |
| ap_model | Hardware model |
| ap_mac | Ethernet MAC address |
| ap_location | Configured location string |
| ap_state | Operational state |
| slots | Number of radio slots |
| country | Country code |
| wlc_host | Controller hostname |
| first_seen | First discovery timestamp |
| last_seen | Most recent discovery timestamp |

**Audit Logging:**
- Removed APs are logged with action `ap_inventory_cleanup`
- Includes AP name, MAC, model, WLC host, and last seen time

### SolarWinds Inventory

**Purpose:** Provides hardware/software inventory view for CVE impact assessment.

**Location:** `/tools/solarwinds/inventory`

**Features:**
- Summary charts (devices by vendor, top software versions)
- Multi-select filters (vendor, model, software version)
- Version search with wildcards and regex
- Vendor → Model → Version hierarchy view
- Click-to-filter on version counts
- Full inventory CSV export
- Aggregation summary CSV export

**Version Search Syntax:**
| Pattern | Example | Description |
|---------|---------|-------------|
| Plain text | `15.2` | Substring match (case-insensitive) |
| Wildcard | `15.*` | Matches `15.2.3`, `15.10.1`, etc. |
| Regex | `re:^15\.[2-5]` | Regex pattern match |

**CSV Exports:**
1. **Full Export:** All devices with all fields
2. **Summary Export:** Vendor/Model/Version hierarchy with counts

---

## Troubleshooting Guide

### Common Issues

#### 1. Schedule Not Executing at Expected Time

**Symptoms:**
- Scheduled jobs run at wrong time
- Timestamps appear offset

**Diagnosis:**
1. Check configured timezone in Admin > App Settings
2. Verify server system time: `date`
3. Compare configured timezone with server timezone

**Resolution:**
- Ensure application timezone matches your operational timezone
- All schedules use the configured timezone, not server time

#### 2. WLC Dashboard Shows "Poll Failed"

**Symptoms:**
- Poll status shows error
- No data in time-series graphs

**Diagnosis:**
1. Check WLC credentials in Settings
2. Verify network connectivity to controllers
3. Check SSH access to controllers manually

**Resolution:**
- Update credentials if changed
- Verify firewall rules allow SSH (port 22)
- Test with: `ssh username@wlc-host`

#### 3. SolarWinds Sync Returns Zero Nodes

**Symptoms:**
- Node count shows 0
- Filters show no options

**Diagnosis:**
1. Check SolarWinds credentials in Settings
2. Verify SWIS API port (17778)
3. Check SSL verification setting

**Resolution:**
- Test connection with "Test Connection" button
- Disable SSL verification if using self-signed certificate
- Verify API endpoint: `https://server:17778/SolarWinds/InformationService/v3/Json/Query`

#### 4. Certificate Tracker Shows "Unknown" Expiry

**Symptoms:**
- Certificates display with "Unknown" status
- Days until expiry shows "-"

**Diagnosis:**
1. Check certificate file format (must be PEM)
2. Verify certificate contains expiry date
3. Check for parsing errors in logs

**Resolution:**
- Re-upload certificate in PEM format
- Convert from other formats: `openssl x509 -in cert.der -inform DER -out cert.pem`

#### 5. Bulk SSH Job Fails with "Authentication Failed"

**Symptoms:**
- Job completes with all devices failed
- Error shows authentication failure

**Diagnosis:**
1. Check credentials are correct
2. Verify device type selection
3. Test SSH manually to target device

**Resolution:**
- Update credentials in job configuration
- Ensure correct device type (cisco_ios vs cisco_xe vs aruba_os)
- Check for account lockout on target devices

#### 6. AP Inventory Not Populating

**Symptoms:**
- AP Inventory page shows empty
- WLC Dashboard shows APs but inventory doesn't

**Diagnosis:**
1. Check if WLC polling is enabled and running
2. Verify poll_summary contains ap_count > 0
3. Check for database errors

**Resolution:**
- Enable WLC polling in Dashboard Settings
- Wait for next poll cycle (default 5 minutes)
- Manually trigger poll with "Poll Now" button

#### 7. Pages Return 403 Forbidden

**Symptoms:**
- User can log in but cannot access certain pages
- Error message about page being disabled

**Diagnosis:**
1. Check Page Settings in Admin panel
2. Verify user role (user vs superadmin)

**Resolution:**
- Enable page in Admin > Page Settings
- Grant superadmin role if needed for admin pages

### Log Files

| Log | Location | Contents |
|-----|----------|----------|
| Changes CSV | `./logs/changes.csv` | Configuration changes |
| Audit Log | `audit_log` table (auth DB) | Authentication events |
| Flask Log | stdout | Application errors |

### Health Checks

1. **Application Running:**
   ```bash
   curl http://localhost:5000/login
   ```

2. **Database Accessible:**
   ```bash
   sqlite3 ~/.noc_toolkit/noc_toolkit.db "SELECT COUNT(*) FROM solarwinds_nodes;"
   ```

3. **Background Workers Running:**
   - Check WLC Dashboard for recent poll timestamp
   - Check Bulk SSH Schedules for "last_run" updates
   - Check Changes page for scheduled change execution

---

## Security Considerations

### Password Storage

- **User passwords:** Hashed with werkzeug pbkdf2:sha256
- **Device credentials:** Encrypted with Fernet cipher
- **Encryption key:** Stored in `wlc_dashboard.key`

### Access Control

| Role | Permissions |
|------|-------------|
| user | View data, execute operations, view KB |
| superadmin | All above + user management, page settings, delete operations |

### Audit Logging

All significant actions are logged:
- Authentication (login, logout, password change)
- Configuration changes (settings updates)
- Device operations (SSH commands, WLAN toggles)
- Data modifications (create, update, delete)

### Network Security

- SSH connections use standard port 22
- SolarWinds uses HTTPS (port 17778)
- ISE API uses HTTPS (port 9060)
- SSL verification is configurable per integration

---

## Backup and Recovery

### Backup Procedure

```bash
# Backup main data database
cp ~/.noc_toolkit/noc_toolkit.db ~/backup/noc_toolkit_data_$(date +%Y%m%d).db

# Backup auth database
cp ./noc_toolkit.db ~/backup/noc_toolkit_auth_$(date +%Y%m%d).db

# Backup encryption key
cp ./wlc_dashboard.key ~/backup/wlc_dashboard_$(date +%Y%m%d).key

# Backup audit logs
cp -r ./logs ~/backup/logs_$(date +%Y%m%d)/
```

### Recovery Procedure

```bash
# Stop application
pkill -f "python app.py"

# Restore databases
cp ~/backup/noc_toolkit_data_YYYYMMDD.db ~/.noc_toolkit/noc_toolkit.db
cp ~/backup/noc_toolkit_auth_YYYYMMDD.db ./noc_toolkit.db

# Restore encryption key (required for decrypting saved passwords)
cp ~/backup/wlc_dashboard_YYYYMMDD.key ./wlc_dashboard.key

# Start application
python app.py
```

### Important Notes

- The encryption key (`wlc_dashboard.key`) is required to decrypt stored device passwords
- If the key is lost, all stored device credentials will need to be re-entered
- Database backups should be encrypted if stored off-system
- Test recovery procedure periodically

---

## Support

For issues or feature requests:
1. Check this runbook's troubleshooting section
2. Review audit-findings.md for known issues
3. Contact the development team

**Internal Resources:**
- Knowledge Base: `/knowledge-base` (within the application)
- Audit Log Viewer: `/logs` (for configuration changes)
