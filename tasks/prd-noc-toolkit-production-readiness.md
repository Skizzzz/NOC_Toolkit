# PRD: NOC Toolkit Production Readiness & New Features

## Introduction

This PRD covers a comprehensive production readiness review of the NOC Toolkit application, timezone configuration improvements, a new auto-updating AP inventory system, and a SolarWinds-based hardware/software inventory tool. The goal is to ensure the toolkit is reliable for NOC engineers in a live environment while adding critical new capabilities for network asset management and CVE response.

## Goals

- Verify all existing tools and workflows function correctly for production use
- Ensure scheduled changes execute at the correct times with proper timezone handling
- Implement configurable timezone support (default: CST/America/Chicago)
- Create an auto-updating AP inventory that tracks APs across all WLC controllers
- Build a searchable SolarWinds hardware/software inventory for CVE impact analysis
- Document all findings and create a production runbook

## User Stories

### US-001: Audit WLC Dashboard and Polling System
**Description:** As a NOC engineer, I need the WLC Dashboard to reliably poll and display wireless statistics so I can monitor the network in real-time.

**Acceptance Criteria:**
- [ ] Verify WLC dashboard settings save/load correctly
- [ ] Confirm polling interval works as configured
- [ ] Validate time-series data storage and retrieval (24h, 3d, 7d, 30d ranges)
- [ ] Test both Cisco 9800 and Aruba AOS controller support
- [ ] Verify stat cards and graphs render correctly
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-002: Audit Bulk SSH Tool and Templates
**Description:** As a NOC engineer, I need the Bulk SSH tool to reliably execute commands across multiple devices so I can perform bulk operations.

**Acceptance Criteria:**
- [ ] Verify template creation, editing, and deletion works
- [ ] Test command execution against multiple devices
- [ ] Validate variable substitution in templates
- [ ] Confirm results are properly stored and displayed
- [ ] Test CSV export of results
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-003: Audit Bulk SSH Scheduling System
**Description:** As a NOC engineer, I need scheduled SSH jobs to execute at the correct times so automated tasks run reliably.

**Acceptance Criteria:**
- [ ] Verify schedule creation (one-time, cron, interval)
- [ ] Confirm next_run calculation is accurate
- [ ] Test that scheduled jobs execute within 60 seconds of due time
- [ ] Validate schedule enable/disable functionality
- [ ] Verify execution history is recorded
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-004: Audit Change Management Workflow
**Description:** As a NOC engineer, I need the change management system to schedule and execute changes at the correct times with proper audit trails.

**Acceptance Criteria:**
- [ ] Verify change window creation with scheduled datetime
- [ ] Confirm changes execute when scheduled time arrives
- [ ] Test rollback functionality works correctly
- [ ] Validate change event audit trail is complete
- [ ] Verify change status transitions (pending → running → completed/failed)
- [ ] Test that apply and rollback CLI payloads execute correctly
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-005: Audit SolarWinds Integration
**Description:** As a NOC engineer, I need SolarWinds integration to reliably sync node data so I can use it as a source for other tools.

**Acceptance Criteria:**
- [ ] Verify settings page saves credentials correctly
- [ ] Test connection validation works
- [ ] Confirm node sync fetches all expected fields
- [ ] Validate organization mapping works
- [ ] Test that nodes display correctly in the UI
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-006: Audit WLC Summer Guest Automation
**Description:** As a NOC engineer, I need the Summer Guest WLAN automation to enable/disable WLANs at the correct times.

**Acceptance Criteria:**
- [ ] Verify settings configuration saves correctly
- [ ] Confirm scheduled enable/disable executes at configured time
- [ ] Test timezone-aware scheduling works
- [ ] Validate WLAN state changes are logged
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-007: Audit Certificate Tracker and ISE Sync
**Description:** As a NOC engineer, I need certificate tracking to reliably monitor expiration dates and sync from ISE nodes.

**Acceptance Criteria:**
- [ ] Verify certificate upload and parsing works
- [ ] Confirm expiration calculations are accurate
- [ ] Test ISE node sync functionality
- [ ] Validate scheduled sync runs at configured interval
- [ ] Test certificate deletion works
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-008: Audit Device Inventory Tool
**Description:** As a NOC engineer, I need the device inventory to reliably scan and store hardware/firmware information.

**Acceptance Criteria:**
- [ ] Verify device scanning works for all supported vendors (Cisco IOS, IOS-XE, NX-OS, Aruba)
- [ ] Confirm inventory data is stored correctly
- [ ] Test CSV export functionality
- [ ] Validate SolarWinds node linking
- [ ] Test device deletion from inventory
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-009: Audit Topology Builder
**Description:** As a NOC engineer, I need the topology builder to reliably discover network neighbors and visualize topology.

**Acceptance Criteria:**
- [ ] Verify CDP/LLDP neighbor collection works
- [ ] Confirm multi-vendor support (Cisco, Dell, etc.)
- [ ] Test topology visualization renders correctly
- [ ] Validate device type auto-detection
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-010: Audit Authentication and Admin Panel
**Description:** As a NOC engineer, I need authentication and admin features to work securely and reliably.

**Acceptance Criteria:**
- [ ] Verify login/logout functionality
- [ ] Confirm user creation and role assignment works
- [ ] Test password change functionality
- [ ] Validate page settings (feature visibility) work
- [ ] Confirm audit logging captures all actions
- [ ] Test KB access level permissions
- [ ] Document any issues found and fixes applied
- [ ] **Verify in browser using dev-browser skill**

---

### US-011: Add Timezone Configuration to Admin Panel
**Description:** As an admin, I want to configure the application timezone so all scheduled operations use the correct local time.

**Acceptance Criteria:**
- [ ] Add `app_settings` table with `timezone` field (default: 'America/Chicago')
- [ ] Create admin settings page at `/admin/settings` for timezone configuration
- [ ] Add timezone dropdown with common US timezones (EST, CST, MST, PST, etc.)
- [ ] Display current configured timezone on settings page
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-012: Integrate Timezone Setting into Scheduling Systems
**Description:** As a NOC engineer, I need all scheduled operations to respect the configured timezone so changes execute at the correct local time.

**Acceptance Criteria:**
- [ ] Update change window scheduler to use configured timezone
- [ ] Update bulk SSH scheduler to use configured timezone
- [ ] Update WLC Summer Guest scheduler to use configured timezone
- [ ] Update certificate sync scheduler to use configured timezone
- [ ] Update WLC dashboard polling display to show times in configured timezone
- [ ] Add `get_app_timezone()` helper function
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-013: Create Auto-Updating AP Inventory Database Schema
**Description:** As a developer, I need database tables to store the auto-updating AP inventory with proper deduplication.

**Acceptance Criteria:**
- [ ] Create `ap_inventory` table with fields: ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state, slots, country, wlc_host, first_seen, last_seen
- [ ] Add unique constraint on (ap_mac, wlc_host) to prevent duplicates
- [ ] Create index on last_seen for efficient cleanup queries
- [ ] Create `ap_inventory_settings` table for configuration
- [ ] Typecheck/lint passes

---

### US-014: Implement AP Inventory Polling During Dashboard Updates
**Description:** As a NOC engineer, I want AP inventory to update automatically during normal WLC polling so I always have current data.

**Acceptance Criteria:**
- [ ] Extend dashboard polling to collect AP details (name, IP, model, MAC, location, state, slots, country)
- [ ] Insert new APs with first_seen = now, last_seen = now
- [ ] Update existing APs' last_seen timestamp on each poll
- [ ] Only insert if AP MAC + WLC host combo doesn't exist (no duplicates)
- [ ] Track which WLC controller each AP belongs to
- [ ] Typecheck/lint passes

---

### US-015: Implement AP Inventory Cleanup (3-Day Stale Removal)
**Description:** As a NOC engineer, I want APs not seen for 5+ days to be automatically removed so the inventory stays current.

**Acceptance Criteria:**
- [ ] Add cleanup function that runs after each AP inventory update
- [ ] Delete AP records where last_seen < (now - 5 days)
- [ ] Log removed APs for audit purposes
- [ ] Do not remove APs that were just added (protect against clock issues)
- [ ] Typecheck/lint passes

---

### US-016: Create AP Inventory Dashboard Page
**Description:** As a NOC engineer, I want a dedicated page to view the auto-updating AP inventory with filtering and export options.

**Acceptance Criteria:**
- [ ] Create `/tools/wlc/ap-inventory` route and template
- [ ] Display AP inventory table with all fields including WLC host
- [ ] Add search/filter by AP name, model, WLC, location
- [ ] Show first_seen and last_seen timestamps
- [ ] Add total AP count summary
- [ ] Group or filter by WLC controller
- [ ] Add navigation from WLC dashboard
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-017: Implement AP Inventory CSV Export
**Description:** As a NOC engineer, I want to download the AP inventory as CSV for reporting and analysis.

**Acceptance Criteria:**
- [ ] Add CSV export button to AP inventory page
- [ ] Export includes all fields: AP Name, IP, Model, MAC, Location, State, Slots, Country, WLC Host, First Seen, Last Seen
- [ ] Apply current filters to export (filtered export)
- [ ] Filename format: `ap_inventory_YYYY-MM-DD.csv`
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-018: Create SolarWinds Hardware/Software Inventory Schema
**Description:** As a developer, I need database tables to store hardware/software inventory data from SolarWinds for CVE analysis.

**Acceptance Criteria:**
- [ ] Extend `solarwinds_nodes` table or create `sw_inventory` table with: node_id, hostname, vendor, model, hardware_version, software_version, ip_address, organization, last_synced
- [ ] Add indexes for efficient searching by vendor, model, software_version
- [ ] Ensure data is populated from existing SolarWinds sync
- [ ] Typecheck/lint passes

---

### US-019: Create SolarWinds Inventory Dashboard Page
**Description:** As a NOC engineer, I want a dashboard to view and search hardware/software inventory so I can assess CVE impact.

**Acceptance Criteria:**
- [ ] Create `/tools/solarwinds/inventory` route and template
- [ ] Display summary charts: device count by vendor, devices by software version
- [ ] Add searchable/filterable data table with all inventory fields
- [ ] Enable multi-select filters for vendor, model, software version
- [ ] Show total device counts per filter selection
- [ ] Add navigation from SolarWinds nodes page
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-020: Implement SolarWinds Inventory Search and Aggregation
**Description:** As a NOC engineer, I want to search inventory by version and see counts so I can quickly assess CVE exposure.

**Acceptance Criteria:**
- [ ] Add search box for software version (partial match supported)
- [ ] Display aggregated counts: "X devices running version Y"
- [ ] Allow clicking version count to see device list
- [ ] Support regex or wildcard search for version ranges
- [ ] Show results grouped by vendor → model → version hierarchy
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-021: Implement SolarWinds Inventory Export
**Description:** As a NOC engineer, I want to export inventory search results for CVE reports and remediation tracking.

**Acceptance Criteria:**
- [ ] Add CSV export for full inventory
- [ ] Add CSV export for current search/filter results
- [ ] Include all fields: hostname, vendor, model, hardware_version, software_version, ip_address, organization
- [ ] Add aggregation summary export (counts per version)
- [ ] Filename format: `solarwinds_inventory_YYYY-MM-DD.csv`
- [ ] Typecheck/lint passes
- [ ] **Verify in browser using dev-browser skill**

---

### US-022: Create Production Readiness Documentation
**Description:** As a NOC engineer, I need documentation of all audit findings and a runbook for using the toolkit in production.

**Acceptance Criteria:**
- [ ] Create `docs/audit-findings.md` with all issues found and fixes applied
- [ ] Create `docs/production-runbook.md` with operational procedures
- [ ] Document all scheduled job systems and their timing behavior
- [ ] Document timezone configuration and its effects
- [ ] Include troubleshooting guide for common issues
- [ ] Document the new AP inventory and SolarWinds inventory features

---

## Functional Requirements

### Timezone Configuration
- FR-1: System must store timezone configuration in database with default 'America/Chicago' (CST)
- FR-2: Admin panel must provide interface to change timezone setting
- FR-3: All scheduled operations must convert scheduled times to configured timezone
- FR-4: All displayed timestamps must show in configured timezone

### Auto-Updating AP Inventory
- FR-5: System must collect AP inventory data during WLC dashboard polling
- FR-6: System must store unique APs identified by (MAC address, WLC host) combination
- FR-7: System must update last_seen timestamp on each successful poll
- FR-8: System must automatically remove APs not seen for more than 3 days
- FR-9: System must never create duplicate AP records
- FR-10: System must track which WLC controller each AP belongs to
- FR-11: System must provide CSV export of AP inventory with all fields

### SolarWinds Hardware/Software Inventory
- FR-12: System must store vendor, model, hardware version, and software version for each SolarWinds node
- FR-13: System must provide searchable dashboard with charts showing device distribution
- FR-14: System must support filtering by vendor, model, and software version
- FR-15: System must display aggregated counts per software version for CVE assessment
- FR-16: System must provide CSV export of inventory and search results

### Production Readiness
- FR-17: All existing tools must be tested and documented
- FR-18: All scheduled operations must execute within 60 seconds of scheduled time
- FR-19: All configuration changes must be persisted to database
- FR-20: All errors must be logged with sufficient detail for troubleshooting

## Non-Goals (Out of Scope)

- Automatic CVE scanning or vulnerability database integration
- Real-time alerting or notifications for AP changes
- Multi-tenant support or organization-level timezone settings
- Historical AP inventory (tracking when APs were removed)
- Automatic remediation based on CVE findings
- Integration with ticketing systems
- Mobile-responsive design changes (existing design preserved)

## Technical Considerations

- **Database:** Use existing SQLite database; add new tables with proper indexes
- **Timezone Handling:** Use Python `pytz` or `zoneinfo` module for timezone conversions
- **Polling Integration:** Extend existing `_dashboard_poll_once()` to include AP inventory updates
- **Thread Safety:** Use existing `_DB_LOCK` for AP inventory writes
- **Performance:** Add indexes for frequent queries (last_seen, software_version, vendor)
- **UI Consistency:** Follow existing Tailwind CSS patterns and component structure
- **Existing Manual AP Inventory:** Keep `/tools/wlc-inventory` as a separate manual scan tool

## Design Considerations

- AP Inventory page should match existing WLC dashboard styling
- SolarWinds Inventory dashboard should include:
  - Summary cards showing total devices, vendors, models
  - Pie/bar charts for device distribution by vendor and version
  - Searchable data table below charts
- Use existing table components and export patterns from other tools
- Timezone settings should be on a new "System Settings" admin page

## Success Metrics

- All audit items pass verification with no critical bugs
- Scheduled changes execute within 60 seconds of scheduled time in configured timezone
- AP inventory updates automatically with each dashboard poll
- No duplicate APs exist in inventory (verified by unique constraint)
- Stale APs are removed after 3 days of not being seen
- NOC engineers can search SolarWinds inventory and find device counts by version in under 10 seconds
- CSV exports work for both AP inventory and SolarWinds inventory

## Open Questions

1. Should AP inventory show a "days since last seen" column for at-risk APs?
2. Should SolarWinds inventory include custom property fields beyond organization?
3. Should there be an option to extend the 3-day cleanup period via settings?
4. Should the production runbook include video walkthroughs or just text documentation?
