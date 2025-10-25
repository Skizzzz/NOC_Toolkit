# Security & Feature Improvements - NOC Toolkit

## Overview
This document outlines major security enhancements and feature improvements implemented in the NOC Toolkit.

## 1. Security Enhancements

### Authentication System
- **New Module**: `tools/security.py` - Complete authentication and authorization system
- **Features**:
  - User login/logout with session management
  - Password hashing using `werkzeug.security` (bcrypt)
  - Role-based access control (user, superadmin)
  - Audit logging for all security events
  - Password change functionality
  - User management for superadmins

### Password Encryption
- **Encryption**: Device credentials (SSH passwords, enable secrets) are now encrypted at rest using Fernet (symmetric encryption)
- **Key Storage**: Encryption key stored in `.encryption_key` file with 600 permissions
- **Migration**: Automatic migration of existing plaintext passwords to encrypted format on startup
- **WLC Dashboard Settings**: Passwords encrypted before storage, decrypted only when used for SSH connections

### Protected Routes
- **WLC Dashboard Settings**: Now requires superadmin authentication (`@require_superadmin`)
- **SolarWinds Settings**: Now requires superadmin authentication (`@require_superadmin`)
- **Admin Panel**: User management accessible only to superadmins
- **Profile**: All authenticated users can change their password

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123` (or value from `NOC_ADMIN_PASSWORD` env var)
- **⚠️ IMPORTANT**: Change the default password immediately after first login!

### New Templates
1. **[login.html](templates/login.html)** - Modern login page with gradient design
2. **[profile.html](templates/profile.html)** - User profile and password change
3. **[admin_users.html](templates/admin_users.html)** - User management interface (superadmin only)

### Sidebar Updates
- User avatar and info displayed at bottom of sidebar
- Profile and Logout buttons
- Admin Panel button (superadmin only)
- Flexbox layout ensures user section stays at bottom

## 2. Bug Fixes

### DataTables Error - Jobs Center
**Issue**: `DataTables warning: Requested unknown parameter '[object Object]' for row 0, column 4`

**Fix**: Updated `refreshJobs()` function in [templates/jobs_center.html](templates/jobs_center.html:475)
- Wrapped `created_at_formatted` in `<span>` with `data-order` attribute for proper sorting
- DataTables now correctly sorts by timestamp while displaying formatted date

**Location**: Line 475 in jobs_center.html

### Device Type Cleanup
**Change**: Removed Arista, Juniper, and HP device types from dropdowns per user request

**Files Modified**:
- [templates/bulk_ssh.html](templates/bulk_ssh.html:401-409) - Bulk SSH Terminal form
- [templates/bulk_ssh_templates.html](templates/bulk_ssh_templates.html:321-329) - Template creation form

**Remaining Options**:
- Cisco IOS
- Cisco IOS-XE
- Cisco NX-OS
- Cisco ASA
- Dell OS10
- Dell Force10
- Dell PowerConnect

**Note**: [templates/topology_tool.html](templates/topology_tool.html) already had Cisco/Dell only

## 3. New Network Topology Builder

### Complete UI Redesign
**New File**: [templates/topology_builder.html](templates/topology_builder.html)

**Features**:
1. **Three Discovery Modes**:
   - **Single Device**: Discover neighbors for one device
   - **Organization**: Scan all devices with a SolarWinds organization tag
   - **Bulk Discovery**: Enter a list of devices (hostnames/IPs) to scan in parallel

2. **Interactive Filtering**:
   - Real-time search across devices, neighbors, and IP addresses
   - **Auto-hide Access Points** - Toggle switch to hide/show AP neighbors (enabled by default)
   - Smooth animations and visual feedback

3. **Enhanced Visualization**:
   - Modern card-based layout for each device
   - Clean neighbor tables with hover effects
   - Statistics dashboard showing:
     - Total Devices
     - Successful Scans
     - Errors
     - Total Neighbors (updates with AP filter)
   - Color-coded AP rows (light yellow background)

4. **CSV Export**:
   - One-click export button
   - Includes all topology data in standardized format
   - Works for single, org, and bulk discoveries

5. **UX Improvements**:
   - Tab-based interface for different discovery modes
   - Auto-complete from SolarWinds inventory
   - Device metadata display (vendor, model, organization)
   - Error cards for failed devices
   - Empty state messaging

### Backend Updates
**File**: [app.py](app.py)

**Changes**:
- Added `bulk` scope handling to `topology_report()` route (lines 2074-2117)
- Parses device list from textarea (one device per line)
- Attempts SolarWinds resolution, falls back to raw IP/hostname
- Parallel topology discovery for multiple devices
- Updated template references from `topology_tool.html` to `topology_builder.html`

**Route**: `POST /tools/topology/report`

**Scopes**:
- `node` - Single device discovery
- `organization` - Organization-wide discovery
- `bulk` - Custom device list discovery

## 4. Environment Variables (Recommended)

For production deployment, set these environment variables:

```bash
# Flask secret key (for session encryption)
export FLASK_SECRET_KEY="your-secure-random-key-here"

# NOC Toolkit encryption key (for device password encryption)
export NOC_ENCRYPTION_KEY="your-fernet-key-here"

# Default admin password (on first setup)
export NOC_ADMIN_PASSWORD="your-secure-admin-password"
```

**Generate Fernet Key**:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

## 5. Database Schema Changes

### New Tables
1. **users** - User accounts and authentication
   - id, username, password_hash, role, created_at, last_login

2. **sessions** - Session management (currently unused, for future enhancement)
   - id, user_id, session_token, ip_address, user_agent, created_at, expires_at

3. **audit_log** - Security audit trail
   - id, user_id, username, action, resource, ip_address, timestamp, details

### Modified Tables
- **wlc_dashboard_settings**: `password` and `secret` columns now store encrypted values

## 6. Security Best Practices Implemented

✅ Passwords hashed with bcrypt (via werkzeug.security)
✅ Device credentials encrypted at rest with Fernet
✅ Session-based authentication with secure secret keys
✅ Role-based access control (RBAC)
✅ Audit logging for security events
✅ Password requirements (minimum 8 characters)
✅ Automatic password migration from plaintext
✅ Encrypted passwords never displayed in UI
✅ Login/logout auditing
✅ Settings changes logged with user attribution

## 7. Migration Notes

### First Startup After Update
1. **Database Initialization**: `init_security_db()` creates new tables automatically
2. **Password Migration**: `migrate_existing_passwords()` encrypts existing WLC passwords
3. **Default Admin Created**: If no users exist, `admin/admin123` account is created
4. **Console Output**: Check logs for migration status and default credentials

### User Migration Path
1. First user to log in should be with `admin/admin123`
2. Immediately go to Profile and change password
3. Create additional user accounts via Admin Panel if needed
4. Assign superadmin role to trusted users who need access to settings

## 8. Testing Checklist

- [ ] Login with default credentials works
- [ ] Password change functionality works
- [ ] Superadmin can access WLC Dashboard Settings
- [ ] Superadmin can access SolarWinds Settings
- [ ] Regular users cannot access protected routes
- [ ] WLC Dashboard polling works with decrypted credentials
- [ ] Jobs Center refresh button works without DataTables errors
- [ ] Topology Builder tabs switch properly
- [ ] AP auto-hide toggle works
- [ ] Search filter works across devices and neighbors
- [ ] CSV export includes all topology data
- [ ] Bulk discovery mode processes multiple devices
- [ ] User info displays correctly in sidebar
- [ ] Logout clears session properly

## 9. Files Modified

### New Files
- `tools/security.py` - Authentication and encryption module
- `templates/login.html` - Login page
- `templates/profile.html` - User profile page
- `templates/admin_users.html` - User management page
- `templates/topology_builder.html` - New topology builder interface

### Modified Files
- `app.py` - Added security imports, decorators, auth routes, topology bulk scope
- `templates/base.html` - Added user info section to sidebar with flexbox layout
- `templates/jobs_center.html` - Fixed DataTables refresh bug
- `templates/bulk_ssh.html` - Removed non-Cisco/Dell device types
- `templates/bulk_ssh_templates.html` - Removed non-Cisco/Dell device types

## 10. API Endpoints

### Authentication
- `GET/POST /login` - User login
- `GET /logout` - User logout
- `GET/POST /profile` - User profile and password change
- `GET/POST /admin/users` - User management (superadmin only)

### Topology (Enhanced)
- `GET /tools/topology` - Topology builder interface
- `POST /tools/topology/report` - Execute topology discovery (supports `node`, `organization`, `bulk` scopes)
- `POST /tools/topology/export` - Export topology data as CSV

## 11. Future Enhancements (Not Implemented)

Potential improvements for future releases:
- Two-factor authentication (2FA)
- API tokens for programmatic access
- Session timeout and automatic logout
- Password complexity requirements configuration
- Account lockout after failed login attempts
- Email notifications for security events
- LDAP/Active Directory integration
- OAuth2 integration (SSO)
- More granular permissions (read-only access, tool-specific access)

---

**Last Updated**: 2025-01-18
**Version**: 2.0.0
**Author**: Claude (Anthropic)
