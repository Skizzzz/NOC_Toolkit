# Changelog

All notable changes to NOC Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker and Docker Compose configuration for containerized deployment
- Production-ready requirements structure (base, prod, dev)
- Health check endpoint at `/health`
- Project documentation (README, DEPLOYMENT, DEVELOPMENT, CONTRIBUTING)
- `pyproject.toml` for modern Python project configuration

### Changed
- Requirements now split into `requirements/base.txt`, `requirements/prod.txt`, and `requirements/dev.txt`
- Dockerfile updated to use layered requirements

## [1.0.0] - Initial Release

### Features
- **WLC Dashboard** - Real-time monitoring of Cisco 9800 and Aruba wireless controllers
- **AP Inventory** - Access point tracking with export capabilities
- **RF Analysis** - Radio frequency metrics and troubleshooting
- **Client Troubleshooting** - Wireless client investigation tools
- **Summer Guest Management** - Seasonal WLAN state control

- **Phrase Search** - Search running configurations across multiple devices
- **Global Config** - Apply configuration changes across device fleets
- **Change Management** - Schedule and track configuration changes with rollback
- **Bulk SSH** - Mass command execution with templates and scheduling

- **SolarWinds Integration** - Node inventory synchronization
- **Certificate Tracker** - SSL/TLS certificate monitoring and expiration tracking
- **ISE Node Management** - Cisco ISE node and certificate synchronization
- **Certificate Converter** - Format conversion (PFX, PEM, DER)

- **Knowledge Base** - Internal documentation with role-based access
- **Job Center** - Background task monitoring and history
- **Audit Logging** - User action tracking
- **Network Topology** - Topology visualization

### Security
- Role-based access control (User, Admin, Superadmin)
- Encrypted credential storage using Fernet
- Session-based authentication
- Page visibility controls
- Audit logging of sensitive operations

---

## Version History Format

### Types of Changes

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Vulnerability fixes
