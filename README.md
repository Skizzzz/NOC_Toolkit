# NOC Toolkit

A comprehensive web-based Network Operations Center toolkit for managing network infrastructure, automating repetitive tasks, and centralizing operational data.

## Features

### Wireless LAN Controller (WLC) Management
- **Dashboard** - Real-time monitoring of client counts and AP statistics across Cisco 9800 and Aruba controllers
- **AP Inventory** - Track and export access point inventory with location, model, and status information
- **RF Analysis** - Monitor radio frequency metrics and troubleshoot wireless issues
- **Client Troubleshooting** - Investigate client connectivity problems across controllers
- **Summer Guest Management** - Seasonal WLAN state management for guest networks

### Network Configuration Management
- **Phrase Search** - Search running configurations across multiple devices for specific patterns
- **Global Config** - Apply configuration changes across multiple devices simultaneously
- **Change Management** - Schedule and track configuration changes with rollback support
- **Bulk SSH** - Execute commands across multiple devices with templates and scheduling

### Inventory & Monitoring
- **SolarWinds Integration** - Sync and browse node inventory from SolarWinds
- **Certificate Tracker** - Monitor SSL/TLS certificates and track expiration dates
- **ISE Node Management** - Manage Cisco ISE nodes and synchronize certificates
- **Network Topology** - Visualize network topology relationships

### Operational Tools
- **Knowledge Base** - Internal documentation with role-based access control
- **Job Tracking** - Monitor and review background task execution
- **Audit Logging** - Track user actions for compliance and troubleshooting
- **Certificate Converter** - Convert between certificate formats (PFX, PEM, DER)

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/noc-toolkit.git
   cd noc-toolkit
   ```

2. Create environment configuration:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. Generate secure secrets:
   ```bash
   # Generate Flask secret key
   python -c "import secrets; print(secrets.token_hex(32))"

   # Generate PostgreSQL password
   python -c "import secrets; print(secrets.token_urlsafe(24))"
   ```

4. Start the application:
   ```bash
   docker-compose up -d
   ```

5. Access the application at `http://localhost:5000`

### Manual Installation

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for local development setup instructions.

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment instructions
- [Development Setup](docs/DEVELOPMENT.md) - Local development environment
- [Contributing Guidelines](docs/CONTRIBUTING.md) - How to contribute to the project

## Requirements

- Python 3.11+
- PostgreSQL 15+ (production) or SQLite (development)
- Docker and Docker Compose (recommended for deployment)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FLASK_SECRET_KEY` | Yes | Secret key for session management |
| `POSTGRES_PASSWORD` | Yes* | PostgreSQL password (*required for Docker) |
| `NOC_ENCRYPTION_KEY` | No | Key for encrypting stored credentials |
| `NOC_ADMIN_PASSWORD` | No | Initial admin password (first run only) |
| `WLC_DASHBOARD_KEY` | No | Encryption key for WLC dashboard credentials |
| `FLASK_ENV` | No | Environment mode (development/production) |
| `APP_PORT` | No | Application port (default: 5000) |

See `.env.example` for a complete list of configuration options.

## Project Structure

```
noc-toolkit/
├── app.py                 # Main Flask application
├── tools/                 # Backend modules
│   ├── bulk_ssh.py       # Bulk SSH job execution
│   ├── cert_tracker.py   # Certificate parsing utilities
│   ├── db_jobs.py        # Database operations
│   ├── security.py       # Authentication and authorization
│   ├── solarwinds.py     # SolarWinds API integration
│   └── ...
├── templates/            # Jinja2 HTML templates
├── static/               # CSS, JavaScript, images
├── requirements/         # Python dependencies
│   ├── base.txt         # Core dependencies
│   ├── prod.txt         # Production (adds gunicorn)
│   └── dev.txt          # Development (adds testing tools)
├── docs/                 # Documentation
├── Dockerfile           # Container image definition
└── docker-compose.yml   # Multi-container orchestration
```

## Security

- All stored credentials are encrypted using Fernet symmetric encryption
- Session-based authentication with configurable timeouts
- Role-based access control (User, Admin, Superadmin)
- Page visibility controls for feature access
- Audit logging of sensitive operations

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

For issues and feature requests, please use the [GitHub Issues](https://github.com/your-org/noc-toolkit/issues) page.
