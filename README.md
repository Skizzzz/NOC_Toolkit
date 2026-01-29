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
   git clone https://github.com/Skizzzz/NOC_Toolkit.git
   cd NOC_Toolkit
   ```

2. Create environment configuration:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. Generate secure secrets:
   ```bash
   # Generate Flask secret key
   python3 -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32))"

   # Generate PostgreSQL password
   python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(24))"

   # Generate encryption key for stored credentials
   python3 -c "from cryptography.fernet import Fernet; print('NOC_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
   ```

4. Start the application:
   ```bash
   docker-compose up -d
   ```

5. Verify deployment:
   ```bash
   # Check health endpoint
   curl http://localhost:5000/health
   ```

6. Access the application at `http://localhost:5000`

### Troubleshooting Docker Deployment

**Permission denied errors on startup**

If you see errors like `/app/data/wlc_dashboard.key: Permission denied` in the container logs, the Docker volumes have incorrect ownership. Fix this by removing the volumes and rebuilding:

```bash
# Stop containers and remove volumes
sudo docker-compose down -v

# Rebuild the image
sudo docker-compose build --no-cache

# Start fresh
sudo docker-compose up -d
```

Alternatively, if you need to preserve existing data in the volumes:

```bash
# Stop containers
sudo docker-compose down

# Fix permissions on the data volume
sudo docker run --rm -v noc-toolkit-data:/app/data alpine chown -R 1000:1000 /app/data

# Start containers
sudo docker-compose up -d
```

### Manual Installation

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for local development setup instructions.

### First-Time Setup

On first launch, the application will redirect to a setup wizard where you can:
- Create the initial admin account
- Configure database connections
- Set up SolarWinds and WLC integrations

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
├── src/                   # Application source code
│   ├── app.py            # Flask application factory
│   ├── config.py         # Configuration management
│   ├── blueprints/       # Feature modules (routes + templates)
│   │   ├── admin/        # User & settings management
│   │   ├── auth/         # Authentication & authorization
│   │   ├── bulk_ssh/     # Bulk SSH job execution
│   │   ├── certs/        # Certificate tracking & conversion
│   │   ├── config/       # Network configuration management
│   │   ├── jobs/         # Background job monitoring
│   │   ├── kb/           # Knowledge base
│   │   ├── setup/        # Initial setup wizard
│   │   ├── solarwinds/   # SolarWinds integration
│   │   └── wlc/          # Wireless LAN controller tools
│   ├── models/           # SQLAlchemy database models
│   └── core/             # Shared utilities & security
├── tools/                # Legacy backend modules
│   ├── bulk_ssh.py       # Bulk SSH execution engine
│   ├── cert_tracker.py   # Certificate parsing utilities
│   ├── security.py       # Encryption helpers
│   └── solarwinds.py     # SolarWinds API integration
├── migrations/           # Alembic database migrations
├── tests/                # Test suites
│   ├── e2e/             # End-to-end Playwright tests
│   └── conftest.py      # Pytest fixtures
├── requirements/         # Python dependencies
│   ├── base.txt         # Core dependencies
│   ├── prod.txt         # Production (adds gunicorn)
│   └── dev.txt          # Development (adds testing tools)
├── docs/                 # Documentation
├── Dockerfile           # Container image definition
├── docker-compose.yml   # Multi-container orchestration
└── wsgi.py              # WSGI entry point for production
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

For issues and feature requests, please use the [GitHub Issues](https://github.com/Skizzzz/NOC_Toolkit/issues) page.
