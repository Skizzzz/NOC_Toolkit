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

## Requirements

- Linux (Ubuntu/Debian or RHEL/Rocky/AlmaLinux)
- Python 3.11+
- PostgreSQL 15+
- Network access to managed devices (switches, controllers, etc.)

## Installation (Linux)

### 1. Install system dependencies

**Ubuntu / Debian:**

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git \
  postgresql postgresql-contrib libpq-dev
```

**RHEL / Rocky / AlmaLinux:**

```bash
sudo dnf install -y python3.11 python3.11-pip python3.11-devel git \
  postgresql-server postgresql-devel
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

Verify versions:

```bash
python3 --version   # 3.11+
psql --version      # 15+
```

### 2. Create the PostgreSQL database

```bash
sudo -u postgres psql <<SQL
CREATE USER noc WITH PASSWORD 'your-db-password-here';
CREATE DATABASE noc_toolkit OWNER noc;
GRANT ALL PRIVILEGES ON DATABASE noc_toolkit TO noc;
SQL
```

### 3. Clone the repository

```bash
cd /opt
sudo git clone https://github.com/Skizzzz/NOC_Toolkit.git noc-toolkit
sudo chown -R $USER:$USER /opt/noc-toolkit
cd /opt/noc-toolkit
```

### 4. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements/prod.txt
```

### 5. Configure environment variables

```bash
cp .env.example .env
```

Generate secure values and add them to `.env`:

```bash
# Generate a Flask secret key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate an encryption key for stored credentials
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Edit `.env` with your values:

```bash
FLASK_SECRET_KEY=<generated-secret-key>
FLASK_ENV=production
DATABASE_URL=postgresql://noc:your-db-password-here@localhost:5432/noc_toolkit
NOC_ENCRYPTION_KEY=<generated-encryption-key>
```

### 6. Initialize the database

```bash
source venv/bin/activate
set -a && source .env && set +a
python scripts/init_db.py
```

This runs all Alembic migrations and seeds initial data (page settings, app settings).

### 7. Verify the application starts

```bash
source venv/bin/activate
set -a && source .env && set +a
gunicorn wsgi:application --bind 127.0.0.1:5000 --workers 1
```

Open `http://<server-ip>:5000` in a browser. Press `Ctrl+C` to stop once verified.

### First-Time Setup

On first launch, the application will redirect to a setup wizard where you can:
- Create the initial admin account
- Configure database connections
- Set up SolarWinds and WLC integrations

---

## Running in production with systemd (auto-start)

### 1. Create a system user

```bash
sudo useradd -r -s /usr/sbin/nologin noc-toolkit
sudo chown -R noc-toolkit:noc-toolkit /opt/noc-toolkit
```

### 2. Create the systemd service

```bash
sudo tee /etc/systemd/system/noc-toolkit.service > /dev/null <<'EOF'
[Unit]
Description=NOC Toolkit (Gunicorn)
After=network.target postgresql.service
Requires=postgresql.service

[Service]
User=noc-toolkit
Group=noc-toolkit
WorkingDirectory=/opt/noc-toolkit
EnvironmentFile=/opt/noc-toolkit/.env
ExecStart=/opt/noc-toolkit/venv/bin/gunicorn wsgi:application \
  --bind 127.0.0.1:5000 \
  --workers 4 \
  --threads 2 \
  --timeout 120 \
  --access-logfile /opt/noc-toolkit/logs/access.log \
  --error-logfile /opt/noc-toolkit/logs/error.log
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

Adjust `--workers` to match your server: `(2 x CPU cores) + 1`.

### 3. Create the logs directory

```bash
sudo mkdir -p /opt/noc-toolkit/logs
sudo chown noc-toolkit:noc-toolkit /opt/noc-toolkit/logs
```

### 4. Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable noc-toolkit
sudo systemctl start noc-toolkit
```

### 5. Check status

```bash
sudo systemctl status noc-toolkit
sudo journalctl -u noc-toolkit -f
```

---

## Reverse proxy with nginx (recommended)

Placing nginx in front of Gunicorn provides SSL termination, static file serving, and connection buffering.

### 1. Install nginx

```bash
# Ubuntu/Debian
sudo apt install -y nginx

# RHEL/Rocky
sudo dnf install -y nginx
```

### 2. Create the site config

```bash
sudo tee /etc/nginx/sites-available/noc-toolkit <<'EOF'
server {
    listen 80;
    server_name noc.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
```

### 3. Enable the site

```bash
# Ubuntu/Debian (sites-enabled pattern)
sudo ln -s /etc/nginx/sites-available/noc-toolkit /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# RHEL/Rocky (place config in conf.d instead)
# sudo cp /etc/nginx/sites-available/noc-toolkit /etc/nginx/conf.d/noc-toolkit.conf

sudo nginx -t
sudo systemctl enable --now nginx
```

### 4. Add SSL with Let's Encrypt (optional)

```bash
sudo apt install -y certbot python3-certbot-nginx   # Debian/Ubuntu
sudo certbot --nginx -d noc.example.com
```

---

## Firewall

Open only the ports you need:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# firewalld (RHEL/Rocky)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## Updating

```bash
cd /opt/noc-toolkit
sudo -u noc-toolkit git pull origin main
sudo -u noc-toolkit bash -c 'source venv/bin/activate && pip install -r requirements/prod.txt'
sudo -u noc-toolkit bash -c 'source venv/bin/activate && set -a && source .env && set +a && python scripts/init_db.py'
sudo systemctl restart noc-toolkit
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FLASK_SECRET_KEY` | Yes | Secret key for session management |
| `FLASK_ENV` | Yes | `production` for production deployments |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `NOC_ENCRYPTION_KEY` | No | Fernet key for encrypting stored credentials |
| `NOC_ADMIN_PASSWORD` | No | Initial admin password (first run only) |
| `WLC_DASHBOARD_KEY` | No | Encryption key for WLC dashboard credentials |

See `.env.example` for a complete list of configuration options.

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md) - Docker-based deployment
- [Development Setup](docs/DEVELOPMENT.md) - Local development environment
- [Contributing Guidelines](docs/CONTRIBUTING.md) - How to contribute

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
