#!/bin/bash
# NOC Toolkit - Linux Server Setup Script
# Run as root or with sudo: sudo bash setup.sh
#
# This script:
# 1. Creates a system user for the application
# 2. Installs Python 3.11+ and system dependencies
# 3. Sets up a virtual environment with all dependencies
# 4. Configures directories and permissions
# 5. Installs the systemd service
# 6. Generates a .env file from the template

set -e

APP_DIR="/opt/noc-toolkit"
APP_USER="hed"

echo "=========================================="
echo "  NOC Toolkit Production Setup"
echo "=========================================="

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo bash setup.sh)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo "ERROR: Cannot detect OS. This script supports Ubuntu/Debian and RHEL/Rocky/Alma."
    exit 1
fi

echo "Detected OS: $OS $OS_VERSION"

# --- Install system packages ---
echo ""
echo "[1/7] Installing system packages..."
case "$OS" in
    ubuntu|debian)
        apt-get update -qq
        apt-get install -y -qq python3 python3-venv python3-pip python3-dev \
            gcc libffi-dev openssl nginx >/dev/null 2>&1
        ;;
    rhel|rocky|almalinux|centos)
        dnf install -y python3 python3-pip python3-devel \
            gcc libffi-devel openssl nginx >/dev/null 2>&1
        ;;
    *)
        echo "WARNING: Unsupported OS '$OS'. Install Python 3.11+, gcc, libffi-dev, openssl, nginx manually."
        ;;
esac

# Verify Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]); then
    echo "WARNING: Python $PYTHON_VERSION detected. Python 3.11+ is recommended."
    echo "The application may still work with Python 3.9+."
fi

echo "  Python version: $PYTHON_VERSION"

# --- Create application user ---
echo ""
echo "[2/7] Creating application user..."
if id "$APP_USER" &>/dev/null; then
    echo "  User '$APP_USER' already exists."
else
    useradd -r -d "$APP_DIR" -s /bin/bash -m "$APP_USER"
    echo "  Created user '$APP_USER'."
fi

# --- Stop old service and kill stale processes ---
echo ""
echo "[3/8] Stopping any running instances..."
systemctl stop noc-prod 2>/dev/null || true
# Kill any stale gunicorn processes running as the app user
pkill -u "$APP_USER" -f gunicorn 2>/dev/null || true
sleep 1

# --- Clean old install and set up application directory ---
echo ""
echo "[4/8] Setting up application directory..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "  Copying files from $SCRIPT_DIR ..."

# Preserve data, logs, and .env from old install
# Remove old application code, venv, and stale files
if [ -d "$APP_DIR" ]; then
    echo "  Existing install found -- cleaning old application files..."
    rm -rf "$APP_DIR/venv"
    rm -rf "$APP_DIR/tools"
    rm -rf "$APP_DIR/templates"
    rm -rf "$APP_DIR/static"
    rm -f "$APP_DIR/app.py"
    rm -f "$APP_DIR/requirements.txt"
    rm -f "$APP_DIR/gunicorn.conf.py"
fi

mkdir -p "$APP_DIR"

# Copy fresh application files
cp "$SCRIPT_DIR/app.py" "$APP_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$APP_DIR/"
cp "$SCRIPT_DIR/gunicorn.conf.py" "$APP_DIR/"
cp -r "$SCRIPT_DIR/tools" "$APP_DIR/"
cp -r "$SCRIPT_DIR/templates" "$APP_DIR/"
cp -r "$SCRIPT_DIR/static" "$APP_DIR/"

# Create data and working directories
mkdir -p "$APP_DIR/data" "$APP_DIR/logs" "$APP_DIR/tmp/wlc_csv" "$APP_DIR/tmp/wlc_rf_csv"

# --- Create fresh virtual environment ---
echo ""
echo "[5/8] Creating Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
echo "  Dependencies installed."

# --- Generate .env file ---
echo ""
echo "[6/8] Configuring environment..."
if [ ! -f "$APP_DIR/.env" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ENCRYPTION_KEY=$("$APP_DIR/venv/bin/python3" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    cat > "$APP_DIR/.env" <<EOF
# NOC Toolkit Production Configuration
# Generated on $(date)

FLASK_SECRET_KEY=$SECRET_KEY
NOC_ENCRYPTION_KEY=$ENCRYPTION_KEY
NOC_TOOLKIT_DB_PATH=$APP_DIR/data/noc_toolkit.db
NOC_TOOLKIT_DATA_DIR=$APP_DIR/data
APP_PORT=5000
APP_VERSION=v2.0
LOG_LEVEL=info
EOF

    echo "  Generated .env with secure random keys."
else
    echo "  .env already exists, skipping."
fi

# --- Set permissions ---
echo ""
echo "[7/8] Setting permissions..."
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 600 "$APP_DIR/.env"
echo "  Permissions set."

# --- Install systemd service ---
echo ""
echo "[8/8] Installing systemd service..."
cp "$SCRIPT_DIR/noc-prod.service" /etc/systemd/system/noc-prod.service
systemctl daemon-reload
systemctl enable noc-prod
echo "  Service installed and enabled."

# --- Optional: install nginx config ---
if [ -d /etc/nginx/sites-available ]; then
    cp "$SCRIPT_DIR/nginx-noc-toolkit.conf" /etc/nginx/sites-available/noc-toolkit
    echo "  Nginx config copied to /etc/nginx/sites-available/noc-toolkit"
    echo "  To enable: ln -s /etc/nginx/sites-available/noc-toolkit /etc/nginx/sites-enabled/"
elif [ -d /etc/nginx/conf.d ]; then
    cp "$SCRIPT_DIR/nginx-noc-toolkit.conf" /etc/nginx/conf.d/noc-toolkit.conf
    echo "  Nginx config copied to /etc/nginx/conf.d/noc-toolkit.conf"
fi

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Review config:     nano $APP_DIR/.env"
echo "  2. Start the service: systemctl start noc-prod"
echo "  3. Check status:      systemctl status noc-prod"
echo "  4. View logs:         journalctl -u noc-prod -f"
echo "  5. Check health:      curl http://localhost:5000/health"
echo ""
echo "  The default admin login is admin / admin123"
echo "  CHANGE THIS IMMEDIATELY after first login!"
echo ""
echo "Optional:"
echo "  - Enable nginx reverse proxy (see nginx-noc-toolkit.conf)"
echo "  - Configure SSL certificates for HTTPS"
echo ""
