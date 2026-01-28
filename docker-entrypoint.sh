#!/bin/bash
set -e

# NOC Toolkit Docker Entrypoint
# Handles database initialization and startup

echo "[entrypoint] Starting NOC Toolkit..."

# Create necessary directories if they don't exist
mkdir -p /app/data /app/logs /app/tmp/wlc_csv /app/tmp/wlc_rf_csv

# Wait for PostgreSQL to be ready (if using PostgreSQL)
if [ -n "$POSTGRES_HOST" ]; then
    echo "[entrypoint] Waiting for PostgreSQL..."
    until pg_isready -h "$POSTGRES_HOST" -p "${POSTGRES_PORT:-5432}" -U "${POSTGRES_USER:-noc_toolkit}"; do
        echo "[entrypoint] PostgreSQL is unavailable - sleeping"
        sleep 2
    done
    echo "[entrypoint] PostgreSQL is ready!"
fi

# Generate encryption key if not provided
if [ -z "$NOC_ENCRYPTION_KEY" ] && [ ! -f /app/data/.encryption_key ]; then
    echo "[entrypoint] Generating encryption key..."
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > /app/data/.encryption_key
    chmod 600 /app/data/.encryption_key
fi

# Generate WLC dashboard key if not provided
if [ -z "$WLC_DASHBOARD_KEY" ] && [ ! -f /app/data/wlc_dashboard.key ]; then
    echo "[entrypoint] Generating WLC dashboard key..."
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > /app/data/wlc_dashboard.key
    chmod 600 /app/data/wlc_dashboard.key
fi

# Initialize database (SQLite for now, PostgreSQL migration in later stories)
echo "[entrypoint] Initializing database..."
python -c "
from tools.db_jobs import init_db
from tools.security import init_security_db
init_db()
init_security_db()
print('[entrypoint] Database initialized successfully')
"

echo "[entrypoint] Starting application..."
exec "$@"
