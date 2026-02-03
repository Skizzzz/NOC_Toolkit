#!/bin/bash
set -e

echo "=== NOC Toolkit Starting ==="

# Create required directories
mkdir -p /opt/noc-toolkit/data
mkdir -p /opt/noc-toolkit/logs
mkdir -p /opt/noc-toolkit/tmp/wlc_csv
mkdir -p /opt/noc-toolkit/tmp/wlc_rf_csv

# Set defaults for required env vars
export NOC_TOOLKIT_DB_PATH="${NOC_TOOLKIT_DB_PATH:-/opt/noc-toolkit/data/noc_toolkit.db}"
export NOC_TOOLKIT_DATA_DIR="${NOC_TOOLKIT_DATA_DIR:-/opt/noc-toolkit/data}"

# Validate required environment variables
if [ "$FLASK_SECRET_KEY" = "CHANGE-ME-generate-a-real-secret-key" ] || [ -z "$FLASK_SECRET_KEY" ]; then
    echo "WARNING: FLASK_SECRET_KEY is not set or using default value."
    echo "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
    echo "Generating a temporary key for this session..."
    export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

echo "Database path: $NOC_TOOLKIT_DB_PATH"
echo "Data directory: $NOC_TOOLKIT_DATA_DIR"
echo "=== Starting application ==="

exec "$@"
