# NOC Toolkit - Production Deployment

This is a self-contained production deployment folder. It includes patched
copies of `app.py` and `tools/security.py` that resolve database path issues
for production environments (all SQLite connections use the `NOC_TOOLKIT_DB_PATH`
environment variable instead of hardcoded relative paths).

## Quick Start (Bare Metal)

```bash
# 1. Copy this folder to the server
scp -r noc-toolkit-prod/ hed@server:~/

# 2. SSH in and run setup
ssh hed@server
sudo bash ~/noc-toolkit-prod/setup.sh

# 3. Start the service
sudo systemctl start noc-prod

# 4. Verify
curl http://localhost:5000/health
```

The setup script handles everything:
- Installs Python, gcc, libffi, openssl, nginx
- Creates the `hed` user (if it doesn't already exist)
- Stops any old running instances and cleans stale files
- Copies app files to `/opt/noc-toolkit/`
- Creates a fresh Python venv with all dependencies
- Generates secure keys (FLASK_SECRET_KEY, NOC_ENCRYPTION_KEY)
- Installs the `noc-prod` systemd service

## Quick Start (Docker)

```bash
# 1. Copy this folder to the server
scp -r noc-toolkit-prod/ hed@server:~/

# 2. SSH in, create .env, and start
ssh hed@server
cd ~/noc-toolkit-prod
cp .env.example .env
nano .env   # set FLASK_SECRET_KEY
docker compose up -d

# 3. Verify
curl http://localhost:5000/health
```

## First Login

- Username: `admin`
- Password: `admin123`
- **Change this immediately** after first login.

## Configuration

All config is in `/opt/noc-toolkit/.env` (bare metal) or `.env` in the
project root (Docker). Key settings:

| Variable | Required | Description |
|---|---|---|
| `FLASK_SECRET_KEY` | Yes | Session encryption key |
| `NOC_ENCRYPTION_KEY` | No | Device credential encryption (auto-generated) |
| `NOC_TOOLKIT_DB_PATH` | No | SQLite database location (default: `/opt/noc-toolkit/data/noc_toolkit.db`) |
| `NOC_TOOLKIT_DATA_DIR` | No | Data directory (default: `/opt/noc-toolkit/data`) |
| `APP_PORT` | No | Listen port (default: `5000`) |
| `APP_VERSION` | No | Version label shown in footer (default: `v2.0`) |
| `GUNICORN_WORKERS` | No | Worker count (default: auto based on CPU) |
| `LOG_LEVEL` | No | Log level: debug, info, warning, error (default: `info`) |

## File Layout

```
/opt/noc-toolkit/
  app.py              # Main application (patched for production DB paths)
  gunicorn.conf.py    # Gunicorn WSGI config
  tools/              # Helper modules (security.py patched for production)
  templates/          # HTML templates
  static/             # Static assets (JS/CSS)
  data/               # SQLite database + encryption keys (persistent)
  logs/               # access.log, error.log
  venv/               # Python virtual environment
  .env                # Configuration (secrets -- not in git)
```

## Management

```bash
# Service control
sudo systemctl start noc-prod
sudo systemctl stop noc-prod
sudo systemctl restart noc-prod
sudo systemctl status noc-prod

# Application logs
journalctl -u noc-prod -f
tail -f /opt/noc-toolkit/logs/error.log

# Backup database
cp /opt/noc-toolkit/data/noc_toolkit.db ~/noc-backup-$(date +%Y%m%d).db
```

## Updating

To deploy a new version, copy the updated `noc-toolkit-prod/` folder to the
server and re-run setup. It will preserve your `data/`, `logs/`, and `.env`:

```bash
scp -r noc-toolkit-prod/ hed@server:~/
ssh hed@server
sudo bash ~/noc-toolkit-prod/setup.sh
sudo systemctl restart noc-prod
```

## Nginx Reverse Proxy (Optional)

```bash
sudo cp ~/noc-toolkit-prod/nginx-noc-toolkit.conf /etc/nginx/sites-available/noc-toolkit
sudo ln -s /etc/nginx/sites-available/noc-toolkit /etc/nginx/sites-enabled/
sudo nano /etc/nginx/sites-available/noc-toolkit   # edit server_name and SSL paths
sudo nginx -t && sudo systemctl reload nginx
```

## Troubleshooting

**500 errors on save/settings pages:**
The production `app.py` and `tools/security.py` in this folder have been
patched to use `NOC_TOOLKIT_DB_PATH` for all database connections. If you
see `sqlite3.OperationalError: attempt to write a readonly database`, make
sure you are using the files from this folder, not the main project root.

**Service won't start (Worker failed to boot):**
Check the actual error: `sudo -u hed /opt/noc-toolkit/venv/bin/gunicorn --error-logfile - --log-level error app:app --chdir /opt/noc-toolkit`

**Port already in use:**
Kill stale processes: `sudo pkill -u hed -f gunicorn` then restart the service.
