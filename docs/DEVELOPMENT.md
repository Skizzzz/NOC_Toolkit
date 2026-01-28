# Development Setup

This guide covers setting up NOC Toolkit for local development.

## Prerequisites

- Python 3.11 or higher
- Git
- SQLite (included with Python) or PostgreSQL
- Network access to test devices (optional, for integration testing)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/noc-toolkit.git
cd noc-toolkit
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install development dependencies (includes testing tools)
pip install -r requirements/dev.txt
```

### 4. Configure Environment

```bash
# Create environment file
cp .env.example .env

# For development, you can use simpler values:
# FLASK_SECRET_KEY=dev-secret-key
# FLASK_ENV=development
```

Or set environment variables directly:

```bash
export FLASK_SECRET_KEY=dev-secret-key
export FLASK_ENV=development
```

### 5. Initialize Database

The application automatically initializes the SQLite database on first run:

```bash
python app.py
```

### 6. Access the Application

Open `http://localhost:5000` in your browser.

Default credentials (development only):
- Username: `admin`
- Password: `admin123`

## Development Workflow

### Running the Application

```bash
# Standard run
python app.py

# With auto-reload (recommended for development)
FLASK_ENV=development python app.py
```

The application runs on `http://localhost:5000` by default.

### Code Style

The project uses the following tools for code quality:

```bash
# Format code with Black
black app.py tools/

# Check style with flake8
flake8 app.py tools/

# Type checking with mypy
mypy app.py tools/
```

Configuration for these tools is in `pyproject.toml`.

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_example.py

# Run E2E tests only
pytest -m e2e

# Skip slow tests
pytest -m "not slow"
```

### Syntax Checking

Quick syntax verification without running:

```bash
python3 -m py_compile app.py
python3 -m py_compile tools/db_jobs.py
```

## Project Structure

```
noc-toolkit/
├── app.py                 # Main Flask application with all routes
├── tools/                 # Backend modules
│   ├── __init__.py
│   ├── bulk_ssh.py       # Bulk SSH job execution
│   ├── cert_converter.py # Certificate format conversion
│   ├── cert_tracker.py   # Certificate parsing utilities
│   ├── db_jobs.py        # Database operations (SQLite)
│   ├── device_inventory.py
│   ├── global_config.py  # Global config push
│   ├── netmiko_helpers.py # SSH connection utilities
│   ├── phrase_search.py  # Config phrase search
│   ├── push_config.py    # Config deployment
│   ├── schedule_worker.py # Background task scheduler
│   ├── security.py       # Authentication/authorization
│   ├── solarwinds.py     # SolarWinds API integration
│   ├── template_engine.py # Command template processing
│   ├── topology.py       # Network topology builder
│   ├── wlc_clients.py    # WLC client operations
│   ├── wlc_inventory.py  # AP inventory collection
│   ├── wlc_rf.py         # RF metrics collection
│   └── wlc_summer_guest.py
├── templates/            # Jinja2 HTML templates
│   ├── base.html        # Base template with navigation
│   ├── login.html
│   └── ...
├── static/              # Static assets (CSS, JS, images)
├── requirements/
│   ├── base.txt        # Core dependencies
│   ├── prod.txt        # Production additions (gunicorn)
│   └── dev.txt         # Development additions (pytest, etc.)
├── docs/               # Documentation
├── tests/              # Test suite
├── pyproject.toml      # Project configuration
└── .env.example        # Environment template
```

## Key Components

### Database (tools/db_jobs.py)

The database module handles all SQLite operations:
- Job tracking and events
- Settings storage
- Inventory caching
- Certificate tracking

Database file location: `noc_toolkit.db` (configurable via `NOC_TOOLKIT_DB_PATH`)

### Security (tools/security.py)

Authentication and authorization:
- User management with role-based access
- Session handling
- Password encryption
- Audit logging

Key decorators:
- `@require_login` - Requires authenticated user
- `@require_superadmin` - Requires superadmin role
- `@require_page_enabled("page-name")` - Requires page to be enabled

### Network Operations (tools/netmiko_helpers.py)

SSH connection management using Netmiko:
- Connection pooling
- Timeout handling
- Multi-vendor support (Cisco IOS, IOS-XE, Aruba)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_SECRET_KEY` | `change-me-in-prod` | Session encryption key |
| `FLASK_ENV` | `production` | Flask environment mode |
| `NOC_TOOLKIT_DB_PATH` | `noc_toolkit.db` | SQLite database path |
| `NOC_TOOLKIT_DATA_DIR` | `.` | Data directory for files |
| `NOC_ENCRYPTION_KEY` | Auto-generated | Credential encryption key |
| `NOC_ADMIN_PASSWORD` | `admin123` | Initial admin password |
| `WLC_DASHBOARD_KEY` | Auto-generated | WLC credential encryption |

## Adding New Features

### Adding a New Route

1. Add the route in `app.py`:
```python
@app.route("/tools/my-feature")
@require_login
@require_page_enabled("my-feature")
def my_feature():
    return render_template("my_feature.html")
```

2. Create the template in `templates/my_feature.html`

3. Add navigation entry in `templates/base.html`

4. Add page settings entry in `db_jobs.py` if visibility control is needed

### Adding a Backend Module

1. Create the module in `tools/`:
```python
# tools/my_module.py
def my_function():
    pass
```

2. Import in `app.py`:
```python
from tools.my_module import my_function
```

## Debugging

### Enable Debug Mode

```bash
FLASK_ENV=development FLASK_DEBUG=1 python app.py
```

### Database Inspection

```bash
# Open SQLite CLI
sqlite3 noc_toolkit.db

# List tables
.tables

# Describe table
.schema jobs
```

### Log Output

Application logs appear in the console when running in development mode. For production, logs are written to `logs/` directory.

## Common Issues

### Import Errors

Ensure virtual environment is activated:
```bash
source venv/bin/activate
pip install -r requirements/dev.txt
```

### Database Locked

SQLite may lock during concurrent writes. Restart the application if this occurs:
```bash
# Kill existing process
pkill -f "python app.py"

# Restart
python app.py
```

### Connection Timeouts

Network operations may timeout when connecting to devices. Adjust timeouts in `tools/netmiko_helpers.py` if needed.

## IDE Setup

### VS Code

Recommended extensions:
- Python (Microsoft)
- Pylance
- Black Formatter

Settings (`.vscode/settings.json`):
```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true
}
```

### PyCharm

1. Set project interpreter to the virtual environment
2. Enable Black as the formatter
3. Configure flake8 as external tool
