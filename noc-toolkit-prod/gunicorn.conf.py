"""Gunicorn configuration for NOC Toolkit production deployment."""

import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('APP_PORT', '5000')}"

# Worker processes
# Formula: (2 x CPU cores) + 1
workers = int(os.environ.get("GUNICORN_WORKERS", (2 * multiprocessing.cpu_count()) + 1))
threads = int(os.environ.get("GUNICORN_THREADS", 4))
worker_class = "gthread"

# Timeouts
timeout = 120  # Network operations can be slow
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = "/opt/noc-toolkit/logs/access.log"
errorlog = "/opt/noc-toolkit/logs/error.log"
loglevel = os.environ.get("LOG_LEVEL", "info")

# Process naming
proc_name = "noc-toolkit"

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Preload app for better memory usage with multiple workers
preload_app = False  # Disabled due to SQLite threading constraints
