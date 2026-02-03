FROM python:3.11-slim

# Install system dependencies needed by netmiko/cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r hed && useradd -r -g hed -d /opt/noc-toolkit -s /bin/bash hed

# Set working directory
WORKDIR /opt/noc-toolkit

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY gunicorn.conf.py .
COPY tools/ tools/
COPY templates/ templates/
COPY static/ static/

# Create required directories
RUN mkdir -p data logs tmp/wlc_csv tmp/wlc_rf_csv \
    && chown -R hed:hed /opt/noc-toolkit

# Copy entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Switch to non-root user
USER hed

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
