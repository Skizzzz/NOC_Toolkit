# Deployment Guide

This guide covers deploying NOC Toolkit in a production environment using Docker.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- At least 2GB RAM available
- Network access to target devices (switches, controllers, etc.)

## Quick Deployment

### 1. Clone and Configure

```bash
git clone https://github.com/Skizzzz/NOC_Toolkit.git
cd NOC_Toolkit

# Create environment file
cp .env.example .env
```

### 2. Generate Secure Credentials

Generate strong secrets for production:

```bash
# Flask secret key (session security)
python3 -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32))"

# PostgreSQL password
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(24))"

# Encryption key for stored credentials
python3 -c "from cryptography.fernet import Fernet; print('NOC_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

Add the generated values to your `.env` file.

### 3. Configure Environment

Edit `.env` with your production settings:

```bash
# Required
FLASK_SECRET_KEY=<generated-key>
POSTGRES_PASSWORD=<generated-password>

# Recommended
FLASK_ENV=production
APP_PORT=5000

# Optional - encryption for stored credentials
NOC_ENCRYPTION_KEY=<generated-key>
```

### 4. Deploy

```bash
# Build and start containers
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f app
```

### 5. Verify Deployment

```bash
# Check health endpoint
curl http://localhost:5000/health

# Expected response:
# {"service": "noc-toolkit", "status": "healthy"}
```

Access the application at `http://localhost:5000` and log in with the default credentials or the password set via `NOC_ADMIN_PASSWORD`.

## Production Configuration

### Reverse Proxy (nginx)

For production deployments, use a reverse proxy with SSL termination:

```nginx
server {
    listen 443 ssl http2;
    server_name noc.example.com;

    ssl_certificate /etc/ssl/certs/noc.crt;
    ssl_certificate_key /etc/ssl/private/noc.key;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for real-time updates
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

server {
    listen 80;
    server_name noc.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Resource Limits

Add resource limits in `docker-compose.yml` for production:

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### Scaling Workers

Adjust Gunicorn workers based on available CPU cores:

```yaml
# In docker-compose.yml, modify the CMD
command: ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "8", "--threads", "4", "app:app"]
```

Formula: `workers = (2 x CPU cores) + 1`

## Backup and Restore

### Database Backup

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U noc_toolkit noc_toolkit > backup_$(date +%Y%m%d).sql

# Backup with compression
docker-compose exec postgres pg_dump -U noc_toolkit noc_toolkit | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Database Restore

```bash
# Restore from backup
cat backup.sql | docker-compose exec -T postgres psql -U noc_toolkit noc_toolkit

# Restore from compressed backup
gunzip -c backup.sql.gz | docker-compose exec -T postgres psql -U noc_toolkit noc_toolkit
```

### Volume Backup

```bash
# Backup all volumes
docker run --rm \
  -v noc-toolkit-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/data-backup.tar.gz -C /data .

docker run --rm \
  -v noc-toolkit-postgres:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres-backup.tar.gz -C /data .
```

## Monitoring

### Health Check

The `/health` endpoint returns application status:

```bash
curl -s http://localhost:5000/health | jq
```

### Container Logs

```bash
# Follow all logs
docker-compose logs -f

# Application logs only
docker-compose logs -f app

# Last 100 lines
docker-compose logs --tail=100 app
```

### Container Metrics

```bash
# Resource usage
docker stats noc-toolkit-app noc-toolkit-postgres
```

## Updating

### Standard Update

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Zero-Downtime Update

```bash
# Build new image
docker-compose build app

# Recreate with minimal downtime
docker-compose up -d --no-deps app
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs for errors
docker-compose logs app

# Verify environment variables
docker-compose config

# Check if ports are available
netstat -tlnp | grep 5000
```

### Database Connection Issues

```bash
# Verify PostgreSQL is healthy
docker-compose exec postgres pg_isready

# Check database exists
docker-compose exec postgres psql -U noc_toolkit -c '\l'

# Test connection from app container
docker-compose exec app python -c "import psycopg2; print('OK')"
```

### Permission Errors

```bash
# Fix volume permissions
docker-compose down
docker volume rm noc-toolkit-data
docker-compose up -d
```

### Reset to Clean State

```bash
# WARNING: This deletes all data!
docker-compose down -v
docker-compose up -d
```

## Security Checklist

Before going to production:

- [ ] Generate unique `FLASK_SECRET_KEY`
- [ ] Set strong `POSTGRES_PASSWORD`
- [ ] Configure `NOC_ENCRYPTION_KEY` for credential storage
- [ ] Set `FLASK_ENV=production`
- [ ] Deploy behind reverse proxy with SSL
- [ ] Restrict network access to management interfaces
- [ ] Configure firewall rules
- [ ] Set up regular backups
- [ ] Change default admin password immediately after first login
- [ ] Review and configure page visibility settings
