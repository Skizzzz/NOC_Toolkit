# PRD: NOC Toolkit Production Readiness

## Introduction

This initiative transforms the NOC Toolkit from a development-ready application to a production-grade, easily deployable system. The project will be restructured for GitHub deployment with Docker, the monolithic `app.py` will be split into Flask blueprints by feature domain, SQLite will be replaced with PostgreSQL for scalability (supporting 100k+ APs), and comprehensive Playwright E2E tests will be added for verification. Additionally, the deprecated `/tools/device-inventory` page will be removed in favor of the SolarWinds-based inventory at `/tools/solarwinds/inventory`.

## Goals

- Enable one-command deployment on new machines via Docker Compose
- Support 15,000+ devices and 100,000+ access points with PostgreSQL
- Improve code maintainability by splitting app.py into focused blueprints
- Provide full E2E test coverage with Playwright for all major workflows
- Secure first-run experience with interactive setup wizard (no passwords in logs)
- Remove deprecated device inventory page, consolidating on SolarWinds inventory
- Establish clear project structure that scales with team contributions

---

## User Stories

### Phase 1: Project Restructure & Docker Setup

#### US-001: Create Docker and Docker Compose Configuration
**Description:** As a DevOps engineer, I want to deploy NOC Toolkit with a single `docker-compose up` command so that new machine setup takes minutes instead of hours.

**Acceptance Criteria:**
- [ ] Create `Dockerfile` with Python 3.11+ base image
- [ ] Create `docker-compose.yml` with services: `app`, `postgres`, `redis` (optional cache)
- [ ] Create `.env.example` with all required environment variables documented
- [ ] Create `docker-entrypoint.sh` that handles database initialization
- [ ] Application starts successfully with `docker-compose up`
- [ ] Health check endpoint `/health` returns 200 when app is ready
- [ ] PostgreSQL data persists in named volume
- [ ] **Verify container starts and health endpoint responds using Playwright**

#### US-002: Create Production-Ready Requirements and Dependencies
**Description:** As a developer, I want clearly separated development and production dependencies so that production images are lean and secure.

**Acceptance Criteria:**
- [ ] Create `requirements/base.txt` with core dependencies
- [ ] Create `requirements/prod.txt` extending base with gunicorn, psycopg2-binary
- [ ] Create `requirements/dev.txt` extending base with pytest, playwright, black, flake8
- [ ] Update `Dockerfile` to use `requirements/prod.txt`
- [ ] Add `pyproject.toml` for modern Python project configuration
- [ ] All imports resolve successfully after restructure

#### US-003: Create Project Documentation for GitHub
**Description:** As a new contributor, I want clear documentation so that I can understand how to set up, run, and contribute to the project.

**Acceptance Criteria:**
- [ ] Create/update `README.md` with project overview, features, and quick start
- [ ] Create `docs/DEPLOYMENT.md` with production deployment guide
- [ ] Create `docs/DEVELOPMENT.md` with local development setup
- [ ] Create `docs/CONTRIBUTING.md` with contribution guidelines
- [ ] Create `CHANGELOG.md` for version history
- [ ] Add architecture diagram showing component relationships

---

### Phase 2: Flask Blueprints Restructure

#### US-004: Create Blueprint Directory Structure
**Description:** As a developer, I want the codebase organized by feature domain so that I can quickly find and modify related code.

**Acceptance Criteria:**
- [ ] Create `src/` directory as main package
- [ ] Create `src/blueprints/` directory with subdirectories:
  - `auth/` (login, logout, profile)
  - `admin/` (users, settings, page settings)
  - `wlc/` (dashboard, ap inventory, rf, clients, summer guest)
  - `solarwinds/` (nodes, inventory)
  - `config/` (phrase search, global config, changes)
  - `bulk_ssh/` (jobs, templates, schedules)
  - `certs/` (tracker, converter, ISE nodes)
  - `jobs/` (job center, detail, progress)
  - `kb/` (knowledge base)
  - `api/` (JSON API endpoints)
- [ ] Each blueprint directory contains `__init__.py`, `routes.py`, `templates/` subdirectory
- [ ] Create `src/core/` for shared utilities (db, security, helpers)
- [ ] Create `src/models/` for database models

#### US-005: Extract Auth Blueprint
**Description:** As a developer, I want authentication routes in a dedicated blueprint so that auth logic is isolated and testable.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/auth/routes.py` with routes: `/login`, `/logout`, `/profile`
- [ ] Move `login.html`, `profile.html` templates to `src/blueprints/auth/templates/`
- [ ] Register blueprint in main app factory
- [ ] Login flow works end-to-end
- [ ] **Verify login/logout flow using Playwright**

#### US-006: Extract Admin Blueprint
**Description:** As a developer, I want admin routes in a dedicated blueprint so that administrative functions are clearly separated.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/admin/routes.py` with routes: `/admin/users`, `/admin/settings`, `/admin/page-settings`
- [ ] Move admin templates to `src/blueprints/admin/templates/`
- [ ] Maintain superadmin role requirement decorators
- [ ] All admin functions work correctly
- [ ] **Verify admin user management using Playwright**

#### US-007: Extract WLC Blueprint
**Description:** As a developer, I want WLC-related routes in a dedicated blueprint so that wireless controller features are grouped together.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/wlc/routes.py` with routes:
  - `/tools/wlc` (menu)
  - `/tools/wlc/dashboard` and `/api/wlc/dashboard`
  - `/tools/wlc/ap-inventory`
  - `/tools/wlc/summer-guest`
  - `/tools/wlc-rf`, `/tools/wlc-rf-troubleshoot`
  - `/tools/wlc-clients-troubleshoot`
- [ ] Move WLC templates to `src/blueprints/wlc/templates/`
- [ ] Dashboard polling continues to work
- [ ] AP inventory auto-updates correctly
- [ ] **Verify WLC dashboard displays data using Playwright**

#### US-008: Extract SolarWinds Blueprint
**Description:** As a developer, I want SolarWinds routes in a dedicated blueprint so that inventory features are cleanly organized.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/solarwinds/routes.py` with routes:
  - `/tools/solarwinds/nodes`
  - `/tools/solarwinds/inventory`
  - `/api/solarwinds/nodes`
- [ ] Move SolarWinds templates to `src/blueprints/solarwinds/templates/`
- [ ] Node sync from SolarWinds API works correctly
- [ ] Inventory aggregation and export functions work
- [ ] **Verify SolarWinds inventory page loads and filters using Playwright**

#### US-009: Extract Config Blueprint
**Description:** As a developer, I want configuration management routes in a dedicated blueprint.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/config/routes.py` with routes:
  - `/tools/phrase-search`, `/search`, `/download-csv`
  - `/tools/global-config`, `/global/*`
  - `/changes`, `/changes/<id>`
  - `/actions/*`
- [ ] Move config templates to `src/blueprints/config/templates/`
- [ ] Config search and apply workflows function correctly
- [ ] Change window scheduling works
- [ ] **Verify phrase search workflow using Playwright**

#### US-010: Extract Bulk SSH Blueprint
**Description:** As a developer, I want bulk SSH routes in a dedicated blueprint.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/bulk_ssh/routes.py` with routes:
  - `/tools/bulk-ssh`
  - `/tools/bulk-ssh/templates`
  - `/tools/bulk-ssh/schedules`
  - `/tools/bulk-ssh/results/<job_id>`
  - `/api/bulk-ssh/*`
- [ ] Move bulk SSH templates to `src/blueprints/bulk_ssh/templates/`
- [ ] Template CRUD operations work
- [ ] Schedule creation and execution works
- [ ] **Verify bulk SSH job submission using Playwright**

#### US-011: Extract Certs Blueprint
**Description:** As a developer, I want certificate management routes in a dedicated blueprint.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/certs/routes.py` with routes:
  - `/certs`, `/certs/<id>`, `/certs/upload`
  - `/cert-converter`, `/cert-chain`
  - `/ise-nodes`
- [ ] Move cert templates to `src/blueprints/certs/templates/`
- [ ] Certificate upload and parsing works
- [ ] ISE node sync works
- [ ] **Verify certificate upload flow using Playwright**

#### US-012: Extract Jobs Blueprint
**Description:** As a developer, I want job management routes in a dedicated blueprint.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/jobs/routes.py` with routes:
  - `/jobs`, `/jobs/<job_id>`
  - `/api/jobs`, `/api/jobs/<job_id>/progress`
- [ ] Move job templates to `src/blueprints/jobs/templates/`
- [ ] Job listing and progress streaming works
- [ ] **Verify job progress page updates using Playwright**

#### US-013: Extract Knowledge Base Blueprint
**Description:** As a developer, I want knowledge base routes in a dedicated blueprint.

**Acceptance Criteria:**
- [ ] Create `src/blueprints/kb/routes.py` with routes:
  - `/knowledge-base`
  - `/knowledge-base/create`
  - `/knowledge-base/<id>`, `/knowledge-base/<id>/edit`
- [ ] Move KB templates to `src/blueprints/kb/templates/`
- [ ] Article CRUD with visibility levels works
- [ ] **Verify KB article creation using Playwright**

#### US-014: Create Application Factory Pattern
**Description:** As a developer, I want the app to use the factory pattern so that testing and configuration is easier.

**Acceptance Criteria:**
- [ ] Create `src/app.py` with `create_app(config_name)` factory function
- [ ] Create `src/config.py` with configuration classes (Development, Production, Testing)
- [ ] Register all blueprints in factory
- [ ] Initialize extensions (db, login manager) in factory
- [ ] Create `wsgi.py` as production entry point
- [ ] Application starts with `gunicorn wsgi:app`

#### US-015: Update Base Template and Navigation
**Description:** As a developer, I want the base template to work with the new blueprint structure.

**Acceptance Criteria:**
- [ ] Move `base.html` to `src/templates/base.html`
- [ ] Update all `url_for()` calls to use blueprint prefixes
- [ ] Navigation sidebar renders correctly
- [ ] Page enable/disable settings work with new routes
- [ ] Static files served correctly from `src/static/`
- [ ] **Verify navigation works across all pages using Playwright**

---

### Phase 3: PostgreSQL Migration

#### US-016: Create PostgreSQL Database Models
**Description:** As a developer, I want SQLAlchemy models so that the application works with PostgreSQL.

**Acceptance Criteria:**
- [ ] Add `Flask-SQLAlchemy` and `psycopg2-binary` to requirements
- [ ] Create `src/models/` with model files:
  - `user.py` (User, Session)
  - `job.py` (Job, JobEvent)
  - `wlc.py` (WLCDashboardSettings, WLCSample, APInventory)
  - `solarwinds.py` (SolarWindsSettings, SolarWindsNode)
  - `config.py` (ChangeWindow, ChangeEvent)
  - `bulk_ssh.py` (BulkSSHJob, BulkSSHResult, BulkSSHTemplate, BulkSSHSchedule)
  - `cert.py` (Certificate, ISENode, CertSyncSettings)
  - `settings.py` (AppSettings, PageSettings)
  - `kb.py` (KBArticle)
  - `audit.py` (AuditLog)
- [ ] All models include proper indexes matching current SQLite schema
- [ ] Foreign key relationships defined correctly

#### US-017: Create Database Migration System
**Description:** As a developer, I want Alembic migrations so that database schema changes are versioned and reproducible.

**Acceptance Criteria:**
- [ ] Add `Flask-Migrate` (Alembic) to requirements
- [ ] Initialize migrations with `flask db init`
- [ ] Create initial migration with all models
- [ ] Migration runs successfully on fresh PostgreSQL database
- [ ] Create `scripts/init_db.py` for first-time database setup

#### US-018: Update Database Access Layer
**Description:** As a developer, I want the data access layer to use SQLAlchemy so that queries work with PostgreSQL.

**Acceptance Criteria:**
- [ ] Refactor `tools/db_jobs.py` functions to use SQLAlchemy models
- [ ] Create `src/core/database.py` with database utilities
- [ ] All existing functionality works with PostgreSQL backend
- [ ] Connection pooling configured for production workloads
- [ ] Database connection uses `DATABASE_URL` environment variable

#### US-019: Update Background Workers for PostgreSQL
**Description:** As a developer, I want background workers to work with PostgreSQL connection handling.

**Acceptance Criteria:**
- [ ] Update `schedule_worker.py` to use SQLAlchemy sessions properly
- [ ] Ensure proper session cleanup in background threads
- [ ] WLC dashboard polling works with PostgreSQL
- [ ] Bulk SSH scheduler works with PostgreSQL
- [ ] No connection pool exhaustion under load

---

### Phase 4: Security Improvements

#### US-020: Create First-Run Setup Wizard
**Description:** As an administrator, I want a web-based setup wizard on first run so that I can securely set the admin password without it appearing in logs.

**Acceptance Criteria:**
- [ ] Detect first-run state (no users in database)
- [ ] Redirect all routes to `/setup` when in first-run state
- [ ] Create `src/blueprints/setup/` blueprint with setup wizard
- [ ] Setup wizard page collects:
  - Admin username (default: admin)
  - Admin password (with confirmation)
  - Optional: SolarWinds connection settings
  - Optional: Application timezone
- [ ] Password validation: minimum 12 characters, complexity requirements
- [ ] After setup, redirect to login page
- [ ] Setup route returns 404 after initial setup complete
- [ ] **Verify setup wizard flow using Playwright**

#### US-021: Remove Password Logging
**Description:** As a security engineer, I want no passwords logged to console or files so that credentials are not exposed.

**Acceptance Criteria:**
- [ ] Remove `print()` statement logging default password in `security.py:146`
- [ ] Audit all `print()` statements for credential exposure
- [ ] Replace print statements with proper Python logging
- [ ] Configure logging to exclude sensitive fields
- [ ] Add `logging.conf` or configure in app factory

#### US-022: Secure Secret Key Handling
**Description:** As a security engineer, I want the Flask secret key to be required in production so that sessions cannot be forged.

**Acceptance Criteria:**
- [ ] Remove default value from `FLASK_SECRET_KEY`
- [ ] Application refuses to start in production without `FLASK_SECRET_KEY`
- [ ] Document secret key generation in deployment docs
- [ ] Add secret key to `.env.example` with generation instructions

---

### Phase 5: Remove Deprecated Device Inventory

#### US-023: Remove Device Inventory Page and Routes
**Description:** As a product owner, I want the deprecated `/tools/device-inventory` page removed so that users use the SolarWinds-based inventory instead.

**Acceptance Criteria:**
- [ ] Remove `/tools/device-inventory` route and related routes:
  - `POST /tools/device-inventory/scan`
  - `GET /tools/device-inventory/export`
  - `POST /tools/device-inventory/<device>/delete`
  - `GET /api/device-inventory`
- [ ] Remove `templates/device_inventory.html`
- [ ] Remove `device_inventory` table from models (keep migration for cleanup)
- [ ] Remove device inventory functions from `db_jobs.py`
- [ ] Update navigation to remove Device Inventory link
- [ ] Update page settings to remove device-inventory entry
- [ ] `tools/device_inventory.py` can remain for any shared utilities used elsewhere
- [ ] **Verify device inventory page returns 404 using Playwright**

#### US-024: Update Documentation for Inventory Consolidation
**Description:** As a user, I want documentation updated to reflect that SolarWinds Inventory is the source of truth.

**Acceptance Criteria:**
- [ ] Update README to reference SolarWinds Inventory
- [ ] Add note in CHANGELOG about device inventory deprecation
- [ ] Update any internal knowledge base articles referencing device inventory

---

### Phase 6: Playwright E2E Testing

#### US-025: Set Up Playwright Test Infrastructure
**Description:** As a developer, I want a Playwright test infrastructure so that I can write and run E2E tests.

**Acceptance Criteria:**
- [ ] Add `pytest-playwright` to dev requirements
- [ ] Create `tests/` directory structure:
  - `tests/e2e/` for Playwright tests
  - `tests/conftest.py` with fixtures
  - `tests/e2e/conftest.py` with Playwright fixtures
- [ ] Create `playwright.config.py` or `pytest.ini` configuration
- [ ] Create Docker Compose override for test environment
- [ ] Create test database seeding script
- [ ] Tests can run with `pytest tests/e2e/`
- [ ] Add GitHub Actions workflow for CI testing

#### US-026: Create Auth E2E Tests
**Description:** As a developer, I want E2E tests for authentication flows.

**Acceptance Criteria:**
- [ ] Test: Login with valid credentials succeeds
- [ ] Test: Login with invalid credentials shows error
- [ ] Test: Logout redirects to login page
- [ ] Test: Protected pages redirect to login when not authenticated
- [ ] Test: Password change works correctly
- [ ] All tests pass in CI

#### US-027: Create Admin E2E Tests
**Description:** As a developer, I want E2E tests for admin functionality.

**Acceptance Criteria:**
- [ ] Test: Create new user
- [ ] Test: Edit user role
- [ ] Test: Delete user (non-admin)
- [ ] Test: Change timezone setting
- [ ] Test: Toggle page visibility
- [ ] Test: Non-admin cannot access admin pages
- [ ] All tests pass in CI

#### US-028: Create WLC Dashboard E2E Tests
**Description:** As a developer, I want E2E tests for WLC dashboard functionality.

**Acceptance Criteria:**
- [ ] Test: Dashboard page loads with charts
- [ ] Test: Dashboard settings can be saved
- [ ] Test: AP inventory page displays data
- [ ] Test: AP inventory export downloads CSV
- [ ] Test: Time range selector updates chart data
- [ ] All tests pass in CI

#### US-029: Create SolarWinds Inventory E2E Tests
**Description:** As a developer, I want E2E tests for SolarWinds inventory functionality.

**Acceptance Criteria:**
- [ ] Test: Inventory page loads with node list
- [ ] Test: Search/filter reduces visible nodes
- [ ] Test: Vendor aggregation displays correctly
- [ ] Test: Version aggregation displays correctly
- [ ] Test: Export downloads CSV
- [ ] Test: Settings page saves connection info
- [ ] All tests pass in CI

#### US-030: Create Bulk SSH E2E Tests
**Description:** As a developer, I want E2E tests for bulk SSH functionality.

**Acceptance Criteria:**
- [ ] Test: Create SSH template
- [ ] Test: Edit SSH template
- [ ] Test: Delete SSH template
- [ ] Test: Create scheduled job
- [ ] Test: View job results page
- [ ] Test: Export job results
- [ ] All tests pass in CI

#### US-031: Create Certificate Tracker E2E Tests
**Description:** As a developer, I want E2E tests for certificate management.

**Acceptance Criteria:**
- [ ] Test: Upload certificate file
- [ ] Test: View certificate details
- [ ] Test: Certificate expiration display
- [ ] Test: Add ISE node
- [ ] Test: Certificate converter tool
- [ ] All tests pass in CI

#### US-032: Create Config Management E2E Tests
**Description:** As a developer, I want E2E tests for configuration management.

**Acceptance Criteria:**
- [ ] Test: Phrase search form submission
- [ ] Test: Search results display
- [ ] Test: Action preview page
- [ ] Test: Change window creation
- [ ] Test: Change window detail view
- [ ] All tests pass in CI

#### US-033: Create Knowledge Base E2E Tests
**Description:** As a developer, I want E2E tests for knowledge base functionality.

**Acceptance Criteria:**
- [ ] Test: View article list
- [ ] Test: Create new article
- [ ] Test: Edit article
- [ ] Test: Delete article
- [ ] Test: Visibility filtering works
- [ ] All tests pass in CI

#### US-034: Create Setup Wizard E2E Tests
**Description:** As a developer, I want E2E tests for the first-run setup wizard.

**Acceptance Criteria:**
- [ ] Test: Fresh database redirects to setup
- [ ] Test: Setup wizard validates password requirements
- [ ] Test: Setup wizard creates admin user
- [ ] Test: After setup, redirects to login
- [ ] Test: Setup page not accessible after initial setup
- [ ] All tests pass in CI

#### US-035: Create Smoke Test Suite
**Description:** As a developer, I want a smoke test that validates all pages load without errors.

**Acceptance Criteria:**
- [ ] Test iterates through all navigation links
- [ ] Each page returns 200 status (or 302 redirect for auth)
- [ ] No JavaScript console errors on any page
- [ ] No broken images or missing static files
- [ ] Test completes in under 2 minutes
- [ ] All tests pass in CI

---

## Functional Requirements

### Docker & Deployment
- FR-1: Application must start with `docker-compose up` command
- FR-2: PostgreSQL database must be automatically initialized on first run
- FR-3: Application must use gunicorn as WSGI server in production
- FR-4: Health endpoint `/health` must return 200 when application is ready
- FR-5: All environment variables must be documented in `.env.example`

### Project Structure
- FR-6: All Flask routes must be organized into blueprints by feature domain
- FR-7: Each blueprint must have its own templates subdirectory
- FR-8: Application must use factory pattern (`create_app()`)
- FR-9: Configuration must support Development, Production, and Testing modes

### Database
- FR-10: Application must use PostgreSQL as the database backend
- FR-11: Database schema must be managed via Alembic migrations
- FR-12: All models must use SQLAlchemy ORM
- FR-13: Connection pooling must be configured for production workloads

### Security
- FR-14: First run must present a setup wizard to create admin user
- FR-15: No passwords or secrets may be logged to console or files
- FR-16: Flask secret key must be required (no default value) in production
- FR-17: Setup wizard must enforce password complexity (min 12 chars)

### Deprecated Features
- FR-18: `/tools/device-inventory` route must return 404
- FR-19: Device inventory navigation link must not appear
- FR-20: SolarWinds Inventory at `/tools/solarwinds/inventory` must be the primary inventory page

### Testing
- FR-21: Playwright E2E tests must exist for all major user workflows
- FR-22: Tests must run in CI via GitHub Actions
- FR-23: Smoke test must verify all pages load without errors

---

## Non-Goals (Out of Scope)

- SQLite to PostgreSQL data migration tool (clean break - new deployments only)
- Redis caching layer (future enhancement)
- Kubernetes/Helm deployment (Docker Compose only for now)
- ServiceNow integration (separate PRD)
- API versioning (existing API routes unchanged)
- Unit tests for individual functions (E2E tests only in this PRD)
- Mobile-responsive redesign
- Multi-tenancy or organization isolation

---

## Technical Considerations

### Blueprint URL Prefixes
| Blueprint | URL Prefix | Example Routes |
|-----------|------------|----------------|
| auth | (none) | `/login`, `/logout`, `/profile` |
| admin | `/admin` | `/admin/users`, `/admin/settings` |
| wlc | `/tools/wlc` | `/tools/wlc/dashboard`, `/tools/wlc/ap-inventory` |
| solarwinds | `/tools/solarwinds` | `/tools/solarwinds/nodes`, `/tools/solarwinds/inventory` |
| config | `/tools` | `/tools/phrase-search`, `/changes` |
| bulk_ssh | `/tools/bulk-ssh` | `/tools/bulk-ssh/templates` |
| certs | `/certs` | `/certs`, `/cert-converter` |
| jobs | `/jobs` | `/jobs`, `/jobs/<id>` |
| kb | `/knowledge-base` | `/knowledge-base`, `/knowledge-base/<id>` |
| api | `/api` | `/api/wlc/dashboard`, `/api/jobs/<id>/progress` |

### Database Connection
```
DATABASE_URL=postgresql://user:pass@localhost:5432/noc_toolkit
```

### Required Environment Variables (Production)
```
DATABASE_URL=postgresql://...
FLASK_SECRET_KEY=<generated-secret>
NOC_ENCRYPTION_KEY=<generated-key>
```

### Docker Compose Services
```yaml
services:
  app:
    build: .
    ports: ["8080:8080"]
    depends_on: [postgres]
    environment:
      DATABASE_URL: postgresql://...
  postgres:
    image: postgres:15
    volumes: [postgres_data:/var/lib/postgresql/data]
```

### Test Database Seeding
Tests will use a separate PostgreSQL database with seeded test data:
- Test admin user
- Sample SolarWinds nodes
- Sample WLC data
- Sample certificates

---

## Success Metrics

- New machine deployment time: < 5 minutes with Docker Compose
- All 35 user stories pass acceptance criteria
- All Playwright E2E tests pass in CI
- Zero credential exposure in logs
- `app.py` reduced from 7,169 lines to < 200 lines (factory + CLI only)
- Each blueprint file < 500 lines

---

## Open Questions

1. Should we add a `make` or `just` command runner for common tasks?
2. Should Redis be included in docker-compose.yml even if not used initially?
3. What should the minimum PostgreSQL version be? (Suggested: 13+)
4. Should we add database backup scripts to the repository?
5. Should Playwright tests run in headless mode only, or support headed mode for debugging?

---

## Implementation Order

Recommended implementation sequence:

1. **Phase 1** (US-001 to US-003): Docker setup and documentation
2. **Phase 3** (US-016 to US-019): PostgreSQL migration (before blueprints, as models inform structure)
3. **Phase 4** (US-020 to US-022): Security improvements
4. **Phase 2** (US-004 to US-015): Flask blueprints restructure
5. **Phase 5** (US-023 to US-024): Remove deprecated device inventory
6. **Phase 6** (US-025 to US-035): Playwright E2E tests

This order ensures the database layer is stable before restructuring routes, and tests are written against the final architecture.
