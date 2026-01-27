# tools/db_jobs.py
import csv
import sqlite3
import json
import threading
import os
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

# Use America/Chicago timezone for consistency with app.py and schedule_worker.py
_CST_TZ = ZoneInfo("America/Chicago")
from typing import Optional, Iterable, List, Dict, Union

try:
    from cryptography.fernet import Fernet
    _HAS_FERNET = True
except ImportError:
    Fernet = None  # type: ignore
    _HAS_FERNET = False

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_ROOT = Path(os.environ.get("NOC_TOOLKIT_DATA_DIR", Path.home() / ".noc_toolkit")).expanduser()
_DATA_ROOT.mkdir(parents=True, exist_ok=True)

_env_db = os.environ.get("NOC_TOOLKIT_DB_PATH")
if _env_db:
    DB_PATH = str(Path(_env_db).expanduser())
else:
    new_path = _DATA_ROOT / "noc_toolkit.db"
    legacy_path = _PROJECT_ROOT / "noc_toolkit.db"
    if new_path.exists():
        DB_PATH = str(new_path)
    else:
        if legacy_path.exists():
            try:
                import shutil
                shutil.copy2(legacy_path, new_path)
                key_src = _PROJECT_ROOT / "wlc_dashboard.key"
                key_dst = _DATA_ROOT / "wlc_dashboard.key"
                if key_src.exists() and not key_dst.exists():
                    shutil.copy2(key_src, key_dst)
            except Exception:
                pass
        DB_PATH = str(new_path)

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
_DB_LOCK = threading.Lock()

_DEFAULT_WLC_DASHBOARD_SETTINGS = {
    "enabled": False,
    "hosts": [],
    "username": "",
    "password": "",
    "secret": "",
    "interval_sec": 600,
    "last_poll_ts": None,
    "last_poll_status": "never",
    "last_poll_message": "",
    "validation": [],
    "poll_summary": None,
    # Aruba controller settings
    "aruba_hosts": [],
    "aruba_username": "",
    "aruba_password": "",
    "aruba_secret": "",
    "aruba_enabled": False,
}

_DEFAULT_WLC_SUMMER_SETTINGS = {
    "enabled": False,
    "hosts": [],
    "username": "",
    "password": "",
    "secret": "",
    "profile_names": ["SummerGuest"],
    "wlan_ids": [10],
    "daily_time": "07:00",
    "timezone": "America/Chicago",
    "last_poll_ts": None,
    "last_poll_status": "never",
    "last_poll_message": "",
    "validation": [],
    "summary": None,
    "auto_prefix": "Summer",
}

_ENC_KEY_CACHE: Optional[bytes] = None


def _get_dashboard_key() -> bytes:
    global _ENC_KEY_CACHE
    if _ENC_KEY_CACHE is not None:
        return _ENC_KEY_CACHE

    env_key = os.environ.get("WLC_DASHBOARD_KEY")
    if env_key:
        key = env_key.encode()
        if _HAS_FERNET and len(key) != 44:
            key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
    elif _HAS_FERNET:
        key_dir = os.path.dirname(DB_PATH)
        os.makedirs(key_dir, exist_ok=True)
        key_path = os.path.join(key_dir, "wlc_dashboard.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key()
            with open(key_path, "wb") as f:
                f.write(key)
    else:
        key = hashlib.sha256((DB_PATH + "-wlc-dash").encode()).digest()

    _ENC_KEY_CACHE = key
    return key


def _encrypt_secret(value: Optional[str]) -> str:
    if not value:
        return ""
    key = _get_dashboard_key()
    raw = value.encode()
    if _HAS_FERNET:
        cipher = Fernet(key)
        return cipher.encrypt(raw).decode()
    else:
        hashed = hashlib.sha256(key).digest()
        xored = bytes(b ^ hashed[i % len(hashed)] for i, b in enumerate(raw))
        return base64.urlsafe_b64encode(xored).decode()


def _decrypt_secret(value: Optional[str]) -> str:
    if not value:
        return ""
    key = _get_dashboard_key()
    try:
        if _HAS_FERNET:
            cipher = Fernet(key)
            return cipher.decrypt(value.encode()).decode()
        else:
            hashed = hashlib.sha256(key).digest()
            raw = base64.urlsafe_b64decode(value.encode())
            plain = bytes(b ^ hashed[i % len(hashed)] for i, b in enumerate(raw))
            return plain.decode()
    except Exception:
        return ""


def _normalize_daily_time(value: Optional[str]) -> str:
    if not value:
        return "07:00"
    parts = value.strip().split(":")
    if len(parts) != 2:
        return "07:00"
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except Exception:
        return "07:00"
    hour = max(0, min(hour, 23))
    minute = max(0, min(minute, 59))
    return f"{hour:02d}:{minute:02d}"


def _normalize_profile_names(values: Iterable) -> List[str]:
    seen = set()
    names: List[str] = []
    for raw in values or []:
        text = str(raw or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(text)
    return names


def _normalize_wlan_ids(values: Iterable) -> List[int]:
    seen = set()
    ids: List[int] = []
    for raw in values or []:
        if raw is None:
            continue
        try:
            number = int(str(raw).strip())
        except Exception:
            continue
        if number < 0 or number in seen:
            continue
        seen.add(number)
        ids.append(number)
    return ids


def _conn():
    cx = sqlite3.connect(DB_PATH, check_same_thread=False)
    cx.row_factory = sqlite3.Row
    return cx


def _legacy_log_csv_path() -> str:
    data_candidate = Path(DB_PATH).resolve().parent / "logs" / "changes.csv"
    if data_candidate.exists():
        return str(data_candidate)
    project_candidate = _PROJECT_ROOT / "logs" / "changes.csv"
    return str(project_candidate)


def _maybe_seed_change_logs(cx: sqlite3.Connection):
    """Populate change_logs table from legacy CSV if empty."""
    try:
        cur = cx.execute("SELECT COUNT(*) FROM change_logs")
        if (cur.fetchone() or [0])[0]:
            return
        csv_path = _legacy_log_csv_path()
        if not os.path.exists(csv_path):
            return
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            rows = []
            for raw in reader:
                rows.append(
                    (
                        (raw.get("timestamp") or "").strip(),
                        (raw.get("username") or "").strip(),
                        (raw.get("tool") or "").strip(),
                        (raw.get("job_id") or "").strip(),
                        (raw.get("switch_ip") or "").strip(),
                        (raw.get("result") or "").strip(),
                        (raw.get("message") or "").strip(),
                        (raw.get("config_lines") or "").strip(),
                    )
                )
        if rows:
            cx.executemany(
                "INSERT INTO change_logs(ts, username, tool, job_id, switch_ip, result, message, config_lines) VALUES(?,?,?,?,?,?,?,?)",
                rows,
            )
    except Exception:
        # Legacy import is best-effort; ignore failures to avoid breaking startup.
        pass


def init_db():
    """
    Initialize database, tables, indexes, and set pragmatic defaults
    for durability and concurrency.
    """
    with _conn() as cx:
        # Pragmas: WAL for better concurrency; NORMAL sync for speed with durability
        try:
            cx.execute("PRAGMA journal_mode=WAL;")
            cx.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            # Pragmas are best-effort; ignore if unavailable
            pass

        # Core tables
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs(
              job_id TEXT PRIMARY KEY,
              created TEXT,
              tool TEXT,
              params_json TEXT,
              done INTEGER DEFAULT 0,
              cancelled INTEGER DEFAULT 0
            )
            """
        )
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS job_events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              job_id TEXT,
              ts TEXT,
              type TEXT,              -- created|sample|error|done|cancelled|note
              payload_json TEXT
            )
            """
        )

        # Indexes
        cx.execute("CREATE INDEX IF NOT EXISTS idx_job_events_job ON job_events(job_id)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_job_events_type ON job_events(type)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_job_events_ts ON job_events(ts)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_jobs_tool ON jobs(tool)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created)")

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS wlc_dashboard_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              enabled INTEGER DEFAULT 0,
              hosts_json TEXT,
              username TEXT,
              password TEXT,
              secret TEXT,
              interval_sec INTEGER DEFAULT 600,
              updated TEXT,
              last_poll_ts TEXT,
              last_poll_status TEXT,
              last_poll_message TEXT
            )
            """
        )

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS wlc_dashboard_samples(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT,
              host TEXT,
              total_clients INTEGER,
              ap_count INTEGER,
              ap_details_json TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_wlc_dash_ts ON wlc_dashboard_samples(ts)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_wlc_dash_host ON wlc_dashboard_samples(host)")
        try:
            cx.execute("ALTER TABLE wlc_dashboard_samples ADD COLUMN ap_details_json TEXT")
        except Exception:
            pass
        try:
            cx.execute(
                "DELETE FROM wlc_dashboard_samples WHERE rowid NOT IN (SELECT MIN(rowid) FROM wlc_dashboard_samples GROUP BY ts, host)"
            )
        except Exception:
            pass
        cx.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wlc_dash_unique ON wlc_dashboard_samples(ts, host)")
        try:
            cx.execute("ALTER TABLE wlc_dashboard_settings ADD COLUMN validation_json TEXT")
        except Exception:
            pass
        try:
            cx.execute("ALTER TABLE wlc_dashboard_settings ADD COLUMN poll_summary_json TEXT")
        except Exception:
            pass
        # Migration: Add Aruba controller settings columns
        try:
            cx.execute("ALTER TABLE wlc_dashboard_settings ADD COLUMN aruba_hosts_json TEXT")
        except Exception:
            pass
        try:
            cx.execute("ALTER TABLE wlc_dashboard_settings ADD COLUMN aruba_enabled INTEGER DEFAULT 0")
        except Exception:
            pass

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS wlc_summer_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              enabled INTEGER DEFAULT 0,
              hosts_json TEXT,
              username TEXT,
              password TEXT,
              secret TEXT,
              profile_names_json TEXT,
              wlan_ids_json TEXT,
              daily_time TEXT,
              timezone TEXT,
              updated TEXT,
              last_poll_ts TEXT,
              last_poll_status TEXT,
              last_poll_message TEXT,
              validation_json TEXT,
              summary_json TEXT
            )
            """
        )

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS wlc_summer_samples(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT,
              host TEXT,
              profile_name TEXT,
              wlan_id INTEGER,
              ssid TEXT,
              enabled INTEGER,
              status_text TEXT,
              raw_json TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_wlc_summer_ts ON wlc_summer_samples(ts)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_wlc_summer_host ON wlc_summer_samples(host)")
        cx.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_wlc_summer_unique ON wlc_summer_samples(ts, host, COALESCE(wlan_id, -1), COALESCE(profile_name, ''), COALESCE(ssid, ''))"
        )

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS solarwinds_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              base_url TEXT,
              username TEXT,
              password TEXT,
              verify_ssl INTEGER DEFAULT 1,
              updated TEXT,
              last_poll_ts TEXT,
              last_poll_status TEXT,
              last_poll_message TEXT
            )
            """
        )

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS solarwinds_nodes(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              node_id TEXT,
              caption TEXT,
              organization TEXT,
              vendor TEXT,
              model TEXT,
              version TEXT,
              ip_address TEXT,
              status TEXT,
              last_seen TEXT,
              extra_json TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_solarwinds_node_id ON solarwinds_nodes(node_id)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_solarwinds_caption ON solarwinds_nodes(caption)")
        try:
            cx.execute("ALTER TABLE solarwinds_nodes ADD COLUMN vendor TEXT")
        except Exception:
            pass

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS change_windows(
              change_id TEXT PRIMARY KEY,
              created TEXT,
              scheduled TEXT,
              tool TEXT,
              change_number TEXT,
              payload_json TEXT,
              rollback_json TEXT,
              status TEXT,
              started TEXT,
              completed TEXT,
              rollback_started TEXT,
              rollback_completed TEXT,
              apply_job_id TEXT,
              rollback_job_id TEXT,
              message TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_windows_scheduled ON change_windows(scheduled)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_windows_status ON change_windows(status)")

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS change_events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              change_id TEXT,
              ts TEXT,
              type TEXT,
              message TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_events_change ON change_events(change_id)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_events_ts ON change_events(ts)")

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS change_logs(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT,
              username TEXT,
              tool TEXT,
              job_id TEXT,
              switch_ip TEXT,
              result TEXT,
              message TEXT,
              config_lines TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_logs_ts ON change_logs(ts)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_logs_tool ON change_logs(tool)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_change_logs_user ON change_logs(username)")

        # Bulk SSH tables
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS bulk_ssh_jobs(
              job_id TEXT PRIMARY KEY,
              created TEXT,
              username TEXT,
              command TEXT,
              device_count INTEGER DEFAULT 0,
              completed_count INTEGER DEFAULT 0,
              success_count INTEGER DEFAULT 0,
              failed_count INTEGER DEFAULT 0,
              status TEXT DEFAULT 'running',
              done INTEGER DEFAULT 0
            )
            """
        )
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS bulk_ssh_results(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              job_id TEXT,
              device TEXT,
              status TEXT,
              output TEXT,
              error TEXT,
              duration_ms INTEGER,
              completed_at TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_jobs_created ON bulk_ssh_jobs(created)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_jobs_username ON bulk_ssh_jobs(username)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_results_job ON bulk_ssh_results(job_id)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_results_device ON bulk_ssh_results(device)")

        # Bulk SSH Templates
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS bulk_ssh_templates(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT UNIQUE NOT NULL,
              description TEXT,
              command TEXT NOT NULL,
              variables TEXT,
              device_type TEXT DEFAULT 'cisco_ios',
              category TEXT DEFAULT 'general',
              created TEXT,
              updated TEXT,
              created_by TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_templates_category ON bulk_ssh_templates(category)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_templates_name ON bulk_ssh_templates(name)")

        # Scheduled Bulk SSH Jobs
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS bulk_ssh_schedules(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT UNIQUE NOT NULL,
              description TEXT,
              devices_json TEXT,
              command TEXT,
              template_id INTEGER,
              schedule_type TEXT DEFAULT 'once',
              schedule_config TEXT,
              next_run TEXT,
              last_run TEXT,
              last_job_id TEXT,
              enabled INTEGER DEFAULT 1,
              alert_on_failure INTEGER DEFAULT 0,
              alert_email TEXT,
              created TEXT,
              created_by TEXT,
              username TEXT,
              password_encrypted TEXT,
              secret_encrypted TEXT,
              device_type TEXT DEFAULT 'cisco_ios'
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_schedules_next_run ON bulk_ssh_schedules(next_run)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_bulk_ssh_schedules_enabled ON bulk_ssh_schedules(enabled)")

        # Certificate Tracker tables
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              cn TEXT,
              expires TEXT,
              issued_to TEXT,
              issued_by TEXT,
              used_by TEXT,
              notes TEXT,
              devices TEXT,
              source_type TEXT,
              source_ip TEXT,
              source_hostname TEXT,
              uploaded TEXT,
              updated TEXT,
              serial TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_certs_cn ON certificates(cn)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_certs_expires ON certificates(expires)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_certs_source ON certificates(source_type)")

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS ise_nodes(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              hostname TEXT,
              ip TEXT,
              username TEXT,
              password_encrypted TEXT,
              enabled INTEGER DEFAULT 1,
              last_sync TEXT,
              last_sync_status TEXT,
              last_sync_message TEXT,
              created TEXT,
              updated TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_ise_nodes_hostname ON ise_nodes(hostname)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_ise_nodes_ip ON ise_nodes(ip)")

        # Add version and patch columns if they don't exist (migration)
        try:
            cx.execute("ALTER TABLE ise_nodes ADD COLUMN ise_version TEXT")
        except Exception:
            pass  # Column already exists
        try:
            cx.execute("ALTER TABLE ise_nodes ADD COLUMN ise_patch TEXT")
        except Exception:
            pass  # Column already exists

        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS cert_sync_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              enabled INTEGER DEFAULT 0,
              interval_hours INTEGER DEFAULT 24,
              last_sync_ts TEXT,
              last_sync_status TEXT,
              last_sync_message TEXT
            )
            """
        )

        # Page visibility settings
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS page_settings(
              page_key TEXT PRIMARY KEY,
              page_name TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              category TEXT,
              updated_at TEXT
            )
            """
        )

        # App-wide settings (timezone, etc.)
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              timezone TEXT DEFAULT 'America/Chicago',
              updated_at TEXT
            )
            """
        )

        # Device Inventory table
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS device_inventory(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              device TEXT UNIQUE,
              device_type TEXT,
              vendor TEXT,
              model TEXT,
              serial_number TEXT,
              firmware_version TEXT,
              hostname TEXT,
              uptime TEXT,
              last_scanned TEXT,
              scan_status TEXT,
              scan_error TEXT,
              solarwinds_node_id TEXT,
              extra_json TEXT
            )
            """
        )
        cx.execute("CREATE INDEX IF NOT EXISTS idx_device_inv_device ON device_inventory(device)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_device_inv_vendor ON device_inventory(vendor)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_device_inv_model ON device_inventory(model)")

        # AP Inventory table - auto-updated from WLC polling
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS ap_inventory(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ap_name TEXT,
              ap_ip TEXT,
              ap_model TEXT,
              ap_mac TEXT,
              ap_location TEXT,
              ap_state TEXT,
              slots TEXT,
              country TEXT,
              wlc_host TEXT,
              first_seen TEXT,
              last_seen TEXT
            )
            """
        )
        # Unique constraint on (ap_mac, wlc_host) to prevent duplicates
        cx.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ap_inv_mac_wlc ON ap_inventory(ap_mac, wlc_host)")
        # Index on last_seen for efficient cleanup queries
        cx.execute("CREATE INDEX IF NOT EXISTS idx_ap_inv_last_seen ON ap_inventory(last_seen)")
        # Additional indexes for common queries
        cx.execute("CREATE INDEX IF NOT EXISTS idx_ap_inv_name ON ap_inventory(ap_name)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_ap_inv_wlc ON ap_inventory(wlc_host)")
        cx.execute("CREATE INDEX IF NOT EXISTS idx_ap_inv_model ON ap_inventory(ap_model)")

        # AP Inventory settings table
        cx.execute(
            """
            CREATE TABLE IF NOT EXISTS ap_inventory_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              enabled INTEGER DEFAULT 1,
              cleanup_days INTEGER DEFAULT 5,
              updated_at TEXT
            )
            """
        )

        _maybe_seed_change_logs(cx)
        _init_page_settings(cx)


def insert_job(job_id: str, tool: str, created: str, params: dict):
    """
    Insert (or replace) a job row and emit a 'created' event.
    """
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "INSERT OR REPLACE INTO jobs(job_id, created, tool, params_json, done, cancelled) VALUES(?,?,?,?,0,0)",
                (job_id, created, tool, json.dumps(params)),
            )
            cx.execute(
                "INSERT INTO job_events(job_id, ts, type, payload_json) VALUES(?,?,?,?)",
                (job_id, created, "created", "{}"),
            )
    except Exception:
        # Fail silently to avoid crashing callers; callers can still proceed in-memory
        pass


def append_event(job_id: str, etype: str, payload: Optional[dict] = None, ts: Optional[str] = None):
    """
    Append a single event row.
    """
    if ts is None:
        ts = datetime.now().isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "INSERT INTO job_events(job_id, ts, type, payload_json) VALUES(?,?,?,?)",
                (job_id, ts, etype, json.dumps(payload or {})),
            )
    except Exception:
        pass


def append_events_bulk(job_id: str, events: Iterable[dict]):
    """
    Append multiple events within a single transaction.
    Each event dict should have keys: type, payload (optional), ts (optional)
    """
    rows = []
    now_iso = datetime.now().isoformat(timespec="seconds")
    for e in events:
        etype = e.get("type", "note")
        ets = e.get("ts") or now_iso
        payload = json.dumps(e.get("payload") or {})
        rows.append((job_id, ets, etype, payload))
    if not rows:
        return
    try:
        with _DB_LOCK, _conn() as cx:
            cx.executemany(
                "INSERT INTO job_events(job_id, ts, type, payload_json) VALUES(?,?,?,?)",
                rows,
            )
    except Exception:
        pass


def mark_done(job_id: str, *, cancelled: bool = False):
    """
    Mark job as done (and optionally cancelled) and emit a terminal event.
    """
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE jobs SET done=1, cancelled=? WHERE job_id=?",
                (1 if cancelled else 0, job_id),
            )
            cx.execute(
                "INSERT INTO job_events(job_id, ts, type, payload_json) VALUES(?,?,?,?)",
                (
                    job_id,
                    datetime.now().isoformat(timespec="seconds"),
                    "cancelled" if cancelled else "done",
                    "{}",
                ),
            )
    except Exception:
        pass


def has_event(job_id: str, etype: str) -> bool:
    """Return True if at least one event with the given type exists for the job."""
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                "SELECT 1 FROM job_events WHERE job_id = ? AND type = ? ORDER BY id DESC LIMIT 1",
                (job_id, etype),
            )
            return cur.fetchone() is not None
    except Exception:
        return False


def list_jobs(limit: int = 200):
    """
    Returns newest-first jobs with quick aggregates:
      - samples_count (number of 'sample' events)
      - last_ts (timestamp of last event)
    """
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT
                  j.job_id, j.created, j.tool, j.done, j.cancelled, j.params_json,
                  COALESCE((
                     SELECT COUNT(*) FROM job_events e
                     WHERE e.job_id = j.job_id AND e.type='sample'
                  ), 0) AS samples_count,
                  (
                     SELECT e.ts FROM job_events e
                     WHERE e.job_id = j.job_id
                     ORDER BY e.id DESC LIMIT 1
                  ) AS last_ts
                FROM jobs j
                ORDER BY j.job_id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = [dict(r) for r in cur.fetchall()]
    except Exception:
        rows = []

    # parse params once here
    for r in rows:
        try:
            r["params"] = json.loads(r.pop("params_json") or "{}")
        except Exception:
            r["params"] = {}
    return rows


def load_job(job_id: str):
    """
    Return (job_meta_dict, events_list)
    """
    try:
        with _DB_LOCK, _conn() as cx:
            meta = cx.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if not meta:
                return None, []
            meta = dict(meta)
            try:
                meta["params"] = json.loads(meta.pop("params_json") or "{}")
            except Exception:
                meta["params"] = {}
            ev = cx.execute("SELECT * FROM job_events WHERE job_id=? ORDER BY id", (job_id,)).fetchall()
            events = [dict(e) for e in ev]
    except Exception:
        return None, []

    # parse payloads
    for e in events:
        try:
            e["payload"] = json.loads(e.pop("payload_json") or "{}")
        except Exception:
            e["payload"] = {}
    return meta, events


def job_status(job_id: str) -> str:
    """
    Convenience helper: 'running' | 'done' | 'cancelled' | 'missing'
    """
    meta, _ = load_job(job_id)
    if not meta:
        return "missing"
    if meta.get("cancelled"):
        return "cancelled"
    if meta.get("done"):
        return "done"
    return "running"


def cleanup_old_jobs(days: int = 30) -> int:
    """
    Purge jobs and events older than N days.
    Returns number of jobs removed (best-effort).
    NOTE: created and ts are ISO strings; ISO lexical order equals chronological order.
    """
    cutoff_iso = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    removed = 0
    try:
        with _DB_LOCK, _conn() as cx:
            # collect old job_ids first
            cur = cx.execute("SELECT job_id FROM jobs WHERE created < ?", (cutoff_iso,))
            old_ids = [r["job_id"] for r in cur.fetchall()]
            if old_ids:
                # delete events first for FK-safety (even though no FK was declared)
                cx.executemany("DELETE FROM job_events WHERE job_id = ?", [(jid,) for jid in old_ids])
                cx.executemany("DELETE FROM jobs WHERE job_id = ?", [(jid,) for jid in old_ids])
                removed = len(old_ids)
    except Exception:
        pass
    return removed


def load_wlc_dashboard_settings():
    data = dict(_DEFAULT_WLC_DASHBOARD_SETTINGS)
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM wlc_dashboard_settings WHERE id=1").fetchone()
            if not row:
                cx.execute(
                    "INSERT INTO wlc_dashboard_settings(id, enabled, hosts_json, username, password, secret, interval_sec, updated, last_poll_ts, last_poll_status, last_poll_message, validation_json, poll_summary_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        1,
                        0,
                        json.dumps([]),
                        "",
                        _encrypt_secret(""),
                        _encrypt_secret(""),
                        300,
                        datetime.now().isoformat(timespec="seconds"),
                        None,
                        "never",
                        "",
                        json.dumps([]),
                        json.dumps(None),
                    ),
                )
                return data
            row = dict(row)
            data["enabled"] = bool(row.get("enabled"))
            try:
                data["hosts"] = json.loads(row.get("hosts_json") or "[]")
            except Exception:
                data["hosts"] = []
            data["username"] = row.get("username", "")
            data["password"] = _decrypt_secret(row.get("password"))
            data["secret"] = _decrypt_secret(row.get("secret"))
            data["interval_sec"] = row.get("interval_sec", 600) or 600
            data["last_poll_ts"] = row.get("last_poll_ts")
            data["last_poll_status"] = row.get("last_poll_status", "never")
            data["last_poll_message"] = row.get("last_poll_message", "")
            try:
                data["validation"] = json.loads(row.get("validation_json") or "[]")
            except Exception:
                data["validation"] = []
            try:
                data["poll_summary"] = json.loads(row.get("poll_summary_json") or "null")
            except Exception:
                data["poll_summary"] = None
            # Load Aruba controller settings
            try:
                data["aruba_hosts"] = json.loads(row.get("aruba_hosts_json") or "[]")
            except Exception:
                data["aruba_hosts"] = []
            data["aruba_enabled"] = bool(row.get("aruba_enabled"))
    except Exception:
        pass
    return data


def save_wlc_dashboard_settings(settings: dict):
    payload = dict(_DEFAULT_WLC_DASHBOARD_SETTINGS)
    payload.update(settings or {})
    hosts_json = json.dumps(payload.get("hosts") or [])
    validation_json = json.dumps(payload.get("validation") or [])
    poll_summary_json = json.dumps(payload.get("poll_summary"))
    aruba_hosts_json = json.dumps(payload.get("aruba_hosts") or [])
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO wlc_dashboard_settings(id, enabled, hosts_json, username, password, secret, interval_sec, updated, last_poll_ts, last_poll_status, last_poll_message, validation_json, poll_summary_json, aruba_hosts_json, aruba_enabled)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  enabled=excluded.enabled,
                  hosts_json=excluded.hosts_json,
                  username=excluded.username,
                  password=excluded.password,
                  secret=excluded.secret,
                  interval_sec=excluded.interval_sec,
                  updated=excluded.updated,
                  last_poll_ts=excluded.last_poll_ts,
                  last_poll_status=excluded.last_poll_status,
                  last_poll_message=excluded.last_poll_message,
                  validation_json=excluded.validation_json,
                  poll_summary_json=excluded.poll_summary_json,
                  aruba_hosts_json=excluded.aruba_hosts_json,
                  aruba_enabled=excluded.aruba_enabled
                """,
                (
                    1,
                    1 if payload.get("enabled") else 0,
                    hosts_json,
                    payload.get("username", ""),
                    _encrypt_secret(payload.get("password")),
                    _encrypt_secret(payload.get("secret")),
                    int(payload.get("interval_sec", 600) or 600),
                    datetime.now().isoformat(timespec="seconds"),
                    payload.get("last_poll_ts"),
                    payload.get("last_poll_status", "never"),
                    payload.get("last_poll_message", ""),
                    validation_json,
                    poll_summary_json,
                    aruba_hosts_json,
                    1 if payload.get("aruba_enabled") else 0,
                ),
            )
    except Exception:
        pass


def update_wlc_dashboard_poll_status(*, ts: Optional[str], status: str, message: str = ""):
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE wlc_dashboard_settings SET last_poll_ts=?, last_poll_status=?, last_poll_message=?, updated=? WHERE id=1",
                (
                    ts,
                    status,
                    message,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
    except Exception:
        pass


def insert_wlc_dashboard_samples(ts_iso: str, metrics: List[Dict]):
    if not metrics:
        return
    rows = []
    for m in metrics:
        rows.append(
            (
                ts_iso,
                m.get("host", ""),
                int(m.get("total_clients") or 0),
                int(m.get("ap_count") or 0),
                json.dumps(m.get("ap_details") or []),
            )
        )
    cutoff_iso = (datetime.now() - timedelta(days=31)).isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.executemany(
                "INSERT INTO wlc_dashboard_samples(ts, host, total_clients, ap_count, ap_details_json) VALUES(?,?,?,?,?)",
                rows,
            )
            cx.execute("DELETE FROM wlc_dashboard_samples WHERE ts < ?", (cutoff_iso,))
    except Exception:
        pass


def fetch_wlc_dashboard_series(hours: int) -> List[Dict]:
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    data: list[dict] = []
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT ts,
                       COALESCE(SUM(total_clients), 0) AS total_clients,
                       COALESCE(SUM(ap_count), 0) AS total_aps
                FROM wlc_dashboard_samples
                WHERE ts >= ?
                GROUP BY ts
                ORDER BY ts
                """,
                (cutoff,),
            )
            for row in cur.fetchall():
                data.append({
                    "ts": row["ts"],
                    "clients": row["total_clients"],
                    "aps": row["total_aps"],
                })
    except Exception:
        pass
    return data


def fetch_wlc_dashboard_latest_totals() -> Dict:
    info: Dict = {"ts": None, "clients": 0, "aps": 0}
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute(
                """
                SELECT ts,
                       SUM(total_clients) AS total_clients,
                       SUM(ap_count) AS total_aps
                FROM wlc_dashboard_samples
                WHERE ts = (SELECT MAX(ts) FROM wlc_dashboard_samples)
                """
            ).fetchone()
            if row and row["ts"]:
                info["ts"] = row["ts"]
                info["clients"] = row["total_clients"] or 0
                info["aps"] = row["total_aps"] or 0
    except Exception:
        pass
    return info


def fetch_wlc_dashboard_latest_details() -> Dict[str, Dict]:
    data: Dict[str, Dict] = {}
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT s.host, s.total_clients, s.ap_count, s.ap_details_json
                FROM wlc_dashboard_samples s
                INNER JOIN (
                    SELECT host, MAX(ts) AS max_ts FROM wlc_dashboard_samples GROUP BY host
                ) latest ON latest.host = s.host AND latest.max_ts = s.ts
                """
            )
            for row in cur.fetchall():
                details = []
                try:
                    details = json.loads(row["ap_details_json"] or "[]")
                except Exception:
                    details = []
                data[row["host"]] = {
                    "total_clients": row["total_clients"] or 0,
                    "ap_count": row["ap_count"] or 0,
                    "ap_details": details,
                }
    except Exception:
        pass
    return data


def load_wlc_summer_settings() -> dict:
    data = dict(_DEFAULT_WLC_SUMMER_SETTINGS)
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM wlc_summer_settings WHERE id=1").fetchone()
            if not row:
                cx.execute(
                    """
                    INSERT INTO wlc_summer_settings(
                      id, enabled, hosts_json, username, password, secret,
                      profile_names_json, wlan_ids_json, daily_time, timezone, updated,
                      last_poll_ts, last_poll_status, last_poll_message, validation_json, summary_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        1,
                        0,
                        json.dumps([]),
                        "",
                        _encrypt_secret(""),
                        _encrypt_secret(""),
                        json.dumps(data["profile_names"]),
                        json.dumps(data["wlan_ids"]),
                        data["daily_time"],
                        data["timezone"],
                        datetime.now().isoformat(timespec="seconds"),
                        None,
                        "never",
                        "",
                        json.dumps([]),
                        json.dumps(None),
                    ),
                )
                return data

            row_dict = dict(row)
            data["enabled"] = bool(row_dict.get("enabled"))
            try:
                hosts = json.loads(row_dict.get("hosts_json") or "[]")
                clean_hosts = []
                seen_hosts = set()
                for host in hosts:
                    text = str(host or "").strip()
                    if not text:
                        continue
                    key = text.lower()
                    if key in seen_hosts:
                        continue
                    seen_hosts.add(key)
                    clean_hosts.append(text)
                data["hosts"] = clean_hosts
            except Exception:
                data["hosts"] = []
            data["username"] = row_dict.get("username", "")
            data["password"] = _decrypt_secret(row_dict.get("password"))
            data["secret"] = _decrypt_secret(row_dict.get("secret"))
            try:
                profiles = json.loads(row_dict.get("profile_names_json") or "[]")
            except Exception:
                profiles = []
            data["profile_names"] = _normalize_profile_names(profiles) or list(_DEFAULT_WLC_SUMMER_SETTINGS["profile_names"])
            try:
                wlan_ids_raw = json.loads(row_dict.get("wlan_ids_json") or "[]")
            except Exception:
                wlan_ids_raw = []
            data["wlan_ids"] = _normalize_wlan_ids(wlan_ids_raw) or list(_DEFAULT_WLC_SUMMER_SETTINGS["wlan_ids"])
            data["daily_time"] = _normalize_daily_time(row_dict.get("daily_time"))
            tz_value = row_dict.get("timezone") or data["timezone"]
            data["timezone"] = tz_value
            data["last_poll_ts"] = row_dict.get("last_poll_ts")
            data["last_poll_status"] = row_dict.get("last_poll_status", "never")
            data["last_poll_message"] = row_dict.get("last_poll_message", "")
            try:
                data["validation"] = json.loads(row_dict.get("validation_json") or "[]")
            except Exception:
                data["validation"] = []
            try:
                data["summary"] = json.loads(row_dict.get("summary_json") or "null")
            except Exception:
                data["summary"] = None
            data.setdefault("auto_prefix", "Summer")
    except Exception:
        pass
    return data


def save_wlc_summer_settings(settings: dict):
    payload = dict(_DEFAULT_WLC_SUMMER_SETTINGS)
    payload.update(settings or {})

    hosts_clean = []
    seen_hosts = set()
    for host in payload.get("hosts") or []:
        text = str(host or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        hosts_clean.append(text)

    profile_names = _normalize_profile_names(payload.get("profile_names") or [])
    if not profile_names:
        profile_names = list(_DEFAULT_WLC_SUMMER_SETTINGS["profile_names"])

    wlan_ids = _normalize_wlan_ids(payload.get("wlan_ids") or [])
    if not wlan_ids:
        wlan_ids = list(_DEFAULT_WLC_SUMMER_SETTINGS["wlan_ids"])

    daily_time = _normalize_daily_time(payload.get("daily_time"))
    timezone_value = payload.get("timezone") or _DEFAULT_WLC_SUMMER_SETTINGS["timezone"]

    validation_json = json.dumps(payload.get("validation") or [])
    summary_json = json.dumps(payload.get("summary"))

    payload.setdefault("auto_prefix", "Summer")

    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO wlc_summer_settings(
                  id, enabled, hosts_json, username, password, secret,
                  profile_names_json, wlan_ids_json, daily_time, timezone, updated,
                  last_poll_ts, last_poll_status, last_poll_message, validation_json, summary_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  enabled=excluded.enabled,
                  hosts_json=excluded.hosts_json,
                  username=excluded.username,
                  password=excluded.password,
                  secret=excluded.secret,
                  profile_names_json=excluded.profile_names_json,
                  wlan_ids_json=excluded.wlan_ids_json,
                  daily_time=excluded.daily_time,
                  timezone=excluded.timezone,
                  updated=excluded.updated,
                  last_poll_ts=excluded.last_poll_ts,
                  last_poll_status=excluded.last_poll_status,
                  last_poll_message=excluded.last_poll_message,
                  validation_json=excluded.validation_json,
                  summary_json=excluded.summary_json
                """,
                (
                    1,
                    1 if payload.get("enabled") else 0,
                    json.dumps(hosts_clean),
                    payload.get("username", ""),
                    _encrypt_secret(payload.get("password")),
                    _encrypt_secret(payload.get("secret")),
                    json.dumps(profile_names),
                    json.dumps(wlan_ids),
                    daily_time,
                    timezone_value,
                    datetime.now().isoformat(timespec="seconds"),
                    payload.get("last_poll_ts"),
                    payload.get("last_poll_status", "never"),
                    payload.get("last_poll_message", ""),
                    validation_json,
                    summary_json,
                ),
            )
    except Exception:
        pass


def update_wlc_summer_poll_status(*, ts: Optional[str], status: str, message: str = ""):
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE wlc_summer_settings SET last_poll_ts=?, last_poll_status=?, last_poll_message=?, updated=? WHERE id=1",
                (
                    ts,
                    status,
                    message,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
    except Exception:
        pass


def insert_wlc_summer_samples(ts_iso: str, samples: List[Dict]):
    if not samples:
        return
    rows = []
    for sample in samples:
        enabled = sample.get("enabled")
        if enabled is None:
            enabled_value = None
        else:
            enabled_value = 1 if bool(enabled) else 0
        rows.append(
            (
                ts_iso,
                sample.get("host", ""),
                sample.get("profile_name", ""),
                sample.get("wlan_id"),
                sample.get("ssid", ""),
                enabled_value,
                sample.get("status_text", ""),
                json.dumps(sample.get("raw")),
            )
        )

    cutoff_iso = (datetime.now() - timedelta(days=180)).isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.executemany(
                """
                INSERT OR REPLACE INTO wlc_summer_samples(
                  ts, host, profile_name, wlan_id, ssid, enabled, status_text, raw_json
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                rows,
            )
            cx.execute("DELETE FROM wlc_summer_samples WHERE ts < ?", (cutoff_iso,))
    except Exception:
        pass


def fetch_wlc_summer_latest_details() -> Dict[str, Dict]:
    data: Dict[str, Dict] = {}
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT s.host, s.ts, s.profile_name, s.wlan_id, s.ssid, s.enabled, s.status_text, s.raw_json
                FROM wlc_summer_samples s
                INNER JOIN (
                    SELECT host, MAX(ts) AS max_ts FROM wlc_summer_samples GROUP BY host
                ) latest ON latest.host = s.host AND latest.max_ts = s.ts
                ORDER BY s.host, COALESCE(s.wlan_id, 0), s.profile_name, s.ssid
                """
            )
            for row in cur.fetchall():
                host = row["host"]
                entry = data.setdefault(host, {"ts": row["ts"], "entries": []})
                entry["ts"] = row["ts"]
                try:
                    raw_payload = json.loads(row["raw_json"] or "null")
                except Exception:
                    raw_payload = None
                entry["entries"].append(
                    {
                        "profile_name": row["profile_name"],
                        "wlan_id": row["wlan_id"],
                        "ssid": row["ssid"],
                        "enabled": None if row["enabled"] is None else bool(row["enabled"]),
                        "status_text": row["status_text"],
                        "raw": raw_payload,
                    }
                )
    except Exception:
        pass
    return data


def fetch_wlc_summer_recent_runs(limit: int = 30) -> List[Dict]:
    runs: List[Dict] = []
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT ts,
                       COUNT(*) AS total_entries,
                       SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled_count,
                       SUM(CASE WHEN enabled = 0 THEN 1 ELSE 0 END) AS disabled_count
                FROM wlc_summer_samples
                GROUP BY ts
                ORDER BY ts DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in cur.fetchall():
                runs.append(
                    {
                        "ts": row["ts"],
                        "total": row["total_entries"] or 0,
                        "enabled": row["enabled_count"] or 0,
                        "disabled": row["disabled_count"] or 0,
                    }
                )
    except Exception:
        pass
    return runs


def load_solarwinds_settings() -> dict:
    defaults = {
        "base_url": "",
        "username": "",
        "password": "",
        "verify_ssl": True,
        "last_poll_ts": None,
        "last_poll_status": "never",
        "last_poll_message": "",
    }
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM solarwinds_settings WHERE id=1").fetchone()
            if not row:
                cx.execute(
                    "INSERT INTO solarwinds_settings(id, base_url, username, password, verify_ssl, updated, last_poll_ts, last_poll_status, last_poll_message) VALUES(1,'','',?,1,?,?,?,?)",
                    (
                        _encrypt_secret(""),
                        datetime.now().isoformat(timespec="seconds"),
                        None,
                        "never",
                        "",
                    ),
                )
                return defaults
            data = dict(row)
            defaults["base_url"] = data.get("base_url") or ""
            defaults["username"] = data.get("username") or ""
            defaults["password"] = _decrypt_secret(data.get("password"))
            defaults["verify_ssl"] = bool(data.get("verify_ssl", 1))
            defaults["last_poll_ts"] = data.get("last_poll_ts")
            defaults["last_poll_status"] = data.get("last_poll_status", "never")
            defaults["last_poll_message"] = data.get("last_poll_message", "")
    except Exception:
        pass
    return defaults


def save_solarwinds_settings(settings: dict) -> None:
    payload = load_solarwinds_settings()
    payload.update(settings or {})
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO solarwinds_settings(id, base_url, username, password, verify_ssl, updated, last_poll_ts, last_poll_status, last_poll_message)
                VALUES(1,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  base_url=excluded.base_url,
                  username=excluded.username,
                  password=excluded.password,
                  verify_ssl=excluded.verify_ssl,
                  updated=excluded.updated,
                  last_poll_ts=excluded.last_poll_ts,
                  last_poll_status=excluded.last_poll_status,
                  last_poll_message=excluded.last_poll_message
                """,
                (
                    payload.get("base_url", ""),
                    payload.get("username", ""),
                    _encrypt_secret(payload.get("password")),
                    1 if payload.get("verify_ssl", True) else 0,
                    datetime.now().isoformat(timespec="seconds"),
                    payload.get("last_poll_ts"),
                    payload.get("last_poll_status", "never"),
                    payload.get("last_poll_message", ""),
                ),
            )
    except Exception:
        pass


def update_solarwinds_poll_status(*, ts: Optional[str], status: str, message: str = "") -> None:
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE solarwinds_settings SET last_poll_ts=?, last_poll_status=?, last_poll_message=?, updated=? WHERE id=1",
                (
                    ts,
                    status,
                    message,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
    except Exception:
        pass


def replace_solarwinds_nodes(nodes: List[Dict]) -> None:
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM solarwinds_nodes")
            if not nodes:
                return
            rows = []
            for node in nodes:
                rows.append(
                    (
                        str(node.get("node_id") or ""),
                        node.get("caption") or "",
                        node.get("organization") or "",
                        node.get("vendor") or "",
                        node.get("model") or "",
                        node.get("version") or "",
                        node.get("ip_address") or "",
                        node.get("status") or "",
                        node.get("last_seen") or "",
                        json.dumps(node.get("extra") or {}),
                    )
                )
            cx.executemany(
                """
                INSERT INTO solarwinds_nodes(node_id, caption, organization, vendor, model, version, ip_address, status, last_seen, extra_json)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )
    except Exception:
        pass


def fetch_solarwinds_nodes() -> List[Dict]:
    results: List[Dict] = []
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                "SELECT node_id, caption, organization, vendor, model, version, ip_address, status, last_seen, extra_json FROM solarwinds_nodes ORDER BY caption"
            )
            for row in cur.fetchall():
                extra = {}
                try:
                    extra = json.loads(row["extra_json"] or "{}")
                except Exception:
                    extra = {}
                results.append(
                    {
                        "node_id": row["node_id"],
                        "caption": row["caption"],
                        "organization": row["organization"],
                        "vendor": row["vendor"],
                        "model": row["model"],
                        "version": row["version"],
                        "ip_address": row["ip_address"],
                        "status": row["status"],
                        "last_seen": row["last_seen"],
                        "extra": extra,
                    }
                )
    except Exception:
        pass
    return results


def insert_change_log(
    *,
    ts: str,
    username: str,
    tool: str,
    job_id: str,
    switch_ip: str,
    result: str,
    message: str,
    config_lines: str,
):
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO change_logs(ts, username, tool, job_id, switch_ip, result, message, config_lines)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (ts, username, tool, job_id, switch_ip, result, message, config_lines),
            )
    except Exception:
        pass


def fetch_change_logs(
    *,
    username: Optional[str] = None,
    tool: Optional[str] = None,
    result: Optional[str] = None,
    ip: Optional[str] = None,
    q: Optional[str] = None,
    date_from: Optional[Union[str, datetime]] = None,
    date_to: Optional[Union[str, datetime]] = None,
    limit: Optional[int] = None,
    offset: int = 0,
) -> tuple[list[dict], int]:
    def _normalize_dt(value):
        if not value:
            return None
        if isinstance(value, datetime):
            return value.isoformat(timespec="seconds")
        return str(value)

    where = []
    params: list[str] = []

    if username:
        where.append("LOWER(username) LIKE ?")
        params.append(f"%{username.lower()}%")
    if tool:
        where.append("tool = ?")
        params.append(tool)
    if result:
        where.append("result = ?")
        params.append(result)
    if ip:
        where.append("LOWER(switch_ip) LIKE ?")
        params.append(f"%{ip.lower()}%")
    if q:
        where.append(
            "LOWER(message || ' ' || config_lines || ' ' || switch_ip || ' ' || job_id) LIKE ?"
        )
        params.append(f"%{q.lower()}%")

    start_ts = _normalize_dt(date_from)
    end_ts = _normalize_dt(date_to)
    if start_ts:
        where.append("ts >= ?")
        params.append(start_ts)
    if end_ts:
        where.append("ts <= ?")
        params.append(end_ts)

    where_clause = " WHERE " + " AND ".join(where) if where else ""
    order_clause = " ORDER BY ts DESC"

    # Use separate param lists so COUNT(*) doesn't include LIMIT/OFFSET values.
    count_params = list(params)
    query = (
        "SELECT ts AS timestamp, username, tool, job_id, switch_ip, result, message, config_lines FROM change_logs"
        + where_clause
        + order_clause
    )

    query_params = list(params)
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        query_params.extend([int(limit), int(max(offset, 0))])

    rows: list[dict] = []
    total = 0
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(query, query_params)
            rows = [dict(r) for r in cur.fetchall()]
            total = cx.execute(
                "SELECT COUNT(*) FROM change_logs" + where_clause,
                count_params,
            ).fetchone()[0]
    except Exception:
        rows, total = [], 0
    return rows, total


def fetch_change_log_tools() -> list[str]:
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                "SELECT DISTINCT tool FROM change_logs WHERE tool IS NOT NULL AND tool != '' ORDER BY tool"
            )
            return [row[0] for row in cur.fetchall()]
    except Exception:
        return []


# ===================== CHANGE WINDOWS =====================


def _encode_change_payload(payload: Optional[dict]) -> dict:
    data = dict(payload or {})
    if "password" in data and data["password"]:
        data["password_enc"] = _encrypt_secret(data.pop("password"))
    if "secret" in data and data["secret"]:
        data["secret_enc"] = _encrypt_secret(data.pop("secret"))
    return data


def _decode_change_payload(data: Optional[dict]) -> dict:
    payload = dict(data or {})
    if "password_enc" in payload:
        payload["password"] = _decrypt_secret(payload.pop("password_enc"))
    if "secret_enc" in payload:
        payload["secret"] = _decrypt_secret(payload.pop("secret_enc"))
    return payload


def schedule_change_window(
    *,
    change_id: str,
    tool: str,
    change_number: Optional[str],
    scheduled: str,
    payload: dict,
    rollback_payload: Optional[dict] = None,
    status: str = "scheduled",
    message: Optional[str] = None,
) -> None:
    stored_payload = json.dumps(_encode_change_payload(payload))
    stored_rollback = json.dumps(_encode_change_payload(rollback_payload or {}))
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT OR REPLACE INTO change_windows(
                  change_id, created, scheduled, tool, change_number,
                  payload_json, rollback_json, status, message
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    change_id,
                    datetime.now().isoformat(timespec="seconds"),
                    scheduled,
                    tool,
                    change_number or "",
                    stored_payload,
                    stored_rollback,
                    status,
                    message or "",
                ),
            )
            cx.execute(
                "INSERT INTO change_events(change_id, ts, type, message) VALUES(?,?,?,?)",
                (change_id, created, "created", message or "change scheduled"),
            )
    except Exception:
        pass


def update_change_window(change_id: str, **fields) -> None:
    if not fields:
        return
    if "status" in fields and fields.get("status") in {"completed", "failed"}:
        fields.setdefault("completed", datetime.now().isoformat(timespec="seconds"))
    assignments = []
    params = []
    for key, value in fields.items():
        if key == "payload":
            assignments.append("payload_json = ?")
            params.append(json.dumps(_encode_change_payload(value)))
        elif key == "rollback_payload":
            assignments.append("rollback_json = ?")
            params.append(json.dumps(_encode_change_payload(value)))
        else:
            assignments.append(f"{key} = ?")
            params.append(value)
    params.append(change_id)
    query = f"UPDATE change_windows SET {', '.join(assignments)} WHERE change_id = ?"
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(query, params)
    except Exception:
        pass


def append_change_event(change_id: str, etype: str, message: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "INSERT INTO change_events(change_id, ts, type, message) VALUES(?,?,?,?)",
                (change_id, ts, etype, message),
            )
    except Exception:
        pass


def list_change_windows(limit: int = 200) -> list[dict]:
    rows: list[dict] = []
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT * FROM change_windows
                ORDER BY COALESCE(scheduled, created) DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in cur.fetchall():
                item = dict(row)
                try:
                    item["payload"] = _decode_change_payload(json.loads(item.pop("payload_json") or "{}"))
                except Exception:
                    item["payload"] = {}
                try:
                    item["rollback_payload"] = _decode_change_payload(json.loads(item.pop("rollback_json") or "{}"))
                except Exception:
                    item["rollback_payload"] = {}
                rows.append(item)
    except Exception:
        pass
    return rows


def load_change_window(change_id: str) -> tuple[Optional[dict], list[dict]]:
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM change_windows WHERE change_id=?", (change_id,)).fetchone()
            if not row:
                return None, []
            item = dict(row)
            try:
                item["payload"] = _decode_change_payload(json.loads(item.pop("payload_json") or "{}"))
            except Exception:
                item["payload"] = {}
            try:
                item["rollback_payload"] = _decode_change_payload(json.loads(item.pop("rollback_json") or "{}"))
            except Exception:
                item["rollback_payload"] = {}
            events_cur = cx.execute(
                "SELECT * FROM change_events WHERE change_id=? ORDER BY ts",
                (change_id,),
            )
            events = [dict(e) for e in events_cur.fetchall()]
            return item, events
    except Exception:
        return None, []


def fetch_due_change_windows(now_iso: str) -> list[dict]:
    rows: list[dict] = []
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                SELECT * FROM change_windows
                WHERE status = 'scheduled' AND scheduled <= ?
                ORDER BY scheduled
                """,
                (now_iso,),
            )
            for row in cur.fetchall():
                item = dict(row)
                try:
                    item["payload"] = _decode_change_payload(json.loads(item.pop("payload_json") or "{}"))
                except Exception:
                    item["payload"] = {}
                try:
                    item["rollback_payload"] = _decode_change_payload(json.loads(item.pop("rollback_json") or "{}"))
                except Exception:
                    item["rollback_payload"] = {}
                rows.append(item)
    except Exception:
        pass
    return rows


def fetch_upcoming_changes_for_hosts(tool: str, hosts: Iterable[str]) -> Dict[str, Dict]:
    host_set = {str(h) for h in (hosts or []) if h}
    if not host_set:
        return {}

    upcoming: Dict[str, Dict] = {}
    now_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                "SELECT change_id, change_number, scheduled, message, payload_json FROM change_windows WHERE status='scheduled' AND tool=?",
                (tool,),
            )
            for row in cur.fetchall():
                scheduled = row["scheduled"]
                if not scheduled or scheduled < now_utc:
                    continue
                try:
                    payload = _decode_change_payload(json.loads(row["payload_json"] or "{}"))
                except Exception:
                    payload = {}
                metadata = payload.get("metadata") or {}
                host = str(metadata.get("host") or "")
                if host not in host_set:
                    continue
                existing = upcoming.get(host)
                if existing and existing.get("scheduled_iso") <= scheduled:
                    continue
                change_data = {
                    "change_id": row["change_id"],
                    "change_number": row["change_number"] or "",
                    "scheduled_iso": scheduled,
                    "message": row["message"] or "",
                    "status": row.get("status") or "scheduled",
                }
                upcoming[host] = change_data
    except Exception:
        pass
    return upcoming


# ========================================
# Bulk SSH Functions
# ========================================

def insert_bulk_ssh_job(job_id: str, created: str, username: str, command: str, device_count: int) -> None:
    """Insert a new bulk SSH job."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """INSERT INTO bulk_ssh_jobs(job_id, created, username, command, device_count, status, done)
                   VALUES(?,?,?,?,?,'running',0)""",
                (job_id, created, username, command, device_count),
            )
    except Exception:
        pass


def insert_bulk_ssh_result(
    job_id: str, device: str, status: str, output: str, error: str, duration_ms: int, completed_at: str
) -> None:
    """Insert a result for a single device."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """INSERT INTO bulk_ssh_results(job_id, device, status, output, error, duration_ms, completed_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (job_id, device, status, output, error, duration_ms, completed_at),
            )
    except Exception:
        pass


def update_bulk_ssh_job_progress(job_id: str, completed: int, success: int, failed: int) -> None:
    """Update job progress counters."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """UPDATE bulk_ssh_jobs
                   SET completed_count=?, success_count=?, failed_count=?
                   WHERE job_id=?""",
                (completed, success, failed, job_id),
            )
    except Exception:
        pass


def mark_bulk_ssh_job_done(job_id: str, status: str = "completed") -> None:
    """Mark a bulk SSH job as done."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """UPDATE bulk_ssh_jobs
                   SET done=1, status=?
                   WHERE job_id=?""",
                (status, job_id),
            )
    except Exception:
        pass


def load_bulk_ssh_job(job_id: str) -> Optional[dict]:
    """Load a bulk SSH job by ID."""
    try:
        with _conn() as cx:
            row = cx.execute("SELECT * FROM bulk_ssh_jobs WHERE job_id=?", (job_id,)).fetchone()
            if not row:
                return None
            return dict(row)
    except Exception:
        return None


def load_bulk_ssh_results(job_id: str) -> List[dict]:
    """Load all results for a bulk SSH job."""
    try:
        with _conn() as cx:
            rows = cx.execute(
                "SELECT * FROM bulk_ssh_results WHERE job_id=? ORDER BY completed_at", (job_id,)
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def list_bulk_ssh_jobs(limit: int = 100) -> List[dict]:
    """List recent bulk SSH jobs."""
    try:
        with _conn() as cx:
            rows = cx.execute(
                "SELECT * FROM bulk_ssh_jobs ORDER BY created DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


# ========================================
# Bulk SSH Template Functions
# ========================================

def create_bulk_ssh_template(
    name: str, command: str, description: str = "", variables: str = "",
    device_type: str = "cisco_ios", category: str = "general", created_by: str = ""
) -> Optional[int]:
    """Create a new command template."""
    try:
        created = datetime.now().isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            cursor = cx.execute(
                """INSERT INTO bulk_ssh_templates(name, description, command, variables, device_type, category, created, updated, created_by)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (name, description, command, variables, device_type, category, created, created, created_by),
            )
            return cursor.lastrowid
    except Exception:
        return None


def update_bulk_ssh_template(
    template_id: int, name: str, command: str, description: str = "",
    variables: str = "", device_type: str = "cisco_ios", category: str = "general"
) -> bool:
    """Update an existing template."""
    try:
        updated = datetime.now().isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """UPDATE bulk_ssh_templates
                   SET name=?, description=?, command=?, variables=?, device_type=?, category=?, updated=?
                   WHERE id=?""",
                (name, description, command, variables, device_type, category, updated, template_id),
            )
            return True
    except Exception:
        return False


def delete_bulk_ssh_template(template_id: int) -> bool:
    """Delete a template."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM bulk_ssh_templates WHERE id=?", (template_id,))
            return True
    except Exception:
        return False


def load_bulk_ssh_template(template_id: int) -> Optional[dict]:
    """Load a template by ID."""
    try:
        with _conn() as cx:
            row = cx.execute("SELECT * FROM bulk_ssh_templates WHERE id=?", (template_id,)).fetchone()
            if not row:
                return None
            return dict(row)
    except Exception:
        return None


def list_bulk_ssh_templates(category: Optional[str] = None) -> List[dict]:
    """List all templates, optionally filtered by category."""
    try:
        with _conn() as cx:
            if category:
                rows = cx.execute(
                    "SELECT * FROM bulk_ssh_templates WHERE category=? ORDER BY name", (category,)
                ).fetchall()
            else:
                rows = cx.execute("SELECT * FROM bulk_ssh_templates ORDER BY category, name").fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


# ========================================
# Bulk SSH Schedule Functions
# ========================================

def create_bulk_ssh_schedule(
    name: str, devices_json: str, command: str, username: str, password: str,
    schedule_type: str = "once", schedule_config: str = "", next_run: str = "",
    description: str = "", template_id: Optional[int] = None, secret: str = "",
    device_type: str = "cisco_ios", alert_on_failure: bool = False,
    alert_email: str = "", created_by: str = ""
) -> Optional[int]:
    """Create a new scheduled job."""
    try:
        created = datetime.now().isoformat(timespec="seconds")
        password_enc = _encrypt_secret(password)
        secret_enc = _encrypt_secret(secret) if secret else ""

        with _DB_LOCK, _conn() as cx:
            cursor = cx.execute(
                """INSERT INTO bulk_ssh_schedules(
                    name, description, devices_json, command, template_id, schedule_type, schedule_config,
                    next_run, enabled, alert_on_failure, alert_email, created, created_by,
                    username, password_encrypted, secret_encrypted, device_type
                   ) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?)""",
                (name, description, devices_json, command, template_id, schedule_type, schedule_config,
                 next_run, 1 if alert_on_failure else 0, alert_email, created, created_by,
                 username, password_enc, secret_enc, device_type),
            )
            return cursor.lastrowid
    except Exception:
        return None


def update_bulk_ssh_schedule_run(schedule_id: int, last_run: str, last_job_id: str, next_run: str) -> bool:
    """Update schedule after a run."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """UPDATE bulk_ssh_schedules
                   SET last_run=?, last_job_id=?, next_run=?
                   WHERE id=?""",
                (last_run, last_job_id, next_run, schedule_id),
            )
            return True
    except Exception:
        return False


def toggle_bulk_ssh_schedule(schedule_id: int, enabled: bool) -> bool:
    """Enable or disable a schedule."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE bulk_ssh_schedules SET enabled=? WHERE id=?",
                (1 if enabled else 0, schedule_id),
            )
            return True
    except Exception:
        return False


def delete_bulk_ssh_schedule(schedule_id: int) -> bool:
    """Delete a schedule."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM bulk_ssh_schedules WHERE id=?", (schedule_id,))
            return True
    except Exception:
        return False


def load_bulk_ssh_schedule(schedule_id: int) -> Optional[dict]:
    """Load a schedule by ID with decrypted credentials."""
    try:
        with _conn() as cx:
            row = cx.execute("SELECT * FROM bulk_ssh_schedules WHERE id=?", (schedule_id,)).fetchone()
            if not row:
                return None
            schedule = dict(row)
            # Decrypt credentials
            schedule["password"] = _decrypt_secret(schedule.get("password_encrypted", ""))
            schedule["secret"] = _decrypt_secret(schedule.get("secret_encrypted", ""))
            return schedule
    except Exception:
        return None


def list_bulk_ssh_schedules() -> List[dict]:
    """List all schedules."""
    try:
        with _conn() as cx:
            rows = cx.execute("SELECT * FROM bulk_ssh_schedules ORDER BY name").fetchall()
            schedules = []
            for row in rows:
                schedule = dict(row)
                # Don't include decrypted passwords in list view
                schedule["password"] = "***" if schedule.get("password_encrypted") else ""
                schedule["secret"] = "***" if schedule.get("secret_encrypted") else ""
                schedules.append(schedule)
            return schedules
    except Exception:
        return []


def fetch_due_bulk_ssh_schedules() -> List[dict]:
    """Fetch schedules that are due to run."""
    try:
        # Use configured app timezone for consistency with schedule creation
        app_tz = get_app_timezone_info()
        now = datetime.now(app_tz).isoformat(timespec="seconds")
        with _conn() as cx:
            rows = cx.execute(
                """SELECT * FROM bulk_ssh_schedules
                   WHERE enabled=1 AND next_run IS NOT NULL AND next_run <= ?
                   ORDER BY next_run""",
                (now,)
            ).fetchall()
            schedules = []
            for row in rows:
                schedule = dict(row)
                # Decrypt credentials for execution
                schedule["password"] = _decrypt_secret(schedule.get("password_encrypted", ""))
                schedule["secret"] = _decrypt_secret(schedule.get("secret_encrypted", ""))
                schedules.append(schedule)
            return schedules
    except Exception:
        return []


# ===================== CERTIFICATE TRACKER =====================


def insert_certificate(
    *,
    cn: str,
    expires: str,
    issued_to: Optional[str] = None,
    issued_by: Optional[str] = None,
    used_by: Optional[str] = None,
    notes: Optional[str] = None,
    devices: Optional[str] = None,
    source_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    source_hostname: Optional[str] = None,
    serial: Optional[str] = None,
) -> Optional[int]:
    """Insert a new certificate and return its ID."""
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                INSERT INTO certificates(cn, expires, issued_to, issued_by, used_by, notes, devices,
                                         source_type, source_ip, source_hostname, uploaded, updated, serial)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (cn, expires, issued_to, issued_by, used_by, notes, devices,
                 source_type, source_ip, source_hostname, now, now, serial),
            )
            return cur.lastrowid
    except Exception:
        return None


def update_certificate(
    cert_id: int,
    *,
    cn: Optional[str] = None,
    expires: Optional[str] = None,
    issued_to: Optional[str] = None,
    issued_by: Optional[str] = None,
    used_by: Optional[str] = None,
    notes: Optional[str] = None,
    devices: Optional[str] = None,
) -> bool:
    """Update certificate fields. Only non-None values are updated."""
    updates = []
    params = []
    if cn is not None:
        updates.append("cn=?")
        params.append(cn)
    if expires is not None:
        updates.append("expires=?")
        params.append(expires)
    if issued_to is not None:
        updates.append("issued_to=?")
        params.append(issued_to)
    if issued_by is not None:
        updates.append("issued_by=?")
        params.append(issued_by)
    if used_by is not None:
        updates.append("used_by=?")
        params.append(used_by)
    if notes is not None:
        updates.append("notes=?")
        params.append(notes)
    if devices is not None:
        updates.append("devices=?")
        params.append(devices)

    if not updates:
        return False

    updates.append("updated=?")
    params.append(datetime.now().isoformat(timespec="seconds"))
    params.append(cert_id)

    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                f"UPDATE certificates SET {', '.join(updates)} WHERE id=?",
                params,
            )
            return True
    except Exception:
        return False


def delete_certificate(cert_id: int) -> bool:
    """Delete a certificate by ID."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM certificates WHERE id=?", (cert_id,))
            return True
    except Exception:
        return False


def get_certificate(cert_id: int) -> Optional[Dict]:
    """Get a single certificate by ID."""
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM certificates WHERE id=?", (cert_id,)).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def list_certificates(
    *,
    cn_filter: Optional[str] = None,
    source_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = 500,
) -> List[Dict]:
    """List certificates with optional filters."""
    where = []
    params = []

    if cn_filter:
        where.append("LOWER(cn) LIKE ?")
        params.append(f"%{cn_filter.lower()}%")
    if source_type:
        where.append("source_type=?")
        params.append(source_type)
    if source_ip:
        where.append("source_ip=?")
        params.append(source_ip)

    where_clause = " WHERE " + " AND ".join(where) if where else ""
    params.append(limit)

    try:
        with _DB_LOCK, _conn() as cx:
            rows = cx.execute(
                f"SELECT * FROM certificates{where_clause} ORDER BY expires LIMIT ?",
                params,
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []


def get_certificate_stats() -> Dict:
    """Get certificate statistics for dashboard."""
    try:
        from dateutil import parser as date_parser
        now = datetime.now()

        with _DB_LOCK, _conn() as cx:
            rows = cx.execute("SELECT expires, source_type FROM certificates").fetchall()

            total = len(rows)
            expired = 0
            expiring_14 = 0
            expiring_30 = 0
            expiring_60 = 0
            ise_count = 0
            uploaded_count = 0

            for row in rows:
                expires_str = row[0] or ""
                source_type = row[1] or ""

                # Count expired and expiring certificates by parsing the date
                if expires_str:
                    try:
                        exp_date = date_parser.parse(expires_str, fuzzy=True)
                        # Make both timezone-naive for comparison
                        if exp_date.tzinfo:
                            exp_date = exp_date.replace(tzinfo=None)

                        days_left = (exp_date - now).days

                        if days_left < 0:
                            expired += 1
                        elif days_left <= 14:
                            expiring_14 += 1
                        elif days_left <= 30:
                            expiring_30 += 1
                        elif days_left <= 60:
                            expiring_60 += 1
                    except (ValueError, TypeError):
                        pass

                # Count by source type
                if source_type == 'ise':
                    ise_count += 1
                elif source_type == 'upload' or not source_type:
                    uploaded_count += 1

            return {
                "total": total,
                "expired": expired,
                "expiring_14": expiring_14,
                "expiring_30": expiring_30,
                "expiring_60": expiring_60,
                "ise_synced": ise_count,
                "uploaded": uploaded_count,
            }
    except Exception:
        return {"total": 0, "expired": 0, "expiring_14": 0, "expiring_30": 0, "expiring_60": 0, "ise_synced": 0, "uploaded": 0}


def certificate_exists(serial: str) -> bool:
    """Check if a certificate with the same serial number already exists."""
    if not serial:
        return False
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute(
                "SELECT 1 FROM certificates WHERE serial=? LIMIT 1",
                (serial,),
            ).fetchone()
            return row is not None
    except Exception:
        return False


# ===================== ISE NODE MANAGEMENT =====================


def insert_ise_node(
    *,
    hostname: str,
    ip: str,
    username: str,
    password: str,
    enabled: bool = True,
) -> Optional[int]:
    """Insert a new ISE node and return its ID."""
    now = datetime.now().isoformat(timespec="seconds")
    password_enc = _encrypt_secret(password)
    try:
        with _DB_LOCK, _conn() as cx:
            cur = cx.execute(
                """
                INSERT INTO ise_nodes(hostname, ip, username, password_encrypted, enabled, created, updated)
                VALUES(?,?,?,?,?,?,?)
                """,
                (hostname, ip, username, password_enc, 1 if enabled else 0, now, now),
            )
            return cur.lastrowid
    except Exception:
        return None


def update_ise_node(
    node_id: int,
    *,
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> bool:
    """Update ISE node fields."""
    updates = []
    params = []

    if hostname is not None:
        updates.append("hostname=?")
        params.append(hostname)
    if ip is not None:
        updates.append("ip=?")
        params.append(ip)
    if username is not None:
        updates.append("username=?")
        params.append(username)
    if password is not None:
        updates.append("password_encrypted=?")
        params.append(_encrypt_secret(password))
    if enabled is not None:
        updates.append("enabled=?")
        params.append(1 if enabled else 0)

    if not updates:
        return False

    updates.append("updated=?")
    params.append(datetime.now().isoformat(timespec="seconds"))
    params.append(node_id)

    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                f"UPDATE ise_nodes SET {', '.join(updates)} WHERE id=?",
                params,
            )
            return True
    except Exception:
        return False


def update_ise_node_sync_status(
    node_id: int,
    *,
    status: str,
    message: str = "",
) -> bool:
    """Update the sync status of an ISE node."""
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE ise_nodes SET last_sync=?, last_sync_status=?, last_sync_message=? WHERE id=?",
                (now, status, message, node_id),
            )
            return True
    except Exception:
        return False


def update_ise_node_version(
    node_id: int,
    *,
    version: str = "",
    patch: str = "",
) -> bool:
    """Update the version and patch info of an ISE node."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE ise_nodes SET ise_version=?, ise_patch=? WHERE id=?",
                (version, patch, node_id),
            )
            return True
    except Exception:
        return False


def delete_ise_node(node_id: int) -> bool:
    """Delete an ISE node by ID."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM ise_nodes WHERE id=?", (node_id,))
            return True
    except Exception:
        return False


def get_ise_node(node_id: int) -> Optional[Dict]:
    """Get a single ISE node by ID (with decrypted password)."""
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM ise_nodes WHERE id=?", (node_id,)).fetchone()
            if not row:
                return None
            node = dict(row)
            node["password"] = _decrypt_secret(node.get("password_encrypted", ""))
            return node
    except Exception:
        return None


def list_ise_nodes(*, include_passwords: bool = False) -> List[Dict]:
    """List all ISE nodes."""
    try:
        with _DB_LOCK, _conn() as cx:
            rows = cx.execute("SELECT * FROM ise_nodes ORDER BY hostname").fetchall()
            nodes = []
            for row in rows:
                node = dict(row)
                if include_passwords:
                    node["password"] = _decrypt_secret(node.get("password_encrypted", ""))
                else:
                    node["password"] = "***" if node.get("password_encrypted") else ""
                nodes.append(node)
            return nodes
    except Exception:
        return []


def get_enabled_ise_nodes() -> List[Dict]:
    """Get all enabled ISE nodes with decrypted passwords for sync."""
    try:
        with _DB_LOCK, _conn() as cx:
            rows = cx.execute(
                "SELECT * FROM ise_nodes WHERE enabled=1 ORDER BY hostname"
            ).fetchall()
            nodes = []
            for row in rows:
                node = dict(row)
                node["password"] = _decrypt_secret(node.get("password_encrypted", ""))
                nodes.append(node)
            return nodes
    except Exception:
        return []


# ===================== CERT SYNC SETTINGS =====================


def load_cert_sync_settings() -> Dict:
    """Load certificate sync settings."""
    defaults = {
        "enabled": False,
        "interval_hours": 24,
        "last_sync_ts": None,
        "last_sync_status": "never",
        "last_sync_message": "",
    }
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT * FROM cert_sync_settings WHERE id=1").fetchone()
            if row:
                return {
                    "enabled": bool(row["enabled"]),
                    "interval_hours": row["interval_hours"] or 24,
                    "last_sync_ts": row["last_sync_ts"],
                    "last_sync_status": row["last_sync_status"] or "never",
                    "last_sync_message": row["last_sync_message"] or "",
                }
    except Exception:
        pass
    return defaults


def save_cert_sync_settings(settings: Dict) -> bool:
    """Save certificate sync settings."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT OR REPLACE INTO cert_sync_settings(id, enabled, interval_hours, last_sync_ts, last_sync_status, last_sync_message)
                VALUES(1, ?, ?, ?, ?, ?)
                """,
                (
                    1 if settings.get("enabled") else 0,
                    settings.get("interval_hours", 24),
                    settings.get("last_sync_ts"),
                    settings.get("last_sync_status"),
                    settings.get("last_sync_message"),
                ),
            )
            return True
    except Exception:
        return False


def update_cert_sync_status(*, status: str, message: str = "") -> bool:
    """Update the last sync status."""
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE cert_sync_settings SET last_sync_ts=?, last_sync_status=?, last_sync_message=? WHERE id=1",
                (now, status, message),
            )
            return True
    except Exception:
        return False


# ====================== CUSTOMER DASHBOARD ======================

def get_organizations_from_nodes(nodes: List[Dict]) -> List[Dict]:
    """
    Get unique organizations with device counts from SolarWinds nodes.
    Returns list of {"name": str, "count": int} sorted by name.
    """
    org_counts: Dict[str, int] = {}
    for node in nodes:
        org = (node.get("organization") or "").strip()
        if org:
            org_counts[org] = org_counts.get(org, 0) + 1

    return sorted(
        [{"name": name, "count": count} for name, count in org_counts.items()],
        key=lambda x: x["name"].lower()
    )


def map_wlc_hosts_to_organizations(nodes: List[Dict]) -> Dict[str, str]:
    """
    Map WLC hosts (IP or hostname) to organizations by matching against SolarWinds nodes.
    Returns dict mapping host -> organization name.
    """
    host_to_org: Dict[str, str] = {}
    for node in nodes:
        ip = (node.get("ip_address") or "").strip()
        caption = (node.get("caption") or "").strip()
        org = (node.get("organization") or "").strip()
        if org:
            if ip:
                host_to_org[ip] = org
            if caption:
                host_to_org[caption.lower()] = org
                # Also map just the hostname part (before first dot)
                hostname_part = caption.split(".")[0].lower()
                host_to_org[hostname_part] = org
    return host_to_org


def fetch_customer_dashboard_metrics(
    organization: str,
    nodes: List[Dict],
    wlc_details: Dict[str, Dict]
) -> Dict:
    """
    Compute customer-specific metrics for the dashboard.

    Args:
        organization: The organization name to filter by
        nodes: List of SolarWinds nodes
        wlc_details: Dict from fetch_wlc_dashboard_latest_details()

    Returns:
        Dict with metrics including health_score, device counts, wireless stats
    """
    # Filter nodes for this organization
    org_nodes = [n for n in nodes if (n.get("organization") or "").strip() == organization]

    total_devices = len(org_nodes)
    devices_up = sum(1 for n in org_nodes if (n.get("status") or "").lower() in ("up", "node up", "active", "ok"))
    devices_down = total_devices - devices_up
    device_availability = (devices_up / total_devices * 100) if total_devices > 0 else 100.0

    # Map WLC hosts to orgs and find WLCs belonging to this org
    host_to_org = map_wlc_hosts_to_organizations(nodes)

    wlc_controllers = []
    total_clients = 0
    total_aps = 0

    for host, details in wlc_details.items():
        # Check if this WLC belongs to the organization
        matched_org = host_to_org.get(host) or host_to_org.get(host.lower())
        # Also try matching by just the hostname portion
        host_short = host.split(".")[0].lower()
        if not matched_org:
            matched_org = host_to_org.get(host_short)

        if matched_org == organization:
            clients = details.get("total_clients", 0) or 0
            aps = details.get("ap_count", 0) or 0
            total_clients += clients
            total_aps += aps
            wlc_controllers.append({
                "host": host,
                "name": host,  # Could be enhanced with caption lookup
                "clients": clients,
                "aps": aps
            })

    # Calculate health score
    # 60% device availability, 40% wireless (if we have APs, otherwise 100%)
    wireless_score = 100 if total_aps > 0 or not wlc_controllers else 100
    health_score = int(device_availability * 0.6 + wireless_score * 0.4)

    if health_score >= 90:
        health_status = "Healthy"
    elif health_score >= 70:
        health_status = "Warning"
    else:
        health_status = "Critical"

    # Device type breakdown
    device_types: Dict[str, Dict[str, int]] = {}
    for node in org_nodes:
        vendor = (node.get("vendor") or "Other").strip()
        model = (node.get("model") or "").strip()

        # Categorize device type
        if "9800" in model or "wlc" in (node.get("caption") or "").lower():
            dtype = "WLC"
        elif "switch" in model.lower() or "catalyst" in model.lower():
            dtype = "Switch"
        elif "router" in model.lower() or "isr" in model.lower():
            dtype = "Router"
        elif "firewall" in model.lower() or "asa" in model.lower() or "palo" in vendor.lower():
            dtype = "Firewall"
        elif "aruba" in vendor.lower():
            dtype = "Aruba"
        else:
            dtype = "Other"

        if dtype not in device_types:
            device_types[dtype] = {"type": dtype, "count": 0, "up": 0, "down": 0}

        device_types[dtype]["count"] += 1
        is_up = (node.get("status") or "").lower() in ("up", "node up", "active", "ok")
        if is_up:
            device_types[dtype]["up"] += 1
        else:
            device_types[dtype]["down"] += 1

    return {
        "organization": organization,
        "total_devices": total_devices,
        "devices_up": devices_up,
        "devices_down": devices_down,
        "device_availability": round(device_availability, 1),
        "total_clients": total_clients,
        "total_aps": total_aps,
        "wlc_controllers": wlc_controllers,
        "health_score": health_score,
        "health_status": health_status,
        "device_types": list(device_types.values())
    }


# ====================== PAGE VISIBILITY SETTINGS ======================

# Default pages that can be toggled
_DEFAULT_PAGES = [
    # Main
    {"key": "knowledge_base", "name": "Knowledge Base", "category": "Main"},
    {"key": "jobs_center", "name": "Jobs Center", "category": "Main"},
    # Config Tools
    {"key": "tool_phrase_search", "name": "Interface Search", "category": "Config Tools"},
    {"key": "tool_global_config", "name": "Global Config", "category": "Config Tools"},
    {"key": "bulk_ssh", "name": "Bulk SSH Terminal", "category": "Config Tools"},
    {"key": "audit_logs", "name": "Audit Logs", "category": "Config Tools"},
    # WLC Tools
    {"key": "wlc_dashboard", "name": "WLC Dashboard", "category": "WLC Tools"},
    {"key": "wlc_inventory", "name": "AP Inventory", "category": "WLC Tools"},
    {"key": "wlc_rf", "name": "RF Summary", "category": "WLC Tools"},
    {"key": "wlc_summer_guest", "name": "Summer Guest", "category": "WLC Tools"},
    # Infrastructure
    {"key": "device_inventory", "name": "Device Inventory", "category": "Infrastructure"},
    {"key": "solarwinds_nodes", "name": "SolarWinds Nodes", "category": "Infrastructure"},
    {"key": "customer_dashboard", "name": "Customer Dashboard", "category": "Infrastructure"},
    {"key": "topology_tool", "name": "Topology", "category": "Infrastructure"},
    {"key": "changes_list", "name": "Change Windows", "category": "Infrastructure"},
    # Certificates
    {"key": "cert_tracker", "name": "Certificate Tracker", "category": "Certificates"},
    {"key": "cert_converter", "name": "Cert Converter", "category": "Certificates"},
    {"key": "ise_nodes", "name": "ISE Nodes", "category": "Certificates"},
]


def _init_page_settings(cx):
    """Seed default page settings if they don't exist."""
    for page in _DEFAULT_PAGES:
        cx.execute(
            """
            INSERT OR IGNORE INTO page_settings (page_key, page_name, enabled, category)
            VALUES (?, ?, 1, ?)
            """,
            (page["key"], page["name"], page["category"])
        )


def get_page_settings() -> List[Dict]:
    """Get all page settings grouped by category."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.row_factory = sqlite3.Row
            rows = cx.execute(
                "SELECT page_key, page_name, enabled, category FROM page_settings ORDER BY category, page_name"
            ).fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []


def is_page_enabled(page_key: str) -> bool:
    """Check if a specific page is enabled."""
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute(
                "SELECT enabled FROM page_settings WHERE page_key = ?",
                (page_key,)
            ).fetchone()
            # If page not in settings, default to enabled
            return row[0] == 1 if row else True
    except Exception:
        return True  # Default to enabled on error


def get_enabled_pages() -> List[str]:
    """Get list of enabled page keys for navigation filtering."""
    try:
        with _DB_LOCK, _conn() as cx:
            rows = cx.execute(
                "SELECT page_key FROM page_settings WHERE enabled = 1"
            ).fetchall()
            return [row[0] for row in rows]
    except Exception:
        # Return all pages as enabled on error
        return [p["key"] for p in _DEFAULT_PAGES]


def set_page_enabled(page_key: str, enabled: bool) -> bool:
    """Enable or disable a page."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "UPDATE page_settings SET enabled = ?, updated_at = ? WHERE page_key = ?",
                (1 if enabled else 0, datetime.now().isoformat(timespec="seconds"), page_key)
            )
            return True
    except Exception:
        return False


def bulk_update_page_settings(settings: Dict[str, bool]) -> bool:
    """Update multiple page settings at once. settings is {page_key: enabled}."""
    try:
        now = datetime.now().isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            for page_key, enabled in settings.items():
                cx.execute(
                    "UPDATE page_settings SET enabled = ?, updated_at = ? WHERE page_key = ?",
                    (1 if enabled else 0, now, page_key)
                )
            return True
    except Exception:
        return False


# ====================== App Settings Functions ======================

# Default timezone for the application
_DEFAULT_APP_TIMEZONE = "America/Chicago"

# Common US timezones for the dropdown
US_TIMEZONES = [
    ("America/New_York", "Eastern (ET)"),
    ("America/Chicago", "Central (CT)"),
    ("America/Denver", "Mountain (MT)"),
    ("America/Phoenix", "Arizona (MST - no DST)"),
    ("America/Los_Angeles", "Pacific (PT)"),
    ("America/Anchorage", "Alaska (AKT)"),
    ("Pacific/Honolulu", "Hawaii (HST)"),
]


def get_app_timezone() -> str:
    """Get the configured application timezone. Returns IANA timezone string."""
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT timezone FROM app_settings WHERE id=1").fetchone()
            if row and row[0]:
                return row[0]
    except Exception:
        pass
    return _DEFAULT_APP_TIMEZONE


def get_app_timezone_info() -> ZoneInfo:
    """Get the configured application timezone as a ZoneInfo object."""
    return ZoneInfo(get_app_timezone())


def load_app_settings() -> Dict:
    """Load all app settings from the database."""
    settings = {
        "timezone": _DEFAULT_APP_TIMEZONE,
        "updated_at": None,
    }
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute("SELECT timezone, updated_at FROM app_settings WHERE id=1").fetchone()
            if row:
                settings["timezone"] = row[0] or _DEFAULT_APP_TIMEZONE
                settings["updated_at"] = row[1]
    except Exception:
        pass
    return settings


def save_app_settings(*, timezone: str) -> bool:
    """Save app settings to the database."""
    try:
        now = datetime.now().isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO app_settings(id, timezone, updated_at)
                VALUES(1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  timezone=excluded.timezone,
                  updated_at=excluded.updated_at
                """,
                (timezone, now)
            )
            return True
    except Exception:
        return False


# ====================== Device Inventory Functions ======================

def upsert_device_inventory(
    device: str,
    device_type: str,
    vendor: str,
    model: str,
    serial_number: str,
    firmware_version: str,
    hostname: str = "",
    uptime: str = "",
    scan_status: str = "success",
    scan_error: str = "",
    solarwinds_node_id: str = "",
    extra: Optional[dict] = None,
) -> bool:
    """Insert or update a device in the inventory."""
    try:
        now = datetime.now().isoformat(timespec="seconds")
        extra_json = json.dumps(extra) if extra else None
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO device_inventory(
                    device, device_type, vendor, model, serial_number, firmware_version,
                    hostname, uptime, last_scanned, scan_status, scan_error,
                    solarwinds_node_id, extra_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(device) DO UPDATE SET
                    device_type=excluded.device_type,
                    vendor=excluded.vendor,
                    model=excluded.model,
                    serial_number=excluded.serial_number,
                    firmware_version=excluded.firmware_version,
                    hostname=excluded.hostname,
                    uptime=excluded.uptime,
                    last_scanned=excluded.last_scanned,
                    scan_status=excluded.scan_status,
                    scan_error=excluded.scan_error,
                    solarwinds_node_id=excluded.solarwinds_node_id,
                    extra_json=excluded.extra_json
                """,
                (device, device_type, vendor, model, serial_number, firmware_version,
                 hostname, uptime, now, scan_status, scan_error, solarwinds_node_id, extra_json),
            )
            return True
    except Exception:
        return False


def list_device_inventory(
    vendor: Optional[str] = None,
    model_filter: Optional[str] = None,
    firmware_filter: Optional[str] = None,
    limit: int = 500,
) -> List[Dict]:
    """List devices from inventory with optional filters."""
    try:
        with _conn() as cx:
            cx.row_factory = sqlite3.Row
            query = "SELECT * FROM device_inventory WHERE 1=1"
            params = []

            if vendor:
                query += " AND vendor = ?"
                params.append(vendor)
            if model_filter:
                query += " AND model LIKE ?"
                params.append(f"%{model_filter}%")
            if firmware_filter:
                query += " AND firmware_version LIKE ?"
                params.append(f"%{firmware_filter}%")

            query += " ORDER BY vendor, hostname, device LIMIT ?"
            params.append(limit)

            rows = cx.execute(query, params).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                if d.get("extra_json"):
                    try:
                        d["extra"] = json.loads(d["extra_json"])
                    except Exception:
                        d["extra"] = {}
                else:
                    d["extra"] = {}
                results.append(d)
            return results
    except Exception:
        return []


def get_device_inventory(device: str) -> Optional[Dict]:
    """Get a single device from inventory."""
    try:
        with _conn() as cx:
            cx.row_factory = sqlite3.Row
            row = cx.execute(
                "SELECT * FROM device_inventory WHERE device = ?",
                (device,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("extra_json"):
                try:
                    d["extra"] = json.loads(d["extra_json"])
                except Exception:
                    d["extra"] = {}
            else:
                d["extra"] = {}
            return d
    except Exception:
        return None


def delete_device_inventory(device: str) -> bool:
    """Delete a device from inventory."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM device_inventory WHERE device = ?", (device,))
            return True
    except Exception:
        return False


def get_device_inventory_stats() -> Dict:
    """Get summary statistics for device inventory."""
    try:
        with _conn() as cx:
            total = cx.execute("SELECT COUNT(*) FROM device_inventory").fetchone()[0]

            # Count by vendor
            vendor_rows = cx.execute(
                "SELECT vendor, COUNT(*) as cnt FROM device_inventory GROUP BY vendor ORDER BY cnt DESC"
            ).fetchall()
            by_vendor = {row[0]: row[1] for row in vendor_rows if row[0]}

            # Count successful vs failed scans
            success = cx.execute(
                "SELECT COUNT(*) FROM device_inventory WHERE scan_status = 'success'"
            ).fetchone()[0]
            failed = cx.execute(
                "SELECT COUNT(*) FROM device_inventory WHERE scan_status = 'failed'"
            ).fetchone()[0]

            # Get last scan time
            last_scan = cx.execute(
                "SELECT MAX(last_scanned) FROM device_inventory"
            ).fetchone()[0]

            return {
                "total": total,
                "by_vendor": by_vendor,
                "success": success,
                "failed": failed,
                "last_scan": last_scan,
            }
    except Exception:
        return {"total": 0, "by_vendor": {}, "success": 0, "failed": 0, "last_scan": None}


def clear_device_inventory() -> bool:
    """Clear all devices from inventory."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM device_inventory")
            return True
    except Exception:
        return False


# ====================== AP Inventory Functions ======================

_DEFAULT_AP_INVENTORY_SETTINGS = {
    "enabled": True,
    "cleanup_days": 5,
    "updated_at": None,
}


def load_ap_inventory_settings() -> Dict:
    """Load AP inventory settings from the database."""
    settings = dict(_DEFAULT_AP_INVENTORY_SETTINGS)
    try:
        with _DB_LOCK, _conn() as cx:
            row = cx.execute(
                "SELECT enabled, cleanup_days, updated_at FROM ap_inventory_settings WHERE id=1"
            ).fetchone()
            if row:
                settings["enabled"] = bool(row[0])
                settings["cleanup_days"] = row[1] or 5
                settings["updated_at"] = row[2]
    except Exception:
        pass
    return settings


def save_ap_inventory_settings(*, enabled: bool = True, cleanup_days: int = 5) -> bool:
    """Save AP inventory settings to the database."""
    try:
        now = datetime.now().isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO ap_inventory_settings(id, enabled, cleanup_days, updated_at)
                VALUES(1, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  enabled=excluded.enabled,
                  cleanup_days=excluded.cleanup_days,
                  updated_at=excluded.updated_at
                """,
                (1 if enabled else 0, cleanup_days, now)
            )
            return True
    except Exception:
        return False


def upsert_ap_inventory(
    *,
    ap_name: str,
    ap_ip: str = "",
    ap_model: str = "",
    ap_mac: str,
    ap_location: str = "",
    ap_state: str = "",
    slots: str = "",
    country: str = "",
    wlc_host: str,
) -> bool:
    """
    Insert or update an AP in the inventory.
    Uses (ap_mac, wlc_host) as unique key.
    - New APs get first_seen = now, last_seen = now
    - Existing APs get last_seen = now (first_seen preserved)
    """
    try:
        now = datetime.now().isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                """
                INSERT INTO ap_inventory(
                    ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state,
                    slots, country, wlc_host, first_seen, last_seen
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ap_mac, wlc_host) DO UPDATE SET
                    ap_name=excluded.ap_name,
                    ap_ip=excluded.ap_ip,
                    ap_model=excluded.ap_model,
                    ap_location=excluded.ap_location,
                    ap_state=excluded.ap_state,
                    slots=excluded.slots,
                    country=excluded.country,
                    last_seen=excluded.last_seen
                """,
                (ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state,
                 slots, country, wlc_host, now, now),
            )
            return True
    except Exception:
        return False


def upsert_ap_inventory_bulk(aps: List[Dict], wlc_host: str) -> int:
    """
    Bulk insert/update APs in the inventory.
    Each dict in aps should have: ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state, slots, country
    Returns the number of APs successfully upserted.
    """
    if not aps:
        return 0
    count = 0
    try:
        now = datetime.now().isoformat(timespec="seconds")
        rows = []
        for ap in aps:
            if not ap.get("ap_mac"):
                continue
            rows.append((
                ap.get("ap_name", ""),
                ap.get("ap_ip", ""),
                ap.get("ap_model", ""),
                ap.get("ap_mac", ""),
                ap.get("ap_location", ""),
                ap.get("ap_state", ""),
                ap.get("slots", ""),
                ap.get("country", ""),
                wlc_host,
                now,
                now,
            ))
        if not rows:
            return 0
        with _DB_LOCK, _conn() as cx:
            cx.executemany(
                """
                INSERT INTO ap_inventory(
                    ap_name, ap_ip, ap_model, ap_mac, ap_location, ap_state,
                    slots, country, wlc_host, first_seen, last_seen
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ap_mac, wlc_host) DO UPDATE SET
                    ap_name=excluded.ap_name,
                    ap_ip=excluded.ap_ip,
                    ap_model=excluded.ap_model,
                    ap_location=excluded.ap_location,
                    ap_state=excluded.ap_state,
                    slots=excluded.slots,
                    country=excluded.country,
                    last_seen=excluded.last_seen
                """,
                rows,
            )
            count = len(rows)
    except Exception:
        pass
    return count


def list_ap_inventory(
    *,
    wlc_host: Optional[str] = None,
    ap_name_filter: Optional[str] = None,
    ap_model_filter: Optional[str] = None,
    ap_location_filter: Optional[str] = None,
    limit: int = 5000,
) -> List[Dict]:
    """List APs from inventory with optional filters."""
    try:
        with _conn() as cx:
            cx.row_factory = sqlite3.Row
            query = "SELECT * FROM ap_inventory WHERE 1=1"
            params: List = []

            if wlc_host:
                query += " AND wlc_host = ?"
                params.append(wlc_host)
            if ap_name_filter:
                query += " AND ap_name LIKE ?"
                params.append(f"%{ap_name_filter}%")
            if ap_model_filter:
                query += " AND ap_model LIKE ?"
                params.append(f"%{ap_model_filter}%")
            if ap_location_filter:
                query += " AND ap_location LIKE ?"
                params.append(f"%{ap_location_filter}%")

            query += " ORDER BY wlc_host, ap_name LIMIT ?"
            params.append(limit)

            rows = cx.execute(query, params).fetchall()
            return [dict(row) for row in rows]
    except Exception:
        return []


def get_ap_inventory(ap_mac: str, wlc_host: str) -> Optional[Dict]:
    """Get a single AP from inventory by MAC and WLC host."""
    try:
        with _conn() as cx:
            cx.row_factory = sqlite3.Row
            row = cx.execute(
                "SELECT * FROM ap_inventory WHERE ap_mac = ? AND wlc_host = ?",
                (ap_mac, wlc_host)
            ).fetchone()
            if not row:
                return None
            return dict(row)
    except Exception:
        return None


def delete_ap_inventory(ap_mac: str, wlc_host: str) -> bool:
    """Delete an AP from inventory by MAC and WLC host."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute(
                "DELETE FROM ap_inventory WHERE ap_mac = ? AND wlc_host = ?",
                (ap_mac, wlc_host)
            )
            return True
    except Exception:
        return False


def cleanup_stale_ap_inventory(days: int = 5) -> int:
    """
    Remove AP records where last_seen < (now - days).
    Returns the number of APs removed.
    Protects against clock issues by only removing APs seen at least once before today.
    """
    if days < 1:
        return 0
    try:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
        # Also require first_seen to be different from last_seen or older than today
        # to protect newly added APs from being removed due to clock issues
        today_start = datetime.now().replace(hour=0, minute=0, second=0).isoformat(timespec="seconds")
        with _DB_LOCK, _conn() as cx:
            # Count for return value
            cur = cx.execute(
                "SELECT COUNT(*) FROM ap_inventory WHERE last_seen < ? AND first_seen < ?",
                (cutoff, today_start)
            )
            count = cur.fetchone()[0]
            if count > 0:
                cx.execute(
                    "DELETE FROM ap_inventory WHERE last_seen < ? AND first_seen < ?",
                    (cutoff, today_start)
                )
            return count
    except Exception:
        return 0


def get_ap_inventory_stats() -> Dict:
    """Get summary statistics for AP inventory."""
    try:
        with _conn() as cx:
            total = cx.execute("SELECT COUNT(*) FROM ap_inventory").fetchone()[0]

            # Count by WLC host
            wlc_rows = cx.execute(
                "SELECT wlc_host, COUNT(*) as cnt FROM ap_inventory GROUP BY wlc_host ORDER BY cnt DESC"
            ).fetchall()
            by_wlc = {row[0]: row[1] for row in wlc_rows if row[0]}

            # Count by model
            model_rows = cx.execute(
                "SELECT ap_model, COUNT(*) as cnt FROM ap_inventory GROUP BY ap_model ORDER BY cnt DESC LIMIT 20"
            ).fetchall()
            by_model = {row[0]: row[1] for row in model_rows if row[0]}

            # Count by state
            state_rows = cx.execute(
                "SELECT ap_state, COUNT(*) as cnt FROM ap_inventory GROUP BY ap_state ORDER BY cnt DESC"
            ).fetchall()
            by_state = {row[0]: row[1] for row in state_rows if row[0]}

            # Get unique WLC hosts
            wlc_hosts = list(by_wlc.keys())

            # Get last seen time
            last_seen = cx.execute(
                "SELECT MAX(last_seen) FROM ap_inventory"
            ).fetchone()[0]

            return {
                "total": total,
                "by_wlc": by_wlc,
                "by_model": by_model,
                "by_state": by_state,
                "wlc_hosts": wlc_hosts,
                "last_seen": last_seen,
            }
    except Exception:
        return {
            "total": 0,
            "by_wlc": {},
            "by_model": {},
            "by_state": {},
            "wlc_hosts": [],
            "last_seen": None,
        }


def clear_ap_inventory() -> bool:
    """Clear all APs from inventory."""
    try:
        with _DB_LOCK, _conn() as cx:
            cx.execute("DELETE FROM ap_inventory")
            return True
    except Exception:
        return False
