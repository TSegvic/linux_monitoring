"""
database.py
-----------
SQLite layer for the Linux remote monitoring system.

Tables:
  hosts       - monitored machines (hostname, API key, polling interval, ...)
  metrics     - time-series of metrics per host
  alerts      - generated alerts
  thresholds  - alert thresholds (global or per-host)
  users       - web UI users
  commands    - remote command queue (web UI inserts, agent pulls and reports back)
"""

import sqlite3
import secrets
import hashlib
import os
import json as _json
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "monitoring.db")


# ---------- low level ----------

@contextmanager
def get_conn():
    """Yields a connection with row_factory and foreign keys enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create tables and seed default values if the database is empty."""
    with get_conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS hosts (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname         TEXT NOT NULL UNIQUE,
                api_key          TEXT NOT NULL UNIQUE,
                registered_at    TEXT NOT NULL,
                last_seen        TEXT,
                polling_interval INTEGER NOT NULL DEFAULT 5,
                active           INTEGER NOT NULL DEFAULT 1,
                description      TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS metrics (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id    INTEGER NOT NULL,
                ts         TEXT NOT NULL,
                cpu        REAL NOT NULL,
                ram        REAL NOT NULL,
                disk       REAL NOT NULL,
                net_sent   REAL NOT NULL DEFAULT 0,    -- KB/s during interval
                net_recv   REAL NOT NULL DEFAULT 0,    -- KB/s during interval
                processes  INTEGER NOT NULL DEFAULT 0,
                uptime     INTEGER NOT NULL DEFAULT 0, -- seconds since boot
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_host_ts ON metrics(host_id, ts);

            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id    INTEGER NOT NULL,
                ts         TEXT NOT NULL,
                metric     TEXT NOT NULL,      -- cpu, ram, disk, offline
                level      TEXT NOT NULL,      -- warning, critical
                value      REAL,
                threshold  REAL,
                message    TEXT NOT NULL,
                resolved   INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_host_ts ON alerts(host_id, ts);

            CREATE TABLE IF NOT EXISTS thresholds (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,            -- NULL = global threshold
                metric  TEXT NOT NULL,      -- cpu, ram, disk
                warning REAL NOT NULL,
                critical REAL NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            -- SQLite treats NULL != NULL inside UNIQUE constraints, so a plain
            -- UNIQUE(host_id, metric) would not prevent duplicate global rows.
            -- Two partial unique indexes solve this cleanly:
            CREATE UNIQUE INDEX IF NOT EXISTS idx_thr_global
                ON thresholds(metric) WHERE host_id IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_thr_host
                ON thresholds(host_id, metric) WHERE host_id IS NOT NULL;

            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS commands (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id     INTEGER NOT NULL,
                type        TEXT NOT NULL,        -- list_processes | kill_process | exec
                payload     TEXT NOT NULL,        -- JSON string
                status      TEXT NOT NULL DEFAULT 'pending', -- pending|executing|done|failed
                created_at  TEXT NOT NULL,
                executed_at TEXT,
                exit_code   INTEGER,
                result      TEXT,                  -- JSON string
                error       TEXT,
                issued_by   TEXT,                  -- username that queued the command
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_cmd_host_status ON commands(host_id, status);
            CREATE INDEX IF NOT EXISTS idx_cmd_host_created ON commands(host_id, created_at);
        """)

        # default global thresholds (only if not already present)
        defaults = [
            ("cpu",  80.0, 95.0),
            ("ram",  80.0, 95.0),
            ("disk", 85.0, 95.0),
        ]
        for metric, warn, crit in defaults:
            existing = c.execute(
                "SELECT 1 FROM thresholds WHERE host_id IS NULL AND metric = ?",
                (metric,),
            ).fetchone()
            if not existing:
                c.execute(
                    """INSERT INTO thresholds (host_id, metric, warning, critical)
                       VALUES (NULL, ?, ?, ?)""",
                    (metric, warn, crit),
                )

        # default admin/admin user if no users exist
        row = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        if row["n"] == 0:
            create_user(c, "admin", "admin")


# ---------- users ----------

def _hash_password(password: str, salt: str = None) -> str:
    """Return 'salt$hash' for the given password (PBKDF2-SHA256)."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"{salt}${h.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return secrets.compare_digest(_hash_password(password, salt), stored)


def create_user(conn, username: str, password: str):
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, _hash_password(password), datetime.utcnow().isoformat(timespec="seconds")),
    )


def authenticate(username: str, password: str):
    with get_conn() as c:
        row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and _verify_password(password, row["password_hash"]):
            return dict(row)
        return None


# ---------- hosts ----------

def register_host(hostname: str, description: str = "") -> dict:
    """Create a new host with a fresh API key. If the hostname exists, rotate the key."""
    api_key = secrets.token_urlsafe(32)
    now = datetime.utcnow().isoformat(timespec="seconds")
    with get_conn() as c:
        existing = c.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,)).fetchone()
        if existing:
            c.execute("UPDATE hosts SET api_key = ?, active = 1 WHERE id = ?",
                      (api_key, existing["id"]))
            host_id = existing["id"]
        else:
            cur = c.execute(
                """INSERT INTO hosts (hostname, api_key, registered_at, polling_interval, description)
                   VALUES (?, ?, ?, 5, ?)""",
                (hostname, api_key, now, description),
            )
            host_id = cur.lastrowid
        host = c.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return dict(host)


def get_host_by_api_key(api_key: str):
    with get_conn() as c:
        row = c.execute("SELECT * FROM hosts WHERE api_key = ?", (api_key,)).fetchone()
        return dict(row) if row else None


def get_host(host_id: int):
    with get_conn() as c:
        row = c.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
        return dict(row) if row else None


def list_hosts() -> list:
    """Return all hosts together with their latest metric (or None).

    Note: the online/offline decision is a business rule and lives in
    services.HostService, not here. This function only returns stored data.
    """
    with get_conn() as c:
        hosts = c.execute("SELECT * FROM hosts ORDER BY hostname").fetchall()
        result = []
        for h in hosts:
            latest = c.execute(
                "SELECT * FROM metrics WHERE host_id = ? ORDER BY ts DESC LIMIT 1",
                (h["id"],),
            ).fetchone()
            d = dict(h)
            d["latest"] = dict(latest) if latest else None
            result.append(d)
        return result


def update_host_seen(host_id: int):
    with get_conn() as c:
        c.execute("UPDATE hosts SET last_seen = ? WHERE id = ?",
                  (datetime.utcnow().isoformat(timespec="seconds"), host_id))


def delete_host(host_id: int):
    with get_conn() as c:
        c.execute("DELETE FROM hosts WHERE id = ?", (host_id,))


def update_host_config(host_id: int, polling_interval: int = None,
                       active: int = None, description: str = None):
    sets, params = [], []
    if polling_interval is not None:
        sets.append("polling_interval = ?"); params.append(int(polling_interval))
    if active is not None:
        sets.append("active = ?"); params.append(int(bool(active)))
    if description is not None:
        sets.append("description = ?"); params.append(description)
    if not sets:
        return
    params.append(host_id)
    with get_conn() as c:
        c.execute(f"UPDATE hosts SET {', '.join(sets)} WHERE id = ?", params)


# ---------- metrics ----------

def insert_metric(host_id: int, m: dict):
    with get_conn() as c:
        c.execute(
            """INSERT INTO metrics (host_id, ts, cpu, ram, disk, net_sent, net_recv, processes, uptime)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                host_id,
                datetime.utcnow().isoformat(timespec="seconds"),
                float(m.get("cpu", 0)),
                float(m.get("ram", 0)),
                float(m.get("disk", 0)),
                float(m.get("net_sent", 0)),
                float(m.get("net_recv", 0)),
                int(m.get("processes", 0)),
                int(m.get("uptime", 0)),
            ),
        )


def get_metrics(host_id: int, since: datetime = None, limit: int = 500) -> list:
    """Return metrics for a host, oldest first, optionally since a given time."""
    with get_conn() as c:
        if since is None:
            rows = c.execute(
                """SELECT * FROM metrics WHERE host_id = ?
                   ORDER BY ts DESC LIMIT ?""",
                (host_id, limit),
            ).fetchall()
            rows = list(reversed(rows))
        else:
            rows = c.execute(
                """SELECT * FROM metrics WHERE host_id = ? AND ts >= ?
                   ORDER BY ts ASC LIMIT ?""",
                (host_id, since.isoformat(timespec="seconds"), limit),
            ).fetchall()
        return [dict(r) for r in rows]


def prune_old_metrics(days: int = 30):
    """Delete metrics older than N days. Call periodically."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat(timespec="seconds")
    with get_conn() as c:
        c.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))


# ---------- thresholds ----------

def get_thresholds(host_id: int = None) -> dict:
    """Return effective thresholds for a host, falling back to global ones."""
    with get_conn() as c:
        rows = c.execute(
            "SELECT * FROM thresholds WHERE host_id IS NULL OR host_id = ?",
            (host_id,),
        ).fetchall()
        out = {}
        for r in rows:
            # per-host overrides global
            if r["metric"] not in out or r["host_id"] is not None:
                out[r["metric"]] = {"warning": r["warning"], "critical": r["critical"]}
        return out


def set_threshold(metric: str, warning: float, critical: float, host_id: int = None):
    """Insert or update a threshold (global when host_id is None)."""
    with get_conn() as c:
        if host_id is None:
            row = c.execute(
                "SELECT id FROM thresholds WHERE host_id IS NULL AND metric = ?",
                (metric,),
            ).fetchone()
        else:
            row = c.execute(
                "SELECT id FROM thresholds WHERE host_id = ? AND metric = ?",
                (host_id, metric),
            ).fetchone()
        if row:
            c.execute(
                "UPDATE thresholds SET warning = ?, critical = ? WHERE id = ?",
                (float(warning), float(critical), row["id"]),
            )
        else:
            c.execute(
                """INSERT INTO thresholds (host_id, metric, warning, critical)
                   VALUES (?, ?, ?, ?)""",
                (host_id, metric, float(warning), float(critical)),
            )


# ---------- alerts ----------

def insert_alert(host_id: int, metric: str, level: str, message: str,
                 value: float = None, threshold: float = None):
    """Insert an alert, suppressing identical unresolved alerts within the last 5 minutes."""
    now = datetime.utcnow()
    cutoff = (now - timedelta(minutes=5)).isoformat(timespec="seconds")
    with get_conn() as c:
        recent = c.execute(
            """SELECT id FROM alerts
               WHERE host_id = ? AND metric = ? AND level = ?
                 AND resolved = 0 AND ts >= ?""",
            (host_id, metric, level, cutoff),
        ).fetchone()
        if recent:
            return
        c.execute(
            """INSERT INTO alerts (host_id, ts, metric, level, value, threshold, message)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (host_id, now.isoformat(timespec="seconds"),
             metric, level, value, threshold, message),
        )


def list_alerts(host_id: int = None, only_unresolved: bool = False, limit: int = 200) -> list:
    sql = """SELECT a.*, h.hostname FROM alerts a
             JOIN hosts h ON h.id = a.host_id"""
    where, params = [], []
    if host_id is not None:
        where.append("a.host_id = ?"); params.append(host_id)
    if only_unresolved:
        where.append("a.resolved = 0")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY a.ts DESC LIMIT ?"
    params.append(limit)
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def resolve_alert(alert_id: int):
    with get_conn() as c:
        c.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))


# ---------- commands (remote process management) ----------

def queue_command(host_id: int, cmd_type: str, payload: dict, issued_by: str) -> int:
    """Queue a new command for the host. The agent picks it up on its next poll."""
    if cmd_type not in ("list_processes", "kill_process", "exec"):
        raise ValueError(f"unknown command type: {cmd_type}")
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO commands (host_id, type, payload, status, created_at, issued_by)
               VALUES (?, ?, ?, 'pending', ?, ?)""",
            (host_id, cmd_type, _json.dumps(payload),
             datetime.utcnow().isoformat(timespec="seconds"), issued_by),
        )
        return cur.lastrowid


def get_pending_commands(host_id: int, mark_executing: bool = True) -> list:
    """Return pending commands for this host. By default also marks them as
    'executing' so the same command is not handed out twice."""
    with get_conn() as c:
        rows = c.execute(
            """SELECT * FROM commands WHERE host_id = ? AND status = 'pending'
               ORDER BY created_at ASC LIMIT 20""",
            (host_id,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = _json.loads(d["payload"])
            except Exception:
                d["payload"] = {}
            out.append(d)
        if mark_executing and out:
            ids = [r["id"] for r in out]
            qs = ",".join("?" * len(ids))
            c.execute(
                f"UPDATE commands SET status = 'executing' WHERE id IN ({qs})",
                ids,
            )
        return out


def save_command_result(cmd_id: int, status: str, exit_code: int = None,
                        result: dict = None, error: str = None):
    """Called by the agent after executing a command."""
    if status not in ("done", "failed"):
        raise ValueError(f"invalid status: {status}")
    with get_conn() as c:
        c.execute(
            """UPDATE commands
               SET status = ?, executed_at = ?, exit_code = ?, result = ?, error = ?
               WHERE id = ?""",
            (status,
             datetime.utcnow().isoformat(timespec="seconds"),
             exit_code,
             _json.dumps(result) if result is not None else None,
             error,
             cmd_id),
        )


def get_command(cmd_id: int):
    with get_conn() as c:
        row = c.execute("SELECT * FROM commands WHERE id = ?", (cmd_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["payload"] = _json.loads(d["payload"]) if d["payload"] else {}
        except Exception:
            d["payload"] = {}
        try:
            d["result"] = _json.loads(d["result"]) if d["result"] else None
        except Exception:
            d["result"] = None
        return d


def list_commands(host_id: int, limit: int = 30, types: list = None) -> list:
    """Return recent commands for a host, newest first."""
    sql = "SELECT * FROM commands WHERE host_id = ?"
    params = [host_id]
    if types:
        sql += f" AND type IN ({','.join('?'*len(types))})"
        params.extend(types)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with get_conn() as c:
        rows = c.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try: d["payload"] = _json.loads(d["payload"]) if d["payload"] else {}
            except Exception: d["payload"] = {}
            try: d["result"] = _json.loads(d["result"]) if d["result"] else None
            except Exception: d["result"] = None
            out.append(d)
        return out


def get_latest_process_list(host_id: int):
    """Return the most recent successful list_processes result for this host, or None."""
    with get_conn() as c:
        row = c.execute(
            """SELECT * FROM commands
               WHERE host_id = ? AND type = 'list_processes' AND status = 'done'
               ORDER BY executed_at DESC LIMIT 1""",
            (host_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["result"] = _json.loads(d["result"]) if d["result"] else None
        except Exception:
            d["result"] = None
        return d


def cleanup_stuck_commands(stale_minutes: int = 5):
    """Move commands stuck in the 'executing' state back to failed (agent went away)."""
    cutoff = (datetime.utcnow() - timedelta(minutes=stale_minutes)).isoformat(timespec="seconds")
    with get_conn() as c:
        c.execute(
            """UPDATE commands
               SET status = 'failed', error = 'timeout: agent did not return a result',
                   executed_at = ?
               WHERE status = 'executing' AND created_at < ?""",
            (datetime.utcnow().isoformat(timespec="seconds"), cutoff),
        )
