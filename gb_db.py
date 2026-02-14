import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

import settings


_init_lock = threading.Lock()
_initialized = False


def _get_conn():
    conn = sqlite3.connect(settings.DB_PATH, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _conn():
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(settings.DB_PATH), exist_ok=True)
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscribers (
                node_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_status (
                node_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sos_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sos_log_active ON sos_log(active)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dispatcher_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                position INTEGER NOT NULL,
                data_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dispatcher_jobs_position ON dispatcher_jobs(position)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outgoing_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outgoing_emails_quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS failed_dm_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS temp_groups (
                group_name TEXT PRIMARY KEY,
                members_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_activity INTEGER NOT NULL,
                locked INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_temp_groups_last_activity ON temp_groups(last_activity)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS command_receipts (
                command_id TEXT PRIMARY KEY,
                source_file TEXT NOT NULL,
                status TEXT NOT NULL,
                details_json TEXT NOT NULL,
                processed_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_command_receipts_processed_at ON command_receipts(processed_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS command_dead_letters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command_id TEXT NOT NULL,
                source_file TEXT NOT NULL,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_command_dead_letters_created_at ON command_dead_letters(created_at)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS command_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command_id TEXT NOT NULL UNIQUE,
                source_file TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                available_at INTEGER NOT NULL,
                lease_until INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                completed_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_command_jobs_status_available ON command_jobs(status, available_at, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_command_jobs_lease_until ON command_jobs(lease_until)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_command_jobs_updated_at ON command_jobs(updated_at)")
        cols = conn.execute("PRAGMA table_info(temp_groups)").fetchall()
        col_names = {row["name"] for row in cols}
        if "locked" not in col_names:
            conn.execute("ALTER TABLE temp_groups ADD COLUMN locked INTEGER NOT NULL DEFAULT 0")


def _table_has_rows(conn, table_name):
    row = conn.execute(f"SELECT 1 FROM {table_name} LIMIT 1").fetchone()
    return row is not None


def _load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def migrate_from_json():
    with _conn() as conn:
        if not _table_has_rows(conn, "subscribers"):
            data = _load_json(settings.SUBSCRIBERS_FILE) or {}
            now = int(time.time())
            for node_id, sub in data.items():
                conn.execute(
                    "INSERT OR REPLACE INTO subscribers (node_id, data_json, updated_at) VALUES (?, ?, ?)",
                    (node_id, json.dumps(sub), now),
                )

        if not _table_has_rows(conn, "node_status"):
            data = _load_json(settings.NODE_STATUS_FILE) or {}
            now = int(time.time())
            for node_id, status in data.items():
                conn.execute(
                    "INSERT OR REPLACE INTO node_status (node_id, data_json, updated_at) VALUES (?, ?, ?)",
                    (node_id, json.dumps(status), now),
                )

        if not _table_has_rows(conn, "chat_log"):
            data = _load_json(getattr(settings, "CHANNEL0_LOG_FILE", "")) or []
            now = int(time.time())
            for entry in data:
                conn.execute(
                    "INSERT INTO chat_log (data_json, created_at) VALUES (?, ?)",
                    (json.dumps(entry), now),
                )

        if not _table_has_rows(conn, "sos_log"):
            data = _load_json(settings.SOS_LOG_FILE) or []
            now = int(time.time())
            for entry in data:
                active = 1 if entry.get("active") else 0
                conn.execute(
                    "INSERT INTO sos_log (data_json, created_at, active) VALUES (?, ?, ?)",
                    (json.dumps(entry), now, active),
                )

        if not _table_has_rows(conn, "dispatcher_jobs"):
            data = _load_json(settings.DISPATCHER_JOBS_FILE) or []
            now = int(time.time())
            for position, job in enumerate(data):
                conn.execute(
                    "INSERT INTO dispatcher_jobs (position, data_json, updated_at) VALUES (?, ?, ?)",
                    (position, json.dumps(job), now),
                )

        if not _table_has_rows(conn, "outgoing_emails"):
            data = _load_json(settings.OUTGOING_EMAIL_FILE) or []
            now = int(time.time())
            for entry in data:
                conn.execute(
                    "INSERT INTO outgoing_emails (data_json, created_at) VALUES (?, ?)",
                    (json.dumps(entry), now),
                )

        if not _table_has_rows(conn, "failed_dm_queue"):
            data = _load_json(settings.FAILED_DM_QUEUE_FILE) or []
            now = int(time.time())
            for entry in data:
                conn.execute(
                    "INSERT INTO failed_dm_queue (data_json, created_at) VALUES (?, ?)",
                    (json.dumps(entry), now),
                )


def ensure_db():
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        init_db()
        migrate_from_json()
        _initialized = True


def load_subscribers_dict():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute("SELECT node_id, data_json FROM subscribers").fetchall()
    data = {}
    for row in rows:
        try:
            data[row["node_id"]] = json.loads(row["data_json"])
        except Exception:
            data[row["node_id"]] = {}
    return data


def upsert_subscriber(node_id, data):
    ensure_db()
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO subscribers (node_id, data_json, updated_at) VALUES (?, ?, ?)",
            (node_id, json.dumps(data), int(time.time())),
        )


def delete_subscriber(node_id):
    ensure_db()
    with _conn() as conn:
        conn.execute("DELETE FROM subscribers WHERE node_id = ?", (node_id,))


def replace_subscribers(data):
    ensure_db()
    now = int(time.time())
    with _conn() as conn:
        conn.execute("DELETE FROM subscribers")
        for node_id, sub in data.items():
            conn.execute(
                "INSERT OR REPLACE INTO subscribers (node_id, data_json, updated_at) VALUES (?, ?, ?)",
                (node_id, json.dumps(sub), now),
            )


def get_subscribers_mtime():
    ensure_db()
    with _conn() as conn:
        row = conn.execute("SELECT MAX(updated_at) AS mtime FROM subscribers").fetchone()
    return int(row["mtime"] or 0)


def load_node_statuses_dict():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute("SELECT node_id, data_json FROM node_status").fetchall()
    data = {}
    for row in rows:
        try:
            data[row["node_id"]] = json.loads(row["data_json"])
        except Exception:
            data[row["node_id"]] = {}
    return data


def get_node_status(node_id):
    ensure_db()
    with _conn() as conn:
        row = conn.execute(
            "SELECT data_json FROM node_status WHERE node_id = ?",
            (node_id,),
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["data_json"])
    except Exception:
        return None


def upsert_node_status(node_id, data):
    ensure_db()
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO node_status (node_id, data_json, updated_at) VALUES (?, ?, ?)",
            (node_id, json.dumps(data), int(time.time())),
        )


def delete_node_status(node_id):
    ensure_db()
    with _conn() as conn:
        conn.execute("DELETE FROM node_status WHERE node_id = ?", (node_id,))


def replace_node_statuses(data):
    ensure_db()
    now = int(time.time())
    with _conn() as conn:
        conn.execute("DELETE FROM node_status")
        for node_id, status in data.items():
            conn.execute(
                "INSERT OR REPLACE INTO node_status (node_id, data_json, updated_at) VALUES (?, ?, ?)",
                (node_id, json.dumps(status), now),
            )


def append_chat_log(entry, max_entries=200):
    ensure_db()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO chat_log (data_json, created_at) VALUES (?, ?)",
            (json.dumps(entry), int(time.time())),
        )
        if max_entries:
            conn.execute(
                """
                DELETE FROM chat_log
                WHERE id NOT IN (
                    SELECT id FROM chat_log ORDER BY id DESC LIMIT ?
                )
                """,
                (max_entries,),
            )


def get_chat_logs(after_id=0, limit=200):
    ensure_db()
    with _conn() as conn:
        last_row = conn.execute("SELECT MAX(id) AS max_id FROM chat_log").fetchone()
        last_id = int(last_row["max_id"] or 0)
        if after_id and after_id > 0:
            rows = conn.execute(
                "SELECT id, data_json FROM chat_log WHERE id > ? ORDER BY id ASC",
                (after_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, data_json FROM chat_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            rows = list(reversed(rows))
    messages = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        data["id"] = row["id"]
        messages.append(data)
    return messages, last_id


def load_sos_logs():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute("SELECT id, data_json, active FROM sos_log ORDER BY id ASC").fetchall()
    entries = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        data["id"] = row["id"]
        data["active"] = bool(row["active"])
        entries.append(data)
    return entries


def load_active_sos_logs():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute("SELECT id, data_json FROM sos_log WHERE active = 1 ORDER BY id ASC").fetchall()
    entries = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        data["id"] = row["id"]
        data["active"] = True
        entries.append(data)
    return entries


def insert_sos_log(entry):
    ensure_db()
    active = 1 if entry.get("active") else 0
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO sos_log (data_json, created_at, active) VALUES (?, ?, ?)",
            (json.dumps(entry), int(time.time()), active),
        )
        return cur.lastrowid


def update_sos_log(entry_id, entry):
    ensure_db()
    active = 1 if entry.get("active") else 0
    with _conn() as conn:
        conn.execute(
            "UPDATE sos_log SET data_json = ?, active = ? WHERE id = ?",
            (json.dumps(entry), active, entry_id),
        )


def clear_sos_log():
    ensure_db()
    with _conn() as conn:
        conn.execute("DELETE FROM sos_log")


def load_dispatcher_jobs():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT position, data_json FROM dispatcher_jobs ORDER BY position ASC"
        ).fetchall()
    jobs = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        jobs.append(data)
    return jobs


def replace_dispatcher_jobs(jobs):
    ensure_db()
    now = int(time.time())
    with _conn() as conn:
        conn.execute("DELETE FROM dispatcher_jobs")
        for position, job in enumerate(jobs or []):
            conn.execute(
                "INSERT INTO dispatcher_jobs (position, data_json, updated_at) VALUES (?, ?, ?)",
                (position, json.dumps(job), now),
            )


def add_outgoing_email(task):
    ensure_db()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO outgoing_emails (data_json, created_at) VALUES (?, ?)",
            (json.dumps(task), int(time.time())),
        )


def add_outgoing_email_quarantine(task, reason):
    ensure_db()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO outgoing_emails_quarantine (data_json, reason, created_at) VALUES (?, ?, ?)",
            (json.dumps(task), reason, int(time.time())),
        )


def prune_outgoing_email_quarantine(max_rows=500):
    ensure_db()
    with _conn() as conn:
        row = conn.execute("SELECT COUNT(1) AS cnt FROM outgoing_emails_quarantine").fetchone()
        total = int(row["cnt"] or 0)
        if total <= max_rows:
            return
        to_delete = total - max_rows
        conn.execute(
            """
            DELETE FROM outgoing_emails_quarantine
            WHERE id IN (
                SELECT id FROM outgoing_emails_quarantine
                ORDER BY id ASC
                LIMIT ?
            )
            """,
            (to_delete,),
        )


def fetch_outgoing_emails():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data_json FROM outgoing_emails ORDER BY id ASC"
        ).fetchall()
    messages = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        data["id"] = row["id"]
        messages.append(data)
    return messages


def delete_outgoing_emails(ids):
    ensure_db()
    if not ids:
        return
    with _conn() as conn:
        conn.executemany("DELETE FROM outgoing_emails WHERE id = ?", [(i,) for i in ids])


def clear_outgoing_emails():
    ensure_db()
    with _conn() as conn:
        conn.execute("DELETE FROM outgoing_emails")


def count_outgoing_emails():
    ensure_db()
    with _conn() as conn:
        row = conn.execute("SELECT COUNT(1) AS cnt FROM outgoing_emails").fetchone()
    return int(row["cnt"] or 0)


def add_failed_dm(message):
    ensure_db()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO failed_dm_queue (data_json, created_at) VALUES (?, ?)",
            (json.dumps(message), int(time.time())),
        )


def fetch_failed_dm_queue():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data_json FROM failed_dm_queue ORDER BY id ASC"
        ).fetchall()
    messages = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        data["id"] = row["id"]
        messages.append(data)
    return messages


def fetch_failed_dm_for_node(node_id):
    ensure_db()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data_json FROM failed_dm_queue ORDER BY id ASC"
        ).fetchall()
    matched = []
    for row in rows:
        try:
            data = json.loads(row["data_json"])
        except Exception:
            data = {}
        if data.get("destination_id") == node_id:
            data["id"] = row["id"]
            matched.append(data)
    return matched


def delete_failed_dm(ids):
    ensure_db()
    if not ids:
        return
    with _conn() as conn:
        conn.executemany("DELETE FROM failed_dm_queue WHERE id = ?", [(i,) for i in ids])


def clear_failed_dm_queue():
    ensure_db()
    with _conn() as conn:
        conn.execute("DELETE FROM failed_dm_queue")


def count_failed_dm_queue():
    ensure_db()
    with _conn() as conn:
        row = conn.execute("SELECT COUNT(1) AS cnt FROM failed_dm_queue").fetchone()
    return int(row["cnt"] or 0)


def get_temp_group(group_name):
    ensure_db()
    with _conn() as conn:
        row = conn.execute(
            "SELECT group_name, members_json, created_at, last_activity, locked FROM temp_groups WHERE group_name = ?",
            (group_name,),
        ).fetchone()
    if not row:
        return None
    try:
        members = json.loads(row["members_json"])
        if not isinstance(members, list):
            members = []
    except Exception:
        members = []
    return {
        "group_name": row["group_name"],
        "members": members,
        "created_at": int(row["created_at"] or 0),
        "last_activity": int(row["last_activity"] or 0),
        "locked": bool(row["locked"]),
    }


def upsert_temp_group(group_name, members=None, created_at=None, last_activity=None, locked=False):
    ensure_db()
    now = int(time.time())
    members_list = members if isinstance(members, list) else []
    created = int(created_at if created_at is not None else now)
    activity = int(last_activity if last_activity is not None else now)
    locked_int = 1 if locked else 0
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO temp_groups (group_name, members_json, created_at, last_activity, locked)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(group_name) DO UPDATE SET
                members_json = excluded.members_json,
                last_activity = excluded.last_activity,
                locked = excluded.locked
            """,
            (group_name, json.dumps(members_list), created, activity, locked_int),
        )


def delete_temp_group(group_name):
    ensure_db()
    with _conn() as conn:
        conn.execute("DELETE FROM temp_groups WHERE group_name = ?", (group_name,))


def load_temp_groups():
    ensure_db()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT group_name, members_json, created_at, last_activity, locked FROM temp_groups ORDER BY group_name ASC"
        ).fetchall()
    groups = []
    for row in rows:
        try:
            members = json.loads(row["members_json"])
            if not isinstance(members, list):
                members = []
        except Exception:
            members = []
        groups.append(
            {
                "group_name": row["group_name"],
                "members": members,
                "created_at": int(row["created_at"] or 0),
                "last_activity": int(row["last_activity"] or 0),
                "locked": bool(row["locked"]),
            }
        )
    return groups


def touch_temp_group(group_name, now_ts=None):
    ensure_db()
    activity = int(now_ts if now_ts is not None else time.time())
    with _conn() as conn:
        conn.execute(
            "UPDATE temp_groups SET last_activity = ? WHERE group_name = ?",
            (activity, group_name),
        )


def add_temp_group_member(group_name, node_id, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    group = get_temp_group(group_name)
    if group:
        members = list(dict.fromkeys([str(m) for m in group.get("members", []) if m]))
        if node_id not in members:
            members.append(node_id)
        upsert_temp_group(
            group_name,
            members=members,
            created_at=group.get("created_at", now),
            last_activity=now,
            locked=group.get("locked", False),
        )
    else:
        upsert_temp_group(group_name, members=[node_id], created_at=now, last_activity=now, locked=False)


def remove_temp_group_member(group_name, node_id, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    group = get_temp_group(group_name)
    if not group:
        return
    members = [m for m in group.get("members", []) if m and m != node_id]
    upsert_temp_group(
        group_name,
        members=members,
        created_at=group.get("created_at", now),
        last_activity=now,
        locked=group.get("locked", False),
    )


def set_temp_group_locked(group_name, locked=True, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    group = get_temp_group(group_name)
    if not group:
        return False
    upsert_temp_group(
        group_name,
        members=group.get("members", []),
        created_at=group.get("created_at", now),
        last_activity=now,
        locked=bool(locked),
    )
    return True


def prune_expired_temp_groups(ttl_days, now_ts=None):
    ensure_db()
    try:
        ttl_days_int = int(ttl_days)
    except Exception:
        ttl_days_int = 0
    if ttl_days_int <= 0:
        return 0
    now = int(now_ts if now_ts is not None else time.time())
    cutoff = now - (ttl_days_int * 86400)
    with _conn() as conn:
        cur = conn.execute("DELETE FROM temp_groups WHERE last_activity < ?", (cutoff,))
        return int(cur.rowcount or 0)


def _normalize_command_job_statuses(statuses):
    if statuses is None:
        return None
    normalized = []
    for status in statuses:
        status_clean = str(status or "").strip().lower()
        if not status_clean:
            continue
        normalized.append(status_clean)
    if not normalized:
        return None
    return tuple(sorted(set(normalized)))


def _generate_command_id(prefix="cmd", now_ts=None):
    now = int(now_ts if now_ts is not None else time.time())
    return f"{prefix}-{now}-{os.urandom(6).hex()}"


def enqueue_command_job(
    command_data,
    source_file="",
    command_id="",
    max_attempts=5,
    available_at=None,
    now_ts=None,
    details=None,
):
    ensure_db()
    if not isinstance(command_data, dict):
        raise ValueError("command_data must be a dict")

    now = int(now_ts if now_ts is not None else time.time())
    source = str(source_file or "").strip()
    provided_id = str(command_id or command_data.get("command_id") or command_data.get("id") or "").strip()
    if not provided_id:
        provided_id = _generate_command_id("cmd", now_ts=now)
    command_id = provided_id

    attempts_max = max(1, int(max_attempts if max_attempts is not None else 5))
    available = int(available_at if available_at is not None else now)
    details_obj = details if isinstance(details, dict) else {}
    payload = dict(command_data)
    payload["command_id"] = command_id

    with _conn() as conn:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO command_jobs
            (
                command_id, source_file, payload_json, status, attempt_count, max_attempts,
                available_at, lease_until, last_error, details_json, created_at, updated_at, completed_at
            )
            VALUES (?, ?, ?, 'queued', 0, ?, ?, 0, '', ?, ?, ?, 0)
            """,
            (
                command_id,
                source,
                json.dumps(payload),
                attempts_max,
                available,
                json.dumps(details_obj),
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT id, status
            FROM command_jobs
            WHERE command_id = ?
            LIMIT 1
            """,
            (command_id,),
        ).fetchone()

    return {
        "enqueued": bool(cur.rowcount == 1),
        "command_id": command_id,
        "job_id": int(row["id"] if row else 0),
        "status": str(row["status"] if row else ""),
    }


def claim_next_command_job(lease_seconds=30, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    lease = max(5, int(lease_seconds if lease_seconds is not None else 30))
    lease_until = now + lease

    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT
                id, command_id, source_file, payload_json, status, attempt_count, max_attempts,
                available_at, lease_until, last_error, details_json, created_at, updated_at, completed_at
            FROM command_jobs
            WHERE
                (status = 'queued' AND available_at <= ?)
                OR
                (status = 'running' AND lease_until > 0 AND lease_until <= ?)
            ORDER BY id ASC
            LIMIT 1
            """,
            (now, now),
        ).fetchone()
        if not row:
            return None

        row_id = int(row["id"])
        expected_status = str(row["status"])
        if expected_status == "queued":
            cur = conn.execute(
                """
                UPDATE command_jobs
                SET
                    status = 'running',
                    attempt_count = attempt_count + 1,
                    lease_until = ?,
                    updated_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (lease_until, now, row_id),
            )
        else:
            cur = conn.execute(
                """
                UPDATE command_jobs
                SET
                    status = 'running',
                    attempt_count = attempt_count + 1,
                    lease_until = ?,
                    updated_at = ?
                WHERE id = ? AND status = 'running' AND lease_until <= ?
                """,
                (lease_until, now, row_id, now),
            )
        if cur.rowcount != 1:
            return None

        claimed = conn.execute(
            """
            SELECT
                id, command_id, source_file, payload_json, status, attempt_count, max_attempts,
                available_at, lease_until, last_error, details_json, created_at, updated_at, completed_at
            FROM command_jobs
            WHERE id = ?
            LIMIT 1
            """,
            (row_id,),
        ).fetchone()

    if not claimed:
        return None

    try:
        payload = json.loads(claimed["payload_json"])
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}
    try:
        details = json.loads(claimed["details_json"])
        if not isinstance(details, dict):
            details = {}
    except Exception:
        details = {}

    return {
        "id": int(claimed["id"]),
        "command_id": str(claimed["command_id"]),
        "source_file": str(claimed["source_file"]),
        "payload": payload,
        "status": str(claimed["status"]),
        "attempt_count": int(claimed["attempt_count"] or 0),
        "max_attempts": int(claimed["max_attempts"] or 0),
        "available_at": int(claimed["available_at"] or 0),
        "lease_until": int(claimed["lease_until"] or 0),
        "last_error": str(claimed["last_error"] or ""),
        "details": details,
        "created_at": int(claimed["created_at"] or 0),
        "updated_at": int(claimed["updated_at"] or 0),
        "completed_at": int(claimed["completed_at"] or 0),
    }


def mark_command_job_succeeded(job_id, details=None, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    details_obj = details if isinstance(details, dict) else {}
    with _conn() as conn:
        cur = conn.execute(
            """
            UPDATE command_jobs
            SET
                status = 'succeeded',
                lease_until = 0,
                last_error = '',
                details_json = ?,
                updated_at = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (json.dumps(details_obj), now, now, int(job_id)),
        )
    return bool(cur.rowcount == 1)


def mark_command_job_retry(job_id, retry_delay_seconds=5, error_message="", details=None, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    delay = max(1, int(retry_delay_seconds if retry_delay_seconds is not None else 5))
    available = now + delay
    details_obj = details if isinstance(details, dict) else {}
    with _conn() as conn:
        cur = conn.execute(
            """
            UPDATE command_jobs
            SET
                status = 'queued',
                available_at = ?,
                lease_until = 0,
                last_error = ?,
                details_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                available,
                str(error_message or "")[:1000],
                json.dumps(details_obj),
                now,
                int(job_id),
            ),
        )
    return bool(cur.rowcount == 1)


def mark_command_job_failed(job_id, error_message="", details=None, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    details_obj = details if isinstance(details, dict) else {}
    with _conn() as conn:
        cur = conn.execute(
            """
            UPDATE command_jobs
            SET
                status = 'failed',
                lease_until = 0,
                available_at = ?,
                last_error = ?,
                details_json = ?,
                updated_at = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (
                now,
                str(error_message or "")[:1000],
                json.dumps(details_obj),
                now,
                now,
                int(job_id),
            ),
        )
    return bool(cur.rowcount == 1)


def list_command_jobs(statuses=None, limit=100):
    ensure_db()
    status_values = _normalize_command_job_statuses(statuses)
    limit_int = max(1, min(5000, int(limit)))
    query = """
        SELECT
            id, command_id, source_file, payload_json, status, attempt_count, max_attempts,
            available_at, lease_until, last_error, details_json, created_at, updated_at, completed_at
        FROM command_jobs
    """
    params = []
    if status_values:
        placeholders = ",".join("?" for _ in status_values)
        query += f" WHERE status IN ({placeholders})"
        params.extend(status_values)
    query += " ORDER BY id ASC LIMIT ?"
    params.append(limit_int)

    with _conn() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()

    jobs = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}
        try:
            details = json.loads(row["details_json"])
            if not isinstance(details, dict):
                details = {}
        except Exception:
            details = {}
        jobs.append(
            {
                "id": int(row["id"] or 0),
                "command_id": str(row["command_id"] or ""),
                "source_file": str(row["source_file"] or ""),
                "payload": payload,
                "status": str(row["status"] or ""),
                "attempt_count": int(row["attempt_count"] or 0),
                "max_attempts": int(row["max_attempts"] or 0),
                "available_at": int(row["available_at"] or 0),
                "lease_until": int(row["lease_until"] or 0),
                "last_error": str(row["last_error"] or ""),
                "details": details,
                "created_at": int(row["created_at"] or 0),
                "updated_at": int(row["updated_at"] or 0),
                "completed_at": int(row["completed_at"] or 0),
            }
        )
    return jobs


def count_command_jobs(statuses=None):
    ensure_db()
    status_values = _normalize_command_job_statuses(statuses)
    query = "SELECT COUNT(1) AS cnt FROM command_jobs"
    params = []
    if status_values:
        placeholders = ",".join("?" for _ in status_values)
        query += f" WHERE status IN ({placeholders})"
        params.extend(status_values)
    with _conn() as conn:
        row = conn.execute(query, tuple(params)).fetchone()
    return int((row["cnt"] if row else 0) or 0)


def oldest_command_job_age(statuses=None, now_ts=None):
    ensure_db()
    now = int(now_ts if now_ts is not None else time.time())
    status_values = _normalize_command_job_statuses(statuses)
    query = "SELECT MIN(created_at) AS oldest_ts FROM command_jobs"
    params = []
    if status_values:
        placeholders = ",".join("?" for _ in status_values)
        query += f" WHERE status IN ({placeholders})"
        params.extend(status_values)
    with _conn() as conn:
        row = conn.execute(query, tuple(params)).fetchone()
    oldest_ts = int((row["oldest_ts"] if row and row["oldest_ts"] is not None else 0) or 0)
    if oldest_ts <= 0:
        return None
    return max(0, now - oldest_ts)


def prune_command_jobs(retention_hours=168, now_ts=None):
    ensure_db()
    try:
        retention_int = int(retention_hours)
    except Exception:
        retention_int = 0
    if retention_int <= 0:
        return 0
    now = int(now_ts if now_ts is not None else time.time())
    cutoff = now - (retention_int * 3600)
    with _conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM command_jobs
            WHERE status IN ('succeeded', 'failed') AND updated_at < ?
            """,
            (cutoff,),
        )
        return int(cur.rowcount or 0)


def get_command_receipt(command_id):
    ensure_db()
    command_id = str(command_id or "").strip()
    if not command_id:
        return None
    with _conn() as conn:
        row = conn.execute(
            """
            SELECT command_id, source_file, status, details_json, processed_at
            FROM command_receipts
            WHERE command_id = ?
            """,
            (command_id,),
        ).fetchone()
    if not row:
        return None
    try:
        details = json.loads(row["details_json"])
        if not isinstance(details, dict):
            details = {}
    except Exception:
        details = {}
    return {
        "command_id": row["command_id"],
        "source_file": row["source_file"],
        "status": row["status"],
        "details": details,
        "processed_at": int(row["processed_at"] or 0),
    }


def has_command_receipt(command_id, statuses=None):
    receipt = get_command_receipt(command_id)
    if not receipt:
        return False
    if statuses is None:
        return True
    allowed = {str(s).strip().lower() for s in statuses if str(s).strip()}
    if not allowed:
        return True
    return str(receipt.get("status", "")).strip().lower() in allowed


def upsert_command_receipt(command_id, source_file="", status="processed", details=None, processed_at=None):
    ensure_db()
    command_id = str(command_id or "").strip()
    if not command_id:
        return False
    source_file = str(source_file or "").strip()
    status = str(status or "processed").strip() or "processed"
    details_obj = details if isinstance(details, dict) else {}
    when = int(processed_at if processed_at is not None else time.time())
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO command_receipts (command_id, source_file, status, details_json, processed_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(command_id) DO UPDATE SET
                source_file = excluded.source_file,
                status = excluded.status,
                details_json = excluded.details_json,
                processed_at = excluded.processed_at
            """,
            (command_id, source_file, status, json.dumps(details_obj), when),
        )
    return True


def prune_command_receipts(ttl_hours=72, now_ts=None):
    ensure_db()
    try:
        ttl_hours_int = int(ttl_hours)
    except Exception:
        ttl_hours_int = 0
    if ttl_hours_int <= 0:
        return 0
    now = int(now_ts if now_ts is not None else time.time())
    cutoff = now - (ttl_hours_int * 3600)
    with _conn() as conn:
        cur = conn.execute("DELETE FROM command_receipts WHERE processed_at < ?", (cutoff,))
        return int(cur.rowcount or 0)


def add_command_dead_letter(command_id, source_file, reason, details=None, created_at=None):
    ensure_db()
    command_id = str(command_id or "").strip() or "unknown"
    source_file = str(source_file or "").strip()
    reason = str(reason or "").strip() or "unknown"
    details_obj = details if isinstance(details, dict) else {}
    when = int(created_at if created_at is not None else time.time())
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO command_dead_letters (command_id, source_file, reason, details_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (command_id, source_file, reason, json.dumps(details_obj), when),
        )


def count_command_dead_letters():
    ensure_db()
    with _conn() as conn:
        row = conn.execute("SELECT COUNT(1) AS cnt FROM command_dead_letters").fetchone()
    return int((row["cnt"] if row else 0) or 0)


def create_db_backup(output_dir, filename_prefix="guardianbridge_db", now_ts=None, retries=5):
    ensure_db()
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime(now_ts or time.time()))
    filename = f"{filename_prefix}_{timestamp}.db"
    backup_path = os.path.join(output_dir, filename)
    if os.path.exists(backup_path):
        os.remove(backup_path)

    last_error = None
    attempts = max(1, int(retries))
    for attempt in range(attempts):
        src_conn = None
        dst_conn = None
        try:
            src_conn = sqlite3.connect(settings.DB_PATH, timeout=15, check_same_thread=False)
            src_conn.execute("PRAGMA busy_timeout=15000")
            dst_conn = sqlite3.connect(backup_path, timeout=15, check_same_thread=False)
            dst_conn.execute("PRAGMA busy_timeout=15000")
            with dst_conn:
                src_conn.backup(dst_conn)
            return backup_path
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" in str(exc).lower() and attempt < (attempts - 1):
                time.sleep(0.25 * (attempt + 1))
                continue
            raise
        finally:
            if dst_conn is not None:
                dst_conn.close()
            if src_conn is not None:
                src_conn.close()

    raise RuntimeError(f"Unable to create DB backup: {last_error}")


def vacuum_database(retries=5):
    ensure_db()
    attempts = max(1, int(retries))
    last_error = None
    for attempt in range(attempts):
        try:
            with _conn() as conn:
                conn.execute("VACUUM")
            return True
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" in str(exc).lower() and attempt < (attempts - 1):
                time.sleep(0.25 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"Unable to vacuum database: {last_error}")


def restore_database_from_backup(source_db_path, retries=5):
    ensure_db()
    source = os.path.abspath(str(source_db_path or ""))
    if not source or not os.path.isfile(source):
        raise FileNotFoundError(f"Backup file not found: {source_db_path}")

    attempts = max(1, int(retries))
    last_error = None
    for attempt in range(attempts):
        src_conn = None
        dst_conn = None
        try:
            src_conn = sqlite3.connect(source, timeout=20, check_same_thread=False)
            src_conn.execute("PRAGMA busy_timeout=20000")
            dst_conn = sqlite3.connect(settings.DB_PATH, timeout=20, check_same_thread=False)
            dst_conn.execute("PRAGMA busy_timeout=20000")
            dst_conn.execute("PRAGMA foreign_keys=OFF")
            with dst_conn:
                src_conn.backup(dst_conn)
                dst_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            dst_conn.execute("PRAGMA foreign_keys=ON")
            return True
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" in str(exc).lower() and attempt < (attempts - 1):
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
        finally:
            if dst_conn is not None:
                dst_conn.close()
            if src_conn is not None:
                src_conn.close()

    raise RuntimeError(f"Unable to restore database from backup: {last_error}")
