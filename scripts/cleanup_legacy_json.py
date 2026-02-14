#!/usr/bin/env python3
import argparse
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import gb_db
import settings


LEGACY_FILES = [
    ("dispatcher_jobs.json", settings.DISPATCHER_JOBS_FILE, "dispatcher_jobs"),
    ("outgoing_emails.json", settings.OUTGOING_EMAIL_FILE, "outgoing_emails"),
    ("failed_dm_queue.json", settings.FAILED_DM_QUEUE_FILE, "failed_dm_queue"),
]


def _json_entry_count(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception:
        return None
    if isinstance(data, list) or isinstance(data, dict):
        return len(data)
    return None


def _db_count(table_name):
    if table_name == "dispatcher_jobs":
        return len(gb_db.load_dispatcher_jobs() or [])
    if table_name == "outgoing_emails":
        return gb_db.count_outgoing_emails()
    if table_name == "failed_dm_queue":
        return gb_db.count_failed_dm_queue()
    return 0


def _should_delete(db_count, json_count):
    if json_count is None:
        return True
    if json_count == 0:
        return True
    return db_count > 0


def main():
    parser = argparse.ArgumentParser(
        description="Cleanup legacy JSON queue/job files after SQLite migration."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete files. Default is dry-run.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Delete even if DB tables are empty and JSON has data.",
    )
    args = parser.parse_args()

    gb_db.ensure_db()

    print("GuardianBridge legacy JSON cleanup")
    print(f"Data dir: {settings.DATA_DIR}")
    print(f"DB path: {settings.DB_PATH}")
    print("")

    delete_candidates = []
    for label, path, table in LEGACY_FILES:
        json_count = _json_entry_count(path)
        db_count = _db_count(table)
        exists = os.path.exists(path)

        print(f"{label}:")
        print(f"  Path: {path}")
        print(f"  Exists: {exists}")
        print(f"  JSON entries: {json_count if json_count is not None else 'unknown'}")
        print(f"  DB rows: {db_count}")

        safe = _should_delete(db_count, json_count)
        if safe:
            delete_candidates.append(path)
            print("  Status: OK to delete")
        else:
            print("  Status: WARNING - JSON has data but DB is empty")
        print("")

    if not args.apply:
        print("Dry-run complete. Re-run with --apply to delete eligible files.")
        if any(
            _json_entry_count(path) not in (None, 0)
            and _db_count(table) == 0
            for _, path, table in LEGACY_FILES
        ):
            print("Use --force if you want to delete even when DB tables are empty.")
        return 0

    for _, path, table in LEGACY_FILES:
        json_count = _json_entry_count(path)
        db_count = _db_count(table)
        safe = _should_delete(db_count, json_count)
        if not safe and not args.force:
            print(f"Skipping {path} (DB empty, JSON has data). Use --force to override.")
            continue
        if os.path.exists(path):
            os.remove(path)
            print(f"Deleted {path}")
        lock_path = path + ".lock"
        if os.path.exists(lock_path):
            os.remove(lock_path)
            print(f"Deleted {lock_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
