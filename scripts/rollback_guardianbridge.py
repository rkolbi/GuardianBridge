#!/usr/bin/env python3
"""
GuardianBridge one-command DB rollback utility.

Restores data/guardianbridge.db from a selected backup in AutoBackUp
and creates a safety snapshot of the current DB before restore.
Optionally controls guardianbridge.service via systemctl.
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_BASE_DIR = Path("/opt/GuardianBridge")


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _find_backups(auto_backup_dir: Path) -> list[Path]:
    backups = [p for p in auto_backup_dir.glob("guardianbridge_db_*.db") if p.is_file()]
    backups.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return backups


def _sqlite_backup(source_db: Path, dest_db: Path) -> None:
    if not source_db.exists():
        raise FileNotFoundError(f"Source DB not found: {source_db}")
    dest_db.parent.mkdir(parents=True, exist_ok=True)
    if dest_db.exists():
        dest_db.unlink()
    src_conn = None
    dst_conn = None
    try:
        src_conn = sqlite3.connect(str(source_db), timeout=30, check_same_thread=False)
        src_conn.execute("PRAGMA busy_timeout=30000")
        dst_conn = sqlite3.connect(str(dest_db), timeout=30, check_same_thread=False)
        dst_conn.execute("PRAGMA busy_timeout=30000")
        with dst_conn:
            src_conn.backup(dst_conn)
            dst_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        if dst_conn is not None:
            dst_conn.close()
        if src_conn is not None:
            src_conn.close()


def _run_systemctl(service_name: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", *args, service_name],
        check=False,
        capture_output=True,
        text=True,
    )


def _service_active(service_name: str) -> bool:
    result = _run_systemctl(service_name, "is-active")
    return result.returncode == 0 and (result.stdout or "").strip().lower() == "active"


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore guardianbridge.db from AutoBackUp.")
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR), help="GuardianBridge base directory")
    parser.add_argument("--auto-backup-dir", default="", help="AutoBackUp directory")
    parser.add_argument("--backup-file", default="", help="Specific backup DB file to restore")
    parser.add_argument("--list-backups", action="store_true", help="List available backups and exit")
    parser.add_argument("--service-name", default="guardianbridge.service", help="systemd service name")
    parser.add_argument("--no-service-control", action="store_true", help="Do not stop/start service")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    base_dir = Path(args.base_dir).expanduser()
    data_dir = base_dir / "data"
    db_path = data_dir / "guardianbridge.db"
    auto_backup_dir = Path(args.auto_backup_dir).expanduser() if args.auto_backup_dir else (base_dir / "AutoBackUp")
    auto_backup_dir.mkdir(parents=True, exist_ok=True)

    backups = _find_backups(auto_backup_dir)
    if args.list_backups:
        if not backups:
            print(f"No backups found in {auto_backup_dir}")
            return 1
        print(f"Backups in {auto_backup_dir}:")
        for idx, path in enumerate(backups, start=1):
            print(f"{idx:>2}. {path.name}")
        return 0

    if args.backup_file:
        restore_source = Path(args.backup_file).expanduser()
    else:
        if not backups:
            print(f"ERROR: no backups found in {auto_backup_dir}")
            return 1
        restore_source = backups[0]

    if not restore_source.exists():
        print(f"ERROR: backup file not found: {restore_source}")
        return 1

    safety_snapshot = auto_backup_dir / f"guardianbridge_db_pre_rollback_{_timestamp()}.db"

    service_control = (not args.no_service_control) and (shutil.which("systemctl") is not None)
    service_was_active = False

    print(f"Selected restore source: {restore_source}")
    print(f"Current DB path:          {db_path}")
    print(f"Safety snapshot path:     {safety_snapshot}")
    if service_control:
        service_was_active = _service_active(args.service_name)
        print(f"Service control:          enabled ({args.service_name}, active={service_was_active})")
    else:
        print("Service control:          disabled (no-service-control or systemctl unavailable)")

    if not args.yes and not args.dry_run:
        confirm = input("Proceed with rollback? [y/N]: ").strip().lower()
        if confirm not in {"y", "yes"}:
            print("Aborted.")
            return 1

    if args.dry_run:
        print("DRY RUN: would create safety snapshot, restore backup, and manage service state.")
        return 0

    service_stopped = False
    try:
        if service_control and service_was_active:
            stop_res = _run_systemctl(args.service_name, "stop")
            if stop_res.returncode != 0:
                detail = (stop_res.stderr or stop_res.stdout or "unknown").strip()
                raise RuntimeError(f"Failed to stop service {args.service_name}: {detail}")
            service_stopped = True
            print(f"Stopped service: {args.service_name}")

        if db_path.exists():
            _sqlite_backup(db_path, safety_snapshot)
            print(f"Created safety snapshot: {safety_snapshot}")
        else:
            print(f"Current DB missing; skipping safety snapshot: {db_path}")

        _sqlite_backup(restore_source, db_path)
        print(f"Restored DB from backup: {restore_source}")

        if service_control and service_was_active:
            start_res = _run_systemctl(args.service_name, "start")
            if start_res.returncode != 0:
                detail = (start_res.stderr or start_res.stdout or "unknown").strip()
                raise RuntimeError(f"Rollback restored DB but failed to start service {args.service_name}: {detail}")
            service_stopped = False
            print(f"Started service: {args.service_name}")

        print("Rollback completed successfully.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}")
        if service_control and service_stopped:
            restart_res = _run_systemctl(args.service_name, "start")
            if restart_res.returncode == 0:
                print(f"Service restart recovery attempted: {args.service_name}")
            else:
                detail = (restart_res.stderr or restart_res.stdout or "unknown").strip()
                print(f"CRITICAL: could not restart {args.service_name}: {detail}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
