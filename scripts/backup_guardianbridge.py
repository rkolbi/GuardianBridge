#!/usr/bin/env python3
"""
GuardianBridge backup utility.

Creates a timestamped SQLite backup plus an optional ZIP archive of data/ files.
Designed for cron or systemd-timer usage.
"""

import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


DEFAULT_BASE_DIR = Path("/opt/GuardianBridge")


def _timestamp():
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _backup_sqlite(db_path: Path, dest_path: Path) -> None:
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")
    with sqlite3.connect(str(db_path)) as src:
        with sqlite3.connect(str(dest_path)) as dst:
            src.backup(dst)


def _should_skip_data(rel_path: Path) -> bool:
    parts = rel_path.parts
    if not parts:
        return True
    if parts[0] == "commands":
        return True
    name = rel_path.name
    if name.startswith("guardianbridge.db"):
        return True
    if name.endswith(".lock"):
        return True
    return False


def _backup_data_zip(data_dir: Path, dest_zip: Path) -> int:
    if not data_dir.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")
    files_added = 0
    with ZipFile(dest_zip, "w", compression=ZIP_DEFLATED) as zf:
        for path in data_dir.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(data_dir)
            if _should_skip_data(rel):
                continue
            zf.write(path, arcname=str(rel))
            files_added += 1
    return files_added


def _enforce_retention(output_dir: Path, prefix: str, keep: int) -> int:
    if keep <= 0:
        return 0
    files = sorted(
        output_dir.glob(f"{prefix}_*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    removed = 0
    for old_file in files[keep:]:
        try:
            old_file.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="Backup GuardianBridge database and data directory.")
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR), help="GuardianBridge base directory.")
    parser.add_argument("--output-dir", default="", help="Output directory for backups.")
    parser.add_argument("--no-data-zip", action="store_true", help="Skip ZIP backup of data/ directory.")
    parser.add_argument("--retention", type=int, default=14, help="How many backups to keep per type.")
    args = parser.parse_args()

    base_dir = Path(args.base_dir).expanduser()
    data_dir = base_dir / "data"
    db_path = data_dir / "guardianbridge.db"
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else (base_dir / "backups")
    _ensure_dir(output_dir)

    ts = _timestamp()
    db_backup_path = output_dir / f"guardianbridge_db_{ts}.db"
    _backup_sqlite(db_path, db_backup_path)
    print(f"DB backup: {db_backup_path}")

    data_zip_path = None
    if not args.no_data_zip:
        data_zip_path = output_dir / f"guardianbridge_data_{ts}.zip"
        files_added = _backup_data_zip(data_dir, data_zip_path)
        print(f"Data backup: {data_zip_path} (files: {files_added})")

    removed_db = _enforce_retention(output_dir, "guardianbridge_db", args.retention)
    removed_data = _enforce_retention(output_dir, "guardianbridge_data", args.retention)
    if removed_db or removed_data:
        print(f"Retention cleanup: db={removed_db}, data={removed_data}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
