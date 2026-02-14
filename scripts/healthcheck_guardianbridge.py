#!/usr/bin/env python3
"""
GuardianBridge health check script.

Validates dispatcher_status.json freshness and optionally restarts the service.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_BASE_DIR = Path("/opt/GuardianBridge")


def _parse_timestamp(ts: str):
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc)


def _now_like(dt):
    if dt.tzinfo is None:
        return datetime.now()
    return datetime.now(timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianBridge dispatcher health check.")
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR), help="GuardianBridge base directory.")
    parser.add_argument("--status-file", default="", help="Path to dispatcher_status.json.")
    parser.add_argument("--max-age-seconds", type=int, default=120, help="Max allowed age in seconds.")
    parser.add_argument("--restart", action="store_true", help="Restart service if stale.")
    parser.add_argument("--service-name", default="guardianbridge.service", help="systemd service name.")
    args = parser.parse_args()

    base_dir = Path(args.base_dir).expanduser()
    status_path = Path(args.status_file).expanduser() if args.status_file else (base_dir / "data" / "dispatcher_status.json")

    if not status_path.exists():
        print(f"CRITICAL: status file missing: {status_path}")
        return 2

    try:
        data = json.loads(status_path.read_text())
    except Exception as exc:
        print(f"CRITICAL: failed to read status file: {exc}")
        return 2

    last_update = data.get("last_update")
    dt = _parse_timestamp(last_update) if isinstance(last_update, str) else None
    if dt is None:
        mtime = datetime.fromtimestamp(status_path.stat().st_mtime)
        dt = mtime

    age = (_now_like(dt) - dt).total_seconds()
    if age <= args.max_age_seconds:
        print(f"OK: dispatcher status age {int(age)}s (max {args.max_age_seconds}s)")
        return 0

    print(f"STALE: dispatcher status age {int(age)}s (max {args.max_age_seconds}s)")
    if args.restart:
        try:
            subprocess.run(
                ["systemctl", "restart", args.service_name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(f"Restart attempted: {args.service_name}")
        except Exception as exc:
            print(f"CRITICAL: restart failed: {exc}")
            return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
