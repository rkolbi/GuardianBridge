#!/usr/bin/env python3
"""
GuardianBridge pre-release preflight checks.

Runs operational checks for mission-critical readiness:
- service status
- SQLite integrity and queue signals
- dispatcher/weather freshness
- backup recency
- disk capacity
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_BASE_DIR = Path("/opt/GuardianBridge")


@dataclass
class CheckResult:
    name: str
    status: str
    message: str


def _parse_iso_timestamp(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _env_value(env_path: Path, key: str, default: str) -> str:
    if not env_path.exists():
        return default
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return default
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        left, right = line.split("=", 1)
        if left.strip() == key:
            return right.strip().strip("\"'")
    return default


def _run_systemctl(service_name: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", *args, service_name],
        check=False,
        capture_output=True,
        text=True,
    )


def check_service(service_name: str) -> CheckResult:
    if shutil.which("systemctl") is None:
        return CheckResult("service", "SKIP", "systemctl not found; service check skipped.")
    result = _run_systemctl(service_name, "is-active")
    active = (result.stdout or "").strip().lower()
    if result.returncode == 0 and active == "active":
        return CheckResult("service", "PASS", f"{service_name} is active.")
    detail = (result.stdout or result.stderr or "unknown").strip()
    return CheckResult("service", "FAIL", f"{service_name} is not active ({detail}).")


def check_db_integrity(db_path: Path) -> CheckResult:
    if not db_path.exists():
        return CheckResult("db_integrity", "FAIL", f"Database missing: {db_path}")
    try:
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        row = conn.execute("PRAGMA integrity_check").fetchone()
        conn.close()
    except Exception as exc:
        return CheckResult("db_integrity", "FAIL", f"Integrity check failed: {exc}")
    value = str(row[0] if row else "unknown").strip().lower()
    if value == "ok":
        return CheckResult("db_integrity", "PASS", "SQLite integrity_check returned ok.")
    return CheckResult("db_integrity", "FAIL", f"SQLite integrity_check returned: {value}")


def check_queue_signals(
    db_path: Path,
    queue_warn: int,
    queue_fail: int,
    dead_warn: int,
    dead_fail: int,
) -> list[CheckResult]:
    if not db_path.exists():
        return [CheckResult("queue", "FAIL", "Database missing; queue checks unavailable.")]
    try:
        conn = sqlite3.connect(str(db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        queue_row = conn.execute(
            "SELECT COUNT(1) AS cnt FROM command_jobs WHERE status IN ('queued', 'running')"
        ).fetchone()
        dead_row = conn.execute("SELECT COUNT(1) AS cnt FROM command_dead_letters").fetchone()
        email_row = conn.execute("SELECT COUNT(1) AS cnt FROM outgoing_emails").fetchone()
        dm_row = conn.execute("SELECT COUNT(1) AS cnt FROM failed_dm_queue").fetchone()
        conn.close()
    except Exception as exc:
        return [CheckResult("queue", "FAIL", f"Queue checks failed: {exc}")]

    queue_count = int((queue_row["cnt"] if queue_row else 0) or 0)
    dead_count = int((dead_row["cnt"] if dead_row else 0) or 0)
    email_count = int((email_row["cnt"] if email_row else 0) or 0)
    dm_count = int((dm_row["cnt"] if dm_row else 0) or 0)

    queue_status = "PASS"
    if queue_count >= queue_fail:
        queue_status = "FAIL"
    elif queue_count >= queue_warn:
        queue_status = "WARN"

    dead_status = "PASS"
    if dead_count >= dead_fail:
        dead_status = "FAIL"
    elif dead_count >= dead_warn:
        dead_status = "WARN"

    return [
        CheckResult(
            "queue_backlog",
            queue_status,
            f"command_jobs queued/running: {queue_count} (warn>={queue_warn}, fail>={queue_fail})",
        ),
        CheckResult(
            "dead_letters",
            dead_status,
            f"command_dead_letters rows: {dead_count} (warn>={dead_warn}, fail>={dead_fail})",
        ),
        CheckResult("email_queue", "PASS", f"outgoing_emails rows: {email_count}"),
        CheckResult("failed_dm_queue", "PASS", f"failed_dm_queue rows: {dm_count}"),
    ]


def check_dispatcher_freshness(status_path: Path, max_age_seconds: int) -> CheckResult:
    if not status_path.exists():
        return CheckResult("dispatcher_freshness", "FAIL", f"Missing file: {status_path}")
    try:
        payload = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return CheckResult("dispatcher_freshness", "FAIL", f"Invalid dispatcher_status.json: {exc}")

    dt = _parse_iso_timestamp(str(payload.get("last_update", "")))
    if dt is None:
        dt = datetime.fromtimestamp(status_path.stat().st_mtime, tz=timezone.utc)
    age = int((datetime.now(timezone.utc) - dt).total_seconds())

    if age <= max_age_seconds:
        return CheckResult("dispatcher_freshness", "PASS", f"dispatcher_status age={age}s (max={max_age_seconds}s)")
    return CheckResult("dispatcher_freshness", "FAIL", f"dispatcher_status stale: age={age}s (max={max_age_seconds}s)")


def check_weather_freshness(weather_path: Path, max_age_seconds: int) -> CheckResult:
    if not weather_path.exists():
        return CheckResult("weather_freshness", "WARN", f"Missing file: {weather_path}")
    ts = None
    try:
        payload = json.loads(weather_path.read_text(encoding="utf-8"))
        ts = _parse_iso_timestamp(str(payload.get("timestamp", "")))
    except Exception:
        ts = None
    if ts is None:
        ts = datetime.fromtimestamp(weather_path.stat().st_mtime, tz=timezone.utc)
    age = int((datetime.now(timezone.utc) - ts).total_seconds())
    if age <= max_age_seconds:
        return CheckResult("weather_freshness", "PASS", f"weather_current age={age}s (max={max_age_seconds}s)")
    return CheckResult("weather_freshness", "WARN", f"weather_current stale: age={age}s (max={max_age_seconds}s)")


def check_backup_recency(auto_backup_dir: Path, max_age_hours: int) -> CheckResult:
    pattern = "guardianbridge_db_*.db"
    backups = sorted(auto_backup_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return CheckResult("backup_recency", "FAIL", f"No backups found in {auto_backup_dir}")
    latest = backups[0]
    age_seconds = int(time.time() - latest.stat().st_mtime)
    max_age_seconds = max_age_hours * 3600
    if age_seconds <= max_age_seconds:
        return CheckResult("backup_recency", "PASS", f"Latest backup {latest.name} age={age_seconds}s")
    return CheckResult(
        "backup_recency",
        "WARN",
        f"Latest backup {latest.name} is stale (age={age_seconds}s, max={max_age_seconds}s)",
    )


def check_disk(base_dir: Path, min_free_gb_fail: float, min_free_pct_warn: float) -> CheckResult:
    usage = shutil.disk_usage(str(base_dir))
    free_gb = usage.free / (1024 ** 3)
    free_pct = (usage.free / usage.total) * 100.0 if usage.total > 0 else 0.0
    if free_gb < min_free_gb_fail:
        return CheckResult("disk", "FAIL", f"Low disk: {free_gb:.2f} GiB free ({free_pct:.1f}%).")
    if free_pct < min_free_pct_warn:
        return CheckResult("disk", "WARN", f"Disk getting low: {free_gb:.2f} GiB free ({free_pct:.1f}%).")
    return CheckResult("disk", "PASS", f"Disk free: {free_gb:.2f} GiB ({free_pct:.1f}%).")


def _print_results(results: list[CheckResult]) -> None:
    for result in results:
        print(f"[{result.status:<4}] {result.name:<20} {result.message}")
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    print("")
    print(
        "Summary: "
        f"PASS={counts.get('PASS', 0)} "
        f"WARN={counts.get('WARN', 0)} "
        f"FAIL={counts.get('FAIL', 0)} "
        f"SKIP={counts.get('SKIP', 0)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianBridge pre-release preflight checks.")
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR), help="GuardianBridge base directory")
    parser.add_argument("--service-name", default="guardianbridge.service", help="systemd service name")
    parser.add_argument("--max-dispatcher-age-seconds", type=int, default=120)
    parser.add_argument("--max-weather-age-minutes", type=int, default=-1, help="Override WEATHER_DATA_MAX_AGE_MINUTES")
    parser.add_argument("--max-backup-age-hours", type=int, default=24)
    parser.add_argument("--queue-warn", type=int, default=200)
    parser.add_argument("--queue-fail", type=int, default=1000)
    parser.add_argument("--dead-letter-warn", type=int, default=1)
    parser.add_argument("--dead-letter-fail", type=int, default=50)
    parser.add_argument("--min-free-gb-fail", type=float, default=1.0)
    parser.add_argument("--min-free-pct-warn", type=float, default=10.0)
    parser.add_argument("--warnings-ok", action="store_true", help="Exit 0 if there are warnings and no failures")
    args = parser.parse_args()

    base_dir = Path(args.base_dir).expanduser()
    data_dir = base_dir / "data"
    auto_backup_dir = base_dir / "AutoBackUp"
    env_path = base_dir / ".env"
    db_path = data_dir / "guardianbridge.db"
    status_path = data_dir / "dispatcher_status.json"
    weather_path = data_dir / "weather_current.json"

    if args.max_weather_age_minutes > 0:
        weather_max_minutes = int(args.max_weather_age_minutes)
    else:
        weather_max_minutes = int(_env_value(env_path, "WEATHER_DATA_MAX_AGE_MINUTES", "120"))
    weather_max_seconds = max(60, weather_max_minutes * 60)

    results: list[CheckResult] = []
    results.append(check_service(args.service_name))
    results.append(check_db_integrity(db_path))
    results.extend(
        check_queue_signals(
            db_path=db_path,
            queue_warn=max(0, int(args.queue_warn)),
            queue_fail=max(1, int(args.queue_fail)),
            dead_warn=max(0, int(args.dead_letter_warn)),
            dead_fail=max(1, int(args.dead_letter_fail)),
        )
    )
    results.append(check_dispatcher_freshness(status_path, max(30, int(args.max_dispatcher_age_seconds))))
    results.append(check_weather_freshness(weather_path, weather_max_seconds))
    results.append(check_backup_recency(auto_backup_dir, max(1, int(args.max_backup_age_hours))))
    results.append(
        check_disk(
            base_dir=base_dir,
            min_free_gb_fail=max(0.1, float(args.min_free_gb_fail)),
            min_free_pct_warn=max(0.1, float(args.min_free_pct_warn)),
        )
    )

    _print_results(results)

    has_fail = any(r.status == "FAIL" for r in results)
    has_warn = any(r.status == "WARN" for r in results)
    if has_fail:
        return 2
    if has_warn and not args.warnings_ok:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
