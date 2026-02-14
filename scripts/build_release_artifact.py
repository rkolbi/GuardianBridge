#!/usr/bin/env python3
"""
GuardianBridge release artifact builder.

Creates a timestamped tar.gz plus SHA256 checksum and manifest JSON
for repeatable releases and rollback reference.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_BASE_DIR = Path("/opt/GuardianBridge")
INCLUDE_PATHS = [
    "dispatcher",
    "www",
    "scripts",
    "Docs",
    "README.md",
    "about.md",
    "requirements.txt",
    "settings.py",
    "meshtastic_dispatcher.py",
    "email_processor.py",
    "weather_fetcher.py",
    "map_tile_downloader.py",
    "SAME_parser.py",
    "gb_db.py",
]
EXCLUDE_DIR_NAMES = {"data", "AutoBackUp", "__pycache__", ".pytest_cache", ".git", ".idea", ".vscode"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _should_exclude(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_DIR_NAMES:
            return True
    if path.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    return False


def _iter_include_files(base_dir: Path) -> list[Path]:
    files: list[Path] = []
    for rel in INCLUDE_PATHS:
        p = base_dir / rel
        if not p.exists():
            continue
        if p.is_file():
            if not _should_exclude(p.relative_to(base_dir)):
                files.append(p)
            continue
        for child in p.rglob("*"):
            if not child.is_file():
                continue
            rel_child = child.relative_to(base_dir)
            if _should_exclude(rel_child):
                continue
            files.append(child)
    files = sorted(set(files))
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="Build GuardianBridge release artifact.")
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR), help="GuardianBridge base directory")
    parser.add_argument("--output-dir", default="", help="Output directory for artifacts")
    args = parser.parse_args()

    base_dir = Path(args.base_dir).expanduser()
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else (base_dir / "releases")
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = _timestamp()
    artifact_name = f"guardianbridge_release_{ts}.tar.gz"
    artifact_path = output_dir / artifact_name
    manifest_path = output_dir / f"{artifact_name}.manifest.json"
    sha_path = output_dir / f"{artifact_name}.sha256"

    files = _iter_include_files(base_dir)
    if not files:
        raise RuntimeError(f"No files selected for artifact under {base_dir}")

    with tarfile.open(artifact_path, "w:gz") as tar:
        for abs_path in files:
            rel = abs_path.relative_to(base_dir)
            tar.add(str(abs_path), arcname=str(Path("GuardianBridge") / rel))

    artifact_sha = _sha256_file(artifact_path)
    sha_path.write_text(f"{artifact_sha}  {artifact_path.name}\n", encoding="utf-8")

    manifest = {
        "created_utc": ts,
        "base_dir": str(base_dir),
        "artifact": artifact_path.name,
        "artifact_sha256": artifact_sha,
        "file_count": len(files),
        "files": [str(p.relative_to(base_dir)) for p in files],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Artifact: {artifact_path}")
    print(f"SHA256:   {sha_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Files:    {len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

