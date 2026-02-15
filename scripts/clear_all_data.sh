#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data"
NO_BACKUP=0
BACKUP_DIR=""
DRY_RUN=0
ASSUME_YES=0

usage() {
  cat <<'EOF'
Usage: ./scripts/clear_all_data.sh [--data-dir PATH] [--no-backup] [--backup-dir PATH] [--dry-run] [--yes]

Options:
  --data-dir PATH     Data directory to clear (default: ../data relative to script)
  --no-backup         Skip backup creation before deletion
  --backup-dir PATH   Explicit backup directory (default: ../AutoBackUp/data_reset_<timestamp>)
  --dry-run           Show what would be removed without changing files
  --yes               Confirm destructive deletion
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --data-dir requires a value." >&2; exit 1; }
      DATA_DIR="$1"
      ;;
    --no-backup)
      NO_BACKUP=1
      ;;
    --backup-dir)
      shift
      [[ $# -gt 0 ]] || { echo "Error: --backup-dir requires a value." >&2; exit 1; }
      BACKUP_DIR="$1"
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --yes)
      ASSUME_YES=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: Unknown option '$1'." >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ ! -d "$DATA_DIR" ]]; then
  echo "Error: Data directory not found: $DATA_DIR" >&2
  exit 1
fi

DATA_DIR="$(cd "$DATA_DIR" && pwd)"
COMMANDS_DIR="${DATA_DIR}/commands"

assert_writable_dir() {
  local dir="$1"
  local probe="${dir}/.clear_all_data_write_test.tmp"
  if ! printf "ok\n" > "$probe" 2>/dev/null; then
    echo "Error: Write access is required for '${dir}'." >&2
    exit 1
  fi
  rm -f "$probe"
}

targets=()
while IFS= read -r -d '' path; do
  targets+=("$path")
done < <(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print0)

RESOLVED_BACKUP_DIR=""
if [[ $NO_BACKUP -eq 0 ]]; then
  if [[ -n "$BACKUP_DIR" ]]; then
    mkdir -p "$BACKUP_DIR"
    RESOLVED_BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd)"
  else
    PARENT_DIR="$(cd "$DATA_DIR/.." && pwd)"
    BACKUP_ROOT="${PARENT_DIR}/AutoBackUp"
    RESOLVED_BACKUP_DIR="${BACKUP_ROOT}/data_reset_$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$RESOLVED_BACKUP_DIR"
    RESOLVED_BACKUP_DIR="$(cd "$RESOLVED_BACKUP_DIR" && pwd)"
  fi

  case "${RESOLVED_BACKUP_DIR}/" in
    "${DATA_DIR}/"*)
      echo "Error: Backup directory cannot be inside data directory: $RESOLVED_BACKUP_DIR" >&2
      exit 1
      ;;
  esac
fi

commands_entries_count=0
if [[ -d "$COMMANDS_DIR" ]]; then
  commands_entries_count="$(find "$COMMANDS_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
fi

echo
echo "Data directory: $DATA_DIR"
echo "Entries to remove: ${#targets[@]}"
echo "commands/ entries currently present: ${commands_entries_count}"
if [[ $NO_BACKUP -eq 0 ]]; then
  echo "Backup directory: $RESOLVED_BACKUP_DIR"
fi
if [[ $DRY_RUN -eq 1 ]]; then
  echo "Mode: DRY RUN (no files will be changed)"
else
  echo "Mode: LIVE RUN"
fi
echo

if [[ $DRY_RUN -eq 1 ]]; then
  for path in "${targets[@]}"; do
    echo "Would remove entry: $path"
  done
  exit 0
fi

if [[ $ASSUME_YES -eq 0 ]]; then
  echo "Safety check: refusing to delete without --yes." >&2
  echo "Re-run with --yes after reviewing --dry-run output." >&2
  exit 1
fi

assert_writable_dir "$DATA_DIR"

if [[ $NO_BACKUP -eq 0 ]]; then
  assert_writable_dir "$RESOLVED_BACKUP_DIR"
  for path in "${targets[@]}"; do
    cp -a "$path" "$RESOLVED_BACKUP_DIR/"
  done
fi

for path in "${targets[@]}"; do
  rm -rf "$path"
done

mkdir -p "$COMMANDS_DIR"

echo "Data clear complete."
if [[ $NO_BACKUP -eq 0 ]]; then
  echo "Backup saved to: $RESOLVED_BACKUP_DIR"
fi
