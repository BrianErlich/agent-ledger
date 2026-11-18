#!/usr/bin/env bash
# Incremental refresh: ingest new transcript bytes, then recompute events.
# Stops at the first failing step and never overlaps itself. One summary line per run is appended
# to refresh.log in the data directory ($LEDGER_DIR, default ~/.local/share/agent-ledger).
# Needs flock(1) (util-linux; not on stock macOS).
# Example cron line:  30 4 * * *  /path/to/agent-ledger/refresh.sh
set -u
umask 077
here="$(cd "$(dirname "$0")" && pwd)"
data="${LEDGER_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/agent-ledger}"
mkdir -p "$data" || exit 1
exec 9>"$data/.refresh.lock"
flock -n 9 || { echo "$(date -u +%FT%TZ) skipped: another refresh holds the lock" >> "$data/refresh.log"; exit 0; }

start=$(date -u +%FT%TZ)
step() {
  "$@" > /dev/null || { rc=$?; echo "$start -> $(date -u +%FT%TZ) FAIL rc=$rc at: $*" >> "$data/refresh.log"; exit "$rc"; }
}
step python3 "$here/ingest.py" --db "$data/ledger.db"
step python3 "$here/detect.py" --db "$data/ledger.db"
echo "$start -> $(date -u +%FT%TZ) ok" >> "$data/refresh.log"
