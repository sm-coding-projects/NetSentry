#!/bin/zsh
# Restore meta.sqlite from a NetSentry backup zip. Usage: Scripts/restore-manifest.sh <backup.zip> [store root]
set -euo pipefail
ZIP="$1"; ROOT="${2:-$HOME/Library/Application Support/NetSentry/Store}"
[[ -f "$ZIP" ]] || { echo "backup not found: $ZIP" >&2; exit 2; }
if launchctl print "gui/$UID/com.netsentry.collector" >/dev/null 2>&1 || launchctl print "gui/$UID/com.netsentry.collector.dev" >/dev/null 2>&1; then
  echo "Stop the collector first (Settings → Background collector off, or launchctl bootout)." >&2; exit 1
fi
TMP="$(mktemp -d)"; ditto -x -k "$ZIP" "$TMP"
SRC="$(find "$TMP" -name meta.sqlite | head -1)"; [[ -n "$SRC" ]] || { echo "no meta.sqlite in backup" >&2; exit 1; }
sqlite3 "$SRC" "PRAGMA integrity_check" | grep -q '^ok$' || { echo "backup fails integrity check" >&2; exit 1; }
cp "$ROOT/meta.sqlite" "$ROOT/meta.sqlite.pre-restore.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
rm -f "$ROOT/meta.sqlite-wal" "$ROOT/meta.sqlite-shm"
cp "$SRC" "$ROOT/meta.sqlite"; chmod 600 "$ROOT/meta.sqlite"
echo "Restored $SRC → $ROOT/meta.sqlite. Start the collector; recovery will reconcile segments on disk."
