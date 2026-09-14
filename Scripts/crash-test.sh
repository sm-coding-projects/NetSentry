#!/bin/zsh
# P10: SIGKILL the development collector repeatedly while traffic flows; afterwards verify that the manifest
# and segments are consistent and that downtime was recorded as gaps. Requires `dev-agent.sh dev-install`.
set -uo pipefail
cd "$(dirname "$0")/.."
N=${1:-5}
STORE="$HOME/Library/Application Support/NetSentry/Store"
JOB="gui/$(id -u)/com.netsentry.collector.dev"
before=$(sqlite3 "$STORE/meta.sqlite" "select count(*) from segments where state='finalized'")
for i in $(seq 1 $N); do
  ./.build/debug/nsgen ipfix --port 4739 --scenario steady --seconds 8 --rate 300 --domain 9 >/dev/null &
  sleep $((3 + i % 4))
  pid=$(pgrep -f "NetSentryCollector.app/Contents/MacOS/NetSentryCollector" | head -1)
  kill -9 "$pid" 2>/dev/null && echo "iteration $i: killed pid $pid"
  wait
  sleep 7
  newpid=$(pgrep -f "NetSentryCollector.app/Contents/MacOS/NetSentryCollector" | head -1)
  echo "iteration $i: restarted as pid ${newpid:-NONE}"
done
sleep 65   # let the last minute flush
echo "--- manifest:"
sqlite3 "$STORE/meta.sqlite" "select state, count(*) from segments group by state; select count(*) from gaps where kind='collectorDown';"
echo "--- tmp leftovers: $(ls "$STORE/tmp" 2>/dev/null | wc -l | tr -d ' ')"
echo "--- segments after: $(sqlite3 "$STORE/meta.sqlite" "select count(*) from segments where state='finalized'") (before: $before)"
echo "--- recovery log lines:"
/usr/bin/log show --last 5m --info --style compact --predicate 'process == "NetSentryCollector" AND subsystem BEGINSWITH "com.netsentry"' 2>/dev/null | grep -iE "Recovery|integrity|corrupt|orphan|interrupted" | cut -c60-220 | tail -8
