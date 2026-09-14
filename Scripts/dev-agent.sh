#!/bin/zsh
# Development helper: register/unregister the collector LaunchAgent from the Debug build via SMAppService.
set -euo pipefail
cd "$(dirname "$0")/.."
APP="$PWD/build/DerivedData/Build/Products/Debug/NetSentry.app"
case "${1:-}" in
  register)   open -n -W -a "$APP" --args --register-collector ;;
  unregister) open -n -W -a "$APP" --args --unregister-collector ;;
  # After every rebuild the bundle's code identity changes and launchd refuses to spawn the old
  # registration (EX_CONFIG / "No such process"): unregister, wait for launchd, register again.
  # `open -n` starts a new instance even when a dashboard is already running; otherwise LaunchServices hands the
  # arguments to the running instance (which ignores them) and `-W` waits forever.
  reinstall)  echo "unregister:"; open -n -W -a "$APP" --args --unregister-collector; sleep 5; tail -1 ~/Library/Application\ Support/NetSentry/cli-result.txt
              launchctl bootout "gui/$(id -u)/com.netsentry.collector" 2>/dev/null || true; sleep 2   # clear a stale EX_CONFIG job
              for attempt in 1 2 3; do
                echo "register (attempt $attempt):"; open -n -W -a "$APP" --args --register-collector; sleep 5; tail -1 ~/Library/Application\ Support/NetSentry/cli-result.txt
                if launchctl print "gui/$(id -u)/com.netsentry.collector" 2>&1 | grep -q "state = running"; then
                  launchctl print "gui/$(id -u)/com.netsentry.collector" 2>&1 | grep -E "^\s*(state|pid)"; break
                fi
                # launchd sometimes keeps a stale job definition (EX_CONFIG loop); clear it and try again.
                echo "job not running; booting out and retrying"; launchctl bootout "gui/$(id -u)/com.netsentry.collector" 2>/dev/null || true; sleep 3
              done ;;
  # Development loop without SMAppService: a plain launchd agent pointing at the built collector.
  # SMAppService registration is the production path (verified); a rebuilt agent registered through it
  # is killed by a launch-constraint violation until BackgroundTaskManagement refreshes its record.
  dev-install)
              open -n -W -a "$APP" --args --unregister-collector 2>/dev/null || true; sleep 2
              launchctl bootout "gui/$(id -u)/com.netsentry.collector" 2>/dev/null || true
              # unregister turns collection off in the bootstrap config; turn it back on for the dev agent
              python3 -c "import json,os;p=os.path.expanduser('~/Library/Application Support/NetSentry/collector.json');c=json.load(open(p));c['collectionEnabled']=True;json.dump(c,open(p,'w'),indent=2)"
              PLIST="$HOME/Library/LaunchAgents/com.netsentry.collector.dev.plist"
              cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.netsentry.collector.dev</string>
  <key>Program</key><string>$APP/Contents/Library/NetSentryCollector.app/Contents/MacOS/NetSentryCollector</string>
  <key>MachServices</key><dict><key>com.netsentry.collector.xpc</key><true/></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>5</integer>
</dict></plist>
PL
              launchctl bootout "gui/$(id -u)/com.netsentry.collector.dev" 2>/dev/null || true; sleep 1
              launchctl bootstrap "gui/$(id -u)" "$PLIST" && sleep 3
              launchctl print "gui/$(id -u)/com.netsentry.collector.dev" 2>&1 | grep -E "^\s*(state|pid)" ;;
  dev-restart) launchctl kickstart -k "gui/$(id -u)/com.netsentry.collector.dev" && sleep 3
              launchctl print "gui/$(id -u)/com.netsentry.collector.dev" 2>&1 | grep -E "^\s*(state|pid)" ;;
  dev-uninstall)
              launchctl bootout "gui/$(id -u)/com.netsentry.collector.dev" 2>/dev/null || true
              rm -f "$HOME/Library/LaunchAgents/com.netsentry.collector.dev.plist"; echo removed ;;
  logs)       log show --predicate 'subsystem BEGINSWITH "com.netsentry"' --style compact --last "${2:-2m}" ;;
  stream)     log stream --predicate 'subsystem BEGINSWITH "com.netsentry"' --style compact ;;
  status)     launchctl print "gui/$(id -u)/com.netsentry.collector" 2>&1 | head -30 ;;
  *) echo "usage: $0 register|unregister|reinstall|dev-install|dev-restart|dev-uninstall|logs [window]|stream|status"; exit 2 ;;
esac
