#!/bin/zsh
# Regenerates NetSentry.xcodeproj from project.yml. Requires XcodeGen (brew install xcodegen).
set -euo pipefail
cd "$(dirname "$0")/.."
xcodegen generate --spec project.yml
