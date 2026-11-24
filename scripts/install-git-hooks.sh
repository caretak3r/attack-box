#!/usr/bin/env bash
# Point this checkout at the tracked hooks in .githooks/.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit scripts/scan-secrets.sh

echo "core.hooksPath=.githooks"
echo "pre-commit will run scripts/scan-secrets.sh staged"
