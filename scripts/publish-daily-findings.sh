#!/bin/bash
# macOS LaunchAgent. Publish only the two reviewed artifacts for each UTC day.
set -euo pipefail
umask 077
export GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND='ssh -oBatchMode=yes -oConnectTimeout=10 -oForwardAgent=no -oClearAllForwardings=yes'
: "${FINDINGS_FIRST_DAY:?set the first UTC day to publish}"
: "${SECRETS_BLOCKLIST:?set the private blocklist path}"
[[ -r "$SECRETS_BLOCKLIST" && "$FINDINGS_FIRST_DAY" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]
trusted=$(cd "$(dirname "$0")/.." && pwd -P)
origin=git@github.com:caretak3r/attack-box.git
work=$(mktemp -d "${TMPDIR:-/tmp}/attackbox-daily.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
git clone --quiet --depth=1 --single-branch --branch main "$origin" "$work/repo"
cd "$work/repo"
# Never run new code from a remote checkout with the operator's SSH identity.
for file in scripts/daily-findings.py scripts/scan-secrets.sh .githooks/pre-commit .githooks/pre-push; do
  if [[ ! -f "$file" || -L "$file" ]] || ! cmp -s "$trusted/$file" "$file"; then
    echo "Publisher code changed: review and reinstall $file" >&2
    exit 1
  fi
done
git config core.hooksPath "$trusted/.githooks"
git config commit.gpgsign true
# The VPS retains seven UTC dates, including today. Close missed days oldest first.
failed=0
for n in 6 5 4 3 2 1; do
  day=$(date -u -v-"${n}"d +%F)
  [[ "$day" < "$FINDINGS_FIRST_DAY" ]] && continue
  report="findings/$day/README.md"
  map="findings/$day/map.json"
  if [[ "$n" != 1 && -f "$map" && -f "$report" ]] && ! grep -q '^Partial day\.' "$report"; then continue; fi
  if ! python3 -I scripts/daily-findings.py "$day" "$@"; then failed=1; continue; fi
  git add -- "$report" "$map"
  if git diff --cached --quiet -- "$report" "$map"; then
    printf '%s UTC: already published\n' "$day"
  else
    git commit --only -m "docs(findings): close $day UTC" -- "$report" "$map"
    git push origin HEAD:refs/heads/main
  fi
done
exit "$failed"
