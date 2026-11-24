#!/usr/bin/env bash
# scan-secrets.sh - block credentials and private identifiers from a commit.
#
# Usage:
#   scripts/scan-secrets.sh staged     # files staged in the index (pre-commit)
#   scripts/scan-secrets.sh tree       # every tracked file (CI, release gate)
#   scripts/scan-secrets.sh path ...   # explicit files or directories
#
# Exit 0 when clean, 1 when a match is found. Matches print as
# "path:line: rule" and never echo the value itself.
#
# Optional private blocklist: secrets/blocklist.txt (gitignored). One literal
# string per line, 8+ characters, '#' starts a comment. Use it for host IPs,
# account IDs and other identifiers that must never be published. The public
# tree has no copy of that file.
#
# gitleaks also runs when installed; a gitleaks finding fails the same way.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

mode=${1:-staged}
shift || true

blocklist=${SECRETS_BLOCKLIST:-secrets/blocklist.txt}
findings=0

# Test fixtures and templates embed synthetic credentials on purpose.
is_fixture() {
  case "$1" in
    internal/secret/*|*/internal/secret/*|*/testdata/*) return 0 ;;
    *.example|*.sample) return 0 ;;
    *_test.go|test_*.py|*/test-*.sh|*/test-*.bats) return 0 ;;
    .gitleaks.toml|scripts/scan-secrets.sh) return 0 ;;
    *) return 1 ;;
  esac
}

# rule_name<TAB>extended-regexp
rules=(
  $'private-key\t-----BEGIN [A-Z ]*PRIVATE KEY-----'
  $'newrelic-user-key\tNRAK-[A-Za-z0-9]{20,}'
  $'newrelic-ingest-key\tNRII-[A-Za-z0-9_-]{20,}'
  $'newrelic-query-key\tNRIQ-[A-Za-z0-9_-]{20,}'
  $'newrelic-browser-key\tNRJS-[a-f0-9]{16,}'
  $'github-token\t(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|gh[ousr]_[A-Za-z0-9]{30,})'
  $'aws-access-key\tAKIA[0-9A-Z]{16}'
  $'google-api-key\tAIza[0-9A-Za-z_-]{35}'
  $'slack-token\txox[baprs]-[A-Za-z0-9-]{10,}'
  $'openai-key\tsk-(proj-)?[A-Za-z0-9_-]{32,}'
  $'vultr-key\tVULTR_API_KEY[[:space:]]*=[[:space:]]*["'"'"']?[A-Za-z0-9]{20,}'
  $'assigned-secret\t(api[_-]?key|secret[_-]?key|license[_-]?key|access[_-]?token|client[_-]?secret)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_/+.-]{24,}["'"'"']'
  $'url-credential\t[a-z][a-z0-9+.-]*://[^/[:space:]:@]+:[^/[:space:]:@]{8,}@'
)

# report_matches FILE GREP_ARGS...
report_matches() {
  local file=$1 rule=$2 line _
  shift 2
  while IFS=: read -r line _; do
    [ -n "$line" ] || continue
    printf '%s:%s: %s blocked\n' "$file" "$line" "$rule"
    findings=$((findings + 1))
  done < <(LC_ALL=C grep -niE "$@" "$file" 2>/dev/null || true)
}

scan_file() {
  local file=${1#./} entry rule pattern line _
  [ -f "$file" ] || return 0
  # Skip binary files; credentials live in text.
  grep -Iq . "$file" 2>/dev/null || return 0

  if ! is_fixture "$file"; then
    for entry in "${rules[@]}"; do
      rule=${entry%%$'\t'*}
      pattern=${entry#*$'\t'}
      report_matches "$file" "$rule" -e "$pattern"
    done
  fi

  # The private blocklist applies to every file, fixtures included.
  if [ -f "$blocklist" ]; then
    while IFS= read -r needle; do
      case "$needle" in ''|'#'*) continue ;; esac
      [ ${#needle} -ge 8 ] || continue
      report_matches "$file" "private-identifier" -F -e "$needle"
    done < "$blocklist"
  fi
}

scan_list() {
  local file
  while IFS= read -r file; do
    [ -n "$file" ] && scan_file "$file"
  done
}

case "$mode" in
  staged)
    staged=$(git diff --cached --name-only --diff-filter=ACMR)
    [ -n "$staged" ] || exit 0
    scan_list < <(printf '%s\n' "$staged")
    ;;
  tree)
    scan_list < <(git ls-files)
    ;;
  path)
    [ $# -gt 0 ] || { echo "usage: $0 path FILE..." >&2; exit 2; }
    for target in "$@"; do
      if [ -d "$target" ]; then
        scan_list < <(find "$target" -type f -print)
      else
        scan_file "$target"
      fi
    done
    ;;
  *)
    echo "usage: $0 {staged|tree|path}" >&2
    exit 2
    ;;
esac

if command -v gitleaks >/dev/null 2>&1 && [ -f .gitleaks.toml ]; then
  if [ "$mode" = staged ]; then
    gitleaks protect --staged --no-banner --redact -c .gitleaks.toml >/dev/null 2>&1 || {
      echo "gitleaks reported one or more staged findings" >&2
      findings=$((findings + 1))
    }
  else
    gitleaks detect --no-git --source . --no-banner --redact -c .gitleaks.toml >/dev/null 2>&1 || {
      echo "gitleaks reported one or more findings" >&2
      findings=$((findings + 1))
    }
  fi
fi

if [ "$findings" -ne 0 ]; then
  cat >&2 <<'EOF'

Blocked: this change contains a credential or a private identifier.
Remove the value, load it from the environment at runtime, or move it to
secrets/ (gitignored). If it is a real credential, rotate it first.
EOF
  exit 1
fi

exit 0
