#!/usr/bin/env bash
# Relative Markdown link checker for the public tree: every `[text](path)` whose
# target is a repository path must exist. External URLs and anchors are not checked.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
while IFS=: read -r file line link; do
  target=${link%%#*}
  [ -z "$target" ] && continue
  case "$target" in http://*|https://*|mailto:*|ftp://*) continue ;; esac
  dir=$(dirname "$file")
  if [ ! -e "$dir/$target" ] && [ ! -e "$target" ]; then
    echo "check-links: $file:$line -> $link (missing)" >&2; fail=1
  fi
done < <(git ls-files '*.md' ':!docs/historical' ':!RUNBOOK-INTERNAL.md' ':!RELEASE-*.md' ':!.planning' ':!docs/internal' \
         | xargs grep -noE '\]\(([^)<>[:space:]]+)\)' 2>/dev/null \
         | sed -E 's/\]\((.*)\)$/\1/')
[ "$fail" -eq 0 ] && echo "check-links: ok" || { echo "check-links: FAILED" >&2; exit 1; }
