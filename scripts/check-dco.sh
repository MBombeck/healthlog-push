#!/usr/bin/env bash
# Fails when a commit in the given range carries no Signed-off-by line by its author (Developer Certificate
# of Origin 1.1, https://developercertificate.org/). Merge commits and commits by bots are skipped.
# Usage: scripts/check-dco.sh <base>..<head>
set -euo pipefail

range="${1:?usage: scripts/check-dco.sh <base>..<head>}"
status=0
count=0

while read -r sha; do
  [ -n "$sha" ] || continue
  name=$(git log -1 --format='%an' "$sha")
  email=$(git log -1 --format='%ae' "$sha")
  case "$name" in
    *"[bot]") continue ;;
  esac
  count=$((count + 1))
  if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qiF "<${email}>"; then
    echo "check-dco: commit ${sha} has no Signed-off-by line by its author <${email}>" >&2
    status=1
  fi
done < <(git rev-list --no-merges "$range")

if [ "$status" -eq 0 ]; then
  echo "check-dco: ok (${count} commits)"
else
  echo "check-dco: add the line with 'git commit -s' (or 'git rebase --signoff <base>' for several commits)" >&2
fi
exit "$status"
