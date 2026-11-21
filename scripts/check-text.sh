#!/usr/bin/env bash
# Fails when a tracked text file breaks the repository text rules:
# no em dash, en dash, right arrow or middle dot characters, and no
# tooling attribution words. Binary files, vendor/, spec/vectors/*.json
# and this script itself are skipped.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export LC_ALL=C

em_dash=$(printf '\342\200\224')
en_dash=$(printf '\342\200\223')
arrow=$(printf '\342\206\222')
middot=$(printf '\302\267')
chars="${em_dash}|${en_dash}|${arrow}|${middot}"
words='Co-Authored-By|ChatGPT|Claude|copilot'

status=0

while IFS= read -r -d '' file; do
  case "$file" in
    vendor/*|scripts/check-text.sh) continue ;;
    spec/vectors/*.json) continue ;;
  esac
  [ -f "$file" ] || continue

  if grep -I -n -E "$chars" -- "$file" > /dev/null 2>&1; then
    grep -I -n -E "$chars" -- "$file" | sed "s|^|$file:|" >&2
    echo "check-text: $file contains a forbidden character (U+2014, U+2013, U+2192 or U+00B7)" >&2
    status=1
  fi

  if grep -I -n -i -w -E "$words" -- "$file" > /dev/null 2>&1; then
    grep -I -n -i -w -E "$words" -- "$file" | sed "s|^|$file:|" >&2
    echo "check-text: $file contains a forbidden word" >&2
    status=1
  fi
done < <(git ls-files -z)

if [ "$status" -eq 0 ]; then
  echo "check-text: ok"
fi
exit "$status"
