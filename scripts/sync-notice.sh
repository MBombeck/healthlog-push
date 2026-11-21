#!/usr/bin/env bash
# Copies the served legal texts (the single source, internal/notice/) to docs/ for readers of the
# repository. TestLegalTextsInSync fails while the copies differ.
set -euo pipefail
cd "$(dirname "$0")/.."
for name in privacy.md terms.md; do
  cp internal/notice/"$name" docs/"$name"
done
