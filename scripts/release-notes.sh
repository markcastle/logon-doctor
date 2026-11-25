#!/usr/bin/env bash
# Print the CHANGELOG.md section for one version, e.g. `scripts/release-notes.sh 0.1.0`.
# Exits non-zero if that version has no section, which is how CI refuses to publish a
# release nobody has written notes for.
set -euo pipefail
version="${1:?usage: release-notes.sh <version>}"
notes=$(awk -v v="$version" '
  /^## \[/ { printing = (index($0, "## [" v "]") == 1); next }
  /^\[[^]]+\]: / { next }          # link definitions at the bottom of the file
  printing { print }
' CHANGELOG.md)
# Trim leading and trailing blank lines.
notes=$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')
if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "CHANGELOG.md has no section for version $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
