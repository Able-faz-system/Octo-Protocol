#!/usr/bin/env bash
# Fails if any GitHub Actions `uses:` is not pinned to a full commit SHA with a version comment.
#
# Allowed:  owner/repo[/path]@<40-hex-sha> # vX.Y.Z
#           ./local-action
#           docker://image@sha256:<64-hex>
# Usage:    scripts/check-pinned-actions.sh [dir ...]   (default: .github)
set -euo pipefail

dirs=("${@:-.github}")
pinned='^[^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*[^[:space:]]+'
status=0

while IFS= read -r -d '' file; do
  while IFS=: read -r line text; do
    ref=$(sed -E 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*//; s/^["'\'']//; s/["'\'']([[:space:]]|$)/\1/' <<<"$text")
    case "$ref" in
      ./*) continue ;;
      docker://*@sha256:*) [[ "$ref" =~ @sha256:[0-9a-f]{64} ]] && continue ;;
      *) [[ "$ref" =~ $pinned ]] && continue ;;
    esac
    echo "::error file=$file,line=$line::unpinned action: $ref (pin to a full commit SHA with a '# vX.Y.Z' comment)"
    status=1
  done < <(grep -nE '^[[:space:]]*(-[[:space:]]*)?uses:' "$file" || true)
done < <(find "${dirs[@]}" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)

[[ $status -eq 0 ]] && echo "All GitHub Actions are pinned to commit SHAs."
exit "$status"
