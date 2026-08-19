#!/usr/bin/env bash
set -euo pipefail

unexpected="$(rg --files --hidden -g '*.md' -g '!.git/**' | rg -v '^AGENTS\.md$' || true)"
if [[ -n "$unexpected" ]]; then
  echo "人間向け文書はAsciiDocで記述してください:" >&2
  echo "$unexpected" >&2
  exit 1
fi

mapfile -d '' documents < <(git ls-files -z -- '*.adoc')
if [[ "${#documents[@]}" -eq 0 ]]; then
  echo "検査対象のAsciiDoc文書がありません" >&2
  exit 1
fi

for document in "${documents[@]}"; do
  adocweave check \
    --fail-on warning \
    --local-targets \
    --project-root . \
    "$document"
done

echo "AsciiDoc文書を検証しました: ${#documents[@]}件"
