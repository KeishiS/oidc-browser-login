#!/usr/bin/env bash
set -euo pipefail

# 中核crateがHTTP framework、データベース、特定IdP、製品固有crateへ依存しないことを、
# 依存一覧の完全一致で確かめます。依存を増やす場合はこの一覧の更新をreviewで判断します。

metadata="$(mktemp "${TMPDIR:-/tmp}/oidc-browser-login-metadata.XXXXXX.json")"
trap 'rm -f "$metadata"' EXIT
cargo metadata --locked --no-deps --format-version 1 >"$metadata"

jq -e '
  def normal_dependencies($package):
    [.packages[] | select(.name == $package) | .dependencies[] | select(.kind == null) | .name] | sort;
  normal_dependencies("oidc-browser-login") ==
    ["base64", "openidconnect", "serde", "serde_json", "thiserror", "tokio", "tracing", "url"] and
  normal_dependencies("oidc-browser-login-testkit") ==
    ["jsonwebtoken", "oidc-browser-login", "serde_json", "tokio", "wiremock"]
' "$metadata" >/dev/null

echo "crate間の依存境界を確認しました"
