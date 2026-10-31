#!/usr/bin/env bash
set -euo pipefail
dest="$RUNNER_TEMP/cli"
mkdir -p "$dest"
fetch() {
  local name="$1" url="$2" want="$3" out="$dest/$1.tgz"
  curl --fail --silent --show-error --location --proto '=https' --max-filesize 400000000 -o "$out" "$url"
  local got="sha512-$(openssl dgst -sha512 -binary "$out" | base64 -w0)"
  if [ "$got" != "$want" ]; then echo "::error::integrity mismatch for $name"; exit 1; fi
  mkdir "$dest/$name"
  tar -xzf "$out" -C "$dest/$name" --no-same-owner
}
fetch claude "https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-${CLAUDE_VERSION}.tgz" "$CLAUDE_SHA512"
fetch codex "https://registry.npmjs.org/@openai/codex/-/codex-${CODEX_VERSION}-linux-x64.tgz" "$CODEX_SHA512"
claude_bin="$dest/claude/package/claude"
codex_bin="$dest/codex/package/vendor/x86_64-unknown-linux-musl/bin/codex"
test -f "$claude_bin" && test -f "$codex_bin"
chmod 0755 "$claude_bin" "$codex_bin"
sha256sum "$claude_bin" "$codex_bin"
echo "CLAUDE_BIN=$claude_bin" >> "$GITHUB_ENV"
echo "CODEX_BIN=$codex_bin" >> "$GITHUB_ENV"
