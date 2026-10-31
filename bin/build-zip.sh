#!/bin/sh
# Build dist/faable-auth.zip (root folder faable-auth/).
#   --wporg  wordpress.org build: drops the self-updater and marks the
#            distribution, as the plugin directory requires.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/faable-auth" "$OUT"
cp "$ROOT/faable-auth.php" "$ROOT/uninstall.php" "$ROOT/readme.txt" "$TMP/faable-auth/"
cp -R "$ROOT/src" "$TMP/faable-auth/src"

if [ "${1:-}" = "--wporg" ]; then
  rm "$TMP/faable-auth/src/Updater.php"
  sed -i.bak "s/define( 'FAABLE_AUTH_DISTRIBUTION', 'github' );/define( 'FAABLE_AUTH_DISTRIBUTION', 'wporg' );/" "$TMP/faable-auth/faable-auth.php"
  rm "$TMP/faable-auth/faable-auth.php.bak"
  grep -q "'wporg'" "$TMP/faable-auth/faable-auth.php"
  NAME=faable-auth-wporg.zip
else
  NAME=faable-auth.zip
fi

rm -f "$OUT/$NAME"
(cd "$TMP" && zip -qr "$OUT/$NAME" faable-auth)
echo "$OUT/$NAME"
