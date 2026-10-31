#!/bin/sh
# End-to-end test: a real WordPress (wordpress:php8.4-apache + MariaDB) with
# the plugin, against the fake tenant in idp.php. Needs Docker only.
#
#   sh tests/e2e/run.sh          # leaves nothing behind
#   KEEP=1 sh tests/e2e/run.sh   # keep the containers to poke around
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NET=faable-auth-e2e
P=faable-auth-e2e

remove_all() {
  docker rm -f "$P-wp" "$P-db" "$P-idp" >/dev/null 2>&1 || true
  docker volume rm "$P-html" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup() { [ "${KEEP:-}" = 1 ] || remove_all; }
trap cleanup EXIT
remove_all

docker network create "$NET" >/dev/null
docker volume create "$P-html" >/dev/null

docker run -d --name "$P-db" --network "$NET" --network-alias db \
  -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=wp -e MARIADB_USER=wp -e MARIADB_PASSWORD=wp \
  mariadb:11.4 >/dev/null

docker run -d --name "$P-idp" --network "$NET" --network-alias idp.test \
  -v "$ROOT/tests/e2e:/idp:ro" php:8.4-cli php -S 0.0.0.0:8080 /idp/idp.php >/dev/null

# The same wp-config extras for the site and for wp-cli: without them a `wp`
# command sees an http:// tenant as unconfigured and skips every hook.
CONFIG_EXTRA="define('FAABLE_AUTH_ALLOW_INSECURE_HTTP', true); define('FAABLE_AUTH_CONNECT_URL', 'http://idp.test:8080/connect/wordpress'); define('FAABLE_AUTH_CONNECT_EXCHANGE_URL', 'http://idp.test:8080/connect/exchange');"

docker run -d --name "$P-wp" --network "$NET" --network-alias wp.test \
  -v "$P-html:/var/www/html" \
  -v "$ROOT:/var/www/html/wp-content/plugins/faable-auth:ro" \
  -e WORDPRESS_DB_HOST=db -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp \
  -e WORDPRESS_CONFIG_EXTRA="$CONFIG_EXTRA" \
  wordpress:php8.4-apache >/dev/null

cli() {
  docker run --rm --network "$NET" --user 33:33 -e HOME=/tmp \
    -v "$P-html:/var/www/html" \
    -v "$ROOT:/var/www/html/wp-content/plugins/faable-auth:ro" \
    -v "$ROOT/tests/e2e:/e2e:ro" \
    -e WORDPRESS_DB_HOST=db -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp \
    -e WORDPRESS_CONFIG_EXTRA="$CONFIG_EXTRA" \
    wordpress:cli-php8.4 "$@"
}

echo "waiting for WordPress and the database..."
for i in $(seq 1 60); do
  if cli wp --path=/var/www/html db check >/dev/null 2>&1; then break; fi
  sleep 2
done

cli wp --path=/var/www/html core install --url=http://wp.test --title=E2E \
  --admin_user=admin --admin_password=admin-pw --admin_email=admin@example.com --skip-email >/dev/null
cli wp --path=/var/www/html plugin activate faable-auth
cli php /e2e/browser.php
