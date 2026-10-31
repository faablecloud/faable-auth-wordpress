# Faable Auth for WordPress

WordPress plugin that makes a site sign in through [Faable Auth](https://faable.com) (OpenID Connect,
Authorization Code + PKCE). The user-facing documentation is in [`readme.txt`](readme.txt).

## Emergency access

If Faable Auth is unreachable nobody can log in. Two ways in:

```php
// wp-config.php: brings back the password form (remove it afterwards)
define( 'FAABLE_AUTH_BREAK_GLASS', true );
```

```sh
# one-time login URL, valid 10 minutes (on Faable hosting: as a Task)
wp faable-auth login-link <user>
```

## Managed mode (Faable hosting)

The WordPress blueprint overlay ships this plugin in its image and loads it as a must-use plugin when
the platform has configured the site (`FAABLE_AUTH_CLIENT_ID` in the environment), defining
`FAABLE_AUTH_MANAGED` and `FAABLE_AUTH_DISABLE_UPDATER`. With `FAABLE_AUTH_MANAGED`:

- domain, client id and secret come only from the environment/constants (a stored option is ignored);
- the settings page shows "Managed by Faable", with no Connect/Disconnect and the connection read-only;
  the `faable_auth_connect*`/`faable_auth_disconnect` handlers answer 403;
- role map (unless `FAABLE_AUTH_ROLE_MAP` is set), REST M2M options and federated logout stay editable;
- deleting a regular copy of the plugin does not wipe the settings (`uninstall.php`).

## Layout

| File | What |
|---|---|
| `faable-auth.php` | plugin header, bootstrap |
| `src/Login.php` | wp-login.php flow, provisioning, role sync, password lockdown |
| `src/Oidc.php` | discovery, JWKS, token endpoint, Management API roles |
| `src/Jwt.php`, `src/Pkce.php`, `src/RoleMapper.php`, `src/BreakGlass.php`, `src/Crypto.php` | pure logic, unit-tested |
| `src/LoginLink.php`, `src/Cli.php` | one-time links, `wp faable-auth` |
| `src/Rest.php` | Bearer M2M tokens on the REST API |
| `src/Admin.php` | settings page, "Connect with Faable" |
| `src/Updater.php` | GitHub releases updater (not in the wordpress.org build) |

## Tests

```sh
docker run --rm -v "$PWD":/src -w /src php:8.4-cli php tests/run.php   # unit
sh tests/e2e/run.sh                                                   # WordPress + MariaDB + fake tenant
```

## Build

```sh
sh bin/build-zip.sh          # dist/faable-auth.zip for GitHub releases (with the updater)
sh bin/build-zip.sh --wporg  # wordpress.org build: no updater, FAABLE_AUTH_DISTRIBUTION = 'wporg'
```

A GitHub release must be tagged with the version (`v0.1.0`) and carry `faable-auth.zip` as an asset.

License: GPL-2.0-or-later.
