<p align="center">
  <a href="https://faable.com/docs/auth/integrations/wordpress">
    <img src=".github/assets/cover.png" alt="Faable Auth for WordPress: sign in to WordPress with Faable Auth" width="100%">
  </a>
</p>

# Faable Auth for WordPress

A WordPress plugin that signs users in through [Faable Auth](https://faable.com/docs/auth) with
OpenID Connect (Authorization Code + PKCE). Who can get in, and with which role, is decided in your
Auth tenant.

- **Sign in with Faable only.** `wp-login.php` shows a **Log in with Faable** button, and password
  logins, resets, registration and XML-RPC authentication are turned off.
- **Roles from Faable Auth,** synced on every login.
- **Headless front-ends.** The REST API accepts machine-to-machine access tokens.
- **Emergency access** from day one, in case Faable Auth cannot be reached.

It works on any host and with any Faable Auth plan, including Free. It needs WordPress 6.4 or later
and PHP 8.1 or later. Multisite is not supported yet.

📚 Documentation: **[faable.com/docs/auth/integrations/wordpress](https://faable.com/docs/auth/integrations/wordpress)**.
The plugin's own reference is in [`readme.txt`](readme.txt).

## Install

1. Download `faable-auth.zip` from the [latest release](https://github.com/faablecloud/faable-auth-wordpress/releases/latest).
2. In WordPress, go to **Plugins → Add New → Upload Plugin**, then install and activate it.
3. Go to **Settings → Faable Auth** and press **Connect with Faable**.

On [Faable Deploy](https://faable.com/docs/deploy) the WordPress image ships the plugin already
connected, so there is nothing to install.

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

A GitHub release must be tagged with the version (`v1.0.0`) and carry `faable-auth.zip` as an asset.

## Support

- **Documentation:** [faable.com/docs](https://faable.com/docs)
- **Help with your account or deployments:** [support@faable.com](mailto:support@faable.com) or the
  [support page](https://faable.com/docs/platform/support)
- **Bugs and feature requests:** [open an issue](https://github.com/faablecloud/faable-auth-wordpress/issues)
- **Security issues:** report them privately to [support@faable.com](mailto:support@faable.com),
  not in a public issue

## License

[GPL-2.0-or-later](LICENSE) © Faable Cloud SLU
