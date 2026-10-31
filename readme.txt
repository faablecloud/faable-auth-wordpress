=== Faable Auth ===
Contributors: faable
Tags: login, sso, openid connect, oidc, authentication
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Sign in to WordPress with Faable Auth (OpenID Connect). Roles come from Faable Auth, and headless front-ends use machine-to-machine tokens.

== Description ==

Faable Auth makes your site an OpenID Connect client of your Faable Auth tenant:

* **Sign in with Faable only.** wp-login.php shows a "Log in with Faable" button instead of the username and password form. Password resets, registration, XML-RPC authentication and Application Passwords are turned off.
* **Accounts without local passwords.** Users are created on their first login, without a usable local password.
* **Roles from Faable Auth, re-synced on every login.** Users get the WordPress role their Faable Auth role maps to (administrator, editor, author, contributor, subscriber by default; the map is configurable). A user without a mapped role gets no account and sees why.
* **Headless front-ends.** The REST API accepts Faable Auth machine-to-machine (client_credentials) access tokens instead of Basic Auth with an Application Password.
* **Emergency access from day one** (see below).

Works on any host, with any Faable Auth plan (including Free).

= Emergency access =

If Faable Auth cannot be reached, nobody can log in. There are two ways in, and you should know them before you need them:

1. **Break glass.** Add this line to `wp-config.php`:

    define( 'FAABLE_AUTH_BREAK_GLASS', true );

   The username and password form, "Lost your password?" and password resets come back, next to the Faable button. Remove the line once Faable Auth is back. Users created by the plugin have no local password: they use "Lost your password?" to set one, or an administrator sets it with `wp user update <user> --user_pass=<password>`.

2. **One-time login link.** With WP-CLI:

    wp faable-auth login-link <user>

   prints a URL that logs in as that user once, within 10 minutes. On Faable hosting, run it as a Task. Opening the URL shows a confirmation button, so link previews in chat apps do not use it up.

`wp faable-auth status` shows the current mode and configuration (never the secret).

= Configuration =

**On Faable hosting** nothing needs to be set and there is nothing to connect: when the site is installed, Faable creates its OIDC client in the project's Faable Auth tenant, gives the site these environment variables and loads the plugin as a must-use plugin from its image. While the site is hosted on Faable the plugin cannot be deactivated or disconnected: its settings page says "Managed by Faable" and shows the connection read-only. The role map, the headless (REST) options and federated logout stay editable.

* `FAABLE_AUTH_DOMAIN`: the tenant URL, e.g. `https://acme.auth.faable.link` (or its custom domain). It is the issuer of the tokens, without a trailing slash.
* `FAABLE_AUTH_CLIENT_ID`, `FAABLE_AUTH_CLIENT_SECRET`: the site's OIDC client in that tenant.

Optional: `FAABLE_AUTH_ROLE_MAP` (JSON or `faable_role = wp_role` lines), `FAABLE_AUTH_AUDIENCE` (an API whose ID tokens include roles), `FAABLE_AUTH_REST_AUDIENCE`, `FAABLE_AUTH_REST_USER`, `FAABLE_AUTH_REST_CLIENTS`, `FAABLE_AUTH_REST_SCOPE` (machine-to-machine REST), `FAABLE_AUTH_FEDERATED_LOGOUT`. Each can also be a PHP constant in `wp-config.php`. A value set this way wins over the settings page and shows there read-only.

**Anywhere else**, go to Settings → Faable Auth and press **Connect with Faable**. You log in to Faable, pick the project and the Auth tenant, and the site comes back connected. If you cannot use that, create a web client in your tenant with this redirect URI and paste the domain, client ID and secret in the manual section:

    https://<your-site>/wp-login.php?faable-auth=callback

Until the site is connected, the normal WordPress login stays on, so the administrator who connects it can log in.

= Roles =

The roles of a user are read from the ID token's `roles` claim when the site requests an audience (`FAABLE_AUTH_AUDIENCE`) whose API includes roles in ID tokens. Otherwise the plugin reads them from your tenant's Management API (`GET /user/:id/roles`) with a client_credentials token limited to `read:rolemembers`, cached for its lifetime (about one machine-to-machine token a day). If roles cannot be read, the login is refused.

Roles are managed in the project's Faable Auth tenant: being a member of the Faable project gives no role on the site.

= Headless front-ends (REST API) =

Set the token audience (an API identifier of your tenant) and the WordPress user the requests act as. A request with `Authorization: Bearer <token>` is accepted when the token is a client_credentials token of your tenant for that audience, from an allowed client and, if set, with the required scope. It gets the capabilities of that user, so give it the smallest role that works.

Application Passwords are off: move each front-end from Basic Auth to a client_credentials token before connecting the site.

= Developers =

Filters: `faable_auth_wp_role`, `faable_auth_authorize_params`, `faable_auth_rest_user_id`. Actions: `faable_auth_user_created`, `faable_auth_user_synced`, `faable_auth_login_failed`, `faable_auth_login_link_used`.

Multisite is not supported in this version.

== External services ==

This plugin connects to Faable services. It does nothing until it is configured.

* **Your Faable Auth tenant** (the domain you configure, e.g. `https://<tenant>.auth.faable.link`). When someone logs in, their browser is sent to the tenant's login page, and the site calls the tenant to read its configuration and signing keys, exchange the login code for tokens and read the user's roles. The site receives the user's ID, name, email and roles. When a REST request carries a Bearer token, the site may fetch the tenant's public signing keys.
* **Faable dashboard and platform tenant** (`https://dashboard.faable.com`, `https://faable.auth.faable.link`), only when an administrator presses "Connect with Faable": the browser goes to the dashboard with the site URL, and the site then exchanges a one-time code for its client credentials.
* **GitHub** (`https://api.github.com`), only in the build distributed through GitHub releases, to check for plugin updates. The wordpress.org build does not include this.

Faable terms of service: https://faable.com/docs/platform/terms-of-service — privacy policy: https://faable.com/docs/platform/privacy-policy

== Installation ==

1. Install and activate the plugin.
2. Settings → Faable Auth → Connect with Faable (not needed on Faable hosting).
3. Read the emergency access section above.

== Uninstall ==

Removing the plugin brings back the normal WordPress login. Users created by the plugin have no local password: each of them sets one with "Lost your password?".

== Changelog ==

= 0.1.0 =
* First version.
