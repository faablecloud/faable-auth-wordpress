<?php
/**
 * Plugin Name:       Faable Auth
 * Plugin URI:        https://github.com/faablecloud/faable-auth-wordpress
 * Description:       Sign in to WordPress with Faable Auth (OpenID Connect). Replaces the password login, syncs roles on every login and accepts Faable machine-to-machine tokens on the REST API.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Faable
 * Author URI:        https://faable.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       faable-auth
 *
 * @package FaableAuth
 */

defined( 'ABSPATH' ) || exit;

// Loaded twice (e.g. as a regular plugin AND required by a host's
// must-use loader): the first copy wins.
if ( defined( 'FAABLE_AUTH_VERSION' ) ) {
	return;
}

define( 'FAABLE_AUTH_VERSION', '0.1.0' );
define( 'FAABLE_AUTH_FILE', __FILE__ );
// 'github' = this build updates itself from GitHub releases (src/Updater.php).
// The wordpress.org build (bin/build-zip.sh --wporg) rewrites it to 'wporg'.
define( 'FAABLE_AUTH_DISTRIBUTION', 'github' );

foreach ( array( 'Jwt', 'Pkce', 'RoleMapper', 'BreakGlass', 'Crypto', 'Config', 'Oidc', 'LoginLink', 'Login', 'Rest', 'Admin' ) as $faable_auth_class ) {
	require_once __DIR__ . '/src/' . $faable_auth_class . '.php';
}
unset( $faable_auth_class );

// Nothing here needs an activation hook: the plugin also works when a host
// loads it as a must-use plugin, where activation never runs.
add_action(
	'plugins_loaded',
	static function () {
		FaableAuth\Login::init();
		FaableAuth\Rest::init();
		if ( is_admin() ) {
			FaableAuth\Admin::init();
		}
		if ( 'github' === FAABLE_AUTH_DISTRIBUTION && is_readable( __DIR__ . '/src/Updater.php' ) ) {
			require_once __DIR__ . '/src/Updater.php';
			FaableAuth\Updater::init();
		}
	}
);

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once __DIR__ . '/src/Cli.php';
	WP_CLI::add_command( 'faable-auth', 'FaableAuth\\Cli' );
}
