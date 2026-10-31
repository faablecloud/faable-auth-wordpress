<?php
/**
 * Uninstall: remove the plugin's settings and caches.
 *
 * User links (faable_auth_sub meta) are kept on purpose: reinstalling the
 * plugin must find the same accounts. Users created by the plugin have no
 * usable local password; after uninstalling, they set one with
 * "Lost your password?".
 *
 * @package FaableAuth
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// On Faable hosting the plugin runs as a must-use plugin from the platform's
// image; deleting a copy the user also installed as a regular plugin must not
// wipe the settings (role map, REST options) the managed copy keeps using.
if ( defined( 'FAABLE_AUTH_MANAGED' ) && FAABLE_AUTH_MANAGED ) {
	return;
}

delete_option( 'faable_auth_settings' );
delete_site_transient( 'faable_auth_release' );
