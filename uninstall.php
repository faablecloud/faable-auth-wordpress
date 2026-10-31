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

delete_option( 'faable_auth_settings' );
delete_site_transient( 'faable_auth_release' );
