<?php
/**
 * Optional self-hosted updates from GitHub releases of
 * faablecloud/faable-auth-wordpress.
 *
 * Off when:
 *  - the plugin is a wordpress.org build (FAABLE_AUTH_DISTRIBUTION is 'wporg';
 *    bin/build-zip.sh --wporg also leaves this file out of the zip), or
 *  - FAABLE_AUTH_DISABLE_UPDATER is true (Faable hosting ships the plugin in
 *    the image and updates it there), or
 *  - the plugin is not a regular plugin (loaded as a must-use plugin).
 *
 * A release must carry an asset named `faable-auth.zip` whose root folder is
 * `faable-auth/`. The tag is the version (`v1.2.3` or `1.2.3`).
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * GitHub releases updater.
 */
final class Updater {

	const REPO      = 'faablecloud/faable-auth-wordpress';
	const ASSET     = 'faable-auth.zip';
	const CACHE_KEY = 'faable_auth_release';

	/**
	 * Register hooks when enabled.
	 */
	public static function init(): void {
		if ( 'github' !== FAABLE_AUTH_DISTRIBUTION ) {
			return;
		}
		if ( defined( 'FAABLE_AUTH_DISABLE_UPDATER' ) && FAABLE_AUTH_DISABLE_UPDATER ) {
			return;
		}
		if ( 0 !== strpos( wp_normalize_path( FAABLE_AUTH_FILE ), wp_normalize_path( WP_PLUGIN_DIR ) ) ) {
			return;
		}
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'inject' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'info' ), 10, 3 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'flush' ), 10, 0 );
	}

	/**
	 * Latest release, cached 6 h.
	 *
	 * @return array|null {version, package, url, body}
	 */
	public static function latest(): ?array {
		$cached = get_site_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			return $cached['version'] ? $cached : null;
		}
		$res  = wp_remote_get(
			'https://api.github.com/repos/' . self::REPO . '/releases/latest',
			array(
				'timeout' => 10,
				'headers' => array( 'Accept' => 'application/vnd.github+json' ),
			)
		);
		$data = is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ? null : json_decode( (string) wp_remote_retrieve_body( $res ), true );
		$out  = array( 'version' => '' );
		if ( is_array( $data ) && ! empty( $data['tag_name'] ) && empty( $data['draft'] ) && empty( $data['prerelease'] ) ) {
			foreach ( (array) ( $data['assets'] ?? array() ) as $asset ) {
				if ( is_array( $asset ) && self::ASSET === ( $asset['name'] ?? '' ) && ! empty( $asset['browser_download_url'] ) ) {
					$out = array(
						'version' => ltrim( (string) $data['tag_name'], 'vV' ),
						'package' => esc_url_raw( (string) $asset['browser_download_url'] ),
						'url'     => esc_url_raw( (string) ( $data['html_url'] ?? '' ) ),
						'body'    => (string) ( $data['body'] ?? '' ),
					);
				}
			}
		}
		set_site_transient( self::CACHE_KEY, $out, 6 * HOUR_IN_SECONDS );
		return $out['version'] ? $out : null;
	}

	/**
	 * Add the update to the plugins transient.
	 *
	 * @param mixed $transient Transient.
	 */
	public static function inject( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		$rel = self::latest();
		if ( ! $rel || ! version_compare( $rel['version'], FAABLE_AUTH_VERSION, '>' ) ) {
			return $transient;
		}
		$basename                          = plugin_basename( FAABLE_AUTH_FILE );
		$transient->response[ $basename ] = (object) array(
			'slug'         => 'faable-auth',
			'plugin'       => $basename,
			'new_version'  => $rel['version'],
			'package'      => $rel['package'],
			'url'          => $rel['url'],
			'requires_php' => '8.1',
		);
		return $transient;
	}

	/**
	 * "View details" modal.
	 *
	 * @param mixed  $result Result.
	 * @param string $action Action.
	 * @param object $args   Args.
	 */
	public static function info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! is_object( $args ) || ( $args->slug ?? '' ) !== 'faable-auth' ) {
			return $result;
		}
		$rel = self::latest();
		if ( ! $rel ) {
			return $result;
		}
		return (object) array(
			'name'          => 'Faable Auth',
			'slug'          => 'faable-auth',
			'version'       => $rel['version'],
			'download_link' => $rel['package'],
			'homepage'      => $rel['url'],
			'requires_php'  => '8.1',
			'sections'      => array( 'changelog' => wpautop( esc_html( $rel['body'] ) ) ),
		);
	}

	/**
	 * Drop the cache after an update.
	 */
	public static function flush(): void {
		delete_site_transient( self::CACHE_KEY );
	}
}
