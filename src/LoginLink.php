<?php
/**
 * One-time, short-lived login links: the emergency way in that needs no
 * password and no Faable Auth. Created only from the server side
 * (`wp faable-auth login-link <user>`; on Faable hosting, from a Task).
 *
 * The link opens a confirmation page and the login happens on its POST, so a
 * chat app or mail scanner that previews the URL does not burn it.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || defined( 'FAABLE_AUTH_TESTING' ) || exit;

/**
 * Login links.
 */
final class LoginLink {

	const TTL  = 600;
	const META = 'faable_auth_login_link';

	/**
	 * The record stored for a new link (pure).
	 *
	 * @param string $token Raw token.
	 * @param int    $now   Time.
	 */
	public static function record( string $token, int $now ): array {
		return array(
			'hash'    => hash( 'sha256', $token ),
			'expires' => $now + self::TTL,
		);
	}

	/**
	 * Whether a token matches a stored record (pure).
	 *
	 * @param mixed  $record Stored record.
	 * @param string $token  Presented token.
	 * @param int    $now    Time.
	 */
	public static function matches( $record, string $token, int $now ): bool {
		if ( ! is_array( $record ) || empty( $record['hash'] ) || empty( $record['expires'] ) || '' === $token ) {
			return false;
		}
		if ( (int) $record['expires'] < $now ) {
			return false;
		}
		return hash_equals( (string) $record['hash'], hash( 'sha256', $token ) );
	}

	/**
	 * Create a link for a user. Replaces any previous unused link.
	 *
	 * @param \WP_User $user        User.
	 * @param string   $redirect_to Optional landing URL.
	 */
	public static function create( \WP_User $user, string $redirect_to = '' ): string {
		$token = Pkce::random();
		$rec   = self::record( $token, time() );
		if ( '' !== $redirect_to ) {
			$rec['redirect_to'] = esc_url_raw( $redirect_to );
		}
		update_user_meta( $user->ID, self::META, $rec );
		return add_query_arg(
			array(
				'faable-auth' => 'link',
				'u'           => $user->ID,
				't'           => $token,
			),
			wp_login_url()
		);
	}

	/**
	 * Handle `wp-login.php?faable-auth=link`.
	 */
	public static function handle(): void {
		// phpcs:disable WordPress.Security.NonceVerification -- the single-use token is the credential.
		$user_id = isset( $_REQUEST['u'] ) ? absint( $_REQUEST['u'] ) : 0;
		$token   = isset( $_REQUEST['t'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['t'] ) ) : '';
		$is_post = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'];
		// phpcs:enable
		$user   = $user_id ? get_user_by( 'id', $user_id ) : false;
		$record = $user ? get_user_meta( $user->ID, self::META, true ) : null;
		$valid  = $user && self::matches( $record, $token, time() );

		nocache_headers();
		header( 'Referrer-Policy: no-referrer' );

		if ( ! $valid ) {
			status_header( 403 );
			self::page( '<p>' . esc_html__( 'This login link is invalid, already used or expired. Links last 10 minutes and work once. Create a new one with: wp faable-auth login-link <user>', 'faable-auth' ) . '</p>' );
		}

		if ( ! $is_post ) {
			self::page(
				'<form method="post" action="' . esc_url( wp_login_url() ) . '">'
				. '<p>' . esc_html(
					sprintf(
						/* translators: %s: user login */
						__( 'Emergency login as %s.', 'faable-auth' ),
						$user->user_login
					)
				) . '</p>'
				. '<input type="hidden" name="faable-auth" value="link" />'
				. '<input type="hidden" name="u" value="' . esc_attr( (string) $user->ID ) . '" />'
				. '<input type="hidden" name="t" value="' . esc_attr( $token ) . '" />'
				. '<p class="submit"><button type="submit" class="button button-primary button-large">' . esc_html__( 'Log in', 'faable-auth' ) . '</button></p>'
				. '</form>'
			);
		}

		delete_user_meta( $user->ID, self::META ); // Single use.
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		do_action( 'wp_login', $user->user_login, $user );
		do_action( 'faable_auth_login_link_used', $user );
		error_log( sprintf( 'faable-auth: emergency login link used for user %d', $user->ID ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log

		$redirect = is_array( $record ) && ! empty( $record['redirect_to'] ) ? (string) $record['redirect_to'] : admin_url();
		wp_safe_redirect( wp_validate_redirect( $redirect, admin_url() ) );
		exit;
	}

	/**
	 * Render a minimal login-styled page and exit.
	 *
	 * @param string $html Escaped HTML body.
	 */
	private static function page( string $html ): void {
		if ( function_exists( 'login_header' ) ) {
			login_header( __( 'Emergency login', 'faable-auth' ) );
		}
		echo '<div id="loginform">' . $html . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped by the callers.
		if ( function_exists( 'login_footer' ) ) {
			login_footer();
		}
		exit;
	}
}
