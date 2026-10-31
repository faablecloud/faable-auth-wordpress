<?php
/**
 * Bearer M2M tokens on the REST API, for headless front-ends (Next.js…)
 * that today use Basic Auth with an Application Password.
 *
 * A request with `Authorization: Bearer <jwt>` is authenticated when the
 * token is a client_credentials token of THIS tenant (signature against the
 * tenant JWKS, issuer = tenant, `aud` = FAABLE_AUTH_REST_AUDIENCE, `sub` =
 * its own client_id), the client is allowed and, if configured, it carries
 * the required scope. It then acts as the configured WordPress user
 * (FAABLE_AUTH_REST_USER), so its capabilities are that user's.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * REST authentication.
 */
final class Rest {

	/** @var \WP_Error|null Error to report through rest_authentication_errors. */
	private static $error = null;

	/** @var int|null User authenticated by a token in this request. */
	private static $user_id = null;

	/**
	 * Register hooks.
	 */
	public static function init(): void {
		if ( '' === Config::get( 'FAABLE_AUTH_REST_AUDIENCE' ) || '' === Config::domain() ) {
			return;
		}
		add_filter( 'determine_current_user', array( __CLASS__, 'determine_current_user' ), 30 );
		add_filter( 'rest_authentication_errors', array( __CLASS__, 'rest_authentication_errors' ), 90 );
	}

	/**
	 * The bearer token of the request, if any.
	 */
	private static function bearer(): string {
		$h = '';
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $k ) {
			if ( ! empty( $_SERVER[ $k ] ) ) {
				$h = sanitize_text_field( wp_unslash( $_SERVER[ $k ] ) );
				break;
			}
		}
		if ( '' === $h && function_exists( 'getallheaders' ) ) {
			foreach ( (array) getallheaders() as $name => $value ) {
				if ( 'authorization' === strtolower( (string) $name ) ) {
					$h = sanitize_text_field( (string) $value );
				}
			}
		}
		return preg_match( '/^Bearer\s+(\S+)$/i', $h, $m ) ? $m[1] : '';
	}

	/**
	 * Whether this is a REST request (determine_current_user can run before
	 * REST_REQUEST is defined).
	 */
	private static function is_rest_request(): bool {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['rest_route'] ) ) {
			return true;
		}
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path   = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$prefix = (string) wp_parse_url( home_url( '/' . trim( rest_get_url_prefix(), '/' ) . '/' ), PHP_URL_PATH );
		return '' !== $prefix && str_starts_with( $path, $prefix );
	}

	/**
	 * `determine_current_user`.
	 *
	 * @param int|false $user_id User so far.
	 */
	public static function determine_current_user( $user_id ) {
		if ( $user_id || ! self::is_rest_request() ) {
			return $user_id;
		}
		$token = self::bearer();
		if ( '' === $token || ! Jwt::looks_like_jwt( $token ) ) {
			return $user_id;
		}
		$result = self::authenticate( $token );
		if ( is_wp_error( $result ) ) {
			self::$error = $result;
			return $user_id;
		}
		self::$user_id = $result;
		return $result;
	}

	/**
	 * Verify a token and return the WordPress user it acts as.
	 *
	 * @param string $token JWT.
	 * @return int|\WP_Error
	 */
	public static function authenticate( string $token ) {
		$claims = Oidc::configured()->verify( $token, array( 'aud' => Config::get( 'FAABLE_AUTH_REST_AUDIENCE' ) ) );
		if ( is_wp_error( $claims ) ) {
			return new \WP_Error( 'faable_auth_invalid_token', __( 'Invalid Faable access token.', 'faable-auth' ), array( 'status' => 401 ) );
		}
		$client_id = (string) ( $claims['client_id'] ?? '' );
		// A client_credentials token is about the client itself.
		if ( '' === $client_id || ( $claims['sub'] ?? '' ) !== $client_id ) {
			return new \WP_Error( 'faable_auth_not_m2m', __( 'Only machine-to-machine tokens are accepted here.', 'faable-auth' ), array( 'status' => 401 ) );
		}
		$allowed = array_filter( array_map( 'trim', explode( ',', Config::get( 'FAABLE_AUTH_REST_CLIENTS' ) ) ) );
		if ( $allowed && ! in_array( $client_id, $allowed, true ) ) {
			return new \WP_Error( 'faable_auth_client_not_allowed', __( 'This client is not allowed on this site.', 'faable-auth' ), array( 'status' => 403 ) );
		}
		$required = Config::get( 'FAABLE_AUTH_REST_SCOPE' );
		if ( '' !== $required ) {
			$granted = preg_split( '/\s+/', trim( (string) ( $claims['scope'] ?? '' ) . ' ' . (string) ( $claims['permissions'] ?? '' ) ) );
			if ( ! in_array( $required, $granted, true ) ) {
				return new \WP_Error( 'faable_auth_insufficient_scope', __( 'The token lacks the required scope.', 'faable-auth' ), array( 'status' => 403 ) );
			}
		}
		$login = Config::get( 'FAABLE_AUTH_REST_USER' );
		$user  = '' !== $login ? get_user_by( 'login', $login ) : false;
		$uid   = (int) apply_filters( 'faable_auth_rest_user_id', $user ? $user->ID : 0, $claims );
		if ( $uid <= 0 ) {
			return new \WP_Error( 'faable_auth_no_rest_user', __( 'No WordPress user is configured for machine-to-machine requests.', 'faable-auth' ), array( 'status' => 403 ) );
		}
		return $uid;
	}

	/**
	 * `rest_authentication_errors`.
	 *
	 * @param mixed $result Result so far.
	 */
	public static function rest_authentication_errors( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}
		if ( self::$error ) {
			return self::$error;
		}
		// The current user may have been resolved before the REST request was
		// known; make sure a valid token wins over that cached anonymous user.
		if ( ! self::$user_id && ! get_current_user_id() ) {
			$token = self::bearer();
			if ( '' !== $token && Jwt::looks_like_jwt( $token ) ) {
				$r = self::authenticate( $token );
				if ( is_wp_error( $r ) ) {
					return $r;
				}
				self::$user_id = $r;
				wp_set_current_user( $r );
			}
		}
		return $result;
	}
}
