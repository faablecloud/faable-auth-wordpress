<?php
/**
 * Back-channel calls to the Faable Auth tenant: discovery, JWKS, the token
 * endpoint and the one Management API read the plugin needs (a user's roles).
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * OIDC client.
 */
final class Oidc {

	const CACHE_TTL = HOUR_IN_SECONDS;

	/** Tenant base URL, which is also the issuer. */
	private string $issuer;

	/**
	 * Constructor.
	 *
	 * @param string $issuer Tenant base URL.
	 */
	public function __construct( string $issuer ) {
		$this->issuer = rtrim( $issuer, '/' );
	}

	/**
	 * Client for the configured tenant.
	 */
	public static function configured(): self {
		return new self( Config::domain() );
	}

	/**
	 * The issuer.
	 */
	public function issuer(): string {
		return $this->issuer;
	}

	/**
	 * The discovery document (cached). Its `issuer` must equal the configured
	 * domain: a tenant with a custom domain must be configured with it, since
	 * that is the issuer its tokens carry.
	 *
	 * @return array|\WP_Error
	 */
	public function discovery() {
		$key    = 'faable_auth_disc_' . md5( $this->issuer );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$doc = $this->get_json( $this->issuer . '/.well-known/openid-configuration' );
		if ( is_wp_error( $doc ) ) {
			return $doc;
		}
		if ( ( $doc['issuer'] ?? '' ) !== $this->issuer ) {
			return new \WP_Error(
				'faable_auth_issuer_mismatch',
				sprintf(
					/* translators: 1: issuer in discovery, 2: configured domain */
					__( 'The tenant says its issuer is %1$s, but the plugin is configured with %2$s. Use the issuer as the domain.', 'faable-auth' ),
					(string) ( $doc['issuer'] ?? '' ),
					$this->issuer
				)
			);
		}
		set_transient( $key, $doc, self::CACHE_TTL );
		return $doc;
	}

	/**
	 * An endpoint from discovery, with the documented default.
	 *
	 * @param string $name     Metadata name.
	 * @param string $fallback Path under the issuer.
	 * @return string|\WP_Error
	 */
	public function endpoint( string $name, string $fallback ) {
		$doc = $this->discovery();
		if ( is_wp_error( $doc ) ) {
			return $doc;
		}
		$url = $doc[ $name ] ?? '';
		return is_string( $url ) && '' !== $url ? $url : $this->issuer . $fallback;
	}

	/**
	 * The JWKS (cached; refreshed once when a kid is unknown, for key rotation).
	 *
	 * @param bool $force Skip the cache.
	 * @return array|\WP_Error
	 */
	public function jwks( bool $force = false ) {
		$key = 'faable_auth_jwks_' . md5( $this->issuer );
		if ( ! $force ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		} else {
			// At most one forced refetch a minute: an attacker sending random
			// kids must not turn every request into a call to the tenant.
			$guard = $key . '_f';
			if ( get_transient( $guard ) ) {
				$cached = get_transient( $key );
				return is_array( $cached ) ? $cached : new \WP_Error( 'faable_auth_jwks', 'JWKS unavailable' );
			}
			set_transient( $guard, 1, MINUTE_IN_SECONDS );
		}
		$uri = $this->endpoint( 'jwks_uri', '/.well-known/jwks.json' );
		if ( is_wp_error( $uri ) ) {
			return $uri;
		}
		$jwks = $this->get_json( $uri );
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}
		if ( ! isset( $jwks['keys'] ) || ! is_array( $jwks['keys'] ) ) {
			return new \WP_Error( 'faable_auth_jwks', 'Malformed JWKS' );
		}
		set_transient( $key, $jwks, self::CACHE_TTL );
		return $jwks;
	}

	/**
	 * Verify a token issued by this tenant.
	 *
	 * @param string $token  JWT.
	 * @param array  $expect Jwt::verify() expectations (iss is added).
	 * @return array|\WP_Error Claims.
	 */
	public function verify( string $token, array $expect ) {
		$expect['iss'] = $this->issuer;
		$jwks          = $this->jwks();
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}
		try {
			return Jwt::verify( $token, $jwks, $expect );
		} catch ( JwtException $e ) {
			if ( 'unknown kid' !== $e->getMessage() ) {
				return new \WP_Error( 'faable_auth_invalid_token', $e->getMessage() );
			}
		}
		$jwks = $this->jwks( true );
		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}
		try {
			return Jwt::verify( $token, $jwks, $expect );
		} catch ( JwtException $e ) {
			return new \WP_Error( 'faable_auth_invalid_token', $e->getMessage() );
		}
	}

	/**
	 * POST to the token endpoint (client_secret_post).
	 *
	 * @param array $params Form parameters (grant_type, …).
	 * @return array|\WP_Error Token response.
	 */
	public function token( array $params ) {
		$url = $this->endpoint( 'token_endpoint', '/oauth/token' );
		if ( is_wp_error( $url ) ) {
			return $url;
		}
		$params += array(
			'client_id'     => Config::get( 'FAABLE_AUTH_CLIENT_ID' ),
			'client_secret' => Config::get( 'FAABLE_AUTH_CLIENT_SECRET' ),
		);
		$res = wp_remote_post(
			$url,
			array(
				'timeout' => 15,
				'headers' => array( 'Accept' => 'application/json' ),
				'body'    => $params,
			)
		);
		return $this->json_response( $res );
	}

	/**
	 * Exchange an authorization code.
	 *
	 * @param string $code     Code.
	 * @param string $verifier PKCE verifier.
	 * @return array|\WP_Error
	 */
	public function exchange_code( string $code, string $verifier ) {
		return $this->token(
			array(
				'grant_type'    => 'authorization_code',
				'code'          => $code,
				'redirect_uri'  => Config::redirect_uri(),
				'code_verifier' => $verifier,
			)
		);
	}

	/**
	 * The user's account-level roles, read from the tenant's Management API
	 * (`GET /user/:id/roles`) with a client_credentials token limited to
	 * `read:rolemembers`. Used when the ID token carries no `roles` claim.
	 *
	 * The token is cached until shortly before it expires: on the Free plan a
	 * project gets 100 M2M tokens a month, and this keeps one site to about one
	 * a day.
	 *
	 * @param string $sub User id (user_…).
	 * @return string[]|\WP_Error Role names.
	 */
	public function user_roles( string $sub ) {
		$token = $this->management_token();
		if ( is_wp_error( $token ) ) {
			return $token;
		}
		$res  = wp_remote_get(
			$this->issuer . '/user/' . rawurlencode( $sub ) . '/roles',
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept'        => 'application/json',
					'Authorization' => 'Bearer ' . $token,
				),
			)
		);
		$data = $this->json_response( $res );
		if ( is_wp_error( $data ) ) {
			if ( 401 === (int) $data->get_error_data() ) {
				delete_transient( $this->mgmt_key() );
			}
			return $data;
		}
		$list  = isset( $data['results'] ) && is_array( $data['results'] ) ? $data['results'] : $data;
		$names = array();
		foreach ( (array) $list as $role ) {
			if ( is_array( $role ) && isset( $role['name'] ) && is_string( $role['name'] ) ) {
				$names[] = $role['name'];
			}
		}
		return $names;
	}

	/**
	 * A cached Management API token.
	 *
	 * @return string|\WP_Error
	 */
	private function management_token() {
		$cached = get_transient( $this->mgmt_key() );
		if ( is_string( $cached ) && '' !== $cached ) {
			return $cached;
		}
		$doc = $this->discovery();
		if ( is_wp_error( $doc ) ) {
			return $doc;
		}
		if ( empty( $doc['account'] ) || ! is_string( $doc['account'] ) ) {
			return new \WP_Error( 'faable_auth_no_account', __( 'The tenant does not publish its account id; roles cannot be read.', 'faable-auth' ) );
		}
		$res = $this->token(
			array(
				'grant_type' => 'client_credentials',
				'audience'   => 'faable:management:' . $doc['account'],
				'scope'      => 'read:rolemembers',
			)
		);
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$token = (string) ( $res['access_token'] ?? '' );
		if ( '' === $token ) {
			return new \WP_Error( 'faable_auth_token', 'No access token in response' );
		}
		$ttl = max( 60, (int) ( $res['expires_in'] ?? 3600 ) - 300 );
		set_transient( $this->mgmt_key(), $token, $ttl );
		return $token;
	}

	/**
	 * Transient key for the management token.
	 */
	private function mgmt_key(): string {
		return 'faable_auth_mgmt_' . md5( $this->issuer . '|' . Config::get( 'FAABLE_AUTH_CLIENT_ID' ) );
	}

	/**
	 * GET a JSON document.
	 *
	 * @param string $url URL.
	 * @return array|\WP_Error
	 */
	private function get_json( string $url ) {
		return $this->json_response(
			wp_remote_get(
				$url,
				array(
					'timeout' => 10,
					'headers' => array( 'Accept' => 'application/json' ),
				)
			)
		);
	}

	/**
	 * Decode a JSON response; non-2xx becomes a WP_Error carrying the status.
	 *
	 * @param array|\WP_Error $res Response.
	 * @return array|\WP_Error
	 */
	public static function json_response( $res ) {
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		$body = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( $code < 200 || $code >= 300 ) {
			$msg = is_array( $body )
				? (string) ( $body['error_description'] ?? $body['message'] ?? $body['error'] ?? '' )
				: '';
			$err = is_array( $body ) ? (string) ( $body['error'] ?? 'http_error' ) : 'http_error';
			/* translators: %d: HTTP status */
			return new \WP_Error( 'faable_auth_' . sanitize_key( $err ), '' !== $msg ? $msg : sprintf( __( 'Faable answered HTTP %d.', 'faable-auth' ), $code ), $code );
		}
		if ( ! is_array( $body ) ) {
			return new \WP_Error( 'faable_auth_bad_json', __( 'Faable answered something that is not JSON.', 'faable-auth' ), $code );
		}
		return $body;
	}
}
