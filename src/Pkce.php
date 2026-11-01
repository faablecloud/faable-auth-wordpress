<?php
/**
 * PKCE (RFC 7636, S256 only), state and nonce helpers. No WordPress dependency.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * PKCE and one-time value helpers.
 */
final class Pkce {

	/**
	 * A random, URL-safe value with 256 bits of entropy (43 chars): fit for a
	 * code_verifier (RFC 7636 §4.1 asks for 43-128 chars), a state or a nonce.
	 */
	public static function random(): string {
		return Jwt::b64url_encode( random_bytes( 32 ) );
	}

	/**
	 * The S256 code_challenge for a verifier.
	 *
	 * @param string $verifier code_verifier.
	 */
	public static function challenge( string $verifier ): string {
		return Jwt::b64url_encode( hash( 'sha256', $verifier, true ) );
	}

	/**
	 * Whether a verifier is well formed (RFC 7636 §4.1).
	 *
	 * @param string $verifier Candidate.
	 */
	public static function is_valid_verifier( string $verifier ): bool {
		return 1 === preg_match( '/^[A-Za-z0-9\-._~]{43,128}$/', $verifier );
	}

	/**
	 * Storage key for a pending flow, derived from its state so the raw state
	 * never becomes a database key.
	 *
	 * @param string $prefix Namespace (`login`, `connect`).
	 * @param string $state  The state value.
	 */
	public static function storage_key( string $prefix, string $state ): string {
		return 'faable_auth_' . $prefix . '_' . substr( hash( 'sha256', $state ), 0, 32 );
	}

	/**
	 * Validate a callback against the flow stored for its state.
	 *
	 * The flow is looked up by the state the browser came back with, then the
	 * browser binding (a random value in a cookie set when the flow started) is
	 * compared in constant time: a state leaked to another browser cannot be
	 * completed there (login CSRF).
	 *
	 * @param array|false $flow     What was stored (false when missing or expired).
	 * @param string      $state    The `state` received.
	 * @param string|null $binding  The binding cookie received.
	 * @param int|null    $now      Current time (tests).
	 * @return string|null Null when valid, otherwise an error code.
	 */
	public static function check_flow( $flow, string $state, ?string $binding, ?int $now = null ): ?string {
		$now = $now ?? time();
		if ( '' === $state || ! is_array( $flow ) ) {
			return 'state_unknown';
		}
		if ( ! isset( $flow['state'], $flow['expires'] ) || ! hash_equals( (string) $flow['state'], $state ) ) {
			return 'state_mismatch';
		}
		if ( (int) $flow['expires'] < $now ) {
			return 'state_expired';
		}
		if ( isset( $flow['binding'] ) ) {
			if ( null === $binding || ! hash_equals( (string) $flow['binding'], hash( 'sha256', $binding ) ) ) {
				return 'browser_mismatch';
			}
		}
		return null;
	}
}
