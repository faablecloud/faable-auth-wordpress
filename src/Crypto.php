<?php
/**
 * Encryption at rest for the client secret stored in wp_options.
 *
 * libsodium secretbox (XSalsa20-Poly1305) with a key derived from the site's
 * AUTH_KEY and SECURE_AUTH_KEY: a database dump alone does not reveal the
 * secret. Rotating those salts makes the stored secret unreadable; the site
 * then reports "not configured" and the admin reconnects.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || defined( 'FAABLE_AUTH_TESTING' ) || exit;

/**
 * Secretbox helpers.
 */
final class Crypto {

	const PREFIX = 'fa1:';

	/**
	 * Derive the 32-byte key.
	 *
	 * @param string $material Key material (the salts).
	 */
	public static function key( string $material ): string {
		return sodium_crypto_generichash( 'faable-auth/client-secret/v1|' . $material, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}

	/**
	 * Key material from wp-config.php salts.
	 */
	public static function site_material(): string {
		$a = defined( 'AUTH_KEY' ) ? (string) AUTH_KEY : '';
		$b = defined( 'SECURE_AUTH_KEY' ) ? (string) SECURE_AUTH_KEY : '';
		return $a . '|' . $b;
	}

	/**
	 * Encrypt.
	 *
	 * @param string $plain    Plaintext.
	 * @param string $material Key material.
	 */
	public static function encrypt( string $plain, string $material ): string {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = sodium_crypto_secretbox( $plain, $nonce, self::key( $material ) );
		return self::PREFIX . Jwt::b64url_encode( $nonce . $box );
	}

	/**
	 * Decrypt. Returns null when the value is not ours or the key changed.
	 *
	 * @param string $stored   Stored value.
	 * @param string $material Key material.
	 */
	public static function decrypt( string $stored, string $material ): ?string {
		if ( 0 !== strpos( $stored, self::PREFIX ) ) {
			return null;
		}
		$raw = Jwt::b64url_decode( substr( $stored, strlen( self::PREFIX ) ) );
		if ( null === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return null;
		}
		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$plain = sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $nonce, self::key( $material ) );
		return false === $plain ? null : $plain;
	}
}
