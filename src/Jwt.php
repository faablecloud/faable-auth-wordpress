<?php
/**
 * Minimal JWT (JWS compact) verification for the tokens Faable Auth issues.
 *
 * Faable Auth signs every token with RS256 and publishes its keys as a JWKS
 * at `<tenant>/.well-known/jwks.json`. This class has no WordPress
 * dependency on purpose: it is unit-tested on its own.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Thrown when a token fails any check. The message is safe to log, never to
 * show verbatim to an anonymous visitor.
 */
class JwtException extends \RuntimeException {
}

/**
 * JWT helpers.
 */
final class Jwt {

	/** Algorithms accepted. Faable Auth only issues RS256 (see its discovery document). */
	const ALGORITHMS = array( 'RS256' => OPENSSL_ALGO_SHA256 );

	/** Clock skew tolerated on exp / nbf / iat, in seconds. */
	const LEEWAY = 60;

	/**
	 * Base64url encode.
	 *
	 * @param string $data Raw bytes.
	 */
	public static function b64url_encode( string $data ): string {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Base64url decode. Returns null on invalid input.
	 *
	 * @param string $data Encoded string.
	 */
	public static function b64url_decode( string $data ): ?string {
		if ( preg_match( '/[^A-Za-z0-9_-]/', $data ) ) {
			return null;
		}
		$pad = strlen( $data ) % 4;
		if ( 1 === $pad ) {
			return null;
		}
		if ( $pad ) {
			$data .= str_repeat( '=', 4 - $pad );
		}
		$out = base64_decode( strtr( $data, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		return false === $out ? null : $out;
	}

	/**
	 * Whether a string looks like a compact JWS (three base64url parts).
	 *
	 * @param string $token Candidate.
	 */
	public static function looks_like_jwt( string $token ): bool {
		return 1 === preg_match( '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/', $token );
	}

	/**
	 * Decode header and payload WITHOUT verifying. Only for routing decisions
	 * (which kid, which issuer); never trust the result.
	 *
	 * @param string $token Compact JWS.
	 * @return array{0: array, 1: array}
	 * @throws JwtException On malformed input.
	 */
	public static function decode_unverified( string $token ): array {
		$parts = explode( '.', $token );
		if ( 3 !== count( $parts ) ) {
			throw new JwtException( 'malformed token' );
		}
		$header  = json_decode( (string) self::b64url_decode( $parts[0] ), true );
		$payload = json_decode( (string) self::b64url_decode( $parts[1] ), true );
		if ( ! is_array( $header ) || ! is_array( $payload ) ) {
			throw new JwtException( 'malformed token' );
		}
		return array( $header, $payload );
	}

	/**
	 * Verify a token's signature against a JWKS and check its registered claims.
	 *
	 * @param string $token    Compact JWS.
	 * @param array  $jwks     Decoded JWKS document (`{"keys": [...]}`).
	 * @param array  $expect   Checks: `iss` (string, exact), `aud` (string, must be contained),
	 *                         `nonce` (string, exact), `now` (int, for tests).
	 * @return array The verified payload.
	 * @throws JwtException When any check fails.
	 */
	public static function verify( string $token, array $jwks, array $expect ): array {
		list( $header, $payload ) = self::decode_unverified( $token );
		$parts                    = explode( '.', $token );

		$alg = $header['alg'] ?? '';
		if ( ! is_string( $alg ) || ! isset( self::ALGORITHMS[ $alg ] ) ) {
			throw new JwtException( 'unsupported alg' );
		}
		$key = self::find_key( $jwks, $header['kid'] ?? null, $alg );
		if ( null === $key ) {
			throw new JwtException( 'unknown kid' );
		}
		$pem = self::jwk_to_pem( $key );
		$sig = self::b64url_decode( $parts[2] );
		if ( null === $sig || '' === $sig ) {
			throw new JwtException( 'bad signature' );
		}
		$ok = openssl_verify( $parts[0] . '.' . $parts[1], $sig, $pem, self::ALGORITHMS[ $alg ] );
		if ( 1 !== $ok ) {
			throw new JwtException( 'bad signature' );
		}

		self::check_claims( $payload, $expect );
		return $payload;
	}

	/**
	 * Check iss / aud / exp / nbf / nonce.
	 *
	 * @param array $payload Claims.
	 * @param array $expect  See verify().
	 * @throws JwtException When a check fails.
	 */
	public static function check_claims( array $payload, array $expect ): void {
		$now = isset( $expect['now'] ) ? (int) $expect['now'] : time();

		if ( ! isset( $payload['exp'] ) || ! is_numeric( $payload['exp'] ) ) {
			throw new JwtException( 'missing exp' );
		}
		if ( (int) $payload['exp'] + self::LEEWAY < $now ) {
			throw new JwtException( 'expired' );
		}
		if ( isset( $payload['nbf'] ) && (int) $payload['nbf'] - self::LEEWAY > $now ) {
			throw new JwtException( 'not yet valid' );
		}
		if ( isset( $payload['iat'] ) && (int) $payload['iat'] - self::LEEWAY > $now ) {
			throw new JwtException( 'issued in the future' );
		}
		if ( isset( $expect['iss'] ) && ( $payload['iss'] ?? null ) !== $expect['iss'] ) {
			throw new JwtException( 'wrong issuer' );
		}
		if ( isset( $expect['aud'] ) ) {
			$aud = $payload['aud'] ?? array();
			$aud = is_array( $aud ) ? $aud : array( $aud );
			if ( ! in_array( $expect['aud'], $aud, true ) ) {
				throw new JwtException( 'wrong audience' );
			}
			// OIDC Core 3.1.3.7: with several audiences, azp must be us.
			if ( count( $aud ) > 1 && isset( $expect['azp'] ) && ( $payload['azp'] ?? null ) !== $expect['azp'] ) {
				throw new JwtException( 'wrong azp' );
			}
		}
		if ( array_key_exists( 'nonce', $expect ) ) {
			$nonce = $payload['nonce'] ?? null;
			if ( ! is_string( $nonce ) || ! is_string( $expect['nonce'] ) || ! hash_equals( $expect['nonce'], $nonce ) ) {
				throw new JwtException( 'wrong nonce' );
			}
		}
	}

	/**
	 * Pick the JWK for a kid. Without a kid, a JWKS with exactly one usable
	 * RSA key is accepted.
	 *
	 * @param array       $jwks JWKS.
	 * @param string|null $kid  Key id from the header.
	 * @param string      $alg  Algorithm from the header.
	 */
	public static function find_key( array $jwks, $kid, string $alg ): ?array {
		$keys = array_values(
			array_filter(
				(array) ( $jwks['keys'] ?? array() ),
				static function ( $k ) use ( $alg ) {
					return is_array( $k )
						&& ( $k['kty'] ?? '' ) === 'RSA'
						&& ( ! isset( $k['use'] ) || 'sig' === $k['use'] )
						&& ( ! isset( $k['alg'] ) || $k['alg'] === $alg )
						&& isset( $k['n'], $k['e'] );
				}
			)
		);
		if ( null === $kid ) {
			return 1 === count( $keys ) ? $keys[0] : null;
		}
		foreach ( $keys as $k ) {
			if ( ( $k['kid'] ?? null ) === $kid ) {
				return $k;
			}
		}
		return null;
	}

	/**
	 * Convert an RSA JWK (n, e) into a PEM SubjectPublicKeyInfo.
	 *
	 * @param array $jwk RSA JWK.
	 * @throws JwtException On a malformed key.
	 */
	public static function jwk_to_pem( array $jwk ): string {
		$n = self::b64url_decode( (string) ( $jwk['n'] ?? '' ) );
		$e = self::b64url_decode( (string) ( $jwk['e'] ?? '' ) );
		if ( ! $n || ! $e ) {
			throw new JwtException( 'malformed jwk' );
		}
		$int = static function ( string $bytes ): string {
			$bytes = ltrim( $bytes, "\x00" );
			if ( ord( $bytes[0] ) > 0x7f ) {
				$bytes = "\x00" . $bytes;
			}
			return "\x02" . self::der_length( strlen( $bytes ) ) . $bytes;
		};
		$rsa_key   = $int( $n ) . $int( $e );
		$rsa_key   = "\x30" . self::der_length( strlen( $rsa_key ) ) . $rsa_key;
		$bitstring = "\x00" . $rsa_key;
		$bitstring = "\x03" . self::der_length( strlen( $bitstring ) ) . $bitstring;
		// AlgorithmIdentifier: rsaEncryption OID 1.2.840.113549.1.1.1, NULL params.
		$alg_id = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$spki   = $alg_id . $bitstring;
		$spki   = "\x30" . self::der_length( strlen( $spki ) ) . $spki;
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $spki ), 64, "\n" ) . "-----END PUBLIC KEY-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * DER length octets.
	 *
	 * @param int $len Length.
	 */
	private static function der_length( int $len ): string {
		if ( $len < 0x80 ) {
			return chr( $len );
		}
		$bytes = ltrim( pack( 'N', $len ), "\x00" );
		return chr( 0x80 | strlen( $bytes ) ) . $bytes;
	}
}
