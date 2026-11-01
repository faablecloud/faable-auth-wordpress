<?php
/**
 * Plain-PHP unit tests for the parts with no WordPress dependency:
 * role mapping, JWT verification, PKCE/state handling, break glass,
 * login links and secret encryption.
 *
 *   php tests/run.php
 *   docker run --rm -v "$PWD":/src -w /src php:8.4-cli php tests/run.php
 *
 * @package FaableAuth
 */

define( 'FAABLE_AUTH_TESTING', true );
define( 'ABSPATH', __DIR__ . '/' ); // the classes refuse to load outside WordPress.
$root = dirname( __DIR__ );
foreach ( array( 'Jwt', 'Pkce', 'RoleMapper', 'BreakGlass', 'LoginLink', 'Crypto' ) as $c ) {
	require $root . '/src/' . $c . '.php';
}

use FaableAuth\BreakGlass;
use FaableAuth\Crypto;
use FaableAuth\Jwt;
use FaableAuth\JwtException;
use FaableAuth\LoginLink;
use FaableAuth\Pkce;
use FaableAuth\RoleMapper;

$GLOBALS['fails'] = 0;
$GLOBALS['count'] = 0;

function check( string $name, bool $ok ): void {
	$GLOBALS['count']++;
	if ( ! $ok ) {
		$GLOBALS['fails']++;
	}
	echo ( $ok ? "  ok   " : "  FAIL " ) . $name . "\n";
}

function throws( callable $fn, string $message ): bool {
	try {
		$fn();
	} catch ( JwtException $e ) {
		return $e->getMessage() === $message;
	}
	return false;
}

// ---------------------------------------------------------------- RoleMapper
echo "RoleMapper\n";
$map = RoleMapper::default_map();
check( 'membership role is not special (only the map counts)', null === RoleMapper::resolve( array( 'faable-project-member' ), $map ) );
check( 'no mapped role means no account', null === RoleMapper::resolve( array( 'support', 'billing' ), $map ) );
check( 'no roles at all means no account', null === RoleMapper::resolve( array(), $map ) );
check( 'editor maps to editor', 'editor' === RoleMapper::resolve( array( 'Editor' ), $map ) );
check( 'admin alias maps to administrator', 'administrator' === RoleMapper::resolve( array( 'admin' ), $map ) );
check( 'most privileged wins', 'editor' === RoleMapper::resolve( array( 'subscriber', 'editor', 'author' ), $map ) );
$custom = RoleMapper::parse( "staff = editor\n# comment\nreaders=subscriber\nbad = Not A Role!" );
check( 'line map parses', array( 'staff' => 'editor', 'readers' => 'subscriber' ) === $custom );
check( 'custom map replaces defaults', null === RoleMapper::resolve( array( 'editor' ), $custom ) );
check( 'custom map resolves', 'editor' === RoleMapper::resolve( array( 'STAFF' ), $custom ) );
check( 'json map parses', array( 'shop' => 'shop_manager' ) === RoleMapper::parse( '{"Shop":"shop_manager"}' ) );
check( 'empty map = defaults', RoleMapper::default_map() === RoleMapper::parse( '  ' ) );
check( 'custom WP role ranks below core roles', 'author' === RoleMapper::resolve( array( 'shop', 'author' ), array( 'shop' => 'shop_manager', 'author' => 'author' ) ) );
check( 'role missing in the site is skipped', null === RoleMapper::resolve( array( 'shop' ), array( 'shop' => 'shop_manager' ), array( 'administrator', 'editor' ) ) );
check( 'round trip text', $custom === RoleMapper::parse( RoleMapper::to_text( $custom ) ) );

// ---------------------------------------------------------------- JWT
echo "JWT\n";
$key  = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$det  = openssl_pkey_get_details( $key );
$jwk  = array( 'kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'alg' => 'RS256', 'n' => Jwt::b64url_encode( $det['rsa']['n'] ), 'e' => Jwt::b64url_encode( $det['rsa']['e'] ) );
$jwks = array( 'keys' => array( $jwk ) );
$key2 = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );

function sign( array $payload, $key, array $header = array( 'alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'k1' ) ): string {
	$input = Jwt::b64url_encode( json_encode( $header ) ) . '.' . Jwt::b64url_encode( json_encode( $payload ) );
	openssl_sign( $input, $sig, $key, OPENSSL_ALGO_SHA256 );
	return $input . '.' . Jwt::b64url_encode( $sig );
}

$iss   = 'https://acme.auth.faable.link';
$now   = 1_800_000_000;
$id    = array( 'iss' => $iss, 'aud' => 'client_1', 'sub' => 'user_1', 'exp' => $now + 3600, 'iat' => $now, 'nonce' => 'n-1' );
$exp   = array( 'iss' => $iss, 'aud' => 'client_1', 'nonce' => 'n-1', 'now' => $now );
$token = sign( $id, $key );

check( 'jwk -> pem is a valid public key', false !== openssl_pkey_get_public( Jwt::jwk_to_pem( $jwk ) ) );
check( 'valid id_token verifies', 'user_1' === Jwt::verify( $token, $jwks, $exp )['sub'] );
check( 'wrong signing key', throws( fn() => Jwt::verify( sign( $id, $key2 ), $jwks, $exp ), 'bad signature' ) );
$parts = explode( '.', $token );
$tampered = $parts[0] . '.' . Jwt::b64url_encode( json_encode( array( 'sub' => 'user_admin' ) + $id ) ) . '.' . $parts[2];
check( 'tampered payload', throws( fn() => Jwt::verify( $tampered, $jwks, $exp ), 'bad signature' ) );
check( 'alg none refused', throws( fn() => Jwt::verify( Jwt::b64url_encode( '{"alg":"none"}' ) . '.' . $parts[1] . '.', $jwks, $exp ), 'unsupported alg' ) );
check( 'HS256 refused (key confusion)', throws( fn() => Jwt::verify( sign( $id, $key, array( 'alg' => 'HS256', 'kid' => 'k1' ) ), $jwks, $exp ), 'unsupported alg' ) );
check( 'unknown kid', throws( fn() => Jwt::verify( sign( $id, $key, array( 'alg' => 'RS256', 'kid' => 'k9' ) ), $jwks, $exp ), 'unknown kid' ) );
check( 'no kid with single key ok', 'user_1' === Jwt::verify( sign( $id, $key, array( 'alg' => 'RS256' ) ), $jwks, $exp )['sub'] );
check( 'expired', throws( fn() => Jwt::verify( sign( array( 'exp' => $now - 61 ) + $id, $key ), $jwks, $exp ), 'expired' ) );
check( 'within leeway', is_array( Jwt::verify( sign( array( 'exp' => $now - 30 ) + $id, $key ), $jwks, $exp ) ) );
check( 'missing exp', throws( fn() => Jwt::verify( sign( array_diff_key( $id, array( 'exp' => 1 ) ), $key ), $jwks, $exp ), 'missing exp' ) );
check( 'wrong issuer', throws( fn() => Jwt::verify( sign( array( 'iss' => 'https://evil.auth.faable.link' ) + $id, $key ), $jwks, $exp ), 'wrong issuer' ) );
check( 'issuer with trailing slash is another issuer', throws( fn() => Jwt::verify( sign( array( 'iss' => $iss . '/' ) + $id, $key ), $jwks, $exp ), 'wrong issuer' ) );
check( 'wrong audience', throws( fn() => Jwt::verify( sign( array( 'aud' => 'client_2' ) + $id, $key ), $jwks, $exp ), 'wrong audience' ) );
check( 'audience array containing us', is_array( Jwt::verify( sign( array( 'aud' => array( 'x', 'client_1' ), 'azp' => 'client_1' ) + $id, $key ), $jwks, $exp + array( 'azp' => 'client_1' ) ) ) );
check( 'audience array with foreign azp', throws( fn() => Jwt::verify( sign( array( 'aud' => array( 'x', 'client_1' ), 'azp' => 'x' ) + $id, $key ), $jwks, $exp + array( 'azp' => 'client_1' ) ), 'wrong azp' ) );
check( 'wrong nonce', throws( fn() => Jwt::verify( sign( array( 'nonce' => 'other' ) + $id, $key ), $jwks, $exp ), 'wrong nonce' ) );
check( 'missing nonce', throws( fn() => Jwt::verify( sign( array_diff_key( $id, array( 'nonce' => 1 ) ), $key ), $jwks, $exp ), 'wrong nonce' ) );
check( 'nbf in the future', throws( fn() => Jwt::verify( sign( array( 'nbf' => $now + 600 ) + $id, $key ), $jwks, $exp ), 'not yet valid' ) );
check( 'malformed', throws( fn() => Jwt::verify( 'a.b', $jwks, $exp ), 'malformed token' ) );
// An M2M (client_credentials) token as Faable Auth issues it.
$m2m = array( 'iss' => $iss, 'aud' => 'https://wp.example.com/api', 'sub' => 'client_next', 'client_id' => 'client_next', 'scope' => '', 'permissions' => 'wp:read', 'account' => 'acc_1', 'exp' => $now + 600, 'iat' => $now, 'jti' => 'x' );
$c   = Jwt::verify( sign( $m2m, $key ), $jwks, array( 'iss' => $iss, 'aud' => 'https://wp.example.com/api', 'now' => $now ) );
check( 'M2M token verifies with API audience', 'client_next' === $c['sub'] && $c['sub'] === $c['client_id'] );
check( 'M2M token for another API refused', throws( fn() => Jwt::verify( sign( $m2m, $key ), $jwks, array( 'iss' => $iss, 'aud' => 'https://other', 'now' => $now ) ), 'wrong audience' ) );
check( 'looks_like_jwt', Jwt::looks_like_jwt( $token ) && ! Jwt::looks_like_jwt( 'dXNlcjpwYXNz' ) );

// ---------------------------------------------------------------- PKCE / state
echo "PKCE / state\n";
check( 'RFC 7636 appendix B vector', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' === Pkce::challenge( 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' ) );
$v = Pkce::random();
check( 'random verifier is valid', Pkce::is_valid_verifier( $v ) && 43 === strlen( $v ) );
check( 'random values differ', Pkce::random() !== Pkce::random() );
check( 'short verifier invalid', ! Pkce::is_valid_verifier( 'abc' ) );
$state = Pkce::random();
$bind  = Pkce::random();
$flow  = array( 'state' => $state, 'binding' => hash( 'sha256', $bind ), 'expires' => 2000 );
check( 'valid flow', null === Pkce::check_flow( $flow, $state, $bind, 1000 ) );
check( 'missing flow (expired transient / replay)', 'state_unknown' === Pkce::check_flow( false, $state, $bind, 1000 ) );
check( 'empty state', 'state_unknown' === Pkce::check_flow( $flow, '', $bind, 1000 ) );
check( 'other state', 'state_mismatch' === Pkce::check_flow( $flow, 'x' . $state, $bind, 1000 ) );
check( 'expired flow', 'state_expired' === Pkce::check_flow( $flow, $state, $bind, 2001 ) );
check( 'other browser (no cookie)', 'browser_mismatch' === Pkce::check_flow( $flow, $state, null, 1000 ) );
check( 'other browser (other cookie)', 'browser_mismatch' === Pkce::check_flow( $flow, $state, Pkce::random(), 1000 ) );
check( 'connect flow has no binding', null === Pkce::check_flow( array( 'state' => $state, 'expires' => 2000 ), $state, null, 1000 ) );
check( 'storage key hides the state', false === strpos( Pkce::storage_key( 'login', $state ), $state ) && Pkce::storage_key( 'login', $state ) !== Pkce::storage_key( 'connect', $state ) );
check( 'storage key fits a transient name', strlen( Pkce::storage_key( 'connect', $state ) ) <= 172 );

// ---------------------------------------------------------------- Break glass
echo "Break glass\n";
check( 'off by default', false === BreakGlass::is_active( null, null ) );
check( 'constant true', true === BreakGlass::is_active( true, null ) );
check( 'constant false wins over env', false === BreakGlass::is_active( false, '1' ) );
check( 'env 1', true === BreakGlass::is_active( null, '1' ) );
check( 'env "true"', true === BreakGlass::is_active( null, 'TRUE' ) );
check( 'env "0"', false === BreakGlass::is_active( null, '0' ) );
check( 'not configured = native', BreakGlass::MODE_NATIVE === BreakGlass::login_mode( false, false ) );
check( 'not configured + break glass = native', BreakGlass::MODE_NATIVE === BreakGlass::login_mode( false, true ) );
check( 'configured = faable only', BreakGlass::MODE_FAABLE === BreakGlass::login_mode( true, false ) );
check( 'configured + break glass = both', BreakGlass::MODE_BOTH === BreakGlass::login_mode( true, true ) );
check( 'passwords refused in faable mode', false === BreakGlass::passwords_allowed( BreakGlass::MODE_FAABLE ) );
check( 'passwords allowed with break glass', true === BreakGlass::passwords_allowed( BreakGlass::MODE_BOTH ) );

// ---------------------------------------------------------------- Login links
echo "Login links\n";
$t   = Pkce::random();
$rec = LoginLink::record( $t, 1000 );
check( 'stores a hash, not the token', false === strpos( json_encode( $rec ), $t ) );
check( 'valid within 10 minutes', LoginLink::matches( $rec, $t, 1599 ) );
check( 'expired after 10 minutes', ! LoginLink::matches( $rec, $t, 1601 ) );
check( 'wrong token', ! LoginLink::matches( $rec, Pkce::random(), 1100 ) );
check( 'empty token', ! LoginLink::matches( $rec, '', 1100 ) );
check( 'used (meta deleted)', ! LoginLink::matches( '', $t, 1100 ) );

// ---------------------------------------------------------------- Crypto
echo "Secret at rest\n";
$enc = Crypto::encrypt( 'super-secret', 'salt-a|salt-b' );
check( 'ciphertext hides the secret', false === strpos( $enc, 'super-secret' ) );
check( 'decrypts with the same salts', 'super-secret' === Crypto::decrypt( $enc, 'salt-a|salt-b' ) );
check( 'unreadable after salts rotate', null === Crypto::decrypt( $enc, 'salt-c|salt-b' ) );
check( 'garbage is null', null === Crypto::decrypt( 'fa1:zzzz', 'salt-a|salt-b' ) && null === Crypto::decrypt( 'plain', 'x' ) );

echo "\n{$GLOBALS['count']} checks, {$GLOBALS['fails']} failed\n";
exit( $GLOBALS['fails'] ? 1 : 0 );
