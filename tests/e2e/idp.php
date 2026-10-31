<?php
/**
 * A fake Faable Auth tenant + Faable dashboard for the end-to-end test,
 * served with `php -S 0.0.0.0:8080 idp.php`. It implements only what the
 * plugin calls, with the shapes of the real service (auth/src/api_oauth,
 * plugins/token_issuer): discovery with `account`, RS256 JWKS, /authorize
 * with S256 PKCE and RFC 9207 `iss`, /oauth/token (authorization_code and
 * client_credentials), GET /user/:id/roles, and the Connect handoff
 * (/connect/wordpress on the "dashboard", /connect/exchange on the platform
 * tenant). NOT for production use.
 *
 * @package FaableAuth
 */

const ISS     = 'http://idp.test:8080';
const ACCOUNT = 'acc_test';
const DIR     = '/tmp/idp';

// The tenant's users: name => [sub, email, account-level roles].
const USERS = array(
	'alice' => array( 'user_alice', 'alice@example.com', array( 'editor' ) ),
	'bob'   => array( 'user_bob', 'bob@example.com', array( 'support' ) ),
	'carol' => array( 'user_carol', 'carol@example.com', array( 'faable-project-member' ) ), // unmapped: membership gives no role
	'admin' => array( 'user_admin', 'admin@example.com', array( 'administrator' ) ),
);
const CLIENT_ID     = 'client_wp';
const CLIENT_SECRET = 'secret_wp_123';

@mkdir( DIR, 0700, true );

function b64u( string $d ): string {
	return rtrim( strtr( base64_encode( $d ), '+/', '-_' ), '=' );
}
function key_pem(): string {
	$f = DIR . '/key.pem';
	if ( ! is_file( $f ) ) {
		$k = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
		openssl_pkey_export( $k, $pem );
		file_put_contents( $f, $pem );
	}
	return file_get_contents( $f );
}
function jwt( array $claims ): string {
	$h = b64u( json_encode( array( 'alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'test-kid' ) ) );
	$p = b64u( json_encode( $claims + array( 'iss' => ISS, 'iat' => time(), 'exp' => time() + 3600, 'jti' => bin2hex( random_bytes( 8 ) ), 'account' => ACCOUNT ) ) );
	openssl_sign( "$h.$p", $sig, key_pem(), OPENSSL_ALGO_SHA256 );
	return "$h.$p." . b64u( $sig );
}
function json( $data, int $status = 200 ): void {
	http_response_code( $status );
	header( 'Content-Type: application/json' );
	echo json_encode( $data );
	exit;
}
function store( string $name, $value = null ) {
	$f = DIR . '/' . preg_replace( '/[^A-Za-z0-9_-]/', '_', $name ) . '.json';
	if ( null === $value ) {
		if ( ! is_file( $f ) ) {
			return null;
		}
		$v = json_decode( file_get_contents( $f ), true );
		unlink( $f ); // single use
		return $v;
	}
	file_put_contents( $f, json_encode( $value ) );
}
// The write side of the Management API (UserSync): users imported and roles
// created or assigned by the site, kept across requests (unlike store()).
function mgmt( ?array $value = null ): array {
	$f = DIR . '/mgmt.json';
	if ( null !== $value ) {
		file_put_contents( $f, json_encode( $value ) );
		return $value;
	}
	return is_file( $f ) ? json_decode( file_get_contents( $f ), true ) : array( 'users' => array(), 'roles' => array(), 'grants' => array() );
}
// The bearer's scopes, or a 401/403 answer.
function need_scope( string $scope ): void {
	if ( ! preg_match( '/^Bearer (.+)$/', $_SERVER['HTTP_AUTHORIZATION'] ?? '', $t ) ) {
		json( array( 'error' => 'unauthorized' ), 401 );
	}
	$payload = json_decode( base64_decode( strtr( explode( '.', $t[1] )[1], '-_', '+/' ) ), true );
	if ( ( $payload['aud'] ?? '' ) !== 'faable:management:' . ACCOUNT || ! in_array( $scope, explode( ' ', (string) ( $payload['scope'] ?? '' ) ), true ) ) {
		json( array( 'error' => 'insufficient_scope', 'message' => "needs $scope" ), 403 );
	}
}
// Role names of a user: the fixed ones (or their override) plus grants.
function roles_of( string $sub ): ?array {
	$m = mgmt();
	foreach ( USERS as $name => $u ) {
		if ( $u[0] === $sub ) {
			$override = DIR . '/roles_' . $name;
			$base     = is_file( $override ) ? array_filter( explode( ',', trim( file_get_contents( $override ) ) ) ) : $u[2];
			return array_values( array_unique( array_merge( $base, $m['grants'][ $sub ] ?? array() ) ) );
		}
	}
	foreach ( $m['users'] as $u ) {
		if ( $u['sub'] === $sub ) {
			return $m['grants'][ $sub ] ?? array();
		}
	}
	return null;
}
function role_name( string $id ): string {
	return (string) preg_replace( '/^role_/', '', $id );
}

function client_auth(): bool {
	return ( $_POST['client_id'] ?? '' ) === CLIENT_ID && hash_equals( CLIENT_SECRET, (string) ( $_POST['client_secret'] ?? '' ) );
}

$path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
error_log( $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] );

switch ( true ) {
	case '/.well-known/openid-configuration' === $path:
		json(
			array(
				'issuer'                 => ISS,
				'account'                => ACCOUNT,
				'authorization_endpoint' => ISS . '/authorize',
				'token_endpoint'         => ISS . '/oauth/token',
				'userinfo_endpoint'      => ISS . '/userinfo',
				'jwks_uri'               => ISS . '/.well-known/jwks.json',
				'end_session_endpoint'   => ISS . '/logout',
				'code_challenge_methods_supported' => array( 'S256' ),
				'id_token_signing_alg_values_supported' => array( 'RS256' ),
			)
		);

	case '/.well-known/jwks.json' === $path:
		$d = openssl_pkey_get_details( openssl_pkey_get_private( key_pem() ) );
		json( array( 'keys' => array( array( 'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => 'test-kid', 'n' => b64u( $d['rsa']['n'] ), 'e' => b64u( $d['rsa']['e'] ) ) ) ) );

	// Test control: who "logs in" at the next /authorize.
	case '/test/next-user' === $path:
		file_put_contents( DIR . '/next_user', $_GET['u'] ?? 'alice' );
		json( array( 'ok' => true ) );

	case '/test/cc-count' === $path:
		json( array( 'count' => (int) @file_get_contents( DIR . '/cc_count' ) ) );

	// Test control: change a user's roles.
	case '/test/set-roles' === $path:
		file_put_contents( DIR . '/roles_' . preg_replace( '/\W/', '', $_GET['u'] ?? '' ), $_GET['r'] ?? '' );
		json( array( 'ok' => true ) );

	// Test control: mint an M2M token like client_credentials would.
	case '/test/m2m' === $path:
		$cid = $_GET['client'] ?? 'client_next';
		json( array( 'access_token' => jwt( array( 'sub' => $cid, 'client_id' => $cid, 'aud' => $_GET['aud'] ?? '', 'scope' => '', 'permissions' => $_GET['perm'] ?? 'wp:read' ) ) ) );

	// Test control: what the last /authorize received.
	case '/test/last-authorize' === $path:
		json( json_decode( (string) @file_get_contents( DIR . '/last_authorize' ), true ) );

	case '/authorize' === $path:
		file_put_contents( DIR . '/last_authorize', json_encode( $_GET ) );
		if ( ( $_GET['client_id'] ?? '' ) !== CLIENT_ID || ( $_GET['code_challenge_method'] ?? '' ) !== 'S256' || empty( $_GET['code_challenge'] ) ) {
			json( array( 'error' => 'invalid_request' ), 400 );
		}
		$who  = trim( (string) @file_get_contents( DIR . '/next_user' ) ) ?: 'alice';
		$code = bin2hex( random_bytes( 16 ) );
		store( 'code_' . $code, array( 'user' => $who, 'nonce' => $_GET['nonce'] ?? null, 'challenge' => $_GET['code_challenge'], 'redirect_uri' => $_GET['redirect_uri'] ) );
		$sep = false === strpos( $_GET['redirect_uri'], '?' ) ? '?' : '&';
		header( 'Location: ' . $_GET['redirect_uri'] . $sep . http_build_query( array( 'code' => $code, 'state' => $_GET['state'] ?? '', 'iss' => ISS ) ) );
		http_response_code( 302 );
		exit;

	case '/oauth/token' === $path && 'POST' === $_SERVER['REQUEST_METHOD']:
		if ( ! client_auth() ) {
			json( array( 'error' => 'invalid_client' ), 401 );
		}
		if ( 'authorization_code' === ( $_POST['grant_type'] ?? '' ) ) {
			$c = store( 'code_' . ( $_POST['code'] ?? '' ) );
			if ( ! $c || $c['redirect_uri'] !== ( $_POST['redirect_uri'] ?? '' ) ) {
				json( array( 'error' => 'invalid_grant' ), 400 );
			}
			if ( b64u( hash( 'sha256', (string) ( $_POST['code_verifier'] ?? '' ), true ) ) !== $c['challenge'] ) {
				json( array( 'error' => 'invalid_grant', 'error_description' => 'PKCE verification failed' ), 400 );
			}
			list( $sub, $email ) = USERS[ $c['user'] ];
			$id = array( 'sub' => $sub, 'aud' => CLIENT_ID, 'email' => $email, 'email_verified' => true, 'name' => ucfirst( $c['user'] ), 'preferred_username' => $c['user'] );
			if ( $c['nonce'] ) {
				$id['nonce'] = $c['nonce'];
			}
			json( array( 'access_token' => jwt( array( 'sub' => $sub, 'client_id' => CLIENT_ID, 'aud' => ISS . '/userinfo' ) ), 'id_token' => jwt( $id ), 'token_type' => 'Bearer', 'expires_in' => 3600 ) );
		}
		if ( 'client_credentials' === ( $_POST['grant_type'] ?? '' ) ) {
			file_put_contents( DIR . '/cc_count', (string) ( (int) @file_get_contents( DIR . '/cc_count' ) + 1 ) );
			if ( ( $_POST['audience'] ?? '' ) !== 'faable:management:' . ACCOUNT ) {
				json( array( 'error' => 'access_denied' ), 403 );
			}
			// Like auth's per-client allow-list: a client granted read:rolemembers only.
			if ( is_file( DIR . '/read_only_client' ) && 'read:rolemembers' !== ( $_POST['scope'] ?? '' ) ) {
				json( array( 'error' => 'invalid_scope', 'error_description' => 'management_scope_not_allowed: create:users' ), 400 );
			}
			json( array( 'access_token' => jwt( array( 'sub' => CLIENT_ID, 'client_id' => CLIENT_ID, 'aud' => $_POST['audience'], 'scope' => $_POST['scope'] ?? '' ) ), 'token_type' => 'Bearer', 'expires_in' => 86400 ) );
		}
		json( array( 'error' => 'unsupported_grant_type' ), 400 );

	case '/test/mgmt' === $path:
		json( mgmt() );
	// A second role with an existing name (Faable Auth allows it), newer id.
	case '/test/dup-role' === $path:
		$m           = mgmt();
		$m['dups'][] = $_GET['name'];
		mgmt( $m );
		json( array( 'ok' => true ) );
	case '/test/grant' === $path:
		$m = mgmt();
		$m['grants'][ $_GET['sub'] ][] = $_GET['role'];
		mgmt( $m );
		json( array( 'ok' => true ) );
	case '/test/read-only-client' === $path:
		empty( $_GET['off'] ) ? touch( DIR . '/read_only_client' ) : @unlink( DIR . '/read_only_client' );
		json( array( 'ok' => true ) );

	case '/user/import' === $path && 'POST' === $_SERVER['REQUEST_METHOD']:
		need_scope( 'create:users' );
		$body = json_decode( file_get_contents( 'php://input' ), true );
		if ( ! empty( $body['update_existing'] ) ) {
			need_scope( 'update:credentials' );
		}
		$m    = mgmt();
		$out  = array();
		foreach ( $body['users'] as $i => $row ) {
			$sub = null;
			foreach ( USERS as $u ) {
				if ( $u[1] === $row['email'] ) {
					$sub = $u[0];
				}
			}
			foreach ( $m['users'] as $u ) {
				if ( $u['email'] === $row['email'] ) {
					$sub = $u['sub'];
				}
			}
			if ( $sub ) {
				$out[] = array( 'index' => $i, 'email' => $row['email'], 'status' => 'skipped', 'user_id' => $sub );
				continue;
			}
			$sub          = 'user_' . substr( md5( $row['email'] ), 0, 12 );
			$m['users'][] = array( 'sub' => $sub, 'email' => $row['email'], 'name' => $row['name'] ?? '', 'password_hash' => $row['password_hash'] ?? null );
			$out[]        = array( 'index' => $i, 'email' => $row['email'], 'status' => 'created', 'user_id' => $sub );
		}
		mgmt( $m );
		json( array( 'summary' => array( 'total' => count( $out ) ), 'results' => $out ) );

	case '/role' === $path && 'GET' === $_SERVER['REQUEST_METHOD']:
		need_scope( 'read:roles' );
		$names = mgmt()['roles'];
		foreach ( USERS as $u ) {
			$names = array_merge( $names, $u[2] );
		}
		$list = array_map( fn( $n ) => array( 'id' => 'role_' . $n, 'name' => $n ), array_values( array_unique( $names ) ) );
		foreach ( mgmt()['dups'] ?? array() as $n ) {
			// Listed FIRST although newer: the plugin must not rely on the order.
			array_unshift( $list, array( 'id' => 'role_' . $n . '~2', 'name' => $n ) );
		}
		json( array( 'results' => $list ) );

	case '/role' === $path && 'POST' === $_SERVER['REQUEST_METHOD']:
		need_scope( 'create:roles' );
		$body         = json_decode( file_get_contents( 'php://input' ), true );
		$m            = mgmt();
		$m['roles'][] = $body['name'];
		mgmt( $m );
		json( array( 'id' => 'role_' . $body['name'], 'name' => $body['name'] ) );

	case (bool) preg_match( '#^/user/([^/]+)/roles$#', $path, $mt ):
		$sub = urldecode( $mt[1] );
		if ( 'GET' === $_SERVER['REQUEST_METHOD'] ) {
			need_scope( 'read:rolemembers' );
		} else {
			need_scope( 'POST' === $_SERVER['REQUEST_METHOD'] ? 'create:rolemembers' : 'delete:rolemembers' );
			if ( null === roles_of( $sub ) ) {
				json( array( 'error' => 'not_found' ), 404 );
			}
			$body  = json_decode( file_get_contents( 'php://input' ), true );
			$names = array_map( 'role_name', (array) $body['roles'] );
			$m     = mgmt();
			$have  = $m['grants'][ $sub ] ?? array();
			$m['grants'][ $sub ] = array_values( 'POST' === $_SERVER['REQUEST_METHOD'] ? array_unique( array_merge( $have, $names ) ) : array_diff( $have, $names ) );
			if ( 'DELETE' === $_SERVER['REQUEST_METHOD'] ) {
				// A fixed user's own roles can be taken away too.
				foreach ( USERS as $name => $u ) {
					if ( $u[0] === $sub ) {
						file_put_contents( DIR . '/roles_' . $name, implode( ',', array_diff( roles_of( $sub ), $names ) ) );
					}
				}
			}
			mgmt( $m );
		}
		$roles = roles_of( $sub );
		if ( null === $roles ) {
			json( array( 'error' => 'user_not_found' ), 404 );
		}
		json( array_map( fn( $r ) => array( 'id' => 'role_' . $r, 'name' => $r, 'description' => '', 'permissions' => array() ), $roles ) );

	// --- The "dashboard": pretend the admin picked a project and tenant.
	case '/connect/wordpress' === $path:
		foreach ( array( 'site_url', 'return_to', 'state', 'code_challenge' ) as $p ) {
			if ( empty( $_GET[ $p ] ) ) {
				json( array( 'error' => 'invalid_request', 'message' => "missing $p" ), 400 );
			}
		}
		if ( 'S256' !== ( $_GET['code_challenge_method'] ?? '' ) ) {
			json( array( 'error' => 'invalid_request', 'message' => 'S256 only' ), 400 );
		}
		file_put_contents( DIR . '/last_connect', json_encode( $_GET ) );
		$code = bin2hex( random_bytes( 16 ) );
		store( 'handoff_' . $code, array( 'challenge' => $_GET['code_challenge'] ) );
		$sep = false === strpos( $_GET['return_to'], '?' ) ? '?' : '&';
		header( 'Location: ' . $_GET['return_to'] . $sep . http_build_query( array( 'code' => $code, 'state' => $_GET['state'] ) ) );
		http_response_code( 302 );
		exit;

	case '/test/last-connect' === $path:
		json( json_decode( (string) @file_get_contents( DIR . '/last_connect' ), true ) );

	case '/connect/exchange' === $path && 'POST' === $_SERVER['REQUEST_METHOD']:
		$in = json_decode( file_get_contents( 'php://input' ), true );
		$h  = store( 'handoff_' . ( $in['code'] ?? '' ) );
		if ( ! $h ) {
			json( array( 'error' => 'invalid_grant', 'message' => 'Unknown or used code' ), 400 );
		}
		if ( b64u( hash( 'sha256', (string) ( $in['code_verifier'] ?? '' ), true ) ) !== $h['challenge'] ) {
			json( array( 'error' => 'invalid_grant', 'message' => 'PKCE verification failed' ), 400 );
		}
		json( array( 'auth_domain' => ISS, 'client_id' => CLIENT_ID, 'client_secret' => CLIENT_SECRET, 'project_id' => 'project_test', 'account_id' => ACCOUNT ) );
}
json( array( 'error' => 'not_found', 'path' => $path ), 404 );
