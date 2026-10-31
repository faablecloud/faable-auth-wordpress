<?php
/**
 * End-to-end driver: plays the browser (and the operator, through wp-cli)
 * against a real WordPress with the plugin and the fake tenant in idp.php.
 * Run by tests/e2e/run.sh; not meant to be run by hand.
 *
 * @package FaableAuth
 */

const WP  = 'http://wp.test';
const IDP = 'http://idp.test:8080';

$fails = 0;
$count = 0;
function check( string $name, bool $ok, string $detail = '' ): void {
	global $fails, $count;
	$count++;
	if ( ! $ok ) {
		$fails++;
	}
	echo ( $ok ? '  ok   ' : '  FAIL ' ) . $name . ( ! $ok && $detail ? "  -- $detail" : '' ) . "\n";
}

/** A browser: a cookie jar and no automatic redirects. */
final class Browser {
	private string $jar;
	public function __construct() {
		$this->jar = tempnam( sys_get_temp_dir(), 'jar' );
	}
	/** @return array{status:int, location:string, body:string} */
	public function req( string $method, string $url, ?array $post = null, array $headers = array() ): array {
		$ch = curl_init( $url );
		curl_setopt_array(
			$ch,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HEADER         => true,
				CURLOPT_COOKIEJAR      => $this->jar,
				CURLOPT_COOKIEFILE     => $this->jar,
				CURLOPT_CUSTOMREQUEST  => $method,
				CURLOPT_HTTPHEADER     => $headers,
			)
		);
		if ( null !== $post ) {
			curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $post ) );
		}
		$raw  = (string) curl_exec( $ch );
		$hlen = curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
		$head = substr( $raw, 0, $hlen );
		preg_match( '/^Location:\s*(\S+)/mi', $head, $m );
		return array( 'status' => (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE ), 'location' => $m[1] ?? '', 'body' => substr( $raw, $hlen ) );
	}
	public function get( string $url, array $headers = array() ): array {
		return $this->req( 'GET', $url, null, $headers );
	}
	public function post( string $url, array $data ): array {
		return $this->req( 'POST', $url, $data );
	}
	/** Follow redirects, returning every hop. */
	public function follow( string $url, int $max = 8 ): array {
		$hops = array();
		for ( $i = 0; $i < $max; $i++ ) {
			$r      = $this->get( $url );
			$hops[] = array( 'url' => $url ) + $r;
			if ( $r['status'] < 300 || $r['status'] >= 400 || '' === $r['location'] ) {
				break;
			}
			$url = $r['location'];
		}
		return $hops;
	}
}

function q( string $url ): array {
	parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $out );
	return $out;
}
function idp( string $path ): array {
	return json_decode( (string) file_get_contents( IDP . $path ), true ) ?? array();
}
function wp_cli( string $args ): string {
	return trim( (string) shell_exec( 'wp --path=/var/www/html --allow-root ' . $args . ' 2>&1' ) );
}
function faable_login( Browser $b, string $who, string $redirect = '' ): array {
	idp( '/test/next-user?u=' . $who );
	return $b->follow( WP . '/wp-login.php?faable-auth=start' . ( $redirect ? '&redirect_to=' . rawurlencode( $redirect ) : '' ) );
}

echo "Before connecting\n";
$admin = new Browser();
$r     = $admin->get( WP . '/wp-login.php' );
check( 'native login form while not configured', 200 === $r['status'] && str_contains( $r['body'], 'name="pwd"' ) );
$r = $admin->post( WP . '/wp-login.php', array( 'log' => 'admin', 'pwd' => 'admin-pw', 'testcookie' => '1', 'redirect_to' => WP . '/wp-admin/' ) );
check( 'admin logs in with password', 302 === $r['status'] && str_contains( $r['location'], '/wp-admin' ), $r['status'] . ' ' . $r['location'] );

echo "Settings page and Connect with Faable\n";
$r = $admin->get( WP . '/wp-admin/options-general.php?page=faable-auth' );
check( 'settings page renders', 200 === $r['status'] && str_contains( $r['body'], 'Connect with Faable' ) && str_contains( $r['body'], 'wp-login.php?faable-auth=callback' ) );
check( 'settings page documents emergency access', str_contains( $r['body'], 'FAABLE_AUTH_BREAK_GLASS' ) && str_contains( $r['body'], 'wp faable-auth login-link' ) );
preg_match( '/name="action" value="faable_auth_connect".*?name="_wpnonce" value="([^"]+)"/s', $r['body'], $m );
$r = $admin->post( WP . '/wp-admin/admin-post.php', array( 'action' => 'faable_auth_connect', '_wpnonce' => $m[1] ?? '' ) );
$c = q( $r['location'] );
check( 'Connect redirects to the dashboard', 302 === $r['status'] && str_starts_with( $r['location'], IDP . '/connect/wordpress?' ), $r['location'] );
check( 'Connect sends site_url, return_to, state, S256 challenge', 'http://wp.test' === ( $c['site_url'] ?? '' ) && WP . '/wp-admin/admin-post.php?action=faable_auth_connect_return' === ( $c['return_to'] ?? '' ) && 43 === strlen( $c['state'] ?? '' ) && 43 === strlen( $c['code_challenge'] ?? '' ) && 'S256' === ( $c['code_challenge_method'] ?? '' ), json_encode( $c ) );
$hops = $admin->follow( $r['location'] );
$last = end( $hops );
check( 'handoff exchanged and stored', str_contains( $last['body'], 'Connected.' ) && str_contains( $last['body'], 'client_wp' ), substr( strip_tags( $last['body'] ), 0, 300 ) );
check( 'secret never shown on the page', ! str_contains( $last['body'], 'secret_wp_123' ) );
$opt = wp_cli( 'option get faable_auth_settings --format=json' );
check( 'secret stored encrypted', str_contains( $opt, '"client_secret_enc":"fa1:' ) && ! str_contains( $opt, 'secret_wp_123' ) );
$replay = $admin->get( $hops[1]['url'] ?? WP );
$replay = $admin->get( WP . '/wp-admin/options-general.php?page=faable-auth' );
check( 'replayed handoff return is refused', str_contains( $replay['body'], 'expired or was started by someone else' ) );

echo "Faable-only login\n";
$anon = new Browser();
$r    = $anon->get( WP . '/wp-login.php' );
check( 'login page has only the Faable button', str_contains( $r['body'], 'Log in with Faable' ) && ! str_contains( $r['body'], 'name="pwd"' ) );
$r = $anon->post( WP . '/wp-login.php', array( 'log' => 'admin', 'pwd' => 'admin-pw', 'testcookie' => '1' ) );
check( 'password POST does not log in', 200 === $r['status'] && ! str_contains( implode( ',', array( $r['location'] ) ), 'wp-admin' ) );
$r = $anon->get( WP . '/wp-admin/' );
check( '... and wp-admin still redirects to login', 302 === $r['status'] && str_contains( $r['location'], 'wp-login.php' ) );
$r = $anon->get( WP . '/wp-login.php?action=lostpassword' );
check( 'lost password replaced by Faable page', str_contains( $r['body'], 'Log in with Faable' ) && ! str_contains( $r['body'], 'user_login' ) );
$r = $anon->get( WP . '/wp-login.php?action=register' );
check( 'register replaced by Faable page', str_contains( $r['body'], 'Log in with Faable' ) );

$alice = new Browser();
$hops  = faable_login( $alice, 'alice', WP . '/wp-admin/profile.php' );
$auth  = q( $hops[1]['url'] ?? '' );
check( 'start redirects to the tenant /authorize', str_starts_with( $hops[0]['location'], IDP . '/authorize?' ) );
check( 'authorize: code + S256 PKCE + state + nonce', 'code' === ( $auth['response_type'] ?? '' ) && 'S256' === ( $auth['code_challenge_method'] ?? '' ) && ! empty( $auth['state'] ) && ! empty( $auth['nonce'] ) && 'openid profile email' === ( $auth['scope'] ?? '' ) );
check( 'authorize: redirect_uri is the contract one', WP . '/wp-login.php?faable-auth=callback' === ( $auth['redirect_uri'] ?? '' ), $auth['redirect_uri'] ?? '' );
$cb = $hops[2] ?? array( 'status' => 0, 'location' => '' );
check( 'callback logs in and lands on redirect_to', 302 === $cb['status'] && WP . '/wp-admin/profile.php' === $cb['location'], $cb['status'] . ' ' . $cb['location'] . ' ' . substr( strip_tags( $cb['body'] ?? '' ), 0, 200 ) );
$r = $alice->get( WP . '/wp-admin/profile.php' );
check( 'alice is logged in', 200 === $r['status'] && str_contains( $r['body'], 'alice@example.com' ) );
check( 'profile shows no password fields', ! str_contains( $r['body'], 'id="pass1"' ) );
check( 'alice is an editor', 'editor' === wp_cli( 'user get alice --field=roles' ) );
check( 'alice has no usable local password', '*faable-auth*' === wp_cli( 'user get alice --field=user_pass' ) );
check( 'alice is linked to her Faable sub', 'user_alice' === wp_cli( 'user meta get alice faable_auth_sub' ) );

$replay = $alice->get( $hops[2]['url'] );
check( 'replayed callback is refused', 400 === $replay['status'] && str_contains( $replay['body'], 'took too long or was started in another browser' ) );

$mallory = new Browser();
idp( '/test/next-user?u=alice' );
$start   = $mallory->get( WP . '/wp-login.php?faable-auth=start' );
$atk     = $mallory->get( $start['location'] );
$victim  = new Browser();
$r       = $victim->get( $atk['location'] );
check( 'callback from another browser is refused (login CSRF)', 400 === $r['status'] && ! str_contains( $r['location'], 'wp-admin' ) );

echo "Roles\n";
$bob  = new Browser();
$hops = faable_login( $bob, 'bob' );
$last = end( $hops );
check( 'user without a mapped role is refused with an explanation', 403 === $last['status'] && str_contains( $last['body'], 'has no access to this site' ) );
check( '... and gets no account', str_contains( wp_cli( 'user get bob@example.com --field=ID' ), 'Error' ) );

$carol = new Browser();
$hops  = faable_login( $carol, 'carol' );
$last = end( $hops );
check( 'a user whose only role is unmapped gets no account', 403 === $last['status'] && str_contains( wp_cli( 'user get carol@example.com --field=ID' ), 'Error' ) );

$adm = new Browser();
faable_login( $adm, 'admin' );
check( 'existing WP admin linked by verified email, not duplicated', 'user_admin' === wp_cli( 'user meta get 1 faable_auth_sub' ) && '1' === wp_cli( 'user list --search=admin@example.com --field=ID' ) );

idp( '/test/set-roles?u=alice&r=author' );
faable_login( new Browser(), 'alice' );
check( 're-sync: alice demoted to author on next login', 'author' === wp_cli( 'user get alice --field=roles' ) );
idp( '/test/set-roles?u=alice&r=' );
$hops = faable_login( new Browser(), 'alice' );
check( 're-sync: alice loses every role and is refused', 403 === end( $hops )['status'] && '' === wp_cli( 'user get alice --field=roles' ) );
$r = $alice->get( WP . '/wp-admin/profile.php' );
check( "... and her open session is gone", 302 === $r['status'] );
idp( '/test/set-roles?u=alice&r=editor' );
check( 'management token cached: one client_credentials for all logins', 1 === ( idp( '/test/cc-count' )['count'] ?? 0 ), json_encode( idp( '/test/cc-count' ) ) );

echo "Password back doors\n";
$x = new Browser();
$r = $x->req( 'POST', WP . '/xmlrpc.php', null, array( 'Content-Type: text/xml' ) );
$xml = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>admin-pw</value></param></params></methodCall>';
$ch  = curl_init( WP . '/xmlrpc.php' );
curl_setopt_array( $ch, array( CURLOPT_POST => true, CURLOPT_POSTFIELDS => $xml, CURLOPT_RETURNTRANSFER => true ) );
$out = (string) curl_exec( $ch );
check( 'XML-RPC refuses authenticated calls', str_contains( $out, 'faultCode' ) && ! str_contains( $out, 'blogid' ) );
$r = $x->get( WP . '/wp-json/wp/v2/users/me', array( 'Authorization: Basic ' . base64_encode( 'admin:admin-pw' ) ) );
check( 'REST Basic auth with the password refused', 401 === $r['status'] );
$r = $x->get( WP . '/wp-json/' );
check( 'Application Passwords not advertised', ! str_contains( $r['body'], 'authorize-application.php' ) );

echo "REST with M2M tokens\n";
wp_cli( 'user create headless headless@example.com --role=editor' );
wp_cli( 'option patch insert faable_auth_settings rest_audience https://wp.example.com/api' );
wp_cli( 'option patch insert faable_auth_settings rest_user headless' );
$tok = idp( '/test/m2m?client=client_next&aud=' . rawurlencode( 'https://wp.example.com/api' ) )['access_token'];
$r   = $x->get( WP . '/wp-json/wp/v2/users/me?context=edit', array( 'Authorization: Bearer ' . $tok ) );
check( 'M2M token authenticates as the configured user', 200 === $r['status'] && 'headless' === ( json_decode( $r['body'], true )['username'] ?? '' ), $r['status'] . ' ' . substr( $r['body'], 0, 200 ) );
$r = $x->get( WP . '/wp-json/wp/v2/posts?status=draft', array( 'Authorization: Bearer ' . $tok ) );
check( '... with that user\'s capabilities (drafts readable)', 200 === $r['status'] );
$bad = idp( '/test/m2m?client=client_next&aud=' . rawurlencode( 'https://other.api' ) )['access_token'];
$r   = $x->get( WP . '/wp-json/wp/v2/users/me', array( 'Authorization: Bearer ' . $bad ) );
check( 'token for another audience is 401', 401 === $r['status'] );
$r = $x->get( WP . '/wp-json/wp/v2/users/me', array( 'Authorization: Bearer ' . substr( $tok, 0, -4 ) . 'AAAA' ) );
check( 'tampered token is 401', 401 === $r['status'] );
wp_cli( 'option patch insert faable_auth_settings rest_clients client_other' );
$r = $x->get( WP . '/wp-json/wp/v2/users/me', array( 'Authorization: Bearer ' . $tok ) );
check( 'client not in the allow-list is 403', 403 === $r['status'] );
wp_cli( 'option patch update faable_auth_settings rest_clients client_next' );
wp_cli( 'option patch insert faable_auth_settings rest_scope wp:write' );
$r = $x->get( WP . '/wp-json/wp/v2/users/me', array( 'Authorization: Bearer ' . $tok ) );
check( 'token without the required scope is 403', 403 === $r['status'] );
wp_cli( 'option patch update faable_auth_settings rest_scope wp:read' );
$r = $x->get( WP . '/wp-json/wp/v2/users/me', array( 'Authorization: Bearer ' . $tok ) );
check( 'token with the required permission is 200', 200 === $r['status'] );

echo "Emergency access\n";
$link = wp_cli( 'faable-auth login-link admin' );
check( 'login-link prints a URL', str_starts_with( $link, WP . '/wp-login.php?faable-auth=link' ), $link );
$e = new Browser();
$r = $e->get( $link );
check( 'link GET only shows a confirmation (previewers do not burn it)', 200 === $r['status'] && str_contains( $r['body'], 'Emergency login as admin' ) );
$p = q( $link );
$r = $e->post( WP . '/wp-login.php', array( 'faable-auth' => 'link', 'u' => $p['u'], 't' => $p['t'] ) );
check( 'link POST logs in', 302 === $r['status'] && str_contains( $r['location'], '/wp-admin' ) );
check( '... as admin', 200 === $e->get( WP . '/wp-admin/options-general.php' )['status'] );
$r = ( new Browser() )->post( WP . '/wp-login.php', array( 'faable-auth' => 'link', 'u' => $p['u'], 't' => $p['t'] ) );
check( 'link works once', 403 === $r['status'] );

echo '    ' . wp_cli( 'config set FAABLE_AUTH_BREAK_GLASS true --raw' ) . "\n";
sleep( 3 ); // opcache revalidates wp-config.php every 2 s in the official image.
$bg = new Browser();
$r  = $bg->get( WP . '/wp-login.php' );
check( 'break glass: password form is back, with the Faable button', str_contains( $r['body'], 'name="pwd"' ) && str_contains( $r['body'], 'Log in with Faable' ) && str_contains( $r['body'], 'Emergency access is on' ) );
$r = $bg->post( WP . '/wp-login.php', array( 'log' => 'admin', 'pwd' => 'admin-pw', 'testcookie' => '1', 'redirect_to' => WP . '/wp-admin/' ) );
check( 'break glass: admin logs in with password', 302 === $r['status'] && str_contains( $r['location'], '/wp-admin' ), $r['status'] );
wp_cli( 'config delete FAABLE_AUTH_BREAK_GLASS' );
sleep( 3 );
$r = ( new Browser() )->get( WP . '/wp-login.php' );
check( 'break glass off again: Faable only', ! str_contains( $r['body'], 'name="pwd"' ) );

echo "Env configuration (Faable hosting)\n";
$st = trim( (string) shell_exec( 'FAABLE_AUTH_DOMAIN=http://idp.test:8080 FAABLE_AUTH_CLIENT_ID=client_env FAABLE_AUTH_CLIENT_SECRET=s wp --path=/var/www/html --allow-root faable-auth status --format=json 2>&1' ) );
check( 'env vars win over settings', str_contains( $st, '"value":"client_env","source":"env\/constant"' ) && ! str_contains( $st, '"s"' ), $st );

echo "Managed mode (Faable hosting)\n";
// What the overlay does: the connection in constants/env + FAABLE_AUTH_MANAGED.
// A stale option from a former manual connection must be ignored.
wp_cli( 'option patch update faable_auth_settings client_id client_stale' );
wp_cli( "config set FAABLE_AUTH_DOMAIN 'http://idp.test:8080'" );
wp_cli( 'config set FAABLE_AUTH_CLIENT_ID client_wp' );
wp_cli( 'config set FAABLE_AUTH_CLIENT_SECRET secret_wp_123' );
wp_cli( 'config set FAABLE_AUTH_MANAGED true --raw' );
wp_cli( 'config set FAABLE_AUTH_PROJECT_ID project_6a8ebd6160324d4631c12edc' );
wp_cli( 'config set FAABLE_AUTH_ACCOUNT_ID account_6aab075db8185a5d3bd64caf' );
wp_cli( 'option patch update faable_auth_settings account_id account_000000000000000000000bad' );
sleep( 3 );
$st = wp_cli( 'faable-auth status --format=json' );
check( 'status says managed, client from constants', str_contains( $st, 'yes (Faable hosting)' ) && str_contains( $st, '"value":"client_wp","source":"env\/constant"' ), $st );
$r = $e->get( WP . '/wp-admin/options-general.php?page=faable-auth' );
check( 'settings page says Managed by Faable', 200 === $r['status'] && str_contains( $r['body'], 'Managed by Faable' ) && str_contains( $r['body'], 'this site signs in with Faable Auth.' ), substr( strip_tags( $r['body'] ), 0, 300 ) );
check( '... with no Connect or Disconnect', ! str_contains( $r['body'], 'value="faable_auth_connect"' ) && ! str_contains( $r['body'], 'value="faable_auth_disconnect"' ) );
check( '... and the connection read-only (no domain/client/secret inputs)', ! str_contains( $r['body'], 'name="faable_auth[domain]"' ) && ! str_contains( $r['body'], 'name="faable_auth[client_id]"' ) && ! str_contains( $r['body'], 'name="faable_auth[client_secret]"' ) && str_contains( $r['body'], 'client_wp' ) && ! str_contains( $r['body'], 'client_stale' ) );
check( '... with the tenant link from the platform env, not the stale option', str_contains( $r['body'], 'href="https://dashboard.faable.com/auth/project_6a8ebd6160324d4631c12edc/account/account_6aab075db8185a5d3bd64caf"' ) && ! str_contains( $r['body'], 'account_000000000000000000000bad' ) && str_contains( $r['body'], 'Manage users and roles in Faable' ) );
check( '... and the documentation link', str_contains( $r['body'], 'href="https://faable.com/docs/auth/integrations/wordpress"' ) );
check( '... the role map stays editable', (bool) preg_match( '/<textarea name="faable_auth\[role_map\]"[^>]*>/', $r['body'], $ta ) && ! str_contains( $ta[0] ?? '', 'readonly' ) );
preg_match( '/name="action" value="faable_auth_save".*?name="_wpnonce" value="([^"]+)"/s', $r['body'], $m );
$r = $e->post( WP . '/wp-admin/admin-post.php', array( 'action' => 'faable_auth_save', '_wpnonce' => $m[1] ?? '', 'faable_auth' => array( 'domain' => 'https://evil.example', 'client_id' => 'client_evil', 'client_secret' => 'evil', 'role_map' => "editor = editor\nstaff = author" ) ) );
$opt = wp_cli( 'option get faable_auth_settings --format=json' );
check( 'save ignores domain/client/secret but keeps the role map', 302 === $r['status'] && ! str_contains( $opt, 'client_evil' ) && ! str_contains( $opt, 'evil.example' ) && str_contains( $opt, 'staff = author' ), $r['status'] . ' ' . $opt );
$r = ( new Browser() )->get( WP . '/wp-login.php' );
check( 'managed: Faable-only login', str_contains( $r['body'], 'Log in with Faable' ) && ! str_contains( $r['body'], 'name="pwd"' ) );
check( 'the login button carries the Faable emblem on a white disc', (bool) preg_match( '/<a [^>]*faable-auth-button[^>]*><span class="faable-auth-emblem-disc"[^>]*background:#fff[^>]*><img class="faable-auth-emblem" src="data:image\/png;base64,[A-Za-z0-9+\/=]{100,}"/', $r['body'] ) );
$hops = faable_login( new Browser(), 'alice' );
check( 'managed: alice signs in through the platform client', 302 === ( $hops[2]['status'] ?? 0 ) && str_contains( $hops[2]['location'] ?? '', '/wp-admin' ), json_encode( array_map( static fn( $h ) => $h['status'] . ' ' . $h['location'], $hops ) ) );
$alice_id = trim( wp_cli( 'user get alice --field=ID' ) );
$r        = $e->get( WP . '/wp-admin/user-edit.php?user_id=' . $alice_id );
check( 'profile: alice is Managed by Faable Auth', str_contains( $r['body'], 'Managed by Faable Auth' ) );
check( '... with her page in the Faable dashboard', str_contains( $r['body'], 'href="https://dashboard.faable.com/auth/project_6a8ebd6160324d4631c12edc/account/account_6aab075db8185a5d3bd64caf/user/user_alice"' ) );

echo "\nLocal users with Application Passwords\n";
wp_cli( 'user create svc svc@example.com --role=editor' );
wp_cli( "config set FAABLE_AUTH_APP_PASSWORD_USERS 'svc,alice'" );
sleep( 3 );
$svc_pw   = wp_cli( 'user application-password create svc front --porcelain' );
$alice_pw = wp_cli( 'user application-password create alice front --porcelain' );
$rest     = static fn( string $u, string $p ) => ( new Browser() )->get( WP . '/wp-json/wp/v2/users/me?context=edit', array( 'Authorization: Basic ' . base64_encode( "$u:$p" ) ) );
$r        = $rest( 'svc', $svc_pw );
check( 'listed local user: the REST API accepts its Application Password', 200 === $r['status'] && str_contains( $r['body'], '"username":"svc"' ), $r['status'] . ' ' . substr( $r['body'], 0, 200 ) . ' pw=' . strlen( $svc_pw ) );
$r = $rest( 'alice', $alice_pw );
check( 'listed but a Faable user: refused', 401 === $r['status'] || ! str_contains( $r['body'], '"username":"alice"' ), $r['status'] . ' ' . substr( $r['body'], 0, 200 ) );
$r = ( new Browser() )->post( WP . '/wp-login.php', array( 'log' => 'svc', 'pwd' => $svc_pw, 'testcookie' => '1', 'redirect_to' => WP . '/wp-admin/' ) );
check( 'the Application Password does not log in to wp-admin', ! ( 302 === $r['status'] && str_contains( $r['location'], '/wp-admin' ) ), $r['status'] . ' ' . $r['location'] );
$r = $e->get( WP . '/wp-admin/user-edit.php?user_id=' . trim( wp_cli( 'user get svc --field=ID' ) ) );
check( 'profile: svc is a Local service user', str_contains( $r['body'], 'Local service user' ) && ! str_contains( $r['body'], 'Managed by Faable Auth' ) );
$r = $e->get( WP . '/wp-admin/users.php' );
check( 'users list: Sign-in column', str_contains( $r['body'], 'Service (Application Password)' ) && str_contains( $r['body'], '>Faable Auth<' ) );
wp_cli( 'config delete FAABLE_AUTH_APP_PASSWORD_USERS' );
sleep( 3 );
$r = $rest( 'svc', $svc_pw );
check( 'not listed: the same Application Password is refused', 401 === $r['status'], $r['status'] . ' ' . substr( $r['body'], 0, 200 ) );

// Managed but the platform's client id missing: never fall back to the option.
wp_cli( 'config delete FAABLE_AUTH_CLIENT_ID' );
sleep( 3 );
$st = wp_cli( 'faable-auth status --format=json' );
check( 'managed without env: the stored client is not used', ! str_contains( $st, 'client_stale' ) && str_contains( $st, '"value":"native"' ), $st );
$r = $e->get( WP . '/wp-admin/options-general.php?page=faable-auth' );
check( '... the page says the managed configuration is incomplete', str_contains( $r['body'], 'configuration is incomplete' ) && ! str_contains( $r['body'], 'value="faable_auth_connect"' ) );
preg_match( '/name="action" value="faable_auth_save".*?name="_wpnonce" value="([^"]+)"/s', $r['body'], $m );
$e->post( WP . '/wp-admin/admin-post.php', array( 'action' => 'faable_auth_save', '_wpnonce' => $m[1] ?? '', 'faable_auth' => array( 'client_id' => 'client_evil' ) ) );
check( '... and a posted client id is still ignored', ! str_contains( wp_cli( 'option get faable_auth_settings --format=json' ), 'client_evil' ) );
foreach ( array( 'FAABLE_AUTH_MANAGED', 'FAABLE_AUTH_DOMAIN', 'FAABLE_AUTH_CLIENT_SECRET', 'FAABLE_AUTH_PROJECT_ID', 'FAABLE_AUTH_ACCOUNT_ID' ) as $c ) {
	wp_cli( "config delete $c" );
}

echo "\n$count checks, $fails failed\n";
exit( $fails ? 1 : 0 );
