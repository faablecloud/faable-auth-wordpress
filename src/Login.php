<?php
/**
 * wp-login.php through Faable Auth: the OIDC Authorization Code flow with
 * PKCE, state and nonce, user provisioning, role sync, and the lockdown of
 * every password-based way in.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Login handling.
 */
final class Login {

	const FLOW_TTL    = 10 * MINUTE_IN_SECONDS;
	const COOKIE      = 'faable_auth_flow_';
	const META_SUB    = 'faable_auth_sub';
	const META_ISS    = 'faable_auth_iss';
	const META_IDTOK  = 'faable_auth_id_token';
	const UNUSABLE_PW = '*faable-auth*';

	/** The login buttons: full width, emblem and label centred on one line. */
	const BUTTON_STYLE = 'width:100%;display:inline-flex;align-items:center;justify-content:center;gap:8px;text-align:center';

	/**
	 * The Faable emblem for the login buttons, inlined as a data URI: a host
	 * may load the plugin from outside the web root (Faable hosting loads it
	 * from its image), where a plugins_url() would point at nothing.
	 */
	public static function emblem(): string {
		static $img = null;
		if ( null === $img ) {
			$file = dirname( FAABLE_AUTH_FILE ) . '/assets/faable-emblem.png';
			$png  = is_readable( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local file of the plugin.
			$img  = '' === $png ? '' : '<img class="faable-auth-emblem" src="data:image/png;base64,' . base64_encode( $png ) . '" alt="" width="20" height="20" style="flex:none" />'; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- an image data URI.
		}
		return $img;
	}

	/**
	 * Current login mode.
	 */
	public static function mode(): string {
		return BreakGlass::login_mode( Config::is_configured(), BreakGlass::from_environment() );
	}

	/**
	 * Register hooks.
	 */
	public static function init(): void {
		add_action( 'login_init', array( __CLASS__, 'route' ), 1 );

		if ( ! Config::is_configured() ) {
			return;
		}

		// Never, in any mode once configured: XML-RPC authentication. And no
		// Application Passwords (headless clients use Faable M2M tokens),
		// except for the local users the site lists on purpose
		// (FAABLE_AUTH_APP_PASSWORD_USERS): a front-end that already calls the
		// REST API with one keeps working while it moves to M2M.
		add_filter( 'xmlrpc_enabled', '__return_false', 99 );
		$app_password_users = Config::app_password_users();
		add_filter( 'wp_is_application_passwords_available', $app_password_users ? '__return_true' : '__return_false', 99 );
		add_filter( 'wp_is_application_passwords_available_for_user', array( __CLASS__, 'app_passwords_for_user' ), 99, 2 );

		add_action( 'login_form', array( __CLASS__, 'render_button_in_form' ) );
		add_filter( 'logout_redirect', array( __CLASS__, 'logout_redirect' ), 99, 3 );

		if ( BreakGlass::passwords_allowed( self::mode() ) ) {
			return;
		}
		// Faable-only: no password ever authenticates, wherever wp_signon()
		// is called from (wp-login.php, a shop's account form, a plugin).
		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
		if ( ! $app_password_users ) {
			remove_filter( 'authenticate', 'wp_authenticate_application_password', 20 );
		}
		add_filter( 'authenticate', array( __CLASS__, 'refuse_passwords' ), 99, 3 );
		add_filter( 'allow_password_reset', '__return_false', 99 );
		add_filter( 'show_password_fields', '__return_false', 99 );
		add_filter( 'wp_pre_insert_user_data', array( __CLASS__, 'keep_password_unusable' ), 10, 4 );
		add_filter( 'option_users_can_register', '__return_zero', 99 );
	}

	/**
	 * Route wp-login.php requests.
	 */
	public static function route(): void {
		// phpcs:disable WordPress.Security.NonceVerification -- OAuth callback and one-time links carry their own CSRF protection (state + browser binding, single-use token).
		$fa = isset( $_REQUEST['faable-auth'] ) ? sanitize_key( wp_unslash( $_REQUEST['faable-auth'] ) ) : '';
		if ( 'link' === $fa ) {
			LoginLink::handle();
			return;
		}
		$mode = self::mode();
		if ( BreakGlass::MODE_NATIVE === $mode ) {
			return;
		}
		if ( 'start' === $fa ) {
			self::start();
		}
		if ( 'callback' === $fa ) {
			self::callback();
		}
		if ( BreakGlass::MODE_BOTH === $mode ) {
			return;
		}
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		// phpcs:enable
		if ( in_array( $action, array( 'login', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register' ), true ) ) {
			self::render_login_page();
		}
		// Everything else (logout, postpass, confirmaction, …) stays native.
	}

	/**
	 * The "Log in with Faable" URL.
	 *
	 * @param string $redirect_to Where to land after login.
	 */
	public static function start_url( string $redirect_to = '' ): string {
		$args = array( 'faable-auth' => 'start' );
		if ( '' !== $redirect_to ) {
			$args['redirect_to'] = rawurlencode( $redirect_to );
		}
		return add_query_arg( $args, wp_login_url() );
	}

	/**
	 * Begin the Authorization Code flow.
	 */
	private static function start(): void {
		$oidc      = Oidc::configured();
		$authorize = $oidc->endpoint( 'authorization_endpoint', '/authorize' );
		if ( is_wp_error( $authorize ) ) {
			self::fail( 'unavailable', $authorize );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
		$state       = Pkce::random();
		$verifier    = Pkce::random();
		$nonce       = Pkce::random();
		$binding     = Pkce::random();

		set_transient(
			Pkce::storage_key( 'login', $state ),
			array(
				'state'       => $state,
				'verifier'    => $verifier,
				'nonce'       => $nonce,
				'binding'     => hash( 'sha256', $binding ),
				'redirect_to' => $redirect_to,
				'expires'     => time() + self::FLOW_TTL,
			),
			self::FLOW_TTL
		);
		self::set_cookie( self::cookie_name( $state ), $binding, time() + self::FLOW_TTL );

		$params = array(
			'response_type'         => 'code',
			'client_id'             => Config::get( 'FAABLE_AUTH_CLIENT_ID' ),
			'redirect_uri'          => Config::redirect_uri(),
			'scope'                 => 'openid profile email',
			'state'                 => $state,
			'nonce'                 => $nonce,
			'code_challenge'        => Pkce::challenge( $verifier ),
			'code_challenge_method' => 'S256',
		);
		$audience = Config::get( 'FAABLE_AUTH_AUDIENCE' );
		if ( '' !== $audience ) {
			$params['audience'] = $audience;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['prompt'] ) && 'select_account' === $_GET['prompt'] ) {
			$params['prompt'] = 'select_account';
		}
		$params = apply_filters( 'faable_auth_authorize_params', $params );
		// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the tenant is another host by design.
		wp_redirect( $authorize . ( false === strpos( $authorize, '?' ) ? '?' : '&' ) . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 ) );
		exit;
	}

	/**
	 * Handle the redirect back from Faable Auth.
	 */
	private static function callback(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- state + browser binding are the CSRF protection here.
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$error = isset( $_GET['error'] ) ? sanitize_key( wp_unslash( $_GET['error'] ) ) : '';
		$iss   = isset( $_GET['iss'] ) ? esc_url_raw( wp_unslash( $_GET['iss'] ) ) : '';
		// phpcs:enable

		$key  = Pkce::storage_key( 'login', $state );
		$flow = '' !== $state ? get_transient( $key ) : false;
		if ( false !== $flow ) {
			delete_transient( $key ); // Single use, whatever happens next.
		}
		$cookie  = self::cookie_name( $state );
		$binding = isset( $_COOKIE[ $cookie ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ $cookie ] ) ) : null;
		self::set_cookie( $cookie, '', time() - YEAR_IN_SECONDS );

		$problem = Pkce::check_flow( $flow, $state, $binding );
		if ( null !== $problem ) {
			self::fail( 'state', new \WP_Error( $problem, $problem ) );
		}
		$oidc = Oidc::configured();
		// RFC 9207: Faable Auth sends `iss` with every authorization response.
		if ( '' !== $iss && untrailingslashit( $iss ) !== $oidc->issuer() ) {
			self::fail( 'state', new \WP_Error( 'iss_mismatch', 'iss mismatch' ) );
		}
		if ( '' !== $error ) {
			self::fail( 'access_denied' === $error ? 'cancelled' : 'provider', new \WP_Error( $error, $error ) );
		}
		if ( '' === $code ) {
			self::fail( 'provider', new \WP_Error( 'no_code', 'no code' ) );
		}

		$tokens = $oidc->exchange_code( $code, (string) $flow['verifier'] );
		if ( is_wp_error( $tokens ) ) {
			self::fail( 'provider', $tokens );
		}
		$client_id = Config::get( 'FAABLE_AUTH_CLIENT_ID' );
		$claims    = $oidc->verify(
			(string) ( $tokens['id_token'] ?? '' ),
			array(
				'aud'   => $client_id,
				'azp'   => $client_id,
				'nonce' => (string) $flow['nonce'],
			)
		);
		if ( is_wp_error( $claims ) ) {
			self::fail( 'provider', $claims );
		}
		if ( empty( $claims['sub'] ) || ! is_string( $claims['sub'] ) ) {
			self::fail( 'provider', new \WP_Error( 'no_sub', 'no sub' ) );
		}

		$roles = self::roles_for( $oidc, $claims, (string) ( $tokens['access_token'] ?? '' ) );
		if ( is_wp_error( $roles ) ) {
			self::fail( 'roles', $roles );
		}

		$user = self::provision( $claims, $roles );
		if ( is_wp_error( $user ) ) {
			self::fail( $user->get_error_code(), $user );
		}

		update_user_meta( $user->ID, self::META_IDTOK, (string) $tokens['id_token'] );
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false, is_ssl() );
		do_action( 'wp_login', $user->user_login, $user );

		$requested = (string) ( $flow['redirect_to'] ?? '' );
		$fallback  = user_can( $user, 'edit_posts' ) ? admin_url() : home_url( '/' );
		$redirect  = wp_validate_redirect( '' !== $requested ? $requested : $fallback, $fallback );
		$redirect  = apply_filters( 'login_redirect', $redirect, $requested, $user );
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Faable Auth role names of the user.
	 *
	 * In order: the ID token's `roles` claim (present when the site requests
	 * an audience whose API includes roles in the ID token), the access
	 * token's (same, `include_roles_in_access_token`), and otherwise the
	 * tenant's Management API. Fails closed: no roles readable = no login.
	 *
	 * @param Oidc   $oidc         Client.
	 * @param array  $claims       Verified ID token claims.
	 * @param string $access_token Access token.
	 * @return string[]|\WP_Error
	 */
	private static function roles_for( Oidc $oidc, array $claims, string $access_token ) {
		if ( isset( $claims['roles'] ) && is_array( $claims['roles'] ) ) {
			return array_values( array_filter( $claims['roles'], 'is_string' ) );
		}
		$audience = Config::get( 'FAABLE_AUTH_AUDIENCE' );
		if ( '' !== $audience && Jwt::looks_like_jwt( $access_token ) ) {
			$at = $oidc->verify( $access_token, array( 'aud' => $audience ) );
			if ( ! is_wp_error( $at ) && ( $at['sub'] ?? null ) === $claims['sub'] && isset( $at['roles'] ) && is_array( $at['roles'] ) ) {
				return array_values( array_filter( $at['roles'], 'is_string' ) );
			}
		}
		return $oidc->user_roles( (string) $claims['sub'] );
	}

	/**
	 * Find, link or create the WordPress user and sync its role.
	 *
	 * @param array    $claims ID token claims.
	 * @param string[] $roles  Faable Auth roles.
	 * @return \WP_User|\WP_Error
	 */
	private static function provision( array $claims, array $roles ) {
		$sub    = (string) $claims['sub'];
		$iss    = Config::domain();
		$email  = isset( $claims['email'] ) && is_string( $claims['email'] ) ? sanitize_email( $claims['email'] ) : '';
		$verified = ! empty( $claims['email_verified'] );

		$wp_role = RoleMapper::resolve( $roles, Config::role_map(), array_keys( wp_roles()->get_names() ) );
		$wp_role = apply_filters( 'faable_auth_wp_role', $wp_role, $claims, $roles );

		$user = self::find_linked( $sub, $iss );
		if ( ! $user && '' !== $email && $verified ) {
			$by_email = get_user_by( 'email', $email );
			if ( $by_email && '' === (string) get_user_meta( $by_email->ID, self::META_SUB, true ) ) {
				$user = $by_email; // Link an account that predates the plugin.
			}
		}

		if ( null === $wp_role || '' === $wp_role ) {
			if ( $user ) {
				// Re-sync: the role was taken away in Faable Auth.
				$user->set_role( '' );
				\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
			}
			return new \WP_Error( 'no_role', 'no mapped role' );
		}

		if ( ! $user ) {
			if ( '' === $email ) {
				return new \WP_Error( 'no_email', 'no email' );
			}
			if ( get_user_by( 'email', $email ) ) {
				// Taken by another account, and Faable did not verify this email.
				return new \WP_Error( 'email_taken', 'email in use' );
			}
			$user_id = wp_insert_user(
				array(
					'user_login'   => self::unique_login( $claims, $email ),
					'user_email'   => $email,
					'user_pass'    => wp_generate_password( 64, true, true ),
					'display_name' => sanitize_text_field( (string) ( $claims['name'] ?? '' ) ),
					'first_name'   => sanitize_text_field( (string) ( $claims['given_name'] ?? '' ) ),
					'last_name'    => sanitize_text_field( (string) ( $claims['family_name'] ?? '' ) ),
					'role'         => $wp_role,
				)
			);
			if ( is_wp_error( $user_id ) ) {
				return new \WP_Error( 'provision', $user_id->get_error_message() );
			}
			self::make_password_unusable( (int) $user_id );
			$user = get_user_by( 'id', $user_id );
			do_action( 'faable_auth_user_created', $user, $claims );
		} elseif ( ! in_array( $wp_role, (array) $user->roles, true ) || count( (array) $user->roles ) > 1 ) {
			$user->set_role( $wp_role );
		}

		update_user_meta( $user->ID, self::META_SUB, $sub );
		update_user_meta( $user->ID, self::META_ISS, $iss );
		do_action( 'faable_auth_user_synced', $user, $claims, $roles, $wp_role );
		return $user;
	}

	/**
	 * The user linked to a Faable Auth subject.
	 *
	 * @param string $sub Subject.
	 * @param string $iss Issuer.
	 */
	private static function find_linked( string $sub, string $iss ): ?\WP_User {
		$found = get_users(
			array(
				'meta_key'   => self::META_SUB, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value' => $sub, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'     => 5,
			)
		);
		foreach ( $found as $u ) {
			$u_iss = (string) get_user_meta( $u->ID, self::META_ISS, true );
			if ( '' === $u_iss || $u_iss === $iss ) {
				return $u;
			}
		}
		return null;
	}

	/**
	 * A free user_login.
	 *
	 * @param array  $claims Claims.
	 * @param string $email  Email.
	 */
	private static function unique_login( array $claims, string $email ): string {
		$base = sanitize_user( (string) ( $claims['preferred_username'] ?? '' ), true );
		if ( '' === $base ) {
			$base = sanitize_user( strstr( $email, '@', true ), true );
		}
		if ( '' === $base ) {
			$base = 'faable';
		}
		$base  = substr( $base, 0, 50 );
		$login = $base;
		for ( $i = 2; username_exists( $login ); $i++ ) {
			$login = $base . $i;
		}
		return $login;
	}

	/**
	 * Store a hash no password can match, so a removed plugin leaves no usable
	 * local password behind.
	 *
	 * @param int $user_id User.
	 */
	private static function make_password_unusable( int $user_id ): void {
		global $wpdb;
		$wpdb->update( $wpdb->users, array( 'user_pass' => self::UNUSABLE_PW ), array( 'ID' => $user_id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		clean_user_cache( $user_id );
	}

	/**
	 * In Faable-only mode, a linked user's profile update must not set a
	 * local password through any form that slipped past show_password_fields.
	 *
	 * @param array    $data     User data.
	 * @param bool     $update   Update.
	 * @param int|null $user_id  User.
	 * @param array    $userdata Raw data.
	 */
	public static function keep_password_unusable( $data, $update, $user_id, $userdata = array() ) {
		if ( $update && $user_id && get_user_meta( (int) $user_id, self::META_SUB, true ) && isset( $data['user_pass'] ) ) {
			$current = get_userdata( (int) $user_id );
			if ( $current && self::UNUSABLE_PW === $current->user_pass ) {
				$data['user_pass'] = self::UNUSABLE_PW;
			}
		}
		return $data;
	}

	/**
	 * A local user listed in FAABLE_AUTH_APP_PASSWORD_USERS that has never
	 * signed in with Faable (once linked, Faable is its only way in).
	 *
	 * @param \WP_User $user User.
	 */
	public static function is_local_service_user( \WP_User $user ): bool {
		return $user->ID > 0
			&& in_array( strtolower( $user->user_login ), Config::app_password_users(), true )
			&& '' === (string) get_user_meta( $user->ID, self::META_SUB, true );
	}

	/**
	 * `wp_is_application_passwords_available_for_user`: only the listed local users.
	 *
	 * @param bool     $available Available so far.
	 * @param \WP_User $user      User.
	 */
	public static function app_passwords_for_user( $available, $user ) {
		return $available && $user instanceof \WP_User && self::is_local_service_user( $user );
	}

	/**
	 * `authenticate` filter for Faable-only mode.
	 *
	 * @param mixed  $user     Result so far.
	 * @param string $username Username.
	 * @param string $password Password.
	 */
	public static function refuse_passwords( $user, $username, $password ) {
		// An Application Password of a listed local user, checked by core
		// (REST API requests only) at priority 20: the one password that passes.
		if ( $user instanceof \WP_User && self::is_local_service_user( $user ) && did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}
		if ( '' !== (string) $username || '' !== (string) $password ) {
			return new \WP_Error( 'faable_auth_only', __( 'This site signs in with Faable only.', 'faable-auth' ) );
		}
		return $user;
	}

	/**
	 * Federated logout: send the browser to the tenant's end_session_endpoint.
	 *
	 * @param string   $redirect_to Redirect.
	 * @param string   $requested   Requested redirect.
	 * @param \WP_User $user        User logging out.
	 */
	public static function logout_redirect( $redirect_to, $requested, $user ) {
		if ( ! Config::federated_logout() || ! ( $user instanceof \WP_User ) || ! $user->ID ) {
			return $redirect_to;
		}
		$hint = (string) get_user_meta( $user->ID, self::META_IDTOK, true );
		delete_user_meta( $user->ID, self::META_IDTOK );
		$end = Oidc::configured()->endpoint( 'end_session_endpoint', '/logout' );
		if ( '' === $hint || is_wp_error( $end ) ) {
			return $redirect_to;
		}
		$url = add_query_arg(
			array(
				'id_token_hint'            => rawurlencode( $hint ),
				'client_id'                => rawurlencode( Config::get( 'FAABLE_AUTH_CLIENT_ID' ) ),
				'post_logout_redirect_uri' => rawurlencode( home_url( '/wp-login.php?loggedout=true' ) ),
			),
			$end
		);
		// wp_safe_redirect() would refuse the tenant's host.
		add_filter(
			'allowed_redirect_hosts',
			static function ( $hosts ) use ( $end ) {
				$hosts[] = (string) wp_parse_url( $end, PHP_URL_HOST );
				return $hosts;
			}
		);
		return $url;
	}

	/**
	 * Faable button inside the native form (break-glass mode).
	 */
	public static function render_button_in_form(): void {
		if ( BreakGlass::MODE_BOTH !== self::mode() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		echo '<p class="faable-auth-break-glass" style="margin:0 0 16px;padding:8px;background:#fcf0f1;border-left:4px solid #d63638">'
			. esc_html__( 'Emergency access is on (FAABLE_AUTH_BREAK_GLASS). Turn it off once Faable Auth is back.', 'faable-auth' )
			. '</p>';
		echo '<p style="margin-bottom:16px"><a class="button button-large faable-auth-button" style="' . esc_attr( self::BUTTON_STYLE ) . '" href="' . esc_url( self::start_url( $redirect_to ) ) . '">'
			. self::emblem() . esc_html__( 'Log in with Faable', 'faable-auth' ) . '</a></p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- emblem() is a fixed <img> built from our own file.
	}

	/**
	 * The login page in Faable-only mode.
	 *
	 * @param string $error_code Error to show (see messages()).
	 * @param int    $status     HTTP status.
	 */
	public static function render_login_page( string $error_code = '', int $status = 200 ): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		$interim     = ! empty( $_REQUEST['interim-login'] );
		$logged_out  = ! empty( $_GET['loggedout'] );
		// phpcs:enable
		status_header( $status );
		nocache_headers();

		$errors = new \WP_Error();
		if ( '' !== $error_code ) {
			$errors->add( 'faable_auth_' . $error_code, esc_html( self::messages()[ $error_code ] ?? self::messages()['provider'] ) );
		} elseif ( $logged_out ) {
			$errors->add( 'loggedout', esc_html__( 'You are now logged out.', 'faable-auth' ), 'message' );
		}

		if ( function_exists( 'login_header' ) ) {
			login_header( __( 'Log In', 'faable-auth' ), '', $errors );
		}
		$retry = 'no_role' === $error_code
			? add_query_arg( 'prompt', 'select_account', self::start_url( $redirect_to ) )
			: self::start_url( $redirect_to );
		echo '<div id="loginform" class="faable-auth-login" style="text-align:center">';
		echo '<p style="margin-bottom:16px">' . esc_html__( 'This site uses Faable to sign in.', 'faable-auth' ) . '</p>';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- emblem() is a fixed <img> built from our own file.
		echo '<p><a class="button button-primary button-large faable-auth-button" style="float:none;' . esc_attr( self::BUTTON_STYLE ) . '" href="' . esc_url( $retry ) . '"' . ( $interim ? ' target="_top"' : '' ) . '>'
			. self::emblem()
			. ( 'no_role' === $error_code ? esc_html__( 'Use another account', 'faable-auth' ) : esc_html__( 'Log in with Faable', 'faable-auth' ) )
			. '</a></p>';
		echo '</div>';
		if ( function_exists( 'login_footer' ) ) {
			login_footer();
		}
		exit;
	}

	/**
	 * End the request on the login page with an explanation.
	 *
	 * @param string    $code  Message key.
	 * @param \WP_Error $error Detail, for the error log only.
	 */
	private static function fail( string $code, \WP_Error $error ): void {
		// Details go to the PHP error log, never to the page.
		error_log( sprintf( 'faable-auth: login failed (%s): %s %s', $code, $error->get_error_code(), $error->get_error_message() ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		do_action( 'faable_auth_login_failed', $code, $error );
		self::render_login_page( $code, 'no_role' === $code ? 403 : 400 );
	}

	/**
	 * Messages shown to the visitor.
	 */
	public static function messages(): array {
		return array(
			'no_role'     => __( 'Your Faable account has no access to this site. Ask an administrator of the site to give your account a role in Faable Auth (administrator, editor, author, contributor or subscriber), then log in again.', 'faable-auth' ),
			'cancelled'   => __( 'The login was cancelled.', 'faable-auth' ),
			'state'       => __( 'The login took too long or was started in another browser. Please try again.', 'faable-auth' ),
			'roles'       => __( 'Your roles could not be read from Faable Auth, so access cannot be decided. Please try again in a moment.', 'faable-auth' ),
			'unavailable' => __( 'Faable Auth cannot be reached right now. Please try again in a moment.', 'faable-auth' ),
			'no_email'    => __( 'Your Faable account has no email address, which this site needs to create your account.', 'faable-auth' ),
			'email_taken' => __( 'A user with your email already exists on this site, and your email is not verified in Faable. Verify it and log in again.', 'faable-auth' ),
			'provision'   => __( 'Your account could not be created on this site.', 'faable-auth' ),
			'provider'    => __( 'The login with Faable failed. Please try again.', 'faable-auth' ),
		);
	}

	/**
	 * Cookie name binding a flow to the browser that started it.
	 *
	 * @param string $state State.
	 */
	private static function cookie_name( string $state ): string {
		return self::COOKIE . substr( hash( 'sha256', $state ), 0, 16 );
	}

	/**
	 * Set a cookie scoped to wp-login.php's path.
	 *
	 * @param string $name    Name.
	 * @param string $value   Value.
	 * @param int    $expires Expiry.
	 */
	private static function set_cookie( string $name, string $value, int $expires ): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			$name,
			$value,
			array(
				'expires'  => $expires,
				'path'     => defined( 'SITECOOKIEPATH' ) ? SITECOOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}
}
