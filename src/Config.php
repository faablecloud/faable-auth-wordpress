<?php
/**
 * Where the plugin's configuration comes from.
 *
 * Precedence, per value: environment variable (Faable hosting sets them, no
 * settings needed) > PHP constant of the same name (wp-config.php) > the
 * option saved by the settings page ("Connect with Faable" or manual entry).
 *
 *   FAABLE_AUTH_DOMAIN         Tenant base URL, e.g. https://acme.auth.faable.link
 *                              (or the tenant's verified custom domain). It is
 *                              also the token issuer: no trailing slash.
 *   FAABLE_AUTH_CLIENT_ID      OIDC client id of this site in that tenant.
 *   FAABLE_AUTH_CLIENT_SECRET  Its secret (confidential client).
 *   FAABLE_AUTH_AUDIENCE       Optional. An API identifier of the tenant with
 *                              "include roles in ID token" on: roles then come
 *                              in the ID token instead of a Management API call.
 *   FAABLE_AUTH_ROLE_MAP       Optional. Role map (JSON or `role = wp_role` lines).
 *   FAABLE_AUTH_REST_AUDIENCE  Optional. Enables Bearer M2M tokens on the REST API:
 *                              the API identifier those tokens are issued for.
 *   FAABLE_AUTH_REST_USER      WordPress login the M2M requests act as.
 *   FAABLE_AUTH_REST_CLIENTS   Optional. Comma-separated client ids allowed (empty = any client of the tenant).
 *   FAABLE_AUTH_REST_SCOPE     Optional. A scope/permission every M2M token must carry.
 *   FAABLE_AUTH_APP_PASSWORD_USERS  Optional. Comma-separated logins of LOCAL
 *                              WordPress users (never signed in with Faable)
 *                              that keep Application Passwords for the REST
 *                              API: a front-end that already calls it with one.
 *
 * Managed mode (FAABLE_AUTH_MANAGED, a constant the Faable hosting defines
 * when it loads the plugin as a must-use plugin from its image): the site's
 * connection belongs to the platform. Domain, client id and secret come ONLY
 * from the environment/constants (a value left in the settings is ignored),
 * and the settings page cannot connect, disconnect or edit them. What is the
 * site owner's to decide stays editable: the role map (unless set by env),
 * the REST M2M options and federated logout.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Configuration access.
 */
final class Config {

	const OPTION = 'faable_auth_settings';

	/** Keys that can come from the environment, and their option keys. */
	const KEYS = array(
		'FAABLE_AUTH_DOMAIN'        => 'domain',
		'FAABLE_AUTH_CLIENT_ID'     => 'client_id',
		'FAABLE_AUTH_CLIENT_SECRET' => 'client_secret',
		'FAABLE_AUTH_AUDIENCE'      => 'audience',
		'FAABLE_AUTH_ROLE_MAP'      => 'role_map',
		'FAABLE_AUTH_REST_AUDIENCE' => 'rest_audience',
		'FAABLE_AUTH_REST_USER'     => 'rest_user',
		'FAABLE_AUTH_REST_CLIENTS'  => 'rest_clients',
		'FAABLE_AUTH_REST_SCOPE'    => 'rest_scope',
		'FAABLE_AUTH_APP_PASSWORD_USERS' => 'app_password_users',
	);

	/** The connection values a managed site only takes from env/constants. */
	const MANAGED_KEYS = array( 'FAABLE_AUTH_DOMAIN', 'FAABLE_AUTH_CLIENT_ID', 'FAABLE_AUTH_CLIENT_SECRET' );

	/** The platform tenant that serves the Connect handoff exchange. */
	const DEFAULT_CONNECT_URL  = 'https://dashboard.faable.com/connect/wordpress';
	const DEFAULT_EXCHANGE_URL = 'https://faable.auth.faable.link/connect/exchange';

	/** Where the tenant is managed, and the plugin's documentation. */
	const DASHBOARD_URL = 'https://dashboard.faable.com';
	const DOCS_URL      = 'https://faable.com/docs/auth/integrations/wordpress';

	/**
	 * Whether the hosting platform manages this site's connection (Faable
	 * hosting defines FAABLE_AUTH_MANAGED when it loads the plugin).
	 */
	public static function is_managed(): bool {
		return defined( 'FAABLE_AUTH_MANAGED' ) && FAABLE_AUTH_MANAGED;
	}

	/**
	 * Saved options.
	 */
	public static function options(): array {
		$o = get_option( self::OPTION, array() );
		return is_array( $o ) ? $o : array();
	}

	/**
	 * Save options (merged).
	 *
	 * @param array $values Values.
	 */
	public static function save( array $values ): void {
		update_option( self::OPTION, array_merge( self::options(), $values ), false );
	}

	/**
	 * The value set outside the database (env or constant), or null.
	 *
	 * @param string $name Env/constant name.
	 */
	public static function external( string $name ): ?string {
		$env = getenv( $name );
		if ( false !== $env && '' !== $env ) {
			return (string) $env;
		}
		if ( defined( $name ) && '' !== (string) constant( $name ) ) {
			return (string) constant( $name );
		}
		return null;
	}

	/**
	 * Whether a value is locked by env/constant (the settings page shows it read-only).
	 *
	 * @param string $name Env/constant name.
	 */
	public static function is_locked( string $name ): bool {
		return null !== self::external( $name );
	}

	/**
	 * Resolve a value.
	 *
	 * @param string $name Env/constant name (a key of KEYS).
	 */
	public static function get( string $name ): string {
		$ext = self::external( $name );
		if ( null !== $ext ) {
			return trim( $ext );
		}
		$key = self::KEYS[ $name ] ?? null;
		if ( null === $key ) {
			return '';
		}
		// Managed: the connection is the platform's, never a leftover option
		// (a site connected by hand before it moved to Faable, say).
		if ( self::is_managed() && in_array( $name, self::MANAGED_KEYS, true ) ) {
			return '';
		}
		$o = self::options();
		if ( 'client_secret' === $key ) {
			$enc = (string) ( $o['client_secret_enc'] ?? '' );
			return '' === $enc ? '' : (string) Crypto::decrypt( $enc, Crypto::site_material() );
		}
		return trim( (string) ( $o[ $key ] ?? '' ) );
	}

	/**
	 * Tenant base URL == issuer, normalized (https, no trailing slash).
	 */
	public static function domain(): string {
		return self::normalize_domain( self::get( 'FAABLE_AUTH_DOMAIN' ) );
	}

	/**
	 * Normalize a domain value; '' when unusable. Accepts a bare host.
	 *
	 * @param string $value Raw.
	 */
	public static function normalize_domain( string $value ): string {
		$value = trim( $value );
		if ( '' === $value ) {
			return '';
		}
		if ( ! preg_match( '#^https?://#i', $value ) ) {
			$value = 'https://' . $value;
		}
		$parts = wp_parse_url( $value );
		if ( empty( $parts['host'] ) ) {
			return '';
		}
		$scheme = strtolower( $parts['scheme'] ?? 'https' );
		// Plain http only for local development hosts, or when explicitly
		// allowed for a development setup (never in production).
		$insecure_ok = defined( 'FAABLE_AUTH_ALLOW_INSECURE_HTTP' ) && FAABLE_AUTH_ALLOW_INSECURE_HTTP;
		if ( 'https' !== $scheme && ! $insecure_ok && ! in_array( $parts['host'], array( 'localhost', '127.0.0.1' ), true ) && ! str_ends_with( $parts['host'], '.localhost' ) ) {
			return '';
		}
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		return $scheme . '://' . strtolower( $parts['host'] ) . $port;
	}

	/**
	 * Whether enough is configured to log in with Faable Auth.
	 */
	public static function is_configured(): bool {
		return '' !== self::domain()
			&& '' !== self::get( 'FAABLE_AUTH_CLIENT_ID' )
			&& '' !== self::get( 'FAABLE_AUTH_CLIENT_SECRET' );
	}

	/**
	 * Whether a stored secret exists but cannot be decrypted (salts rotated).
	 */
	public static function secret_unreadable(): bool {
		if ( self::is_managed() || self::is_locked( 'FAABLE_AUTH_CLIENT_SECRET' ) ) {
			return false;
		}
		$enc = (string) ( self::options()['client_secret_enc'] ?? '' );
		return '' !== $enc && null === Crypto::decrypt( $enc, Crypto::site_material() );
	}

	/**
	 * Store a client secret encrypted.
	 *
	 * @param string $secret Plain secret.
	 */
	public static function encrypt_secret( string $secret ): string {
		return Crypto::encrypt( $secret, Crypto::site_material() );
	}

	/**
	 * The role map in effect.
	 */
	public static function role_map(): array {
		return RoleMapper::parse( self::get( 'FAABLE_AUTH_ROLE_MAP' ) );
	}

	/**
	 * The OIDC redirect URI. Fixed by the Connect contract: the dashboard
	 * registers exactly this value.
	 */
	public static function redirect_uri(): string {
		return home_url( '/wp-login.php?faable-auth=callback' );
	}

	/**
	 * The tenant's page in the Faable dashboard, where who signs in and with
	 * which role is managed. Project and tenant come from the environment on
	 * Faable hosting (FAABLE_AUTH_PROJECT_ID / FAABLE_AUTH_ACCOUNT_ID, set by
	 * the installation) or from "Connect with Faable"; without them, the
	 * dashboard's Faable Auth home.
	 */
	public static function manage_url(): string {
		$tenant = self::tenant_url();
		return '' !== $tenant ? $tenant : self::DASHBOARD_URL . '/auth';
	}

	/**
	 * The tenant's page in the dashboard, or '' when project or tenant are unknown.
	 */
	public static function tenant_url(): string {
		$o       = self::is_managed() ? array() : self::options();
		$project = self::external( 'FAABLE_AUTH_PROJECT_ID' ) ?? (string) ( $o['project_id'] ?? '' );
		$account = self::external( 'FAABLE_AUTH_ACCOUNT_ID' ) ?? (string) ( $o['account_id'] ?? '' );
		$project = preg_replace( '/^team_/', 'project_', trim( $project ) );
		$account = trim( $account );
		if ( preg_match( '/^project_[a-f0-9]{24}$/', $project ) && preg_match( '/^account_[a-f0-9]{24}$/', $account ) ) {
			return self::DASHBOARD_URL . '/auth/' . $project . '/account/' . $account;
		}
		return '';
	}

	/**
	 * A tenant user's page in the dashboard, or '' (unknown tenant, or a
	 * subject that is not a Faable Auth user id).
	 *
	 * @param string $sub The user's `sub` in the tenant.
	 */
	public static function user_url( string $sub ): string {
		$tenant = self::tenant_url();
		if ( '' === $tenant || ! preg_match( '/^user_[A-Za-z0-9]+$/', $sub ) ) {
			return '';
		}
		return $tenant . '/user/' . $sub;
	}

	/**
	 * Logins (lowercase) of the local users that keep Application Passwords.
	 *
	 * @return string[]
	 */
	public static function app_password_users(): array {
		$list = array_map( 'trim', explode( ',', strtolower( self::get( 'FAABLE_AUTH_APP_PASSWORD_USERS' ) ) ) );
		return array_values( array_filter( $list, static fn( $l ) => '' !== $l ) );
	}

	/**
	 * Where "Connect with Faable" sends the admin. Overridable for staging.
	 */
	public static function connect_url(): string {
		return self::external( 'FAABLE_AUTH_CONNECT_URL' ) ?? self::DEFAULT_CONNECT_URL;
	}

	/**
	 * The handoff exchange endpoint. Overridable for staging.
	 */
	public static function exchange_url(): string {
		return self::external( 'FAABLE_AUTH_CONNECT_EXCHANGE_URL' ) ?? self::DEFAULT_EXCHANGE_URL;
	}

	/**
	 * Whether to end the Faable Auth session on WordPress logout (RP-initiated
	 * logout). Off by default: it requires `<home>/wp-login.php?loggedout=true`
	 * to be registered in the client's logout URLs, or Faable Auth refuses it.
	 */
	public static function federated_logout(): bool {
		$ext = self::external( 'FAABLE_AUTH_FEDERATED_LOGOUT' );
		if ( null !== $ext ) {
			return in_array( strtolower( $ext ), array( '1', 'true', 'yes', 'on' ), true );
		}
		return ! empty( self::options()['federated_logout'] );
	}
}
