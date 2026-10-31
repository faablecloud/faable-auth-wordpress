<?php
/**
 * Users made in wp-admin go to Faable Auth too.
 *
 * With Faable Auth the login of a site is the tenant's. A user an
 * administrator adds in Users → Add New would otherwise exist only in
 * WordPress and never be able to sign in. So, when WordPress creates a user
 * (and the plugin did not create it itself from a Faable login):
 *
 * - the user is imported into the tenant (`POST /user/import`) with the
 *   WordPress password hash (`$wp$2y$…`, which Faable Auth reads), so the
 *   password the administrator chose works on the Faable login. An email the
 *   tenant already has is linked as is: its password is never touched.
 * - the Faable Auth role for its WordPress role (the reverse of the role
 *   map; created in the tenant when it does not exist) is assigned to it.
 *
 * And from then on a role change in wp-admin is the same change in Faable
 * Auth (the login would otherwise put the old role back), and deleting the
 * user takes away its mapped roles there — never the Faable user, who may use
 * other apps of the tenant.
 *
 * Needs a client with the Management API scopes in WRITE_SCOPES. Without
 * them nothing breaks: the WordPress side is done, the user is flagged on its
 * profile and in the users list, and "Sync to Faable Auth" retries.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

final class UserSync {

	/**
	 * The Management API scopes the write side asks for. No
	 * `update:credentials`: the import never overwrites an existing user's
	 * password (auth asks for it only with `update_existing`).
	 */
	const WRITE_SCOPES = 'create:users read:roles create:roles create:rolemembers delete:rolemembers';

	/** Last sync error of a user, shown on its profile. */
	const META_ERROR = 'faable_auth_sync_error';

	/** True while the plugin itself writes users (Faable login, its own sync). */
	private static bool $quiet = false;

	/**
	 * Role name => ids of the tenant, per request. A list: nothing in Faable
	 * Auth stops two roles from having the same name (31-10-2026, El Talentón
	 * had two `administrator`), and removing only one of them left the user
	 * an administrator.
	 */
	private static ?array $roles = null;

	public static function init(): void {
		add_action( 'user_register', array( __CLASS__, 'on_register' ), 20, 1 );
		add_action( 'set_user_role', array( __CLASS__, 'on_role' ), 20, 3 );
		add_action( 'delete_user', array( __CLASS__, 'on_delete' ), 10, 1 );
	}

	/**
	 * Run `$fn` without pushing anything to Faable Auth: what the plugin
	 * writes from a Faable login already comes from there.
	 *
	 * @param callable $fn What to run.
	 * @return mixed What it returns.
	 */
	public static function quietly( callable $fn ) {
		$was         = self::$quiet;
		self::$quiet = true;
		try {
			return $fn();
		} finally {
			self::$quiet = $was;
		}
	}

	/** Whether pushing is on: a configured site, and not one of our writes. */
	private static function active(): bool {
		return ! self::$quiet && Config::is_configured() && (bool) apply_filters( 'faable_auth_push_users', true );
	}

	/**
	 * A user created in WordPress.
	 *
	 * @param int $user_id User id.
	 */
	public static function on_register( $user_id ): void {
		if ( self::active() ) {
			self::push( (int) $user_id );
		}
	}

	/**
	 * Create (or link) the user in Faable Auth and give it its role there.
	 *
	 * @param int $user_id User id.
	 * @return true|\WP_Error
	 */
	public static function push( int $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user || '' === (string) $user->user_email ) {
			return new \WP_Error( 'faable_auth_no_email', __( 'The user has no email.', 'faable-auth' ) );
		}
		if ( in_array( (string) $user->user_login, Config::app_password_users(), true ) ) {
			// A local service user (FAABLE_AUTH_APP_PASSWORD_USERS) stays out of Faable.
			return new \WP_Error( 'faable_auth_service_user', __( 'Local service users are not synced to Faable Auth.', 'faable-auth' ) );
		}
		$oidc = Oidc::configured();
		$sub  = (string) get_user_meta( $user_id, Login::META_SUB, true );

		if ( '' === $sub ) {
			$row = array_filter(
				array(
					'email'       => (string) $user->user_email,
					'name'        => (string) $user->display_name,
					'given_name'  => (string) $user->first_name,
					'family_name' => (string) $user->last_name,
				),
				static fn( $v ) => '' !== $v
			);
			// Only a hash Faable Auth reads: WordPress 6.8+ bcrypt. An older
			// phpass hash would fail the row; the user then sets a password
			// with "Forgot password" on the Faable login.
			if ( str_starts_with( (string) $user->user_pass, '$wp$2' ) ) {
				$row['password_hash'] = (string) $user->user_pass;
			}
			$res = $oidc->management( 'POST', '/user/import', array( 'users' => array( $row ) ), self::WRITE_SCOPES );
			$out = is_wp_error( $res ) ? null : ( $res['results'][0] ?? null );
			if ( is_wp_error( $res ) || ! is_array( $out ) || empty( $out['user_id'] ) ) {
				$err = is_wp_error( $res ) ? $res : new \WP_Error( 'faable_auth_import', (string) ( $out['error']['message'] ?? __( 'Faable Auth did not create the user.', 'faable-auth' ) ) );
				return self::fail( $user_id, $err );
			}
			$sub = (string) $out['user_id'];
			update_user_meta( $user_id, Login::META_SUB, $sub );
			update_user_meta( $user_id, Login::META_ISS, Config::domain() );
		}

		$wanted = array_filter( array_map( array( __CLASS__, 'faable_role' ), (array) $user->roles ) );
		if ( $wanted ) {
			$ids = array();
			foreach ( $wanted as $name ) {
				$id = self::role_id( $oidc, $name, true );
				if ( is_wp_error( $id ) ) {
					return self::fail( $user_id, $id );
				}
				$ids[] = $id;
			}
			$res = $oidc->management( 'POST', '/user/' . rawurlencode( $sub ) . '/roles', array( 'roles' => array_values( array_unique( $ids ) ) ), self::WRITE_SCOPES );
			if ( is_wp_error( $res ) ) {
				return self::fail( $user_id, $res );
			}
		}
		delete_user_meta( $user_id, self::META_ERROR );
		do_action( 'faable_auth_user_pushed', $user_id, $sub );
		return true;
	}

	/**
	 * A role change in wp-admin: the same change in Faable Auth.
	 *
	 * @param int      $user_id   User id.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Previous roles.
	 */
	public static function on_role( $user_id, $role, $old_roles ): void {
		if ( ! self::active() ) {
			return;
		}
		$user_id = (int) $user_id;
		$sub     = (string) get_user_meta( $user_id, Login::META_SUB, true );
		if ( '' === $sub ) {
			return; // Not in Faable yet: user_register (or a retry) pushes it whole.
		}
		$oidc = Oidc::configured();
		$old  = array_filter( array_map( array( __CLASS__, 'faable_role' ), (array) $old_roles ) );
		$new  = array_filter( array( self::faable_role( (string) $role ) ) );
		$drop = array_diff( $old, $new );
		if ( $drop ) {
			$ids = array();
			foreach ( $drop as $name ) {
				$found = self::role_ids( $oidc, $name );
				if ( is_wp_error( $found ) ) {
					self::fail( $user_id, $found );
					return;
				}
				$ids = array_merge( $ids, $found );
			}
			if ( $ids ) {
				$res = $oidc->management( 'DELETE', '/user/' . rawurlencode( $sub ) . '/roles', array( 'roles' => array_values( array_unique( $ids ) ) ), self::WRITE_SCOPES );
				if ( is_wp_error( $res ) && 404 !== (int) $res->get_error_data() ) {
					self::fail( $user_id, $res );
					return;
				}
			}
		}
		if ( $new ) {
			self::push( $user_id );
		} else {
			delete_user_meta( $user_id, self::META_ERROR );
		}
	}

	/**
	 * A user deleted in WordPress loses its mapped roles in Faable Auth, or
	 * its next Faable login would create it again. The Faable user stays.
	 *
	 * @param int $user_id User id.
	 */
	public static function on_delete( $user_id ): void {
		if ( ! self::active() ) {
			return;
		}
		$user = get_userdata( (int) $user_id );
		$sub  = (string) get_user_meta( (int) $user_id, Login::META_SUB, true );
		if ( ! $user || '' === $sub ) {
			return;
		}
		$oidc = Oidc::configured();
		$ids  = array();
		foreach ( array_unique( array_keys( Config::role_map() ) ) as $name ) {
			$found = self::role_ids( $oidc, $name );
			if ( is_array( $found ) ) {
				$ids = array_merge( $ids, $found );
			}
		}
		if ( $ids ) {
			$res = $oidc->management( 'DELETE', '/user/' . rawurlencode( $sub ) . '/roles', array( 'roles' => array_values( array_unique( $ids ) ) ), self::WRITE_SCOPES );
			if ( is_wp_error( $res ) ) {
				// The user is gone from WordPress: nowhere to show it but the log.
				error_log( 'faable-auth: could not remove the Faable Auth roles of deleted user ' . $sub . ': ' . $res->get_error_message() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		}
	}

	/**
	 * The Faable Auth role name for a WordPress role: the first entry of the
	 * role map that points at it (the default map lists `administrator`
	 * before `admin`).
	 *
	 * @param string $wp_role WordPress role.
	 */
	public static function faable_role( string $wp_role ): ?string {
		foreach ( Config::role_map() as $faable => $wp ) {
			if ( $wp === $wp_role ) {
				return (string) $faable;
			}
		}
		return null;
	}

	/**
	 * The id of the tenant role named `$name` (case-insensitive), created
	 * when `$create` and missing.
	 *
	 * @param Oidc   $oidc   Client.
	 * @param string $name   Role name.
	 * @param bool   $create Create it if missing.
	 * @return string|\WP_Error|null Null when missing and not created.
	 */
	private static function role_id( Oidc $oidc, string $name, bool $create ) {
		$key   = strtolower( $name );
		$found = self::role_ids( $oidc, $name );
		if ( is_wp_error( $found ) ) {
			return $found;
		}
		if ( $found ) {
			return $found[0];
		}
		if ( ! $create ) {
			return null;
		}
		$res = $oidc->management(
			'POST',
			'/role',
			array(
				'name'        => $name,
				'description' => sprintf( 'WordPress %s of %s', $name, wp_parse_url( home_url(), PHP_URL_HOST ) ),
			),
			self::WRITE_SCOPES
		);
		if ( is_wp_error( $res ) || empty( $res['id'] ) ) {
			return is_wp_error( $res ) ? $res : new \WP_Error( 'faable_auth_role', __( 'Faable Auth did not create the role.', 'faable-auth' ) );
		}
		self::$roles[ $key ] = array( (string) $res['id'] );
		return self::$roles[ $key ][0];
	}

	/**
	 * Every tenant role named `$name` (case-insensitive), oldest first.
	 *
	 * @param Oidc   $oidc Client.
	 * @param string $name Role name.
	 * @return string[]|\WP_Error
	 */
	private static function role_ids( Oidc $oidc, string $name ) {
		if ( null === self::$roles ) {
			$res = $oidc->management( 'GET', '/role?pageSize=200', null, self::WRITE_SCOPES );
			if ( is_wp_error( $res ) ) {
				return $res;
			}
			$all = array_filter( (array) ( $res['results'] ?? $res ), static fn( $r ) => is_array( $r ) && isset( $r['id'], $r['name'] ) );
			// Ids are ObjectIds: their hex sorts by creation time.
			usort( $all, static fn( $a, $b ) => strcmp( (string) $a['id'], (string) $b['id'] ) );
			self::$roles = array();
			foreach ( $all as $role ) {
				self::$roles[ strtolower( (string) $role['name'] ) ][] = (string) $role['id'];
			}
		}
		return self::$roles[ strtolower( $name ) ] ?? array();
	}

	/**
	 * Record a failed sync on the user.
	 *
	 * @param int       $user_id User id.
	 * @param \WP_Error $err     What failed.
	 * @return \WP_Error The same error.
	 */
	private static function fail( int $user_id, \WP_Error $err ): \WP_Error {
		update_user_meta( $user_id, self::META_ERROR, $err->get_error_message() );
		return $err;
	}
}
