<?php
/**
 * WP-CLI commands.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Manage Faable Auth sign-in.
 */
final class Cli {

	/**
	 * Print a one-time login URL for a user, valid for 10 minutes.
	 *
	 * Emergency access when Faable Auth cannot be reached. Works whether or not
	 * break glass is on. Any previous unused link of that user stops working.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * [--redirect=<url>]
	 * : Where to land after logging in. Default: the dashboard.
	 *
	 * ## EXAMPLES
	 *
	 *     wp faable-auth login-link admin
	 *
	 * @subcommand login-link
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function login_link( $args, $assoc_args ): void {
		$who  = (string) $args[0];
		$user = is_numeric( $who ) ? get_user_by( 'id', (int) $who ) : ( get_user_by( 'login', $who ) ?: get_user_by( 'email', $who ) );
		if ( ! $user ) {
			\WP_CLI::error( "No user '$who'." );
		}
		\WP_CLI::line( LoginLink::create( $user, (string) ( $assoc_args['redirect'] ?? '' ) ) );
	}

	/**
	 * Create WordPress users in Faable Auth (or link the tenant user with the
	 * same email) with their WordPress password hash and their role, as
	 * Users → Add New does. Users already linked only get their role pushed.
	 *
	 * ## OPTIONS
	 *
	 * [<user>...]
	 * : User IDs, logins or emails.
	 *
	 * [--all]
	 * : Every user that is not a local service user.
	 *
	 * ## EXAMPLES
	 *
	 *     wp faable-auth push-users editor@example.com
	 *     wp faable-auth push-users --all
	 *
	 * @subcommand push-users
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function push_users( $args, $assoc_args ): void {
		if ( ! Config::is_configured() ) {
			\WP_CLI::error( 'Faable Auth is not configured.' );
		}
		$users = array();
		if ( ! empty( $assoc_args['all'] ) ) {
			$users = get_users( array( 'number' => -1 ) );
		}
		foreach ( $args as $who ) {
			$user = is_numeric( $who ) ? get_user_by( 'id', (int) $who ) : ( get_user_by( 'login', $who ) ?: get_user_by( 'email', $who ) );
			if ( ! $user ) {
				\WP_CLI::error( "No user '$who'." );
			}
			$users[] = $user;
		}
		if ( ! $users ) {
			\WP_CLI::error( 'Name the users, or pass --all.' );
		}
		$failed = 0;
		foreach ( $users as $user ) {
			if ( Login::is_local_service_user( $user ) || in_array( (string) $user->user_login, Config::app_password_users(), true ) ) {
				\WP_CLI::line( "skip  {$user->user_login} (local service user)" );
				continue;
			}
			$res = UserSync::push( (int) $user->ID );
			if ( is_wp_error( $res ) ) {
				++$failed;
				\WP_CLI::warning( "{$user->user_login}: " . $res->get_error_message() );
			} else {
				\WP_CLI::line( "ok    {$user->user_login} → " . get_user_meta( $user->ID, Login::META_SUB, true ) );
			}
		}
		if ( $failed ) {
			\WP_CLI::error( "$failed failed." );
		}
		\WP_CLI::success( 'Done.' );
	}

	/**
	 * Show how sign-in is configured (never prints the secret).
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function status( $args, $assoc_args ): void {
		$src = static function ( string $name ): string {
			return Config::is_locked( $name ) ? 'env/constant' : 'settings';
		};
		$rows = array(
			array( 'key' => 'mode', 'value' => Login::mode(), 'source' => '' ),
			array( 'key' => 'managed', 'value' => Config::is_managed() ? 'yes (Faable hosting)' : 'no', 'source' => '' ),
			array( 'key' => 'break_glass', 'value' => BreakGlass::from_environment() ? 'on' : 'off', 'source' => '' ),
			array( 'key' => 'domain', 'value' => Config::domain(), 'source' => $src( 'FAABLE_AUTH_DOMAIN' ) ),
			array( 'key' => 'client_id', 'value' => Config::get( 'FAABLE_AUTH_CLIENT_ID' ), 'source' => $src( 'FAABLE_AUTH_CLIENT_ID' ) ),
			array( 'key' => 'client_secret', 'value' => '' !== Config::get( 'FAABLE_AUTH_CLIENT_SECRET' ) ? 'set' : ( Config::secret_unreadable() ? 'UNREADABLE (salts changed: reconnect)' : 'missing' ), 'source' => $src( 'FAABLE_AUTH_CLIENT_SECRET' ) ),
			array( 'key' => 'redirect_uri', 'value' => Config::redirect_uri(), 'source' => '' ),
			array( 'key' => 'rest_audience', 'value' => Config::get( 'FAABLE_AUTH_REST_AUDIENCE' ), 'source' => $src( 'FAABLE_AUTH_REST_AUDIENCE' ) ),
		);
		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, array( 'key', 'value', 'source' ) );
	}
}
