<?php
/**
 * Emergency access ("break glass") and the login mode it implies.
 * No WordPress dependency.
 *
 * When Faable Auth is down nobody can log in, so two ways in exist from day 1:
 *
 *  1. `define( 'FAABLE_AUTH_BREAK_GLASS', true );` in wp-config.php (or the
 *     env var FAABLE_AUTH_BREAK_GLASS=1) brings back the native
 *     username/password form, password resets and the "Lost your password?"
 *     link, next to the Faable button.
 *  2. `wp faable-auth login-link <user>` prints a one-time URL valid for 10
 *     minutes (see LoginLink). It works whatever the mode.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || defined( 'FAABLE_AUTH_TESTING' ) || exit;

/**
 * Break-glass logic.
 */
final class BreakGlass {

	/** Native WordPress login only: the plugin is not configured yet. */
	const MODE_NATIVE = 'native';
	/** Faable Auth only: the normal mode once configured. */
	const MODE_FAABLE = 'faable';
	/** Both: configured, but break glass is on. */
	const MODE_BOTH = 'both';

	/**
	 * Whether break glass is on.
	 *
	 * @param mixed       $constant Value of the FAABLE_AUTH_BREAK_GLASS constant (null when undefined).
	 * @param string|null $env      Value of the env var (null when unset).
	 */
	public static function is_active( $constant, ?string $env ): bool {
		if ( null !== $constant ) {
			return self::truthy( $constant );
		}
		return null !== $env && self::truthy( $env );
	}

	/**
	 * Read break glass from the real constant and environment.
	 */
	public static function from_environment(): bool {
		$constant = defined( 'FAABLE_AUTH_BREAK_GLASS' ) ? constant( 'FAABLE_AUTH_BREAK_GLASS' ) : null;
		$env      = getenv( 'FAABLE_AUTH_BREAK_GLASS' );
		return self::is_active( $constant, false === $env ? null : $env );
	}

	/**
	 * The login mode.
	 *
	 * A site that is not configured keeps the native login: otherwise the very
	 * administrator who has to press "Connect with Faable" could not log in.
	 *
	 * @param bool $configured  Whether Faable Auth credentials are present.
	 * @param bool $break_glass Whether break glass is on.
	 */
	public static function login_mode( bool $configured, bool $break_glass ): string {
		if ( ! $configured ) {
			return self::MODE_NATIVE;
		}
		return $break_glass ? self::MODE_BOTH : self::MODE_FAABLE;
	}

	/**
	 * Whether local passwords may be used in a mode (login form, resets,
	 * profile password fields).
	 *
	 * @param string $mode Login mode.
	 */
	public static function passwords_allowed( string $mode ): bool {
		return self::MODE_FAABLE !== $mode;
	}

	/**
	 * Truthiness for constants and env strings.
	 *
	 * @param mixed $v Value.
	 */
	private static function truthy( $v ): bool {
		if ( is_bool( $v ) ) {
			return $v;
		}
		return in_array( strtolower( trim( (string) $v ) ), array( '1', 'true', 'yes', 'on' ), true );
	}
}
