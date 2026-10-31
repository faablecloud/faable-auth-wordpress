<?php
/**
 * Maps Faable Auth role names to one WordPress role. No WordPress dependency.
 *
 * Rules (owner's decision):
 *  - a member of the Faable project is an administrator;
 *  - any other user gets the WordPress role their Faable Auth roles map to,
 *    the most privileged one when several map;
 *  - a user whose roles map to nothing gets no account.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || defined( 'FAABLE_AUTH_TESTING' ) || exit;

/**
 * Role mapping.
 */
final class RoleMapper {

	/** WordPress core roles, most privileged first. Custom roles rank below these. */
	const PRECEDENCE = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );

	/**
	 * The default map: Faable Auth role name (case-insensitive) => WordPress role.
	 */
	public static function default_map(): array {
		return array(
			'administrator' => 'administrator',
			'admin'         => 'administrator',
			'editor'        => 'editor',
			'author'        => 'author',
			'contributor'   => 'contributor',
			'subscriber'    => 'subscriber',
		);
	}

	/**
	 * Parse the textual map used by the settings page and the
	 * FAABLE_AUTH_ROLE_MAP env var. Accepts JSON (`{"staff":"editor"}`) or
	 * one `faable_role = wp_role` per line (`,` or `;` also separate pairs).
	 * An empty value means "the default map".
	 *
	 * @param string $text Raw map.
	 * @return array<string,string>
	 */
	public static function parse( string $text ): array {
		$text = trim( $text );
		if ( '' === $text ) {
			return self::default_map();
		}
		$map  = array();
		$json = json_decode( $text, true );
		if ( is_array( $json ) ) {
			foreach ( $json as $k => $v ) {
				if ( is_string( $k ) && is_string( $v ) ) {
					$map[ self::norm( $k ) ] = self::norm( $v );
				}
			}
			return array_filter( $map, array( __CLASS__, 'valid_pair' ), ARRAY_FILTER_USE_BOTH );
		}
		foreach ( preg_split( '/[\r\n,;]+/', $text ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] || false === strpos( $line, '=' ) ) {
				continue;
			}
			list( $k, $v )           = array_map( 'trim', explode( '=', $line, 2 ) );
			$map[ self::norm( $k ) ] = self::norm( $v );
		}
		return array_filter( $map, array( __CLASS__, 'valid_pair' ), ARRAY_FILTER_USE_BOTH );
	}

	/**
	 * Serialize a map back to the textual form.
	 *
	 * @param array $map Map.
	 */
	public static function to_text( array $map ): string {
		$lines = array();
		foreach ( $map as $k => $v ) {
			$lines[] = $k . ' = ' . $v;
		}
		return implode( "\n", $lines );
	}

	/**
	 * Resolve the WordPress role.
	 *
	 * @param string[] $faable_roles      Role names from Faable Auth.
	 * @param bool     $is_project_member Whether the user is a member of the Faable project.
	 * @param array    $map               Faable role => WP role.
	 * @param string[] $existing_wp_roles Roles that exist in this site (empty = do not check).
	 * @return string|null The WP role, or null when the user must be refused.
	 */
	public static function resolve( array $faable_roles, bool $is_project_member, array $map, array $existing_wp_roles = array() ): ?string {
		if ( $is_project_member ) {
			return 'administrator';
		}
		$candidates = array();
		foreach ( $faable_roles as $name ) {
			if ( ! is_string( $name ) ) {
				continue;
			}
			$key = self::norm( $name );
			if ( isset( $map[ $key ] ) ) {
				$wp = $map[ $key ];
				if ( $existing_wp_roles && ! in_array( $wp, $existing_wp_roles, true ) ) {
					continue;
				}
				$candidates[] = $wp;
			}
		}
		if ( ! $candidates ) {
			return null;
		}
		usort(
			$candidates,
			static function ( $a, $b ) {
				return self::rank( $a ) <=> self::rank( $b );
			}
		);
		return $candidates[0];
	}

	/**
	 * Lower rank = more privileged.
	 *
	 * @param string $wp_role Role.
	 */
	private static function rank( string $wp_role ): int {
		$i = array_search( $wp_role, self::PRECEDENCE, true );
		return false === $i ? count( self::PRECEDENCE ) : (int) $i;
	}

	/**
	 * Normalize a role name.
	 *
	 * @param string $s Name.
	 */
	private static function norm( string $s ): string {
		return strtolower( trim( $s ) );
	}

	/**
	 * Keep only sane pairs (WordPress role slugs are [a-z0-9_-]).
	 *
	 * @param string $v WP role.
	 * @param string $k Faable role.
	 */
	private static function valid_pair( $v, $k ): bool {
		return '' !== $k && 1 === preg_match( '/^[a-z0-9_-]+$/', (string) $v );
	}
}
