<?php
/**
 * The REST API does not list the site's users to anonymous visitors.
 *
 * Out of the box `GET /wp-json/wp/v2/users` (and `?rest_route=/wp/v2/users`,
 * and `/wp/v2/users/<id>`) answers anyone with the login, name and avatar of
 * every user who has published something — the administrators of the site, a
 * list of whom to phish. With Faable Auth those are the tenant's people.
 *
 * A request without a signed-in user (cookie, Application Password, or a
 * Bearer token the plugin accepts) gets a 401 on those routes. Everything a
 * signed-in user could do stays as WordPress has it: the editor's author
 * picker, `users/me`, a front-end calling with an Application Password.
 *
 * `add_filter( 'faable_auth_restrict_rest_users', '__return_false' )` turns it
 * off for a site that publishes its authors on purpose.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

final class UserEnumeration {

	/**
	 * The user routes that list or show users; `users/me` is not one.
	 * Case-insensitive like WP_REST_Server's own matching, or `/wp/v2/Users`
	 * would get through.
	 */
	const ROUTES = '#^/wp/v2/users(?:/\d+)?/?$#i';

	public static function init(): void {
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'guard' ), 10, 3 );
	}

	/**
	 * Refuse an anonymous read of the user routes.
	 *
	 * @param mixed            $result  Response so far (null = not handled).
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function guard( $result, $server, $request ) {
		if ( null !== $result || ! $request instanceof \WP_REST_Request ) {
			return $result;
		}
		if ( ! preg_match( self::ROUTES, (string) $request->get_route() ) ) {
			return $result;
		}
		if ( is_user_logged_in() || ! apply_filters( 'faable_auth_restrict_rest_users', true ) ) {
			return $result;
		}
		return new \WP_Error(
			'rest_user_cannot_view',
			__( 'Sorry, you are not allowed to list users.', 'faable-auth' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}
}
