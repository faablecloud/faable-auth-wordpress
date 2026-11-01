<?php
/**
 * Plugin Name: E2E void rest_pre_dispatch
 * Description: Does what acf-to-rest-api 3.x does: hooks `rest_pre_dispatch`
 * from `plugins_loaded` with add_action, so its callback returns null and
 * wipes whatever an earlier callback at the same priority returned.
 */
add_action(
	'plugins_loaded',
	static function () {
		add_action( 'rest_pre_dispatch', static function () {}, 10 );
	}
);
