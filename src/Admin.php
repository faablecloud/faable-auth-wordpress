<?php
/**
 * Settings page (Settings → Faable Auth): "Connect with Faable", the manual
 * fallback, the role map and the REST M2M options.
 *
 * "Connect with Faable" contract:
 *  1. We create `state` and a PKCE verifier (transient, 10 min) and send the
 *     admin to dashboard.faable.com/connect/wordpress with site_url,
 *     return_to, state, code_challenge and code_challenge_method=S256.
 *  2. The dashboard creates an OIDC client (redirect URI = Config::redirect_uri())
 *     and comes back to return_to?code=<handoff>&state=<state>.
 *  3. We check state and POST {code, code_verifier} to
 *     faable.auth.faable.link/connect/exchange, which answers
 *     {auth_domain, client_id, client_secret, project_id, account_id}.
 *
 * Managed mode (Config::is_managed(), Faable hosting): the connection is the
 * platform's. The page says so, offers no Connect/Disconnect and shows the
 * domain and client read-only; the admin-post handlers that would change the
 * connection refuse. The role map, REST and logout options stay editable.
 *
 * @package FaableAuth
 */

namespace FaableAuth;

defined( 'ABSPATH' ) || exit;

/**
 * Admin UI.
 */
final class Admin {

	const PAGE = 'faable-auth';
	const CAP  = 'manage_options';

	/**
	 * Register hooks.
	 */
	public static function init(): void {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_faable_auth_save', array( __CLASS__, 'save' ) );
		add_action( 'admin_post_faable_auth_connect', array( __CLASS__, 'connect_start' ) );
		add_action( 'admin_post_faable_auth_connect_return', array( __CLASS__, 'connect_return' ) );
		add_action( 'admin_post_faable_auth_disconnect', array( __CLASS__, 'disconnect' ) );
		add_action( 'admin_post_faable_auth_push_user', array( __CLASS__, 'push_user' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( FAABLE_AUTH_FILE ), array( __CLASS__, 'action_links' ) );
		add_filter( 'plugin_row_meta', array( __CLASS__, 'row_meta' ), 10, 2 );
		add_action( 'show_user_profile', array( __CLASS__, 'user_profile' ), 1 );
		add_action( 'edit_user_profile', array( __CLASS__, 'user_profile' ), 1 );
		add_filter( 'manage_users_columns', array( __CLASS__, 'users_columns' ) );
		add_filter( 'manage_users_custom_column', array( __CLASS__, 'users_column' ), 10, 3 );
	}

	/**
	 * How a WordPress user signs in: 'faable' (linked to a tenant user),
	 * 'service' (a listed local user with Application Passwords) or 'local'.
	 *
	 * @param \WP_User $user User.
	 */
	public static function sign_in_kind( \WP_User $user ): string {
		if ( '' !== (string) get_user_meta( $user->ID, Login::META_SUB, true ) ) {
			return 'faable';
		}
		return Login::is_local_service_user( $user ) ? 'service' : 'local';
	}

	/**
	 * "Faable Auth" section of a user's profile.
	 *
	 * @param \WP_User $user User being shown.
	 */
	public static function user_profile( $user ): void {
		if ( ! ( $user instanceof \WP_User ) || ! Config::is_configured() ) {
			return;
		}
		$kind = self::sign_in_kind( $user );
		echo '<h2>' . esc_html__( 'Faable Auth', 'faable-auth' ) . '</h2><table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Sign-in', 'faable-auth' ) . '</th><td>';
		if ( 'faable' === $kind ) {
			$sub = (string) get_user_meta( $user->ID, Login::META_SUB, true );
			$url = current_user_can( self::CAP ) ? Config::user_url( $sub ) : '';
			echo '<p><span class="faable-auth-managed-user" style="display:inline-flex;align-items:center;gap:6px;font-weight:600">' . Login::emblem() . esc_html__( 'Managed by Faable Auth', 'faable-auth' ) . '</span></p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- emblem() is a fixed <img> built from our own file.
			echo '<p class="description">' . esc_html__( 'This user signs in with Faable. Email and password are managed in Faable Auth. The role is synced from the tenant on every login, and a role changed here is changed there too.', 'faable-auth' ) . '</p>';
			if ( '' !== $url ) {
				echo '<p><a class="button" href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html__( 'Open in the Faable dashboard', 'faable-auth' ) . ' <span aria-hidden="true">↗</span></a></p>';
			}
		} elseif ( 'service' === $kind ) {
			echo '<p><strong>' . esc_html__( 'Local service user', 'faable-auth' ) . '</strong></p>';
			echo '<p class="description">' . esc_html__( 'Not a Faable Auth user: it cannot log in to wp-admin, but it can call the REST API with an Application Password (listed in Settings → Faable Auth).', 'faable-auth' ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'Not linked to Faable Auth yet.', 'faable-auth' ) . '</p>';
			echo '<p class="description">' . esc_html__( 'Linked on this person\'s first Faable sign-in with the same, verified email; until then this account cannot log in.', 'faable-auth' ) . '</p>';
		}
		$error = (string) get_user_meta( $user->ID, UserSync::META_ERROR, true );
		if ( '' !== $error ) {
			/* translators: %s: the error Faable Auth answered */
			echo '<div class="notice notice-error inline faable-auth-sync-error"><p>' . esc_html( sprintf( __( 'Could not sync this user to Faable Auth: %s', 'faable-auth' ), $error ) ) . '</p></div>';
		}
		if ( 'service' !== $kind && ( '' !== $error || 'local' === $kind ) && current_user_can( 'promote_user', $user->ID ) ) {
			$url = wp_nonce_url( admin_url( 'admin-post.php?action=faable_auth_push_user&user_id=' . $user->ID ), 'faable_auth_push_user_' . $user->ID );
			echo '<p><a class="button" href="' . esc_url( $url ) . '">' . esc_html__( 'Sync to Faable Auth', 'faable-auth' ) . '</a></p>';
			echo '<p class="description">' . esc_html__( 'Creates this user in the Faable Auth tenant (or links the one with the same email) with its WordPress password and role.', 'faable-auth' ) . '</p>';
		}
		echo '</td></tr></table>';
	}

	/**
	 * "Sync to Faable Auth" on a user's profile.
	 */
	public static function push_user(): void {
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- checked below.
		check_admin_referer( 'faable_auth_push_user_' . $user_id );
		if ( ! $user_id || ! current_user_can( 'promote_user', $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'faable-auth' ), '', array( 'response' => 403 ) );
		}
		UserSync::push( $user_id );
		wp_safe_redirect( get_edit_user_link( $user_id ) );
		exit;
	}

	/**
	 * Users list: a "Sign-in" column.
	 *
	 * @param array $columns Columns.
	 */
	public static function users_columns( $columns ) {
		if ( Config::is_configured() ) {
			$columns['faable_auth'] = esc_html__( 'Sign-in', 'faable-auth' );
		}
		return $columns;
	}

	/**
	 * Users list cell.
	 *
	 * @param string $output  Output so far.
	 * @param string $column  Column.
	 * @param int    $user_id User.
	 */
	public static function users_column( $output, $column, $user_id ) {
		if ( 'faable_auth' !== $column ) {
			return $output;
		}
		$user = get_userdata( (int) $user_id );
		if ( ! $user ) {
			return $output;
		}
		$labels = array(
			'faable'  => __( 'Faable Auth', 'faable-auth' ),
			'service' => __( 'Service (Application Password)', 'faable-auth' ),
			'local'   => __( 'Not linked', 'faable-auth' ),
		);
		$failed = '' !== (string) get_user_meta( $user->ID, UserSync::META_ERROR, true );
		return esc_html( $labels[ self::sign_in_kind( $user ) ] . ( $failed ? ' · ' . __( 'sync failed', 'faable-auth' ) : '' ) );
	}

	/**
	 * Documentation link under the plugin's description.
	 *
	 * @param array  $links Links.
	 * @param string $file  Plugin file.
	 */
	public static function row_meta( $links, $file ) {
		if ( plugin_basename( FAABLE_AUTH_FILE ) === $file ) {
			$links[] = '<a href="' . esc_url( Config::DOCS_URL ) . '" target="_blank" rel="noopener">' . esc_html__( 'Documentation', 'faable-auth' ) . '</a>';
		}
		return $links;
	}

	/**
	 * Menu entry.
	 */
	public static function menu(): void {
		add_options_page( __( 'Faable Auth', 'faable-auth' ), __( 'Faable Auth', 'faable-auth' ), self::CAP, self::PAGE, array( __CLASS__, 'render' ) );
	}

	/**
	 * Settings link on the plugins screen.
	 *
	 * @param array $links Links.
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Settings', 'faable-auth' ) . '</a>' );
		return $links;
	}

	/**
	 * Settings page URL.
	 *
	 * @param array $args Extra query args.
	 */
	public static function page_url( array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::PAGE ), $args ), admin_url( 'options-general.php' ) );
	}

	/**
	 * The URL the dashboard sends the admin back to (`return_to`).
	 */
	public static function return_url(): string {
		return admin_url( 'admin-post.php?action=faable_auth_connect_return' );
	}

	/**
	 * Build the Connect URL (pure apart from Config).
	 *
	 * @param string $state     State.
	 * @param string $challenge PKCE challenge.
	 */
	public static function connect_redirect_url( string $state, string $challenge ): string {
		return Config::connect_url() . '?' . http_build_query(
			array(
				'site_url'              => home_url(),
				'return_to'             => self::return_url(),
				'state'                 => $state,
				'code_challenge'        => $challenge,
				'code_challenge_method' => 'S256',
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
	}

	/**
	 * Step 1: send the admin to the dashboard.
	 */
	public static function connect_start(): void {
		self::guard( 'faable_auth_connect' );
		self::refuse_if_managed();
		$state    = Pkce::random();
		$verifier = Pkce::random();
		set_transient(
			Pkce::storage_key( 'connect', $state ),
			array(
				'state'    => $state,
				'verifier' => $verifier,
				'user'     => get_current_user_id(),
				'expires'  => time() + 10 * MINUTE_IN_SECONDS,
			),
			10 * MINUTE_IN_SECONDS
		);
		// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the dashboard is another host by design.
		wp_redirect( self::connect_redirect_url( $state, Pkce::challenge( $verifier ) ) );
		exit;
	}

	/**
	 * Step 3: back from the dashboard; exchange the handoff code.
	 */
	public static function connect_return(): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'faable-auth' ), 403 );
		}
		self::refuse_if_managed();
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- `state` (bound to this admin, single use) is the CSRF protection of a cross-site return.
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$error = isset( $_GET['error'] ) ? sanitize_key( wp_unslash( $_GET['error'] ) ) : '';
		// phpcs:enable
		$key  = Pkce::storage_key( 'connect', $state );
		$flow = '' !== $state ? get_transient( $key ) : false;
		if ( false !== $flow ) {
			delete_transient( $key );
		}
		$problem = Pkce::check_flow( $flow, $state, null );
		if ( null === $problem && (int) ( $flow['user'] ?? 0 ) !== get_current_user_id() ) {
			$problem = 'user_mismatch';
		}
		if ( null !== $problem ) {
			self::back( 'error', __( 'The connection expired or was started by someone else. Press "Connect with Faable" again.', 'faable-auth' ) );
		}
		if ( '' !== $error || '' === $code ) {
			self::back( 'error', __( 'The connection was cancelled in Faable.', 'faable-auth' ) );
		}

		$res  = wp_remote_post(
			Config::exchange_url(),
			array(
				'timeout' => 15,
				'headers' => array(
					'Content-Type' => 'application/json',
					'Accept'       => 'application/json',
				),
				'body'    => wp_json_encode(
					array(
						'code'          => $code,
						'code_verifier' => (string) $flow['verifier'],
					)
				),
			)
		);
		$data = Oidc::json_response( $res );
		if ( is_wp_error( $data ) ) {
			/* translators: %s: error from Faable */
			self::back( 'error', sprintf( __( 'Faable refused the connection: %s', 'faable-auth' ), $data->get_error_message() ) );
		}
		$domain = Config::normalize_domain( (string) ( $data['auth_domain'] ?? '' ) );
		$id     = sanitize_text_field( (string) ( $data['client_id'] ?? '' ) );
		$secret = (string) ( $data['client_secret'] ?? '' );
		if ( '' === $domain || '' === $id || '' === $secret ) {
			self::back( 'error', __( 'Faable answered without the client credentials.', 'faable-auth' ) );
		}
		Config::save(
			array(
				'domain'            => $domain,
				'client_id'         => $id,
				'client_secret_enc' => Config::encrypt_secret( $secret ),
				'account_id'        => sanitize_text_field( (string) ( $data['account_id'] ?? '' ) ),
				'project_id'        => sanitize_text_field( (string) ( $data['project_id'] ?? '' ) ),
				'source'            => 'connect',
				'connected_at'      => time(),
			)
		);
		self::back( 'connected', __( 'Connected. From now on this site signs in with Faable. Keep the emergency access instructions at hand.', 'faable-auth' ) );
	}

	/**
	 * Save manual settings.
	 */
	public static function save(): void {
		self::guard( 'faable_auth_save' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in guard().
		$in     = isset( $_POST['faable_auth'] ) && is_array( $_POST['faable_auth'] ) ? wp_unslash( $_POST['faable_auth'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized per field below.
		// phpcs:enable
		$values = array();
		$fields = array(
			'FAABLE_AUTH_DOMAIN'        => 'domain',
			'FAABLE_AUTH_CLIENT_ID'     => 'client_id',
			'FAABLE_AUTH_AUDIENCE'      => 'audience',
			'FAABLE_AUTH_REST_AUDIENCE' => 'rest_audience',
			'FAABLE_AUTH_REST_USER'     => 'rest_user',
			'FAABLE_AUTH_REST_CLIENTS'  => 'rest_clients',
			'FAABLE_AUTH_REST_SCOPE'    => 'rest_scope',
			'FAABLE_AUTH_APP_PASSWORD_USERS' => 'app_password_users',
		);
		$managed = Config::is_managed();
		foreach ( $fields as $const => $key ) {
			if ( Config::is_locked( $const ) || ! isset( $in[ $key ] ) ) {
				continue;
			}
			// Managed: domain and client are the platform's, whatever is posted.
			if ( $managed && in_array( $const, Config::MANAGED_KEYS, true ) ) {
				continue;
			}
			$values[ $key ] = sanitize_text_field( (string) $in[ $key ] );
		}
		if ( isset( $values['domain'] ) && '' !== $values['domain'] ) {
			$normalized = Config::normalize_domain( $values['domain'] );
			if ( '' === $normalized ) {
				self::back( 'error', __( 'The domain must be an https URL, e.g. https://acme.auth.faable.link', 'faable-auth' ) );
			}
			$values['domain'] = $normalized;
		}
		if ( ! $managed && ! Config::is_locked( 'FAABLE_AUTH_CLIENT_SECRET' ) && isset( $in['client_secret'] ) && '' !== trim( (string) $in['client_secret'] ) ) {
			$values['client_secret_enc'] = Config::encrypt_secret( trim( (string) $in['client_secret'] ) );
			$values['source']            = 'manual';
		}
		if ( ! Config::is_locked( 'FAABLE_AUTH_ROLE_MAP' ) && isset( $in['role_map'] ) ) {
			$values['role_map'] = RoleMapper::to_text( RoleMapper::parse( sanitize_textarea_field( (string) $in['role_map'] ) ) );
		}
		if ( ! Config::is_locked( 'FAABLE_AUTH_FEDERATED_LOGOUT' ) ) {
			$values['federated_logout'] = ! empty( $in['federated_logout'] );
		}
		Config::save( $values );
		self::back( 'saved', __( 'Settings saved.', 'faable-auth' ) );
	}

	/**
	 * Forget the stored credentials (env/constants are untouched).
	 */
	public static function disconnect(): void {
		self::guard( 'faable_auth_disconnect' );
		self::refuse_if_managed();
		Config::save(
			array(
				'domain'            => '',
				'client_id'         => '',
				'client_secret_enc' => '',
				'account_id'        => '',
				'project_id'        => '',
				'source'            => '',
			)
		);
		self::back( 'saved', __( 'Disconnected. The native WordPress login is back until you connect again.', 'faable-auth' ) );
	}

	/**
	 * Capability + nonce check for admin-post handlers.
	 *
	 * @param string $action Nonce action.
	 */
	private static function guard( string $action ): void {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'faable-auth' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * The connection of a managed site cannot be changed from WordPress: it
	 * is created and kept by the hosting platform.
	 */
	private static function refuse_if_managed(): void {
		if ( Config::is_managed() ) {
			wp_die( esc_html__( 'This site is managed by Faable: its Faable Auth connection cannot be changed here.', 'faable-auth' ), 403 );
		}
	}

	/**
	 * Redirect back to the settings page with a notice.
	 *
	 * @param string $type    saved|connected|error.
	 * @param string $message Message.
	 */
	private static function back( string $type, string $message ): void {
		set_transient( 'faable_auth_notice_' . get_current_user_id(), array( $type, $message ), MINUTE_IN_SECONDS );
		wp_safe_redirect( self::page_url() );
		exit;
	}

	/**
	 * Notices: the one-shot result of an action, and configuration problems.
	 */
	public static function notices(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$key    = 'faable_auth_notice_' . get_current_user_id();
		$notice = get_transient( $key );
		if ( is_array( $notice ) ) {
			delete_transient( $key );
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', 'error' === $notice[0] ? 'error' : 'success', esc_html( (string) $notice[1] ) );
		}
		if ( Config::is_managed() && ! Config::is_configured() ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Faable Auth is managed by Faable on this site, but its configuration is incomplete: the native login is active. Contact Faable support.', 'faable-auth' ) . '</p></div>';
		}
		if ( Config::secret_unreadable() ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Faable Auth: the stored client secret cannot be decrypted (the site salts changed). The native login is active again; reconnect in Settings → Faable Auth.', 'faable-auth' ) . '</p></div>';
		}
		if ( BreakGlass::from_environment() && Config::is_configured() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Faable Auth emergency access is ON: password logins are accepted. Remove FAABLE_AUTH_BREAK_GLASS once Faable Auth is reachable.', 'faable-auth' ) . '</p></div>';
		}
	}

	/**
	 * A text input row.
	 *
	 * @param string $const Env/constant name.
	 * @param string $key   Option key.
	 * @param string $label Label.
	 * @param string $help  Help text.
	 */
	private static function row( string $const, string $key, string $label, string $help = '' ): void {
		$locked = Config::is_locked( $const );
		$value  = Config::get( $const );
		echo '<tr><th scope="row"><label for="fa-' . esc_attr( $key ) . '">' . esc_html( $label ) . '</label></th><td>';
		printf(
			'<input type="text" class="regular-text code" id="fa-%1$s" name="faable_auth[%1$s]" value="%2$s" %3$s />',
			esc_attr( $key ),
			esc_attr( $value ),
			$locked ? 'readonly' : ''
		);
		if ( $locked ) {
			/* translators: %s: env var / constant name */
			echo '<p class="description">' . esc_html( sprintf( __( 'Set by %s (environment or wp-config.php).', 'faable-auth' ), $const ) ) . '</p>';
		} elseif ( '' !== $help ) {
			echo '<p class="description">' . esc_html( $help ) . '</p>';
		}
		echo '</td></tr>';
	}

	/**
	 * Render the settings page.
	 */
	public static function render(): void {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$configured = Config::is_configured();
		$managed    = Config::is_managed();
		$mode       = Login::mode();
		$o          = Config::options();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Faable Auth', 'faable-auth' ); ?></h1>

			<?php if ( $managed ) : ?>
				<div class="notice notice-info inline faable-auth-managed"><p><strong><?php esc_html_e( 'Managed by Faable', 'faable-auth' ); ?></strong> — <?php esc_html_e( 'this site signs in with Faable Auth.', 'faable-auth' ); ?></p>
					<p><?php esc_html_e( 'Faable created this site\'s client in your project\'s Faable Auth tenant and keeps it connected while the site is hosted on Faable. Who can sign in, and with which role, is managed in Faable Auth (roles of the tenant).', 'faable-auth' ); ?></p></div>
			<?php endif; ?>

			<?php if ( $configured ) : ?>
				<p class="faable-auth-manage">
					<a class="button button-primary" href="<?php echo esc_url( Config::manage_url() ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Manage users and roles in Faable', 'faable-auth' ); ?> <span aria-hidden="true">↗</span></a>
					<a class="button" href="<?php echo esc_url( Config::DOCS_URL ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Documentation', 'faable-auth' ); ?></a>
				</p>
				<p class="description"><?php esc_html_e( 'Opens your Faable Auth tenant in the Faable dashboard: invite users, give them a role (administrator, editor, author…) and see who signed in.', 'faable-auth' ); ?></p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Connection', 'faable-auth' ); ?></h2>
			<?php if ( $configured ) : ?>
				<p>
					<?php
					/* translators: 1: tenant domain, 2: client id */
					echo esc_html( sprintf( __( 'Signing in through %1$s (client %2$s).', 'faable-auth' ), Config::domain(), Config::get( 'FAABLE_AUTH_CLIENT_ID' ) ) );
					?>
				</p>
			<?php else : ?>
				<p><?php esc_html_e( 'Not connected: the native WordPress login is active. Once connected, only Faable sign-in is accepted.', 'faable-auth' ); ?></p>
			<?php endif; ?>
			<p>
				<?php
				$labels = array(
					BreakGlass::MODE_NATIVE => __( 'native WordPress login', 'faable-auth' ),
					BreakGlass::MODE_FAABLE => __( 'Faable only', 'faable-auth' ),
					BreakGlass::MODE_BOTH   => __( 'Faable and passwords (emergency access ON)', 'faable-auth' ),
				);
				/* translators: %s: login mode */
				echo esc_html( sprintf( __( 'Login mode: %s.', 'faable-auth' ), $labels[ $mode ] ) );
				?>
			</p>
			<?php if ( ! $managed && ! Config::is_locked( 'FAABLE_AUTH_CLIENT_ID' ) ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:8px">
					<input type="hidden" name="action" value="faable_auth_connect" />
					<?php wp_nonce_field( 'faable_auth_connect' ); ?>
					<?php submit_button( $configured ? __( 'Reconnect with Faable', 'faable-auth' ) : __( 'Connect with Faable', 'faable-auth' ), 'primary', 'submit', false ); ?>
				</form>
				<?php if ( $configured ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block">
						<input type="hidden" name="action" value="faable_auth_disconnect" />
						<?php wp_nonce_field( 'faable_auth_disconnect' ); ?>
						<?php submit_button( __( 'Disconnect', 'faable-auth' ), 'secondary', 'submit', false ); ?>
					</form>
				<?php endif; ?>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="faable_auth_save" />
				<?php wp_nonce_field( 'faable_auth_save' ); ?>

				<?php if ( $managed ) : ?>
				<h2><?php esc_html_e( 'Client', 'faable-auth' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><?php esc_html_e( 'Tenant domain', 'faable-auth' ); ?></th><td><code><?php echo esc_html( Config::domain() ); ?></code></td></tr>
					<tr><th scope="row"><?php esc_html_e( 'Client ID', 'faable-auth' ); ?></th><td><code><?php echo esc_html( Config::get( 'FAABLE_AUTH_CLIENT_ID' ) ); ?></code></td></tr>
					<tr><th scope="row"><?php esc_html_e( 'Client secret', 'faable-auth' ); ?></th><td><?php esc_html_e( 'Set by Faable.', 'faable-auth' ); ?></td></tr>
					<tr><th scope="row"><?php esc_html_e( 'Redirect URI', 'faable-auth' ); ?></th><td><code><?php echo esc_html( Config::redirect_uri() ); ?></code></td></tr>
					<?php
					self::row( 'FAABLE_AUTH_AUDIENCE', 'audience', __( 'API audience (optional)', 'faable-auth' ), __( 'An API of your tenant with "include roles in ID token" on. Empty: roles are read from the Management API.', 'faable-auth' ) );
					?>
				</table>
				<?php else : ?>
				<h2><?php esc_html_e( 'Manual configuration', 'faable-auth' ); ?></h2>
				<p><?php esc_html_e( 'Only if you cannot use "Connect with Faable": create a regular web client in your Faable Auth tenant and register this redirect URI:', 'faable-auth' ); ?>
					<code><?php echo esc_html( Config::redirect_uri() ); ?></code></p>
				<table class="form-table" role="presentation">
					<?php
					self::row( 'FAABLE_AUTH_DOMAIN', 'domain', __( 'Tenant domain', 'faable-auth' ), __( 'e.g. https://acme.auth.faable.link (or your custom domain).', 'faable-auth' ) );
					self::row( 'FAABLE_AUTH_CLIENT_ID', 'client_id', __( 'Client ID', 'faable-auth' ) );
					?>
					<tr><th scope="row"><label for="fa-secret"><?php esc_html_e( 'Client secret', 'faable-auth' ); ?></label></th><td>
						<?php if ( Config::is_locked( 'FAABLE_AUTH_CLIENT_SECRET' ) ) : ?>
							<p class="description"><?php esc_html_e( 'Set by FAABLE_AUTH_CLIENT_SECRET (environment or wp-config.php).', 'faable-auth' ); ?></p>
						<?php else : ?>
							<input type="password" class="regular-text" id="fa-secret" name="faable_auth[client_secret]" value="" autocomplete="new-password" placeholder="<?php echo esc_attr( '' !== Config::get( 'FAABLE_AUTH_CLIENT_SECRET' ) ? __( '(stored, encrypted — leave empty to keep)', 'faable-auth' ) : '' ); ?>" />
						<?php endif; ?>
					</td></tr>
					<?php
					self::row( 'FAABLE_AUTH_AUDIENCE', 'audience', __( 'API audience (optional)', 'faable-auth' ), __( 'An API of your tenant with "include roles in ID token" on. Empty: roles are read from the Management API.', 'faable-auth' ) );
					?>
				</table>
				<?php endif; ?>

				<h2><?php esc_html_e( 'Roles', 'faable-auth' ); ?></h2>
				<p><?php esc_html_e( 'One "Faable Auth role = WordPress role" per line. A user whose roles map to nothing is refused. Roles are re-synced on every login.', 'faable-auth' ); ?></p>
				<textarea name="faable_auth[role_map]" rows="7" cols="50" class="code" <?php echo Config::is_locked( 'FAABLE_AUTH_ROLE_MAP' ) ? 'readonly' : ''; ?>><?php echo esc_textarea( RoleMapper::to_text( Config::role_map() ) ); ?></textarea>

				<h2><?php esc_html_e( 'Headless (REST API with machine-to-machine tokens)', 'faable-auth' ); ?></h2>
				<p><?php esc_html_e( 'Front-ends call the REST API with a Faable Auth client_credentials token instead of an Application Password.', 'faable-auth' ); ?></p>
				<table class="form-table" role="presentation">
					<?php
					self::row( 'FAABLE_AUTH_REST_AUDIENCE', 'rest_audience', __( 'Token audience', 'faable-auth' ), __( 'Identifier of the API the tokens are issued for. Empty: Bearer tokens are not accepted.', 'faable-auth' ) );
					self::row( 'FAABLE_AUTH_REST_USER', 'rest_user', __( 'Acts as user (login)', 'faable-auth' ), __( 'Requests get this WordPress user\'s capabilities. Create a dedicated user with the least role that works.', 'faable-auth' ) );
					self::row( 'FAABLE_AUTH_REST_CLIENTS', 'rest_clients', __( 'Allowed client IDs', 'faable-auth' ), __( 'Comma separated. Empty: any client of the tenant.', 'faable-auth' ) );
					self::row( 'FAABLE_AUTH_REST_SCOPE', 'rest_scope', __( 'Required scope (optional)', 'faable-auth' ) );
					self::row( 'FAABLE_AUTH_APP_PASSWORD_USERS', 'app_password_users', __( 'Local users with Application Passwords', 'faable-auth' ), __( 'Comma-separated logins of local WordPress users (not Faable users) that keep calling the REST API with an Application Password, e.g. an existing front-end. They cannot log in to wp-admin. Empty: no Application Passwords at all.', 'faable-auth' ) );
					?>
				</table>

				<h2><?php esc_html_e( 'Logout', 'faable-auth' ); ?></h2>
				<label><input type="checkbox" name="faable_auth[federated_logout]" value="1" <?php checked( Config::federated_logout() ); ?> <?php disabled( Config::is_locked( 'FAABLE_AUTH_FEDERATED_LOGOUT' ) ); ?> />
					<?php esc_html_e( 'Also end the Faable session on logout.', 'faable-auth' ); ?></label>
				<p class="description"><?php esc_html_e( 'Requires this URL in the client\'s logout URLs:', 'faable-auth' ); ?> <code><?php echo esc_html( home_url( '/wp-login.php?loggedout=true' ) ); ?></code></p>

				<?php submit_button(); ?>
			</form>

			<h2><?php esc_html_e( 'Emergency access', 'faable-auth' ); ?></h2>
			<p><?php esc_html_e( 'If Faable Auth cannot be reached, nobody can log in. Two ways in:', 'faable-auth' ); ?></p>
			<ol>
				<li><?php esc_html_e( 'Add this line to wp-config.php to bring back the password form (remove it afterwards):', 'faable-auth' ); ?> <code>define( 'FAABLE_AUTH_BREAK_GLASS', true );</code></li>
				<li><?php esc_html_e( 'Or run this WP-CLI command for a one-time login URL valid 10 minutes:', 'faable-auth' ); ?> <code>wp faable-auth login-link &lt;user&gt;</code></li>
			</ol>
			<?php if ( ! $managed && ! empty( $o['connected_at'] ) ) : ?>
				<p class="description">
					<?php
					/* translators: %s: date */
					echo esc_html( sprintf( __( 'Connected on %s.', 'faable-auth' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $o['connected_at'] ) ) );
					?>
				</p>
			<?php endif; ?>
		</div>
		<?php
	}
}
