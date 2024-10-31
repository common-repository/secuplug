<?php

/**
 * Admin Class
 * @package securefusion
 */

namespace SecureFusion\Lib;

use \WaspCreators\Wasp;
use \SecureFusion\Lib\Traits\WPCommon;


class Admin {

	protected $filesystem;

	protected $settings_page;

	protected $menu_pages;

	protected $admin_link;

	protected $plugin_url;

	use WPCommon;



	public function __construct()
	{
		if (function_exists('admin_url')) {
			$this->admin_link = \admin_url('admin.php');
			$this->plugin_url = \plugins_url('/', SECUREFUSION_BASENAME);
		}
	}



	/**
	 * Add a link to your settings page in your plugin
	 *
	 * @return array
	 */
	public function add_settings_link( $links )
	{
		$settings_link	= '<a href="admin.php?page=securefusion-settings">';
		$settings_link	.= __( 'Settings', 'securefusion' );
		$settings_link	.= '</a>';

		$links[] = $settings_link;

		return $links;
	}



	public function admin_menu()
	{
		$this->menu_pages['main'] = \add_menu_page(
			__( 'SecureFusion', 'securefusion' ),
			__( 'SecureFusion', 'securefusion' ),
			'manage_options',
			'securefusion',
			array($this, 'get_dashboard_html'),
			'dashicons-shield'
		);

		$this->menu_pages['dashboard'] = \add_submenu_page(
			'securefusion',
			__( 'SecureFusion Dashboard', 'securefusion' ),
			__( 'Dashboard', 'securefusion' ),
			'manage_options',
			'securefusion',
			array($this, 'get_dashboard_html')
		);

		$this->menu_pages['settings'] = \add_submenu_page(
			'securefusion',
			__( 'SecureFusion Settings', 'securefusion' ),
			__('Settings', 'securefusion' ),
			'manage_options',
			'securefusion-settings',
			array($this, 'get_settings_html')
		);
	}



	public function get_dashboard_html()
	{
		global $wpdb, $wp_version;

		$settings				= $this->settings_page;

		$disable_all_xmlrpc 	= $settings->get_setting('disable_xmlrpc', false);
		$force_all_https		= $settings->get_setting('force_site_https', false);

		$enable_https			= $settings->get_setting('enable_https', null);

		// login
		$login_url				= $settings->get_setting('custom_login_url', null);
		$change_admin_id		= $settings->get_setting('change_admin_id', null) > 1 ? 1 : 0;
		$change_login_error		= empty($settings->get_setting('change_login_error', null)) ? 0 : 1;

		// firewall
		$filter_bad_requests	= $settings->get_setting('filter_bad_requests', null);
		$disable_rest_api		= $settings->get_setting('disable_rest_api', null);

		if ($disable_all_xmlrpc) {
			$xmlrpc_login		= 1;
			$xmlrpc_pingback	= 1;
			$self_pingback		= 1;
		} else {
			// Gets xml-rpc settings when all xml-rpc services are disabled
			$xmlrpc_login		= $settings->get_setting('disable_xmlrpc_user_login', null);
			$xmlrpc_pingback	= $settings->get_setting('disable_xmlrpc_pingback', null);
			$self_pingback		= $settings->get_setting('disable_self_pingback', null);
		}

		if ($force_all_https) {
			$force_front_https	= 1;
			$force_admin_https	= 1;
			$force_login_https	= 1;
		} else {
			$force_front_https	= $settings->get_setting('force_front_https', null);
			$force_admin_https	= $settings->get_setting('force_admin_https', null);
			$force_login_https	= $settings->get_setting('force_login_https', null);
		}

		$security_pass = true;

		$table_name = $wpdb->prefix . 'securefusion_brute_force_table';

		$total_attempts   = $wpdb->get_var("SELECT SUM(attempts) FROM {$table_name}");
		$unique_ips_count = $wpdb->get_var("SELECT COUNT(DISTINCT ip) FROM {$table_name}");


		?>
		<div class="securefusion-dashboard container">
			<header class="dashboard-header">
				<img src="<?php echo $this->plugin_url; ?>assets/icon.svg" alt="SecureFusion Logo" class="dashboard-logo">
				<div class="dashboard-title">
					<h1>
						<?php _e( 'SecureFusion Dashboard' , 'securefusion' ) ?>
					</h1>
					<p class="description">
						<?php _e( 'You could monitoring your WordPress security settings.', 'securefusion' ) ?>
					</p>
				</div>
			</header>
			<section class="dashboard-overview">
				<div class="dashboard-item">
					<h2><?php _e( 'Security Status', 'securefusion' ); ?></h2>

					<p><?php _e( 'WordPress Version:', 'securefusion' ); echo ' ' . $wp_version; ?></p>

					<?php
						if ( version_compare( $wp_version, '6.4.2', '<' ) ) :
							$security_pass = false;
					?>
						<p class="status disabled"><?php _e( 'Your WordPress version has security vulnurabilities.', 'securefusion' ); ?></p>
					<?php endif; ?>

					<p><?php _e( 'PHP Version:', 'securefusion' ); echo ' ' . phpversion(); ?></p>

					<?php
						if ( version_compare( phpversion(), '8.3.0', '<' ) ) :
							$security_pass = false;
					?>
						<p class="status disabled"><?php _e( 'Your PHP version has security vulnurabilities.', 'securefusion' ); ?></p>
					<?php endif; ?>

					<p><?php _e( 'Failed login attempts:', 'securefusion' ); echo ' ' . (int) $total_attempts; ?></p>
					<p><?php _e( 'IPs of Failed Attempts:', 'securefusion' ); echo ' ' . (int) $unique_ips_count; ?></p>
					<?php if ( $security_pass ) : ?>
						<p class="status enabled">
							<?php _e( 'Everything is running smoothly. No security issues have been detected.', 'securefusion' ); ?>
						</p>
					<?php endif; ?>
				</div>
				<?php
					$settings_link = \add_query_arg(
						array(
							'page' => 'securefusion-settings'
						),
						$this->admin_link
					);

					$this->add_status_box(
						__( "XML-RPC FULL PROTECTION", 'securefusion' ),
						$disable_all_xmlrpc,
						__( "Blocks all remote requests. Most commonly used to prevent all types of remote attacks.", 'securefusion' )
					);

					$this->add_status_box(
						__( "XML-RPC LOGIN PROTECTION", 'securefusion' ),
						$xmlrpc_login,
						__( "Blocks remote login requests. Most commonly used to prevent brute force login attempts.", 'securefusion' )
					);

					$this->add_status_box(
						__( "XML-RPC PINGBACK PROTECTION", 'securefusion' ),
						$xmlrpc_pingback,
						__( "Blocks remote pingback requests. Most commonly used to prevent DDoS attacks.", 'securefusion' )
					);

					$this->add_status_box(
						__( "SELF PINGBACK PROTECTION", 'securefusion' ),
						$self_pingback,
						__( "Blocks remote self-pingback requests. Most commonly used to prevent DDoS attacks.", 'securefusion' )
					);

					$this->add_status_box(
						__( "New Custom Login URL", 'securefusion' ),
						$login_url,
						__( "Hides login url from the attackers.", 'securefusion' )
					);

					$this->add_status_box(
						__( "Enable HTTPS / SSL", 'securefusion' ),
						$enable_https,
						__( "SSL automatically encrypts your privileged information data.", 'securefusion' )
					);

					$this->add_status_box(
						__( "Force HTTPS Login", 'securefusion' ),
						$force_login_https,
						__( "Redirect login page protocol HTTP to HTTPS", 'securefusion' )
					);
					$this->add_status_box(
						__( "Change Login Error", 'securefusion' ),
						$change_login_error,
						__( "Disable default login errors and provide attackers with less than what they need.", 'securefusion' )
					);
					$this->add_status_box(
						__( "Change Admin ID", 'securefusion' ),
						$change_admin_id,
						__( "It's not difficult to predict your Admin ID if it's set to `1`. Secure your site against simple SQL vulnerabilities.", 'securefusion' )
					);
					$this->add_status_box(
						__( "Forge HTTPS Admin", 'securefusion' ),
						$force_admin_https,
						__( "Redirects the admin page protocol from HTTP to HTTPS", 'securefusion' )
					);
					$this->add_status_box(
						__( "Force HTTPS Front Page", 'securefusion' ),
						$force_front_https,
						__( "Redirects the front page protocol from HTTP to HTTPS.", 'securefusion' )
					);
					$this->add_status_box(
						__( "Filter Bad Requests", 'securefusion' ),
						$filter_bad_requests,
						__( "Helps secure your site against attacks like XSS, CSRF, and Code Injections.", 'securefusion' )
					);
					$this->add_status_box(
						__( "Disable Rest API", 'securefusion' ),
						$disable_rest_api,
						__( "Conceals sensitive information from attackers, such as Admin user IDs, user lists, and their IDs.", 'securefusion' )
					);
					
					$this->add_status_box(
						__( "Settings", 'securefusion' ),
						false,
						__( "Manage your security features", 'securefusion' ),
						[
							__( 'Go to settings', 'securefusion' ),
							$settings_link
						]
					);
				?>
			</section>
		</div>
		<?php
	}



	public function get_settings_html()
	{
		$ssl_cond = empty(get_transient('securefusion_ssl_cert_data'));
		$ssl_error = esc_html__( "Only use this if you have an SSL certificate; otherwise, it cannot be enabled.", 'securefusion' );

		if ($ssl_cond) {
			$ssl_error = '<p style="color:red">' .
			esc_html__( 'ERROR! You don’t have any valid SSL certificate. ', 'securefusion' ) .
			'</p>' .
			'<p>' .
				'<b>' . esc_html__( 'Free SSL certificate providers', 'securefusion' ) . '</b> : ' .
				'<a href="https://letsencrypt.org/" target="_blank">' .
                    esc_html__( 'Let’s Encrypt', 'securefusion' ) .
				'</a>' .
				' or ' .
				'<a href="https://www.cloudflare.com/" target="_blank">' .
                    esc_html__( 'Cloudflare', 'securefusion' ) .
				'</a>' .
				'<br />' .
				'<b>Paid SSL certificate providers</b> : ' .
				'<a href="https://sectigo.com/" target="_blank">' .
                    esc_html__( 'Comodo / Sectigo', 'securefusion' ) .
				'</a>' . ' or ' .
				'<a href="https://www.digicert.com" target="_blank">' .
                    esc_html__( 'Digicert', 'securefusion' ) .
				'</a>' .
			'</p>';
		}

		?>
		<div class="secure-fusion-settings container" style="position: relative;float: left;width: 100%;">
			<div class="header">
				<img src="<?php echo $this->plugin_url ?>assets/icon.svg" alt="SecureFusion Logo">
				<div class="header-title">
					<h1><?php _e( 'SecureFusion Security Settings', 'securefusion' ) ?></h1>
					<p class="version-info">
						<?php echo sprintf( esc_html__( 'Version %s - Check out', 'securefusion' ), SECUREFUSION_VERSION ); ?> 
						<a href="https://codeplus.dev/securefusion-wordpress-security-plugin/" target="_blank">
							<?php esc_html_e( 'What\'s New', 'securefusion' ); ?>
						</a>
					</p>
				</div>
				<div class="plugin-links">
					<a href="#">
						<?php esc_html_e( 'Additional Plugins', 'securefusion' ); ?>
					</a>
				</div>
			</div>
			<p class="description">
				<?php _e('You could manage your WordPress security settings.', 'securefusion' ) ?>
			</p>
			<div class="clear"></div>
			<?php
			if ($this->settings_page->is_ready()) {
				?>
				<h2 class="nav-tab-wrapper">
					<a href="#xmlrpc" class="nav-tab">
						<span class="dashicons dashicons-networking"></span>
						<?php _e( 'XMLRPC', 'securefusion' )?>
					</a>
					<a href="#login" class="nav-tab">
						<span class="dashicons dashicons-admin-users"></span>
						<?php _e( 'Login', 'securefusion' )?>
					</a>
					<a href="#ssl" class="nav-tab">
						<span class="dashicons dashicons-admin-network"></span>
						<?php _e( 'SSL', 'securefusion' )?>
					</a>
					<a href="#firewall" class="nav-tab">
						<span class="dashicons dashicons-hidden"></span>
						<?php _e( 'Firewall', 'securefusion' )?>
					</a>
					<a href="#advanced" class="nav-tab">
						<span class="dashicons dashicons-warning"></span>
						<?php _e( 'Advanced', 'securefusion' )?>
					</a>
				</h2>
				<div class="content-box">
					<?php $this->settings_page->form_start()?>
					<div class="content-tab-wrapper">
						<div class="tab-content" id="securefusion-xmlrpc">
							<?php $this->settings_page->run_section('xmlrpc_settings') ?>
						</div>
						<div class="tab-content hidden" id="securefusion-login">
							<?php $this->settings_page->run_section('login_settings') ?>
						</div>
						<div class="tab-content hidden" id="securefusion-ssl">
							<?php $this->settings_page->run_section('ssl_settings') ?>
							<div class="notice notice-error"><p><?php echo $ssl_error ?></p></div>
						</div>
						<div class="tab-content hidden" id="securefusion-firewall">
							<?php $this->settings_page->run_section('firewall_settings') ?>
						</div>
						<div class="tab-content hidden" id="securefusion-advanced">
							<?php $this->settings_page->run_section('advanced_settings') ?>
							<div class="notice notice-error">
								<p>
									<?php _e( "If you don't have experience in cybersecurity or regular expressions, do not modify these areas.", 'securefusion') ?>
								</p>
							</div>
						</div>
					</div>
					<?php $this->settings_page->form_end()?>
				</div>
			</div>
			<?php
		}
	}



	public function welcome_notice()
	{
		$settings = $this->get_settings();

		if ( ! empty( $settings ) ) return;

		if ( ! \PAnD::is_admin_notice_active( 'do-securefusion-settings-forever' ) ) {
			return;
		}

		$settings_menu = $this->admin_link . '?page=securefusion-settings';
		?>
		<div data-dismissible="do-securefusion-settings-forever" class="welcome-panel notice is-dismissible">
			<div class="welcome-panel-content">
				<h2>
					<?php _e( 'Welcome to SecureFusion', 'securefusion' )?>
				</h2>
				<p class="about-description">
					<?php
					echo sprintf(
						__(
							'Thank you for installing SecureFusion! Check out <a href="%s">the Plugin Settings</a>',
							'securefusion'
						),
						$settings_menu
					);
					?>
				</p>
				<div class="welcome-panel-column-container">
					<div class="welcome-panel-column">
						<p>
							<a href="<?php echo $settings_menu?>" class="button button-primary button-hero">
								<?php _e( 'Get started', 'securefusion' ); ?>
							</a>
						</p>
					</div>
				</div>
			</div>
		</div>
		<?php
	}



	public function load()
	{
		$current_user = \wp_get_current_user();

		$ssl_cond = ! empty( get_transient( 'securefusion_ssl_cert_data' ) );

		$conf = [
			[
				// Section info
				'name'	=> 'xmlrpc_settings',
				'title'	=> __( 'XML-RPC SETTINGS', 'securefusion' ),
				'desc'	=> __( 'You can prevent to xmlrpc attacks.', 'securefusion' ),
				// Form items
				'items' => [
					[
						'type'		=> 'radio',
						'name'		=> 'disable_xmlrpc',
						'label'		=> __( 'Disable All XML-RPC Services', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
						'after'	   => '<p class="description">' . __( 'Enabling this option will completely disable XML-RPC functionality, which can prevent certain types of attacks but may affect integrations with other systems and applications.' , 'securefusion' ) . '</p>',
					],
					[
						'type'		=> 'radio',
						'name'		=> 'disable_xmlrpc_user_login',
						'label'		=> __( 'Disable XML-RPC Login Service', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
						'after'	   => '<p class="description">' . __( 'If checked, this will disable login capability through XML-RPC. This helps prevent brute force attacks but may affect some legitimate XML-RPC uses.' , 'securefusion' ) . '</p>',
					],
					[
						'type'		=> 'radio',
						'name'		=> 'disable_xmlrpc_pingback',
						'label'		=> __( 'Disable XML-RPC Pingback Service', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
						'after'	   => '<p class="description">' . __( 'Pingbacks can be abused for DDoS attacks. Disabling this will prevent pingbacks, improving security.' , 'securefusion' ) . '</p>',
					],
					[
						'type'		=> 'radio',
						'name'		=> 'disable_self_pingback',
						'label'		=> __( 'Disable Self Pingback Service', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
						'after'	   => '<p class="description">' . __( 'WordPress generates pingbacks to its own posts by default. This option disables such self-pingbacks.' , 'securefusion' ) . '</p>',
					],
				]
			],
			[
				// Section info
				'name'	=> 'firewall_settings',
				'title'	=> __( 'FIREWALL SETTINGS', 'securefusion' ),
				'desc'	=> __( 'Firewall security settings. (Beta)', 'securefusion' ),
				// Form items
				'items' => [
					[
						'type'		=> 'radio',
						'name'		=> 'filter_bad_requests',
						'label'		=> __( 'Filter Bad Requests', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
					],
					[
						'type'		=> 'radio',
						'name'		=> 'disable_rest_api',
						'label'		=> __( 'Disable Rest API for Visitors', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
					],
					[
						'type'		=> 'radio',
						'name'		=> 'htaccess_hide_versions',
						'label'		=> __( 'Hide apache and PHP version', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
					],
					[
						'type'		=> 'radio',
						'name'		=> 'htaccess_bad_bots',
						'label'		=> __( 'Block bad bots', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
					],
					[
						'type'		=> 'radio',
						'name'		=> 'htaccess_http_headers',
						'label'		=> __( 'Add HTTP Headers for Browser Security', 'securefusion' ),
						'options'	=> [
							[
								'value'	=> '0',
								'label'	=> __( 'No', 'securefusion' ),
							],
							[
								'value'	=> '1',
								'label'	=> __( 'Yes', 'securefusion' ),
							]
						],
					],
				],
			],
			[
				// Section info
				'name'	=> 'login_settings',
				'title'	=> __( 'LOGIN SETTINGS - BE CAREFUL!', 'securefusion' ),
				'desc'	=> __( 'You can hide or secure your login page against the attackers. Please save your new login url before you change it.', 'securefusion' ),
				// Form items
				'items' => [
					[
						'type'		=> 'text_input',
						'name'		=> 'ip_time_limit',
						'label'		=> __( 'Min. Wait Time', 'securefusion' ),
						'before'	=> '',
						'after'		=> __( ' hour(s)', 'securefusion' ) . '<span class="field-tip"> ' . __( 'Minimum Wait Time After Failed Attempt', 'securefusion' ) . '</span>'
					],
					[
						'type'		=> 'text_input',
						'name'		=> 'ip_login_limit',
						'label'		=> __( 'Max. Attempt Limit', 'securefusion' ),
						'before'	=> '',
						'after'		=> __( ' time(s)', 'securefusion' ) . '<span class="field-tip"> ' . __( 'Maksimum Failed Login Attempt Limit', 'securefusion' ) . '</span>'
					],
					[
						'type'		=> 'text_input',
						'name'		=> 'custom_login_url',
						'label'		=> __( 'Custom Login Path', 'securefusion' ),
						'before'	=> '<span class="url-text">' . \get_home_url() . '/</span>',
						'after'		=> '<span class="field-tip">/ (For exam. : hidden-login)</span>'
					],
					[
						'type'		=> 'text_input',
						'name'		=> 'change_login_error',
						'label'		=> __( 'Custom Login Error Message', 'securefusion' ),
					],
					[
						'type'		=> 'text_input',
						'name'		=> 'change_admin_id',
						'label'		=> __( 'Your Admin ID', 'securefusion' ),
						'before'	=> 'Your current ID is ',
						'after'		=> ' for "' . $current_user->user_login . '". ' .
						'<span class="field-tip">' .
						'	We recommended to change this field for each user by one by' .
						'</span>'
					],
				]
			],
			[
				// Section info
				'name'	=> 'ssl_settings',
				'title'	=> __( 'SSL SETTINGS', 'securefusion' ),
				'desc'	=> __( 'HTTPS/SSL security settings.', 'securefusion' ),
				// Form items
				'items' => [
					[
						'cond'		=> $ssl_cond,
						'type'		=> 'radio',
						'name'		=> 'enable_https',
						'label'		=> __( 'HTTPS Support', 'securefusion' ),
						'options'	=> [
							[
								'label' => __( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => __( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'		=> $ssl_cond,
						'type'		=> 'radio',
						'name'		=> 'force_login_https',
						'label'		=> __( 'Force HTTPS on login page', 'securefusion' ),
						'options'	=> [
							[
								'label' => __( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => __( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'		=> $ssl_cond,
						'type'		=> 'radio',
						'name'		=> 'force_admin_https',
						'label'		=> __( 'Force HTTPS on admin page', 'securefusion' ),
						'options'	=> [
							[
								'label' => __( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => __( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'		=> $ssl_cond,
						'type'		=> 'radio',
						'name'		=> 'force_front_https',
						'label'		=> __( 'Force HTTPS on front page', 'securefusion' ),
						'options'	=> [
							[
								'label' => __( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => __( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					],
					[
						'cond'		=> $ssl_cond,
						'type'		=> 'radio',
						'name'		=> 'force_site_https',
						'label'		=> __( 'Force HTTPS site-wide', 'securefusion' ),
						'options'	=> [
							[
								'label' => __( 'Disabled', 'securefusion' ),
								'value' => '',
							],
							[
								'label' => __( 'Enabled', 'securefusion' ),
								'value' => 'https',
							],
						],
					]
				]
            ],
            [
				// Section info
				'name'	=> 'advanced_settings',
				'title'	=> __( 'ADVANCED SETTINGS', 'securefusion' ),
				'desc'	=> __( 'Advanced security settings. `Filter Bad Requests` must be active for it to work. Separated by lines. For example: [a-z0-9]+/#[a-z]*', 'securefusion' ),
				// Form items
				'items' => [
					[
						'type'		=> 'textarea',
						'name'		=> 'cookie_patterns',
						'label'		=> __( 'Cookie Regex Patterns', 'securefusion' ),
						'sanitize'  => 'sanitize_textarea_field',
					],
					[
						'type'		=> 'textarea',
						'name'		=> 'request_patterns',
						'label'		=> __( 'Get/Post Request Regex Patterns', 'securefusion' ),
						'sanitize'  => 'sanitize_textarea_field',
					],
				]
			]
		];

		$this->settings_page->loadForm( $conf );
		$this->settings_page->register();
	}



	public function admin_menu_screen()
	{
		if ( $this->check_admin_menu_screen( $this->menu_pages ) ) {
			$this->admin_menu_zone();
		} else {
			\add_action( 'admin_notices', [ $this, 'welcome_notice' ] );
		}
	}



	public function admin_menu_zone()
	{
		\add_action( 'admin_enqueue_scripts', array( $this, 'admin_theme_styles' ), 1 );
	}



	public function admin_theme_styles()
	{
		\wp_enqueue_style( 'securefusion-admin-theme-main-css', \plugins_url( 'assets/css/admin.css', SECUREFUSION_BASENAME ), '', '1.1.5' );
		\wp_enqueue_script( 'securefusion-admin-js', \plugins_url( 'assets/js/admin.js', SECUREFUSION_BASENAME ), '', '1.1.9' );
	}



	public function add_status_box( $title, $status = false, $desc = "", $button = [] )
	{
		?>
		<div class="dashboard-item">
			<h2>
				<?php echo esc_html( $title ); ?>
			</h2>
			<?php
			if ( ! empty( $desc ) ) : ?>
				<p class="description">
					<?php echo esc_html( $desc ); ?>
				</p>
			<?php
			endif;

			if ( $status !== false ) :
				?>
				<p class="status <?php echo $status ? 'enabled' : 'disabled'; ?>">
					<?php echo $status ? __( 'enabled', 'securefusion' ) : __( 'disabled', 'securefusion' ); ?>
				</p>
				<?php
			endif;

			if ( ! empty( $button ) ) :?>
				<a href="<?php echo esc_attr( $button[1] ); ?>">
					<?php echo esc_html( $button[0] ); ?>
				</a>
			<?php
			endif;
			?>
		</div>
		<?php
	}



	public function init()
	{
		// Settings link
		$filter_name = "plugin_action_links_" . \plugin_basename(SECUREFUSION_BASENAME);
		\add_filter($filter_name, array($this, 'add_settings_link'));

		// Settings Page Form
		$this->settings_page = new Wasp(
			'securefusion-settings',
			'securefusion',
			'securefusion'
		);

		if ($this->settings_page instanceof Wasp) {
			$this->settings_page->wp_form_init([$this, 'load']);
		}

		\add_action('admin_menu', array($this, 'admin_menu'));
		\add_action('current_screen', array($this, 'admin_menu_screen'));
	}
}
