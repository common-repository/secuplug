<?php

/**
 * Main Class
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib as Sources;



class Main {

    protected $login;
    protected $admin;
    protected $xmlrpc;
    protected $ssl_control;
    protected $middleware;



    public function __construct()
    {
        $this->login       = new Sources\Login();
        $this->ssl_control = new Sources\SSLControl();
        $this->admin       = new Sources\Admin();
        $this->xmlrpc      = new Sources\XMLRPC();
        $this->middleware  = new Sources\Middleware();
        $this->middleware->headers();

        add_action( 'admin_init', array( 'PAnD', 'init' ) );

        // ADMIN
        add_action( 'init', array( $this->admin, 'init' ) );

        // XMLRPC
        add_action( 'init', array( $this->xmlrpc, 'init' ) );

        // LOGIN
        add_action( 'init', array( $this->login, 'init' ) );

        // SSL CONTROL
        add_action( 'plugin_loaded', array( $this->ssl_control, 'init' ) );

        // MIDDLEWARE
        add_action( 'plugin_loaded', array( $this->middleware, 'init' ) );
        add_action( 'init', array( $this->middleware, 'filter_bad_requests' ), 10 );
        add_filter( 'wp_authenticate_user', array( $this->middleware, 'track_authenticate_user' ), 30, 2 );
        add_action( 'wp_authenticate', array( $this->middleware, 'track_limit_login_attempts' ), 10, 2);
    }



    public function activate()
    {
        global $wpdb;

        // Default values
        $default_settings = array(
            "disable_xmlrpc"            => "0",
            "disable_xmlrpc_user_login" => "1",
            "disable_xmlrpc_pingback"   => "1",
            "disable_self_pingback"     => "1",
            "ip_time_limit"             => "10",
            "ip_login_limit"            => "5",
            "custom_login_url"          => "",
            "change_login_error"        => "",
            "change_admin_id"           => "",
            "filter_bad_requests"       => "1",
            "disable_rest_api"          => "1",
            "htaccess_hide_versions"    => "1",
            "htaccess_bad_bots"         => "1",
            "htaccess_http_headers"     => "1",
            "cookie_patterns"           => "",
            "request_patterns"          => "",
            "htaccess_flag"             => array( "1", "1", "1" ),
        );

        $old_settings = get_option( 'secuplug_settings' );
        $new_settings = get_option( 'securefusion_settings' );

        // Update new slug in option table
        if ( $old_settings !== false ) {

            delete_option( 'secuplug_settings' );
            $new_settings = $old_settings;
            
        }

        // Override exists settings
        $new_settings = array_merge( $default_settings, $new_settings );

        // Update final settings
        update_option( 'securefusion_settings', $new_settings );

        $old_bf_table = $wpdb->prefix . 'secuplug_brute_force_table';
        $new_bf_table = $wpdb->prefix . 'securefusion_brute_force_table';

        // Check if old table exists
        if ( $wpdb->get_var( "SHOW TABLES LIKE '$old_bf_table'" ) == $old_bf_table ) {
            // Rename old table
            $wpdb->query( "RENAME TABLE $old_bf_table TO $new_bf_table" );
        }

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $new_bf_table (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            ip varchar(50) NOT NULL,
            attempts int DEFAULT '0' NOT NULL,
            expiration int DEFAULT '0' NOT NULL,
            last_attempt int DEFAULT '0' NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }
}
