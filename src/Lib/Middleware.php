<?php

/**
 * Middleware Class
 * @package securefusion
 */

namespace SecureFusion\Lib;

use SecureFusion\Lib\Traits\WPCommon;

class Middleware {

    use WPCommon;



    function init()
    {
        global $wp;

        if (! function_exists('wp_get_current_user')) {
            include(ABSPATH . '/wp-includes/pluggable.php');
        }

        if (\current_user_can('manage_options')) {
            return;
        }

        if ($this->get_settings('filter_bad_requests')) {
            $this->filter_bad_requests();
        }

        if ($this->get_settings('disable_rest_api')) {
            $service_regex = 'users';
            $controlling   = \preg_match('#(^\/?wp\-json\/wp\/v[12]\/?$|^\/?wp\-json\/wp\/v[12]\/?(' . $service_regex . ')\/?.*$)#siu', $_SERVER["REQUEST_URI"]);

            if ($controlling) {
                if (version_compare(get_bloginfo('version'), '4.7', '>=')) {
                    add_filter('rest_authentication_errors', [$this, 'disable_rest_api']);
                } else {
                    $this->disable_rest_api_manually();
                }
            }
        }
    }



    public function headers()
    {
        $htaccess_flag = $this->get_settings( 'htaccess_flag', array( null, null, null, null ) );

        $hide_versions = $this->get_settings( 'htaccess_hide_versions' );
        $bad_bots      = $this->get_settings( 'htaccess_bad_bots' );
        $http_headers  = $this->get_settings( 'htaccess_http_headers' );

        $current_flag  = array( $hide_versions, $bad_bots, $http_headers );

        if ( $htaccess_flag === $current_flag ) {
            return;
        }

        $arr = [];

        if ( $hide_versions ) {
            $arr['hide_versions'] = [
                'ServerSignature off',
                '<IfModule mod_security2.c>',
                '	SecServerSignature "unknown"',
                '</IfModule>',
                '',
            ];
        }

        if ( $bad_bots ) {
            $arr['bad_bots'] = [
                'SetEnvIfNoCase User-Agent "^libwww-perl*" block_bad_bots',
                'Deny from env=block_bad_bots',
                '',
            ];
        }
        
        if ($http_headers) {
            $arr['http_headers'] = [
                '<ifModule mod_headers.c>',
                '	Header set X-Frame-Options "SAMEORIGIN"',
                '	Header set Referrer-Policy "no-referrer-when-downgrade"',
                '	Header unset "X-Powered-By"',
                '	Header set X-XSS-Protection "1; mode=block"',
                '	Header set X-Content-Type-Options "nosniff"',
                '	Header set Strict-Transport-Security "max-age=31536000" env=HTTPS',
                '</IfModule>',
            ];
        }

        $headers = $this->array_merge_values( $arr );

        $this->append_htaccess( $headers, true );
        $this->set_settings( 'htaccess_flag', $current_flag );
    }



    public function filter_bad_requests()
    {
        global $wp, $pagenow;

        // http://vulnsite.com/script.php etc.
        // wp-config.php etc.
        // ../../../../etc/pwd etc.
        // ../../../unwanted.php

        if ( ! $this->get_settings( 'filter_bad_requests' ) ) {
            return;
        }

        $method = strtoupper( $_SERVER['REQUEST_METHOD'] );

        if ( current_user_can( 'manage_options' ) || empty( $method ) ) return;

        $custom_cookie_patterns  = $this->get_settings( 'cookie_patterns' );
        $custom_request_patterns = $this->get_settings( 'request_patterns' );

        $pattern_arr = array( '/[\#]/', '/[\|]/' );
        $replace_arr = array( '\\\\#', '\\\\|' );

        if ( $custom_cookie_patterns ) {
			$custom_cookie_patterns = preg_split( '/\r\n/', $custom_cookie_patterns );
            $custom_cookie_patterns = array_map( function( $val ) use ( $pattern_arr, $replace_arr ) {
				return preg_replace( $pattern_arr, $replace_arr, $val );
			}, $custom_cookie_patterns );
        }

        if ( $custom_request_patterns ) {
			$custom_request_patterns = preg_split( '/\r\n/', $custom_request_patterns );
			$custom_request_patterns = array_map( function( $val ) use ( $pattern_arr, $replace_arr ) {
				return preg_replace( $pattern_arr, $replace_arr, $val );
			}, $custom_request_patterns );
        }
		
		$custom_cookie_patterns = is_array( $custom_cookie_patterns ) ? $custom_cookie_patterns : array();
		$custom_request_patterns = is_array( $custom_request_patterns ) ? $custom_request_patterns : array();

        // Cookie security
        $cookie_filter_items = apply_filters( 'securefusion_cookie_filter_items', $custom_cookie_patterns );

        if ( !empty( $cookie_filter_items ) ) {
            $cookie_pattern = '#' . implode( '|', $cookie_filter_items ) . '#siu';
        }

        if ( !empty( $_COOKIE ) ) {
            if ( !empty( $cookie_pattern ) ) {
                if ( $this->bad_request_control( $_COOKIE, $cookie_pattern ) ) {
                    wp_die(
                        __( 'SecureFusion Firewall has been denied this cookie request.', 'securefusion' ),
                        __( 'Cookie Failure', 'securefusion' ),
                        [
                            'back_link' => true,
                        ]
                    );
                }
            }
        }

        if ( $method === 'GET' && empty( $_GET ) ) return;

        // GET and POST security
        $http_pattern = '(?:(?:http|https)?\:\/\/)?';
        $url_pattern  = $http_pattern . '(?:[a-z0-9_\-\.]+\/+)([a-z0-9_\-\.\/]+)?';

		$default_regex_arr = [
            // SQL Global Variables
            '@@[\w\.\$]+',
            'eval\(\s*[\'\"][\w\s\(\)]+[\'\"]\s*\)',
            'base64_(encode|decode)\s*\(',
            'shell_exec\(\s*[\'\"][\w\s\-\.\/]+[\'\"]\s*\)',
            'phpinfo\(\s*\)',
            '^file_get_contents\(\s*[\'\"][\w\s\-\.\/]+[\'\"]\s*\)',
            $url_pattern . '\.(htaccess|exe|run|cgi)',
            $url_pattern . '(config|boot|vuln|load)\.(php|ini)',
            'mosConfig_[a-zA-Z_]{1,20}',
            // sql injections
            '(union\s+)?(select|insert|delete)\s+\w+(\s*,\s*\w+)*\s+from\s+\w+(\s+where\s+\w+\s*(=|<|>|\!=)\s*[\w\'\"]+)?',
            // special characters " ' < > \ { |
            '.*(&\#x22;|&\#x27;|&\#x3C;|&\#x3E;|&\#x5C;|&\#x7B;|&\#x7C;).*',
            // prevents ../ url patterns
            $http_pattern . '(\/*[a-z0-9_\-\.]+)?(\.\.\/)+([a-z0-9_\-\.])*',
        ];

 		$request_regex_arr = array_merge( $default_regex_arr, $custom_request_patterns );

        $request_filter_items = apply_filters( 'securefusion_request_filter_items', $request_regex_arr );

        $request_pattern = '#' . implode('|', $request_filter_items) . '#siu';

        if ( $method === 'POST' && !empty( $_POST ) ) {
            $input = $_POST;
        } else {
            $input = $_SERVER['QUERY_STRING'];
        }

        if ( $this->bad_request_control( $input, $request_pattern ) ) {
            // Comments
            if ( $pagenow == 'wp-comments-post.php' ) {
                wp_die(
                    __( 'SecureFusion Firewall has been denied this comment submission.', 'securefusion' ),
                    __( 'Comment Submission Failure' ),
                    [
                        'back_link' => true,
                    ]
                );
            }

            wp_die(
                __( 'SecureFusion Firewall has been denied this request.', 'securefusion' ),
                __( 'Request Failure', 'securefusion' ),
                [
                    'back_link' => true,
                ]
            );
        }

        if ( empty( $wp->query_vars ) ) return;

        // WP Query security
        if ( $this->bad_request_control( $wp->query_vars, $request_pattern ) ) {
            wp_die( "WP QUERY VARS ERROR!" );
            wp_die(
                __( 'SecureFusion Firewall has been denied this WP Queries.', 'securefusion' ),
                __( 'WP Query Failure', 'securefusion' ),
                [
                    'back_link' => true,
                ]
            );
        }
    }



    private function bad_request_control( $input, $pattern )
    {
        if ( is_array( $input ) ) {
            $input = http_build_query( $input );
        }

        $input = urldecode( $input );

        // detect unwanted requests
        if ( preg_match( $pattern, $input ) != false ) {
            return true;
        }

        return false;
    }



    public function disable_rest_api( $access )
    {
        return new \WP_Error(
            'rest_disabled',
            static::esc__( 'The REST API on this site has been disabled.' ),
            array( 'status' => rest_authorization_required_code() )
        );
    }



    public function disable_rest_api_manually()
    {
        // v 1.x
        add_filter( 'json_enabled', '__return_false' );
        add_filter( 'json_jsonp_enabled', '__return_false' );

        // v 2.x
        add_filter( 'rest_enabled', '__return_false' );
        add_filter( 'rest_jsonp_enabled', '__return_false' );
    }


    function track_authenticate_user( $user, $password ) {
        // check if the login attempt was not successful
        if ( $user instanceof \WP_User && wp_check_password( $password, $user->user_pass, $user->ID ) ) {
            return $user;
        }

        global $wpdb;

        $bf_table = $wpdb->prefix . 'securefusion_brute_force_table';

        // get client IP
        $ip = $this->get_client_ip();

        if ( !$ip ) {
            return $user;
        }

        // check if IP exists in the table
        $row = $wpdb->get_row(
            $wpdb->prepare( "SELECT * FROM $bf_table WHERE ip = %s", $ip )
        );

        if ( $row ) {
            // if IP exists, increment attempts and update last_attempt
            $wpdb->update(
                $bf_table,
                array(
                    'attempts' => $row->attempts + 1,
                    'last_attempt' => time(),
                ),
                array( 'ip' => $ip ),
                array( '%d', '%d' ),
                array( '%s' )
            );
        } else {
            // if IP does not exist, insert a new row
            $wpdb->insert(
                $bf_table,
                array(
                    'ip' => $ip,
                    'attempts' => 1,
                    'last_attempt' => time(),
                ),
                array( '%s', '%d', '%d' )
            );
        }

        // return the original result
        return $user;
    }


    function track_limit_login_attempts( $username ) {
        global $wpdb;

        $bf_table = $wpdb->prefix . 'securefusion_brute_force_table';

        // get client IP
        $ip = $this->get_client_ip();

        // Check the IP pool
        $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $bf_table WHERE ip = %s", $ip ) );

        $ip_time_limit  = $this->get_settings( 'ip_time_limit' );
        $ip_login_limit = $this->get_settings( 'ip_login_limit' );

        if ( !$ip_login_limit || !$ip_time_limit ) {
            return $username;
        }

        $ip_time_limit *= HOUR_IN_SECONDS;

        if ( $row ) {
            $current_time    = time();
            $time_difference = $current_time - $row->last_attempt;

            // Failed login attempt
            if ( $time_difference <= $ip_time_limit && $row->attempts >= $ip_login_limit ) {
                wp_die(
                    __( '<strong>ERROR</strong>: You have reached the login attempts limit.', 'securefusion' ),
                    __( 'Too many failed login attempts', 'securefusion' ),
                    [
                        'back_link' => true,
                    ]
                );
            }
        }
    }
}
