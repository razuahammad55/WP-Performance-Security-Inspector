<?php
/**
 * Security Audit Functions
 *
 * @package WP_Performance_Security_Inspector
 * @since 1.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Run all security audits
 *
 * @return array Array of audit results
 */
function wppsi_run_security_audit() {
    $results = array();

    $results[] = wppsi_check_rest_api_users();
    $results[] = wppsi_check_xmlrpc();
    $results[] = wppsi_check_user_registration();
    $results[] = wppsi_check_wordpress_version_exposure();
    $results[] = wppsi_check_ssl();
    $results[] = wppsi_check_file_editing();
    $results[] = wppsi_check_database_prefix();
    $results[] = wppsi_check_admin_username();

    return $results;
}

/**
 * Check REST API user enumeration vulnerability
 *
 * @return array Audit result
 */
function wppsi_check_rest_api_users() {
    $rest_url = rest_url( 'wp/v2/users' );
    
    $response = wp_remote_get( $rest_url, array(
        'timeout'   => 10,
        'sslverify' => false,
    ) );

    if ( is_wp_error( $response ) ) {
        return wppsi_create_audit_result(
            __( 'REST API User Enumeration', 'wp-performance-security-inspector' ),
            'warning',
            __( 'Unable to test REST API user endpoint.', 'wp-performance-security-inspector' ),
            __( 'The REST API users endpoint can expose usernames to attackers, making brute force attacks easier.', 'wp-performance-security-inspector' ),
            __( 'Verify manually by visiting /wp-json/wp/v2/users. Use a security plugin or custom code to restrict this endpoint.', 'wp-performance-security-inspector' )
        );
    }

    $response_code = wp_remote_retrieve_response_code( $response );
    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body, true );

    // Check if users are exposed
    if ( 200 === $response_code && is_array( $data ) && ! empty( $data ) ) {
        // Check if user data is actually exposed (not just an empty array)
        $user_exposed = false;
        foreach ( $data as $user ) {
            if ( isset( $user['slug'] ) || isset( $user['name'] ) ) {
                $user_exposed = true;
                break;
            }
        }
        
        if ( $user_exposed ) {
            return wppsi_create_audit_result(
                __( 'REST API User Enumeration', 'wp-performance-security-inspector' ),
                'fail',
                __( 'REST API exposes user information publicly.', 'wp-performance-security-inspector' ),
                __( 'Attackers can discover valid usernames through /wp-json/wp/v2/users, making it easier to launch targeted brute force or social engineering attacks.', 'wp-performance-security-inspector' ),
                __( 'Install a security plugin like Wordfence or add custom code to restrict the REST API users endpoint. Cloudflare can also help block malicious requests.', 'wp-performance-security-inspector' )
            );
        }
    }

    // 401, 403, or empty response means it is protected
    return wppsi_create_audit_result(
        __( 'REST API User Enumeration', 'wp-performance-security-inspector' ),
        'pass',
        __( 'REST API user enumeration is restricted.', 'wp-performance-security-inspector' ),
        __( 'Restricting access to user data through the REST API prevents attackers from easily discovering valid usernames.', 'wp-performance-security-inspector' ),
        ''
    );
}

/**
 * Check if XML-RPC is enabled
 *
 * @return array Audit result
 */
function wppsi_check_xmlrpc() {
    $xmlrpc_url = site_url( '/xmlrpc.php' );
    
    $response = wp_remote_post( $xmlrpc_url, array(
        'timeout'   => 10,
        'sslverify' => false,
        'body'      => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
        'headers'   => array(
            'Content-Type' => 'text/xml',
        ),
    ) );

    if ( is_wp_error( $response ) ) {
        return wppsi_create_audit_result(
            __( 'XML-RPC', 'wp-performance-security-inspector' ),
            'pass',
            __( 'XML-RPC appears to be disabled or blocked.', 'wp-performance-security-inspector' ),
            __( 'Disabling XML-RPC prevents its use as an attack vector for brute force and DDoS attacks.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    $response_code = wp_remote_retrieve_response_code( $response );
    $body = wp_remote_retrieve_body( $response );

    // Check if XML-RPC is responding with methods list
    if ( 200 === $response_code && strpos( $body, 'methodResponse' ) !== false && strpos( $body, 'system.listMethods' ) !== false ) {
        return wppsi_create_audit_result(
            __( 'XML-RPC', 'wp-performance-security-inspector' ),
            'fail',
            __( 'XML-RPC is enabled and responding to requests.', 'wp-performance-security-inspector' ),
            __( 'XML-RPC can be exploited for brute force attacks (trying thousands of passwords in a single request) and DDoS amplification attacks.', 'wp-performance-security-inspector' ),
            __( 'Disable XML-RPC using a security plugin, .htaccess rules, or Cloudflare firewall rules. Note: Jetpack and some mobile apps require XML-RPC.', 'wp-performance-security-inspector' )
        );
    }

    // 403, 405, or blocked response
    if ( in_array( $response_code, array( 403, 405, 401 ), true ) ) {
        return wppsi_create_audit_result(
            __( 'XML-RPC', 'wp-performance-security-inspector' ),
            'pass',
            __( 'XML-RPC access is blocked.', 'wp-performance-security-inspector' ),
            __( 'Blocking XML-RPC access while keeping the file present prevents attacks without breaking functionality that checks for its existence.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'XML-RPC', 'wp-performance-security-inspector' ),
        'warning',
        __( 'XML-RPC status is uncertain.', 'wp-performance-security-inspector' ),
        __( 'Unable to determine if XML-RPC is properly secured. It may be partially accessible.', 'wp-performance-security-inspector' ),
        __( 'Manually verify by visiting /xmlrpc.php. Consider blocking it via .htaccess or Cloudflare for additional security.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if anyone can register accounts
 *
 * @return array Audit result
 */
function wppsi_check_user_registration() {
    $users_can_register = get_option( 'users_can_register' );

    if ( ! $users_can_register ) {
        return wppsi_create_audit_result(
            __( 'User Registration', 'wp-performance-security-inspector' ),
            'pass',
            __( 'Public user registration is disabled.', 'wp-performance-security-inspector' ),
            __( 'Disabling public registration prevents spam accounts and reduces the attack surface of your site.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    // Check default role for registered users
    $default_role = get_option( 'default_role', 'subscriber' );
    
    if ( 'subscriber' === $default_role ) {
        return wppsi_create_audit_result(
            __( 'User Registration', 'wp-performance-security-inspector' ),
            'warning',
            __( 'Public registration is enabled with Subscriber as the default role.', 'wp-performance-security-inspector' ),
            __( 'While Subscriber is the safest default role, open registration can still lead to spam accounts and potential security issues if other plugins grant additional capabilities.', 'wp-performance-security-inspector' ),
            __( 'If registration is not needed, disable it in Settings > General. Otherwise, implement CAPTCHA and consider using a membership plugin for better control.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'User Registration', 'wp-performance-security-inspector' ),
        'fail',
        sprintf(
            /* translators: %s: Default user role */
            __( 'Public registration is enabled with "%s" as the default role.', 'wp-performance-security-inspector' ),
            $default_role
        ),
        __( 'A default role higher than Subscriber can give new users access to the admin dashboard or editing capabilities, posing a significant security risk.', 'wp-performance-security-inspector' ),
        __( 'Immediately change the default role to Subscriber in Settings > General, or disable registration entirely if not required.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if WordPress version is exposed
 *
 * @return array Audit result
 */
function wppsi_check_wordpress_version_exposure() {
    $home_url = home_url( '/' );
    
    $response = wp_remote_get( $home_url, array(
        'timeout'   => 10,
        'sslverify' => false,
    ) );

    if ( is_wp_error( $response ) ) {
        return wppsi_create_audit_result(
            __( 'WordPress Version Exposure', 'wp-performance-security-inspector' ),
            'warning',
            __( 'Unable to check WordPress version exposure.', 'wp-performance-security-inspector' ),
            __( 'Exposing your WordPress version helps attackers identify which vulnerabilities apply to your site.', 'wp-performance-security-inspector' ),
            __( 'Manually check your site source code for the WordPress version meta tag.', 'wp-performance-security-inspector' )
        );
    }

    $body = wp_remote_retrieve_body( $response );
    
    // Check for version in generator meta tag
    $version_exposed = false;
    $exposure_methods = array();
    
    // Check meta generator tag
    if ( preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9.]+)["\']/', $body, $matches ) ) {
        $version_exposed = true;
        $exposure_methods[] = 'meta generator tag';
    }
    
    // Check for version in stylesheet URLs
    if ( preg_match( '/ver=' . preg_quote( get_bloginfo( 'version' ), '/' ) . '/', $body ) ) {
        $version_exposed = true;
        $exposure_methods[] = 'script/style version parameters';
    }
    
    // Check readme.html
    $readme_response = wp_remote_head( site_url( '/readme.html' ), array(
        'timeout'   => 5,
        'sslverify' => false,
    ) );
    
    if ( ! is_wp_error( $readme_response ) && 200 === wp_remote_retrieve_response_code( $readme_response ) ) {
        $version_exposed = true;
        $exposure_methods[] = 'readme.html file';
    }

    if ( $version_exposed ) {
        return wppsi_create_audit_result(
            __( 'WordPress Version Exposure', 'wp-performance-security-inspector' ),
            'fail',
            sprintf(
                /* translators: %s: List of exposure methods */
                __( 'WordPress version is exposed via: %s.', 'wp-performance-security-inspector' ),
                implode( ', ', $exposure_methods )
            ),
            __( 'Knowing your exact WordPress version allows attackers to target known vulnerabilities specific to that version.', 'wp-performance-security-inspector' ),
            __( 'Use a security plugin to remove version information, delete readme.html, and remove version query strings from assets. WP Rocket can handle version string removal.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'WordPress Version Exposure', 'wp-performance-security-inspector' ),
        'pass',
        __( 'WordPress version is not publicly exposed.', 'wp-performance-security-inspector' ),
        __( 'Hiding your WordPress version makes it harder for attackers to identify which vulnerabilities may affect your site.', 'wp-performance-security-inspector' ),
        ''
    );
}

/**
 * Check SSL/HTTPS configuration
 *
 * @return array Audit result
 */
function wppsi_check_ssl() {
    $is_https = wppsi_is_https();
    $site_url = get_option( 'siteurl' );
    $home_url = get_option( 'home' );
    
    $site_uses_https = strpos( $site_url, 'https://' ) === 0;
    $home_uses_https = strpos( $home_url, 'https://' ) === 0;

    if ( $is_https && $site_uses_https && $home_uses_https ) {
        return wppsi_create_audit_result(
            __( 'SSL/HTTPS', 'wp-performance-security-inspector' ),
            'pass',
            __( 'Your site is properly configured to use HTTPS.', 'wp-performance-security-inspector' ),
            __( 'HTTPS encrypts data between your server and visitors, protecting sensitive information and improving SEO rankings.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    if ( $is_https && ( ! $site_uses_https || ! $home_uses_https ) ) {
        return wppsi_create_audit_result(
            __( 'SSL/HTTPS', 'wp-performance-security-inspector' ),
            'warning',
            __( 'HTTPS is active but site URLs are not fully configured for HTTPS.', 'wp-performance-security-inspector' ),
            __( 'Mixed URL configuration can cause mixed content warnings and redirect loops.', 'wp-performance-security-inspector' ),
            __( 'Update your WordPress Address and Site Address in Settings > General to use https://.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'SSL/HTTPS', 'wp-performance-security-inspector' ),
        'fail',
        __( 'Your site is not using HTTPS.', 'wp-performance-security-inspector' ),
        __( 'Without HTTPS, data is transmitted in plain text, exposing passwords, personal information, and session cookies to interception.', 'wp-performance-security-inspector' ),
        __( 'Install an SSL certificate through your hosting provider (many offer free Let\'s Encrypt certificates) or use Cloudflare\'s free SSL.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if file editing is disabled
 *
 * @return array Audit result
 */
function wppsi_check_file_editing() {
    $file_edit_disabled = wppsi_is_constant_enabled( 'DISALLOW_FILE_EDIT' );
    $file_mods_disabled = wppsi_is_constant_enabled( 'DISALLOW_FILE_MODS' );

    if ( $file_mods_disabled ) {
        return wppsi_create_audit_result(
            __( 'File Editing', 'wp-performance-security-inspector' ),
            'pass',
            __( 'All file modifications are disabled (DISALLOW_FILE_MODS is true).', 'wp-performance-security-inspector' ),
            __( 'Preventing file modifications stops attackers from modifying plugin/theme code even if they gain admin access.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    if ( $file_edit_disabled ) {
        return wppsi_create_audit_result(
            __( 'File Editing', 'wp-performance-security-inspector' ),
            'pass',
            __( 'Theme and plugin editor is disabled.', 'wp-performance-security-inspector' ),
            __( 'Disabling the file editor prevents attackers with admin access from injecting malicious code through the WordPress dashboard.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'File Editing', 'wp-performance-security-inspector' ),
        'warning',
        __( 'The built-in theme and plugin editor is enabled.', 'wp-performance-security-inspector' ),
        __( 'If an attacker gains admin access, they can use the file editor to inject malicious code into your themes or plugins.', 'wp-performance-security-inspector' ),
        __( 'Add define( "DISALLOW_FILE_EDIT", true ); to your wp-config.php file to disable the editor.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check database table prefix
 *
 * @return array Audit result
 */
function wppsi_check_database_prefix() {
    global $wpdb;
    
    $prefix = $wpdb->prefix;

    if ( 'wp_' !== $prefix && 'wordpress_' !== $prefix ) {
        return wppsi_create_audit_result(
            __( 'Database Table Prefix', 'wp-performance-security-inspector' ),
            'pass',
            sprintf(
                /* translators: %s: Database prefix (first 3 characters shown) */
                __( 'You are using a custom database prefix (%s...).', 'wp-performance-security-inspector' ),
                substr( $prefix, 0, 3 )
            ),
            __( 'A custom table prefix provides minor protection against automated SQL injection attacks that assume the default prefix.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'Database Table Prefix', 'wp-performance-security-inspector' ),
        'warning',
        __( 'You are using the default WordPress database prefix (wp_).', 'wp-performance-security-inspector' ),
        __( 'The default prefix is targeted by automated attacks. While not a critical issue, a custom prefix adds a small layer of protection.', 'wp-performance-security-inspector' ),
        __( 'For new installations, use a custom prefix. Changing the prefix on an existing site requires careful database modifications and is not recommended without proper backups.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if admin username exists
 *
 * @return array Audit result
 */
function wppsi_check_admin_username() {
    $admin_user = get_user_by( 'login', 'admin' );
    $administrator_user = get_user_by( 'login', 'administrator' );

    if ( ! $admin_user && ! $administrator_user ) {
        return wppsi_create_audit_result(
            __( 'Admin Username', 'wp-performance-security-inspector' ),
            'pass',
            __( 'No user accounts with common admin usernames detected.', 'wp-performance-security-inspector' ),
            __( 'Using unique admin usernames makes brute force attacks more difficult as attackers must guess both username and password.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    $found_usernames = array();
    if ( $admin_user ) {
        $found_usernames[] = 'admin';
    }
    if ( $administrator_user ) {
        $found_usernames[] = 'administrator';
    }

    return wppsi_create_audit_result(
        __( 'Admin Username', 'wp-performance-security-inspector' ),
        'fail',
        sprintf(
            /* translators: %s: List of found admin usernames */
            __( 'Common admin username(s) detected: %s', 'wp-performance-security-inspector' ),
            implode( ', ', $found_usernames )
        ),
        __( 'Usernames like "admin" are the first targets in brute force attacks. Using predictable usernames gives attackers a 50% head start.', 'wp-performance-security-inspector' ),
        __( 'Create a new administrator account with a unique username, transfer content ownership, then delete the old "admin" account.', 'wp-performance-security-inspector' )
    );
}
