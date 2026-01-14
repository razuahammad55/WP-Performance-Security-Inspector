<?php
/**
 * Performance Audit Functions
 *
 * @package WP_Performance_Security_Inspector
 * @since 1.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Run all performance audits
 *
 * @return array Array of audit results
 */
function wppsi_run_performance_audit() {
    $results = array();

    $results[] = wppsi_check_active_plugins();
    $results[] = wppsi_check_page_cache();
    $results[] = wppsi_check_object_cache();
    $results[] = wppsi_check_cdn_presence();
    $results[] = wppsi_check_gzip_compression();
    $results[] = wppsi_check_php_version();
    $results[] = wppsi_check_memory_limit();
    $results[] = wppsi_check_debug_mode();

    return $results;
}

/**
 * Check number of active plugins
 *
 * @return array Audit result
 */
function wppsi_check_active_plugins() {
    $active_plugins = get_option( 'active_plugins', array() );
    
    // Include network-activated plugins for multisite
    if ( is_multisite() ) {
        $network_plugins = get_site_option( 'active_sitewide_plugins', array() );
        $active_plugins = array_merge( $active_plugins, array_keys( $network_plugins ) );
    }
    
    $plugin_count = count( $active_plugins );

    if ( $plugin_count <= 15 ) {
        return wppsi_create_audit_result(
            __( 'Active Plugins Count', 'wp-performance-security-inspector' ),
            'pass',
            sprintf(
                /* translators: %d: Number of active plugins */
                __( 'You have %d active plugins, which is within the recommended range.', 'wp-performance-security-inspector' ),
                $plugin_count
            ),
            __( 'A lower number of plugins reduces server load, decreases page load time, and minimizes potential security vulnerabilities.', 'wp-performance-security-inspector' ),
            ''
        );
    } elseif ( $plugin_count <= 25 ) {
        return wppsi_create_audit_result(
            __( 'Active Plugins Count', 'wp-performance-security-inspector' ),
            'warning',
            sprintf(
                /* translators: %d: Number of active plugins */
                __( 'You have %d active plugins. Consider reviewing if all are necessary.', 'wp-performance-security-inspector' ),
                $plugin_count
            ),
            __( 'Each active plugin adds PHP code that must be loaded on every page request, potentially slowing down your site and increasing memory usage.', 'wp-performance-security-inspector' ),
            __( 'Review your plugins and deactivate any that are not essential. Consider using multifunctional plugins to replace several single-purpose ones.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'Active Plugins Count', 'wp-performance-security-inspector' ),
        'fail',
        sprintf(
            /* translators: %d: Number of active plugins */
            __( 'You have %d active plugins, which is above the recommended maximum of 25.', 'wp-performance-security-inspector' ),
            $plugin_count
        ),
        __( 'Having too many plugins significantly impacts performance, increases memory usage, can cause plugin conflicts, and expands your attack surface for security vulnerabilities.', 'wp-performance-security-inspector' ),
        __( 'Audit your plugins immediately. Remove unused plugins, replace multiple plugins with comprehensive solutions, and consider custom code for simple functionalities.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if page caching is enabled
 *
 * @return array Audit result
 */
function wppsi_check_page_cache() {
    $cache_enabled = wppsi_is_constant_enabled( 'WP_CACHE' );
    
    // Check for common caching plugin indicators
    $caching_plugins = array(
        'wp-rocket/wp-rocket.php',
        'w3-total-cache/w3-total-cache.php',
        'wp-super-cache/wp-cache.php',
        'litespeed-cache/litespeed-cache.php',
        'wp-fastest-cache/wpFastestCache.php',
        'cache-enabler/cache-enabler.php',
        'comet-cache/comet-cache.php',
        'hummingbird-performance/wp-hummingbird.php',
    );
    
    $active_plugins = get_option( 'active_plugins', array() );
    $has_cache_plugin = false;
    $cache_plugin_name = '';
    
    foreach ( $caching_plugins as $plugin ) {
        if ( in_array( $plugin, $active_plugins, true ) ) {
            $has_cache_plugin = true;
            $plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
            $cache_plugin_name = $plugin_data['Name'] ?? basename( $plugin, '.php' );
            break;
        }
    }

    if ( $cache_enabled || $has_cache_plugin ) {
        $message = $has_cache_plugin 
            ? sprintf(
                /* translators: %s: Cache plugin name */
                __( 'Page caching is enabled via %s.', 'wp-performance-security-inspector' ),
                $cache_plugin_name
            )
            : __( 'Page caching is enabled (WP_CACHE is set to true).', 'wp-performance-security-inspector' );
            
        return wppsi_create_audit_result(
            __( 'Page Cache', 'wp-performance-security-inspector' ),
            'pass',
            $message,
            __( 'Page caching serves pre-generated HTML files to visitors instead of processing PHP and database queries for every request, dramatically improving load times.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'Page Cache', 'wp-performance-security-inspector' ),
        'fail',
        __( 'Page caching is not detected on your site.', 'wp-performance-security-inspector' ),
        __( 'Without page caching, WordPress must execute PHP code and query the database for every single page view, resulting in slower response times and higher server load.', 'wp-performance-security-inspector' ),
        __( 'Install WP Rocket for the best caching experience with automatic configuration. Alternative options include LiteSpeed Cache, W3 Total Cache, or WP Super Cache.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if object caching is available
 *
 * @return array Audit result
 */
function wppsi_check_object_cache() {
    global $wp_object_cache;
    
    $has_external_cache = false;
    $cache_type = '';
    
    // Check for Redis
    if ( class_exists( 'Redis' ) || class_exists( 'Predis\Client' ) ) {
        if ( defined( 'WP_REDIS_DISABLED' ) && WP_REDIS_DISABLED ) {
            $has_external_cache = false;
        } elseif ( 
            ( isset( $wp_object_cache->redis ) && $wp_object_cache->redis ) ||
            class_exists( 'WP_Redis' ) ||
            defined( 'WP_REDIS_HOST' )
        ) {
            $has_external_cache = true;
            $cache_type = 'Redis';
        }
    }
    
    // Check for Memcached
    if ( ! $has_external_cache && ( class_exists( 'Memcache' ) || class_exists( 'Memcached' ) ) ) {
        if ( 
            isset( $wp_object_cache->mc ) ||
            ( isset( $wp_object_cache->cache ) && method_exists( $wp_object_cache, 'add_mc_group' ) ) ||
            defined( 'MEMCACHED_SERVERS' )
        ) {
            $has_external_cache = true;
            $cache_type = 'Memcached';
        }
    }
    
    // Check for APCu
    if ( ! $has_external_cache && function_exists( 'apcu_fetch' ) ) {
        if ( file_exists( WP_CONTENT_DIR . '/object-cache.php' ) ) {
            $object_cache_content = file_get_contents( WP_CONTENT_DIR . '/object-cache.php' );
            if ( strpos( $object_cache_content, 'apcu' ) !== false ) {
                $has_external_cache = true;
                $cache_type = 'APCu';
            }
        }
    }
    
    // Generic check for drop-in object cache
    if ( ! $has_external_cache && file_exists( WP_CONTENT_DIR . '/object-cache.php' ) ) {
        $has_external_cache = true;
        $cache_type = __( 'Custom Object Cache', 'wp-performance-security-inspector' );
    }

    if ( $has_external_cache ) {
        return wppsi_create_audit_result(
            __( 'Object Cache', 'wp-performance-security-inspector' ),
            'pass',
            sprintf(
                /* translators: %s: Cache type name */
                __( 'Persistent object caching is enabled using %s.', 'wp-performance-security-inspector' ),
                $cache_type
            ),
            __( 'Object caching stores database query results in memory, reducing database load and speeding up dynamic content generation.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'Object Cache', 'wp-performance-security-inspector' ),
        'warning',
        __( 'No persistent object cache detected.', 'wp-performance-security-inspector' ),
        __( 'WordPress uses object caching to store expensive database queries. Without a persistent cache, these queries run repeatedly, impacting performance on dynamic pages.', 'wp-performance-security-inspector' ),
        __( 'Contact your hosting provider about enabling Redis or Memcached. Many managed WordPress hosts offer this as a one-click option. WP Rocket also provides a Redis integration.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check for CDN presence
 *
 * @return array Audit result
 */
function wppsi_check_cdn_presence() {
    $cdn_detected = false;
    $cdn_name = '';
    
    // Check for Cloudflare
    if ( isset( $_SERVER['HTTP_CF_RAY'] ) || isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
        $cdn_detected = true;
        $cdn_name = 'Cloudflare';
    }
    
    // Check headers for other CDNs
    if ( ! $cdn_detected ) {
        $cdn_header = wppsi_check_http_header( 'x-cdn' );
        if ( $cdn_header ) {
            $cdn_detected = true;
            $cdn_name = sanitize_text_field( $cdn_header );
        }
    }
    
    // Check for common CDN headers
    if ( ! $cdn_detected ) {
        $cdn_checks = array(
            'x-sucuri-id'        => 'Sucuri',
            'x-stackpath-cache'  => 'StackPath',
            'x-fastly-request-id' => 'Fastly',
            'x-akamai-cache'     => 'Akamai',
            'x-cache-status'     => 'CDN', // Generic
        );
        
        foreach ( $cdn_checks as $header => $name ) {
            if ( wppsi_check_http_header( $header ) ) {
                $cdn_detected = true;
                $cdn_name = $name;
                break;
            }
        }
    }
    
    // Check for CDN in site URL
    if ( ! $cdn_detected ) {
        $home_url = home_url();
        $cdn_indicators = array( 'cdn.', 'cloudfront.', 'akamai', 'fastly', 'stackpath', 'bunny' );
        foreach ( $cdn_indicators as $indicator ) {
            if ( stripos( $home_url, $indicator ) !== false ) {
                $cdn_detected = true;
                $cdn_name = __( 'CDN Detected', 'wp-performance-security-inspector' );
                break;
            }
        }
    }

    if ( $cdn_detected ) {
        return wppsi_create_audit_result(
            __( 'CDN (Content Delivery Network)', 'wp-performance-security-inspector' ),
            'pass',
            sprintf(
                /* translators: %s: CDN name */
                __( 'Your site is using %s as a CDN.', 'wp-performance-security-inspector' ),
                $cdn_name
            ),
            __( 'A CDN serves your static assets from servers geographically closer to your visitors, reducing latency and improving page load times globally.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'CDN (Content Delivery Network)', 'wp-performance-security-inspector' ),
        'warning',
        __( 'No CDN detected on your site.', 'wp-performance-security-inspector' ),
        __( 'Without a CDN, all visitors connect directly to your origin server regardless of their location, resulting in higher latency for geographically distant users.', 'wp-performance-security-inspector' ),
        __( 'We recommend Cloudflare for its free tier with CDN, DDoS protection, and additional security features. WP Rocket integrates seamlessly with Cloudflare for optimal performance.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if GZIP compression is enabled
 *
 * @return array Audit result
 */
function wppsi_check_gzip_compression() {
    $home_url = home_url( '/' );
    
    $response = wp_remote_get( $home_url, array(
        'timeout'     => 10,
        'sslverify'   => false,
        'headers'     => array(
            'Accept-Encoding' => 'gzip, deflate',
        ),
    ) );

    if ( is_wp_error( $response ) ) {
        return wppsi_create_audit_result(
            __( 'GZIP Compression', 'wp-performance-security-inspector' ),
            'warning',
            __( 'Unable to verify GZIP compression status.', 'wp-performance-security-inspector' ),
            __( 'GZIP compression reduces file sizes by up to 70%, significantly reducing bandwidth usage and improving load times.', 'wp-performance-security-inspector' ),
            __( 'Check your server configuration or use WP Rocket which automatically enables GZIP compression.', 'wp-performance-security-inspector' )
        );
    }

    $headers = wp_remote_retrieve_headers( $response );
    $content_encoding = isset( $headers['content-encoding'] ) ? $headers['content-encoding'] : '';

    if ( stripos( $content_encoding, 'gzip' ) !== false || stripos( $content_encoding, 'deflate' ) !== false ) {
        return wppsi_create_audit_result(
            __( 'GZIP Compression', 'wp-performance-security-inspector' ),
            'pass',
            __( 'GZIP compression is enabled on your server.', 'wp-performance-security-inspector' ),
            __( 'Your server is compressing responses before sending them to browsers, reducing transfer sizes and improving load times.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    return wppsi_create_audit_result(
        __( 'GZIP Compression', 'wp-performance-security-inspector' ),
        'fail',
        __( 'GZIP compression is not enabled.', 'wp-performance-security-inspector' ),
        __( 'Without compression, your server sends full-size files to visitors, wasting bandwidth and increasing page load times significantly.', 'wp-performance-security-inspector' ),
        __( 'Enable GZIP via .htaccess, nginx config, or use WP Rocket which handles this automatically. Cloudflare also provides automatic compression.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check PHP version
 *
 * @return array Audit result
 */
function wppsi_check_php_version() {
    $current_version = phpversion();
    $version_parts = explode( '.', $current_version );
    $major_minor = floatval( $version_parts[0] . '.' . ( $version_parts[1] ?? 0 ) );

    if ( $major_minor >= 8.1 ) {
        return wppsi_create_audit_result(
            __( 'PHP Version', 'wp-performance-security-inspector' ),
            'pass',
            sprintf(
                /* translators: %s: PHP version number */
                __( 'You are running PHP %s, which is current and fully supported.', 'wp-performance-security-inspector' ),
                $current_version
            ),
            __( 'Using a current PHP version ensures optimal performance, security updates, and compatibility with modern WordPress features.', 'wp-performance-security-inspector' ),
            ''
        );
    } elseif ( $major_minor >= 7.4 ) {
        return wppsi_create_audit_result(
            __( 'PHP Version', 'wp-performance-security-inspector' ),
            'warning',
            sprintf(
                /* translators: %s: PHP version number */
                __( 'You are running PHP %s. Consider upgrading to PHP 8.1+ for better performance.', 'wp-performance-security-inspector' ),
                $current_version
            ),
            __( 'PHP 7.4 reached end of life in November 2022. While it still works, you should upgrade to receive security patches and performance improvements.', 'wp-performance-security-inspector' ),
            __( 'Contact your hosting provider to upgrade to PHP 8.1 or 8.2. Most quality hosts offer one-click PHP version switching.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'PHP Version', 'wp-performance-security-inspector' ),
        'fail',
        sprintf(
            /* translators: %s: PHP version number */
            __( 'You are running PHP %s, which is outdated and no longer supported.', 'wp-performance-security-inspector' ),
            $current_version
        ),
        __( 'Old PHP versions are slower, lack security updates, and may not support modern WordPress features. This is a critical security and performance risk.', 'wp-performance-security-inspector' ),
        __( 'Upgrade to PHP 8.1 or higher immediately through your hosting control panel. Test your site on a staging environment first if possible.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check PHP memory limit
 *
 * @return array Audit result
 */
function wppsi_check_memory_limit() {
    $memory_limit = wppsi_get_memory_limit();
    $memory_formatted = wppsi_format_bytes( $memory_limit );

    if ( $memory_limit >= 256 * 1024 * 1024 ) {
        return wppsi_create_audit_result(
            __( 'PHP Memory Limit', 'wp-performance-security-inspector' ),
            'pass',
            sprintf(
                /* translators: %s: Memory limit value */
                __( 'Your PHP memory limit is %s, which is sufficient for most WordPress sites.', 'wp-performance-security-inspector' ),
                $memory_formatted
            ),
            __( 'Adequate memory allows WordPress to handle complex operations, large media uploads, and demanding plugins without running out of resources.', 'wp-performance-security-inspector' ),
            ''
        );
    } elseif ( $memory_limit >= 128 * 1024 * 1024 ) {
        return wppsi_create_audit_result(
            __( 'PHP Memory Limit', 'wp-performance-security-inspector' ),
            'warning',
            sprintf(
                /* translators: %s: Memory limit value */
                __( 'Your PHP memory limit is %s. Consider increasing to 256MB for optimal performance.', 'wp-performance-security-inspector' ),
                $memory_formatted
            ),
            __( 'While 128MB works for basic sites, complex themes, page builders, or WooCommerce may require more memory to function properly.', 'wp-performance-security-inspector' ),
            __( 'Increase memory limit in wp-config.php by adding: define( "WP_MEMORY_LIMIT", "256M" ); or contact your hosting provider.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'PHP Memory Limit', 'wp-performance-security-inspector' ),
        'fail',
        sprintf(
            /* translators: %s: Memory limit value */
            __( 'Your PHP memory limit is only %s, which is too low for WordPress.', 'wp-performance-security-inspector' ),
            $memory_formatted
        ),
        __( 'Insufficient memory causes white screen errors, failed updates, and prevents plugins from functioning correctly.', 'wp-performance-security-inspector' ),
        __( 'Add define( "WP_MEMORY_LIMIT", "256M" ); to wp-config.php, or contact your host to increase the limit. WordPress recommends at least 128MB.', 'wp-performance-security-inspector' )
    );
}

/**
 * Check if debug mode is enabled
 *
 * @return array Audit result
 */
function wppsi_check_debug_mode() {
    $debug_enabled = wppsi_is_constant_enabled( 'WP_DEBUG' );
    $debug_display = wppsi_is_constant_enabled( 'WP_DEBUG_DISPLAY' );
    $debug_log = wppsi_is_constant_enabled( 'WP_DEBUG_LOG' );

    if ( ! $debug_enabled ) {
        return wppsi_create_audit_result(
            __( 'Debug Mode', 'wp-performance-security-inspector' ),
            'pass',
            __( 'WordPress debug mode is disabled.', 'wp-performance-security-inspector' ),
            __( 'Keeping debug mode off on production sites prevents sensitive error information from being exposed to visitors.', 'wp-performance-security-inspector' ),
            ''
        );
    }

    if ( $debug_enabled && ! $debug_display ) {
        return wppsi_create_audit_result(
            __( 'Debug Mode', 'wp-performance-security-inspector' ),
            'warning',
            __( 'Debug mode is enabled but errors are not displayed publicly.', 'wp-performance-security-inspector' ),
            __( 'While errors are logged privately, debug mode can slightly impact performance. Consider disabling it when not actively debugging.', 'wp-performance-security-inspector' ),
            __( 'Set WP_DEBUG to false in wp-config.php when you are done debugging.', 'wp-performance-security-inspector' )
        );
    }

    return wppsi_create_audit_result(
        __( 'Debug Mode', 'wp-performance-security-inspector' ),
        'fail',
        __( 'Debug mode is enabled and errors are displayed publicly.', 'wp-performance-security-inspector' ),
        __( 'Displaying PHP errors reveals sensitive information about your server configuration, file paths, and potential vulnerabilities to attackers.', 'wp-performance-security-inspector' ),
        __( 'In wp-config.php, set: define( "WP_DEBUG", false ); or at minimum set define( "WP_DEBUG_DISPLAY", false ); to hide errors from visitors.', 'wp-performance-security-inspector' )
    );
}
