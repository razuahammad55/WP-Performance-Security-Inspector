<?php
/**
 * Helper Functions
 *
 * @package WP_Performance_Security_Inspector
 * @since 1.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Get status icon HTML based on status
 *
 * @param string $status The status type (pass, warning, fail)
 * @return string HTML for the status icon
 */
function wppsi_get_status_icon( $status ) {
    $icons = array(
        'pass'    => '<span class="dashicons dashicons-yes-alt" aria-label="' . esc_attr__( 'Passed', 'wp-performance-security-inspector' ) . '"></span>',
        'warning' => '<span class="dashicons dashicons-warning" aria-label="' . esc_attr__( 'Warning', 'wp-performance-security-inspector' ) . '"></span>',
        'fail'    => '<span class="dashicons dashicons-dismiss" aria-label="' . esc_attr__( 'Failed', 'wp-performance-security-inspector' ) . '"></span>',
    );

    return isset( $icons[ $status ] ) ? $icons[ $status ] : $icons['warning'];
}

/**
 * Get CSS class based on score value
 *
 * @param int $score The score value (0-100)
 * @return string CSS class name
 */
function wppsi_get_score_class( $score ) {
    if ( $score >= 80 ) {
        return 'wppsi-score-good';
    } elseif ( $score >= 50 ) {
        return 'wppsi-score-medium';
    }
    return 'wppsi-score-poor';
}

/**
 * Calculate overall score from audit results
 *
 * @param array $results Array of audit results
 * @return int Score percentage (0-100)
 */
function wppsi_calculate_score( $results ) {
    if ( empty( $results ) ) {
        return 0;
    }

    $total_points = 0;
    $max_points = count( $results ) * 100;

    foreach ( $results as $result ) {
        switch ( $result['status'] ) {
            case 'pass':
                $total_points += 100;
                break;
            case 'warning':
                $total_points += 50;
                break;
            case 'fail':
                $total_points += 0;
                break;
        }
    }

    return $max_points > 0 ? round( ( $total_points / $max_points ) * 100 ) : 0;
}

/**
 * Create a standardized audit result array
 *
 * @param string $title       The title of the audit check
 * @param string $status      The status (pass, warning, fail)
 * @param string $message     The result message
 * @param string $explanation Why this matters
 * @param string $fix         How to fix the issue
 * @return array Formatted audit result
 */
function wppsi_create_audit_result( $title, $status, $message, $explanation = '', $fix = '' ) {
    return array(
        'title'       => $title,
        'status'      => $status,
        'message'     => $message,
        'explanation' => $explanation,
        'fix'         => $fix,
    );
}

/**
 * Check if a specific HTTP header exists
 *
 * @param string $header_name The header name to check
 * @return bool|string False if not found, header value if found
 */
function wppsi_check_http_header( $header_name ) {
    $home_url = home_url( '/' );
    
    $response = wp_remote_head( $home_url, array(
        'timeout'     => 10,
        'sslverify'   => false,
        'redirection' => 0,
    ) );

    if ( is_wp_error( $response ) ) {
        return false;
    }

    $headers = wp_remote_retrieve_headers( $response );
    
    if ( isset( $headers[ strtolower( $header_name ) ] ) ) {
        return $headers[ strtolower( $header_name ) ];
    }

    return false;
}

/**
 * Check if we're running on HTTPS
 *
 * @return bool True if HTTPS, false otherwise
 */
function wppsi_is_https() {
    if ( is_ssl() ) {
        return true;
    }
    
    if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) ) ) {
        return true;
    }
    
    if ( isset( $_SERVER['HTTP_X_FORWARDED_SSL'] ) && 'on' === strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_SSL'] ) ) ) ) {
        return true;
    }
    
    return strpos( home_url(), 'https://' ) === 0;
}

/**
 * Get PHP memory limit in bytes
 *
 * @return int Memory limit in bytes
 */
function wppsi_get_memory_limit() {
    $memory_limit = ini_get( 'memory_limit' );
    
    if ( '-1' === $memory_limit ) {
        return PHP_INT_MAX;
    }
    
    return wp_convert_hr_to_bytes( $memory_limit );
}

/**
 * Format bytes to human readable format
 *
 * @param int $bytes Number of bytes
 * @param int $precision Decimal precision
 * @return string Formatted string
 */
function wppsi_format_bytes( $bytes, $precision = 2 ) {
    $units = array( 'B', 'KB', 'MB', 'GB', 'TB' );
    
    $bytes = max( $bytes, 0 );
    $pow = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
    $pow = min( $pow, count( $units ) - 1 );
    
    $bytes /= pow( 1024, $pow );
    
    return round( $bytes, $precision ) . ' ' . $units[ $pow ];
}

/**
 * Check if a WordPress constant is defined and true
 *
 * @param string $constant The constant name to check
 * @return bool True if defined and truthy
 */
function wppsi_is_constant_enabled( $constant ) {
    return defined( $constant ) && constant( $constant );
}
