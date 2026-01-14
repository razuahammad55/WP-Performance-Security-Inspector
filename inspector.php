<?php
/**
 * Plugin Name: WP Performance & Security Inspector
 * Description: Audit WordPress performance and security with actionable recommendations.
 * Version: 1.0.0
 * Author: Razu Ahammad
 */

if (!defined('ABSPATH')) exit;

define('WPSI_PATH', plugin_dir_path(__FILE__));
define('WPSI_URL', plugin_dir_url(__FILE__));

require_once WPSI_PATH . 'includes/helpers.php';
require_once WPSI_PATH . 'includes/performance.php';
require_once WPSI_PATH . 'includes/security.php';

/**
 * Admin Menu
 */
add_action('admin_menu', function () {
    add_menu_page(
        'WP Inspector',
        'WP Inspector',
        'manage_options',
        'wp-inspector',
        'wpsi_dashboard',
        'dashicons-shield-alt',
        56
    );
});

/**
 * Load CSS
 */
add_action('admin_enqueue_scripts', function ($hook) {
    if ($hook === 'toplevel_page_wp-inspector') {
        wp_enqueue_style('wpsi-admin', WPSI_URL . 'assets/admin.css');
    }
});

/**
 * Dashboard UI
 */
function wpsi_dashboard() {
    ?>
    <div class="wpsi-wrap">
        <h1>WP Performance & Security Inspector</h1>

        <div class="wpsi-card">
            <h2>⚡ Performance Audit</h2>
            <?php wpsi_performance_report(); ?>
        </div>

        <div class="wpsi-card">
            <h2>🔐 Security Audit</h2>
            <?php wpsi_security_report(); ?>
        </div>
    </div>
    <?php
}
