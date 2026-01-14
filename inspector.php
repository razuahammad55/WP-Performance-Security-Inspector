<?php
/**
 * Plugin Name: WP Performance & Security Inspector
 * Description: Audits WordPress performance & security issues with actionable recommendations.
 * Version: 1.0.0
 * Author: Razu Ahammad
 */

if (!defined('ABSPATH')) exit;

define('WPSI_PATH', plugin_dir_path(__FILE__));
define('WPSI_URL', plugin_dir_url(__FILE__));

require_once WPSI_PATH . 'includes/performance.php';
require_once WPSI_PATH . 'includes/security.php';

add_action('admin_menu', function () {
    add_menu_page(
        'WP Inspector',
        'WP Inspector',
        'manage_options',
        'wp-inspector',
        'wpsi_dashboard',
        'dashicons-dashboard',
        56
    );
});

function wpsi_dashboard() {
    ?>
    <div class="wrap">
        <h1>WP Performance & Security Inspector</h1>

        <h2>⚡ Performance</h2>
        <?php wpsi_performance_report(); ?>

        <h2>🔐 Security</h2>
        <?php wpsi_security_report(); ?>
    </div>
    <?php
}
