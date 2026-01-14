<?php
/**
 * Plugin Name: WP Performance & Security Inspector
 * Plugin URI: https://github.com/razuahammad/wp-performance-security-inspector
 * Description: A lightweight WordPress plugin that audits real-world performance issues and security misconfigurations. Perfect for client audits and website optimization.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Razu Ahammad
 * Author URI: https://razuahammad.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-performance-security-inspector
 * Domain Path: /languages
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Define plugin constants
 */
define( 'WPPSI_VERSION', '1.0.0' );
define( 'WPPSI_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPPSI_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WPPSI_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Load required files
 */
require_once WPPSI_PLUGIN_DIR . 'includes/helpers.php';
require_once WPPSI_PLUGIN_DIR . 'includes/performance.php';
require_once WPPSI_PLUGIN_DIR . 'includes/security.php';

/**
 * Main Plugin Class
 */
class WP_Performance_Security_Inspector {

    /**
     * Instance of this class
     *
     * @var WP_Performance_Security_Inspector
     */
    private static $instance = null;

    /**
     * Plugin admin page hook suffix
     *
     * @var string
     */
    private $page_hook = '';

    /**
     * Get singleton instance
     *
     * @return WP_Performance_Security_Inspector
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
        add_filter( 'plugin_action_links_' . WPPSI_PLUGIN_BASENAME, array( $this, 'add_plugin_action_links' ) );
    }

    /**
     * Register admin menu page
     */
    public function register_admin_menu() {
        $this->page_hook = add_menu_page(
            __( 'Performance & Security Inspector', 'wp-performance-security-inspector' ),
            __( 'Site Inspector', 'wp-performance-security-inspector' ),
            'manage_options',
            'wp-performance-security-inspector',
            array( $this, 'render_admin_page' ),
            'dashicons-shield-alt',
            80
        );
    }

    /**
     * Enqueue admin assets only on plugin page
     *
     * @param string $hook Current admin page hook
     */
    public function enqueue_admin_assets( $hook ) {
        if ( $hook !== $this->page_hook ) {
            return;
        }

        wp_enqueue_style(
            'wppsi-admin-css',
            WPPSI_PLUGIN_URL . 'assets/admin.css',
            array(),
            WPPSI_VERSION
        );
    }

    /**
     * Add plugin action links
     *
     * @param array $links Existing action links
     * @return array Modified action links
     */
    public function add_plugin_action_links( $links ) {
        $custom_links = array(
            '<a href="' . esc_url( admin_url( 'admin.php?page=wp-performance-security-inspector' ) ) . '">' . 
            esc_html__( 'Run Audit', 'wp-performance-security-inspector' ) . '</a>',
        );
        return array_merge( $custom_links, $links );
    }

    /**
     * Render admin dashboard page
     */
    public function render_admin_page() {
        // Check user capabilities
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-performance-security-inspector' ) );
        }

        // Get audit results
        $performance_results = wppsi_run_performance_audit();
        $security_results = wppsi_run_security_audit();

        // Calculate scores
        $performance_score = wppsi_calculate_score( $performance_results );
        $security_score = wppsi_calculate_score( $security_results );
        $overall_score = round( ( $performance_score + $security_score ) / 2 );

        ?>
        <div class="wrap wppsi-wrap">
            <div class="wppsi-header">
                <h1>
                    <span class="dashicons dashicons-shield-alt"></span>
                    <?php esc_html_e( 'WP Performance & Security Inspector', 'wp-performance-security-inspector' ); ?>
                </h1>
                <p class="wppsi-subtitle">
                    <?php esc_html_e( 'Comprehensive audit of your WordPress site\'s performance and security', 'wp-performance-security-inspector' ); ?>
                </p>
            </div>

            <div class="wppsi-score-overview">
                <div class="wppsi-score-card wppsi-score-overall">
                    <div class="wppsi-score-value <?php echo esc_attr( wppsi_get_score_class( $overall_score ) ); ?>">
                        <?php echo esc_html( $overall_score ); ?>%
                    </div>
                    <div class="wppsi-score-label"><?php esc_html_e( 'Overall Score', 'wp-performance-security-inspector' ); ?></div>
                </div>
                <div class="wppsi-score-card">
                    <div class="wppsi-score-value <?php echo esc_attr( wppsi_get_score_class( $performance_score ) ); ?>">
                        <?php echo esc_html( $performance_score ); ?>%
                    </div>
                    <div class="wppsi-score-label"><?php esc_html_e( 'Performance', 'wp-performance-security-inspector' ); ?></div>
                </div>
                <div class="wppsi-score-card">
                    <div class="wppsi-score-value <?php echo esc_attr( wppsi_get_score_class( $security_score ) ); ?>">
                        <?php echo esc_html( $security_score ); ?>%
                    </div>
                    <div class="wppsi-score-label"><?php esc_html_e( 'Security', 'wp-performance-security-inspector' ); ?></div>
                </div>
            </div>

            <div class="wppsi-dashboard">
                <div class="wppsi-column">
                    <div class="wppsi-card">
                        <div class="wppsi-card-header">
                            <span class="dashicons dashicons-performance"></span>
                            <h2><?php esc_html_e( 'Performance Audit', 'wp-performance-security-inspector' ); ?></h2>
                        </div>
                        <div class="wppsi-card-body">
                            <ul class="wppsi-audit-list">
                                <?php foreach ( $performance_results as $result ) : ?>
                                    <li class="wppsi-audit-item wppsi-status-<?php echo esc_attr( $result['status'] ); ?>">
                                        <div class="wppsi-audit-header">
                                            <span class="wppsi-status-icon">
                                                <?php echo wppsi_get_status_icon( $result['status'] ); ?>
                                            </span>
                                            <strong><?php echo esc_html( $result['title'] ); ?></strong>
                                        </div>
                                        <div class="wppsi-audit-details">
                                            <p class="wppsi-audit-message"><?php echo esc_html( $result['message'] ); ?></p>
                                            <?php if ( ! empty( $result['explanation'] ) ) : ?>
                                                <p class="wppsi-audit-explanation">
                                                    <strong><?php esc_html_e( 'Why it matters:', 'wp-performance-security-inspector' ); ?></strong> 
                                                    <?php echo esc_html( $result['explanation'] ); ?>
                                                </p>
                                            <?php endif; ?>
                                            <?php if ( ! empty( $result['fix'] ) ) : ?>
                                                <p class="wppsi-audit-fix">
                                                    <strong><?php esc_html_e( 'Recommended fix:', 'wp-performance-security-inspector' ); ?></strong> 
                                                    <?php echo esc_html( $result['fix'] ); ?>
                                                </p>
                                            <?php endif; ?>
                                        </div>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="wppsi-column">
                    <div class="wppsi-card">
                        <div class="wppsi-card-header">
                            <span class="dashicons dashicons-lock"></span>
                            <h2><?php esc_html_e( 'Security Audit', 'wp-performance-security-inspector' ); ?></h2>
                        </div>
                        <div class="wppsi-card-body">
                            <ul class="wppsi-audit-list">
                                <?php foreach ( $security_results as $result ) : ?>
                                    <li class="wppsi-audit-item wppsi-status-<?php echo esc_attr( $result['status'] ); ?>">
                                        <div class="wppsi-audit-header">
                                            <span class="wppsi-status-icon">
                                                <?php echo wppsi_get_status_icon( $result['status'] ); ?>
                                            </span>
                                            <strong><?php echo esc_html( $result['title'] ); ?></strong>
                                        </div>
                                        <div class="wppsi-audit-details">
                                            <p class="wppsi-audit-message"><?php echo esc_html( $result['message'] ); ?></p>
                                            <?php if ( ! empty( $result['explanation'] ) ) : ?>
                                                <p class="wppsi-audit-explanation">
                                                    <strong><?php esc_html_e( 'Why it matters:', 'wp-performance-security-inspector' ); ?></strong> 
                                                    <?php echo esc_html( $result['explanation'] ); ?>
                                                </p>
                                            <?php endif; ?>
                                            <?php if ( ! empty( $result['fix'] ) ) : ?>
                                                <p class="wppsi-audit-fix">
                                                    <strong><?php esc_html_e( 'Recommended fix:', 'wp-performance-security-inspector' ); ?></strong> 
                                                    <?php echo esc_html( $result['fix'] ); ?>
                                                </p>
                                            <?php endif; ?>
                                        </div>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="wppsi-footer">
                <div class="wppsi-card wppsi-info-card">
                    <div class="wppsi-card-header">
                        <span class="dashicons dashicons-info"></span>
                        <h2><?php esc_html_e( 'About This Report', 'wp-performance-security-inspector' ); ?></h2>
                    </div>
                    <div class="wppsi-card-body">
                        <p>
                            <?php 
                            printf(
                                /* translators: %s: Current date and time */
                                esc_html__( 'This report was generated on %s. Results reflect the current state of your WordPress installation.', 'wp-performance-security-inspector' ),
                                esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ) )
                            ); 
                            ?>
                        </p>
                        <p>
                            <?php esc_html_e( 'For optimal results, we recommend using WP Rocket for caching and Cloudflare for CDN and additional security features.', 'wp-performance-security-inspector' ); ?>
                        </p>
                    </div>
                </div>
            </div>

            <div class="wppsi-credits">
                <p>
                    <?php 
                    printf(
                        /* translators: %s: Plugin version number */
                        esc_html__( 'WP Performance & Security Inspector v%s | Created by Razu Ahammad', 'wp-performance-security-inspector' ),
                        esc_html( WPPSI_VERSION )
                    ); 
                    ?>
                </p>
            </div>
        </div>
        <?php
    }
}

/**
 * Initialize the plugin
 */
function wppsi_init() {
    WP_Performance_Security_Inspector::get_instance();
}
add_action( 'plugins_loaded', 'wppsi_init' );

/**
 * Plugin activation hook
 */
function wppsi_activate() {
    // Flush rewrite rules on activation
    flush_rewrite_rules();
}
register_activation_hook( __FILE__, 'wppsi_activate' );

/**
 * Plugin deactivation hook
 */
function wppsi_deactivate() {
    // Flush rewrite rules on deactivation
    flush_rewrite_rules();
}
register_deactivation_hook( __FILE__, 'wppsi_deactivate' );
