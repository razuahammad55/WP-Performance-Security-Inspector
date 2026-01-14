<?php

if (!defined('ABSPATH')) exit;

function wpsi_performance_report() {

    $issues = [];

    // Plugin count
    $plugin_count = count((array) get_option('active_plugins'));
    if ($plugin_count > 25) {
        $issues[] = "Too many active plugins ({$plugin_count}). Remove unused plugins.";
    }

    // Cache check
    if (!defined('WP_CACHE') || WP_CACHE !== true) {
        $issues[] = "Page cache is not enabled (WP_CACHE false).";
    }

    // Object cache
    if (
        !class_exists('Redis') &&
        !class_exists('Memcached') &&
        !wp_using_ext_object_cache()
    ) {
        $issues[] = "No object cache detected (Redis/Memcached).";
    }

    // CDN check
    $cdn_detected = false;
    foreach (headers_list() as $header) {
        if (stripos($header, 'cloudflare') !== false) {
            $cdn_detected = true;
            break;
        }
    }

    if (!$cdn_detected) {
        $issues[] = "No CDN detected (Cloudflare recommended).";
    }

    // Output
    if (empty($issues)) {
        echo "<p class='wpsi-ok'>✔ Performance looks good.</p>";
    } else {
        echo "<ul class='wpsi-list'>";
        foreach ($issues as $issue) {
            echo "<li>❌ {$issue}</li>";
        }
        echo "</ul>";
    }

    echo "<p class='wpsi-tip'><strong>Recommended:</strong> WP Rocket + Cloudflare (Free)</p>";
}
