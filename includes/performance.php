<?php

function wpsi_performance_report() {
    $plugins = count(get_option('active_plugins'));
    $issues = [];

    if ($plugins > 25) {
        $issues[] = "Too many active plugins ($plugins). Consider removing unused ones.";
    }

    if (!defined('WP_CACHE') || !WP_CACHE) {
        $issues[] = "Page cache is not enabled.";
    }

    if (!class_exists('Redis') && !class_exists('Memcached')) {
        $issues[] = "No object cache detected.";
    }

    if (empty($issues)) {
        echo "<p style='color:green;'>✔ No major performance issues detected.</p>";
    } else {
        echo "<ul style='color:#b00;'>";
        foreach ($issues as $issue) {
            echo "<li>❌ $issue</li>";
        }
        echo "</ul>";
    }

    echo "<p><strong>Recommended:</strong> WP Rocket + Cloudflare CDN</p>";
}
