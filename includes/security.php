<?php

if (!defined('ABSPATH')) exit;

function wpsi_security_report() {

    $issues = [];

    // REST users endpoint exposure
    $rest_url = home_url('/wp-json/wp/v2/users');
    $response = wp_remote_get($rest_url, ['timeout' => 5]);

    if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        if (strpos($body, '"id"') !== false) {
            $issues[] = "REST API exposes user data (/wp-json/wp/v2/users).";
        }
    }

    // XML-RPC
    if (file_exists(ABSPATH . 'xmlrpc.php')) {
        $issues[] = "XML-RPC is enabled (common attack vector).";
    }

    // User registration
    if (get_option('users_can_register')) {
        $issues[] = "Anyone can register accounts.";
    }

    // WP version exposure
    if (has_action('wp_head', 'wp_generator')) {
        $issues[] = "WordPress version is exposed.";
    }

    // Output
    if (empty($issues)) {
        echo "<p class='wpsi-ok'>✔ No critical security issues found.</p>";
    } else {
        echo "<ul class='wpsi-list'>";
        foreach ($issues as $issue) {
            echo "<li>⚠ {$issue}</li>";
        }
        echo "</ul>";
    }

    echo "<p class='wpsi-tip'><strong>Tip:</strong> Disable XML-RPC, hide REST users, secure wp-admin.</p>";
}
