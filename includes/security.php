<?php

function wpsi_security_report() {
    $issues = [];

    if (get_option('users_can_register')) {
        $issues[] = "User registration is enabled.";
    }

    if (file_exists(ABSPATH . 'xmlrpc.php')) {
        $issues[] = "XML-RPC is enabled.";
    }

    if (strpos(file_get_contents(home_url('/wp-json/wp/v2/users')), 'id') !== false) {
        $issues[] = "REST API exposes user data.";
    }

    if (empty($issues)) {
        echo "<p style='color:green;'>✔ No critical security issues detected.</p>";
    } else {
        echo "<ul style='color:#b00;'>";
        foreach ($issues as $issue) {
            echo "<li>⚠ $issue</li>";
        }
        echo "</ul>";
    }

    echo "<p><strong>Tip:</strong> Hide wp-admin & secure REST endpoints.</p>";
}
