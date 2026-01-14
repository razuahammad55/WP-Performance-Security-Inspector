<?php

if (!defined('ABSPATH')) exit;

/**
 * Simple status badge
 */
function wpsi_badge($status, $text) {
    $class = $status ? 'good' : 'bad';
    return "<span class='wpsi-badge {$class}'>{$text}</span>";
}
