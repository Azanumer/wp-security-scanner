<?php
// WP Security Scanner — cleanup on uninstall.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('wpss_dismissed');
delete_option('wpss_last_critical_count');
$ts = wp_next_scheduled('wpss_weekly_scan');
if ($ts) {
    wp_unschedule_event($ts, 'wpss_weekly_scan');
}
