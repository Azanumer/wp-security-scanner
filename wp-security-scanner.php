<?php
/**
 * Plugin Name: WP Security Scanner
 * Description: Audits your WordPress install for common security misconfigurations — debug display, file editing, XML-RPC, exposed debug.log/readme.html, .git dirs, default DB prefix, pending updates — and reports them with fix hints.
 * Version: 1.0.0
 * Author: Azan Umer
 * License: MIT
 * Text Domain: wp-security-scanner
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WPSS_VERSION', '1.0.0');
define('WPSS_OPTION', 'wpss_dismissed');

/**
 * Run every registered security check.
 *
 * @return array Each item: [severity ('critical'|'warning'|'info'), title, detail, fix]
 */
function wpss_run_checks() {
    $checks = array();

    // 1. Debug output visible to visitors
    if (defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY) {
        $checks[] = array(
            'severity' => 'critical',
            'title'    => 'WP_DEBUG_DISPLAY is enabled',
            'detail'   => 'PHP errors are shown to visitors. This leaks paths, plugin names and DB details.',
            'fix'      => "Set define( 'WP_DEBUG_DISPLAY', false ); in wp-config.php (log instead with WP_DEBUG_LOG).",
        );
    }
    if (defined('WP_DEBUG') && WP_DEBUG && !defined('WP_DEBUG_LOG')) {
        $checks[] = array(
            'severity' => 'warning',
            'title'    => 'WP_DEBUG is on without WP_DEBUG_LOG',
            'detail'   => 'Debug mode is active but errors are not being logged anywhere useful.',
            'fix'      => "Either turn WP_DEBUG off in production, or add define( 'WP_DEBUG_LOG', true );",
        );
    }

    // 2. Theme/plugin file editor in wp-admin
    if (!defined('DISALLOW_FILE_EDIT') || !DISALLOW_FILE_EDIT) {
        $checks[] = array(
            'severity' => 'warning',
            'title'    => 'Theme/plugin file editor is enabled',
            'detail'   => 'Any compromised admin account can edit PHP files directly from wp-admin.',
            'fix'      => "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php.",
        );
    }

    // 3. XML-RPC
    $xmlrpc_disabled = apply_filters('xmlrpc_enabled', true) === false;
    if (!$xmlrpc_disabled) {
        $checks[] = array(
            'severity' => 'warning',
            'title'    => 'XML-RPC is enabled',
            'detail'   => 'xmlrpc.php is a classic target for brute-force and pingback DDoS attacks.',
            'fix'      => "Disable it with: add_filter( 'xmlrpc_enabled', '__return_false' ); (unless the mobile app or Jetpack needs it).",
        );
    }

    // 4. Exposed debug.log
    if (file_exists(WP_CONTENT_DIR . '/debug.log')) {
        $checks[] = array(
            'severity' => 'warning',
            'title'    => 'wp-content/debug.log is exposed',
            'detail'   => 'The debug log is publicly readable and may contain DB credentials or user data.',
            'fix'      => 'Move it outside the web root, protect wp-content with .htaccess/Nginx rules, or disable WP_DEBUG_LOG.',
        );
    }

    // 5. readme.html / license.txt in web root
    foreach (array('readme.html', 'license.txt') as $file) {
        if (file_exists(ABSPATH . $file)) {
            $checks[] = array(
                'severity' => 'info',
                'title'    => $file . ' reveals your WordPress version',
                'detail'   => $file . ' sits in the web root and discloses the exact WP version to attackers.',
                'fix'      => 'Delete ' . $file . ' from the web root (it is not needed at runtime).',
            );
        }
    }

    // 6. .git directory exposed
    if (is_dir(ABSPATH . '.git')) {
        $checks[] = array(
            'severity' => 'critical',
            'title'    => '.git directory is in the web root',
            'detail'   => 'Your full git history (and possibly secrets) may be downloadable via /.git/.',
            'fix'      => 'Move the repo out of the web root, or block /.git/ at the web server level.',
        );
    }

    // 7. Default database table prefix
    global $wpdb;
    if ($wpdb->prefix === 'wp_') {
        $checks[] = array(
            'severity' => 'info',
            'title'    => 'Default database prefix (wp_) in use',
            'detail'   => 'The default prefix makes automated SQL-injection payloads slightly more effective.',
            'fix'      => 'Only changeable on fresh installs (before WP is installed); low priority on existing sites.',
        );
    }

    // 8. Admin SSL not forced
    if (!defined('FORCE_SSL_ADMIN') || !FORCE_SSL_ADMIN) {
        if (is_ssl()) {
            $checks[] = array(
                'severity' => 'info',
                'title'    => 'FORCE_SSL_ADMIN is not set',
                'detail'   => 'The site runs over HTTPS but wp-admin is not forced to it explicitly.',
                'fix'      => "Add define( 'FORCE_SSL_ADMIN', true ); to wp-config.php.",
            );
        } else {
            $checks[] = array(
                'severity' => 'warning',
                'title'    => 'Admin area is not served over HTTPS',
                'detail'   => 'Login cookies travel in plain text — easy to steal on public Wi-Fi.',
                'fix'      => 'Install a free Let\'s Encrypt certificate and redirect HTTP → HTTPS.',
            );
        }
    }

    // 9. Pending core / plugin / theme updates
    if (function_exists('wp_get_update_data')) {
        $updates = wp_get_update_data();
        $total = (int) $updates['counts']['total'];
        if ($total > 0) {
            $checks[] = array(
                'severity' => $updates['counts']['wordpress'] > 0 ? 'critical' : 'warning',
                'title'    => $total . ' update(s) pending',
                'detail'   => sprintf(
                    'Core: %d, Plugins: %d, Themes: %d, Translations: %d.',
                    (int) $updates['counts']['wordpress'],
                    (int) $updates['counts']['plugins'],
                    (int) $updates['counts']['themes'],
                    (int) $updates['counts']['translations']
                ),
                'fix'      => 'Update from Dashboard → Updates. Enable auto-updates for minor core releases and trusted plugins.',
            );
        }
    }

    // 10. Version disclosure via generator tag
    $checks[] = array(
        'severity' => 'info',
        'title'    => 'WordPress version in HTML head',
        'detail'   => 'The <meta name="generator"> tag announces your exact WP version.',
        'fix'      => "Remove it with: remove_action( 'wp_head', 'wp_generator' );",
    );

    return apply_filters('wpss_checks', $checks);
}

/**
 * Count unresolved criticals (for the admin notice).
 */
function wpss_critical_count() {
    $dismissed = get_option(WPSS_OPTION, array());
    $count = 0;
    foreach (wpss_run_checks() as $i => $check) {
        if ($check['severity'] === 'critical' && empty($dismissed[$i])) {
            $count++;
        }
    }
    return $count;
}

// Admin menu: Tools -> Security Scan
add_action('admin_menu', function () {
    add_management_page(
        __('Security Scan', 'wp-security-scanner'),
        __('Security Scan', 'wp-security-scanner'),
        'manage_options',
        'wp-security-scanner',
        'wpss_render_page'
    );
});

function wpss_render_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have permission to view this page.'));
    }

    // Dismiss findings
    if (isset($_POST['wpss_dismiss']) && check_admin_referer('wpss_dismiss_action')) {
        $dismissed = array();
        foreach ((array) $_POST['wpss_dismiss'] as $key) {
            $dismissed[(int) $key] = 1;
        }
        update_option(WPSS_OPTION, $dismissed);
        echo '<div class="notice notice-success"><p>' . esc_html__('Dismissed findings saved.', 'wp-security-scanner') . '</p></div>';
    }

    $dismissed = get_option(WPSS_OPTION, array());
    $checks = wpss_run_checks();
    $visible = array();
    foreach ($checks as $i => $check) {
        if (empty($dismissed[$i])) {
            $visible[$i] = $check;
        }
    }
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Security Scan', 'wp-security-scanner'); ?></h1>
        <p><?php printf(esc_html__('%d finding(s) need attention. Last scanned: %s', 'wp-security-scanner'), count($visible), esc_html(current_time('mysql'))); ?></p>
        <form method="post">
            <?php wp_nonce_field('wpss_dismiss_action'); ?>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Severity', 'wp-security-scanner'); ?></th>
                        <th><?php esc_html_e('Finding', 'wp-security-scanner'); ?></th>
                        <th><?php esc_html_e('Fix', 'wp-security-scanner'); ?></th>
                        <th><?php esc_html_e('Dismiss', 'wp-security-scanner'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($visible)) : ?>
                        <tr><td colspan="4"><?php esc_html_e('All clear — no issues found.', 'wp-security-scanner'); ?></td></tr>
                    <?php else : ?>
                        <?php foreach ($visible as $i => $check) : ?>
                            <tr>
                                <td><strong><?php echo esc_html(strtoupper($check['severity'])); ?></strong></td>
                                <td><strong><?php echo esc_html($check['title']); ?></strong><br><?php echo esc_html($check['detail']); ?></td>
                                <td><?php echo esc_html($check['fix']); ?></td>
                                <td><input type="checkbox" name="wpss_dismiss[]" value="<?php echo (int) $i; ?>"></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            <?php submit_button(__('Save dismissed', 'wp-security-scanner'), 'secondary', 'submit', false); ?>
        </form>
    </div>
    <?php
}

// Admin notice when criticals exist
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) {
        return;
    }
    $count = wpss_critical_count();
    if ($count > 0) {
        $url = admin_url('tools.php?page=wp-security-scanner');
        echo '<div class="notice notice-error"><p>';
        printf(
            /* translators: %1$d count, %2$s URL */
            esc_html(_n('Security Scan found %1$d critical issue. %2$sReview it now%3$s.', 'Security Scan found %1$d critical issues. %2$sReview them now%3$s.', $count, 'wp-security-scanner')),
            (int) $count,
            '<a href="' . esc_url($url) . '">',
            '</a>'
        );
        echo '</p></div>';
    }
});

// Weekly re-scan: email site admin if new criticals appear
add_action('wpss_weekly_scan', 'wpss_weekly_scan_handler');
function wpss_weekly_scan_handler() {
    $count = wpss_critical_count();
    $prev = (int) get_option('wpss_last_critical_count', 0);
    if ($count > 0 && $count > $prev) {
        wp_mail(
            get_option('admin_email'),
            '[' . get_bloginfo('name') . '] Security Scan: ' . $count . ' critical issue(s)',
            'The weekly WP Security Scanner check found ' . $count . " critical issue(s).\n\nReview them at: " . admin_url('tools.php?page=wp-security-scanner')
        );
    }
    update_option('wpss_last_critical_count', $count);
}

register_activation_hook(__FILE__, function () {
    if (!wp_next_scheduled('wpss_weekly_scan')) {
        wp_schedule_event(time(), 'weekly', 'wpss_weekly_scan');
    }
});

register_deactivation_hook(__FILE__, function () {
    $ts = wp_next_scheduled('wpss_weekly_scan');
    if ($ts) {
        wp_unschedule_event($ts, 'wpss_weekly_scan');
    }
});
