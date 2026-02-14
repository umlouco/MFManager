<?php

/**
 * Plugin Name:       MF Manager
 * Plugin URI:        https://www.mario-flores.com/mf-manager/
 * Description:       Connector for the MF website manager dashboard with security scanning and cookie compliance.
 * Version:           9.2.0
 * Requires at least: 5.2
 * Requires PHP:      5.6
 * Author:            Mario Flores
 * Author URI:        https://mario-flores.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mf_manager
 * Domain Path:       /languages
 */

define('MFMANAGER_API_URL', 'https://office.mario-flores.com/api/');

// Include security scanner
require_once plugin_dir_path(__FILE__) . 'includes/class-security-scanner.php';

// Include cookie compliance scanner
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-compliance.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-page-discovery.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-scanner.php';

// Include page view tracker
require_once plugin_dir_path(__FILE__) . 'includes/class-pageview-tracker.php';

// Include audit logger
require_once plugin_dir_path(__FILE__) . 'includes/class-audit-logger.php';

// Include cookie data table
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-data-table.php';

// ─────────────────────────────────────────────────────────────────────────────
//  Plugin activation: create all custom tables once
// ─────────────────────────────────────────────────────────────────────────────
register_activation_hook(__FILE__, 'mfmanager_activation');
function mfmanager_activation()
{
    $pv = new MFManager_Pageview_Tracker();
    $pv->ensure_table();

    $al = new MFManager_Audit_Logger();
    $al->ensure_table();

    $ct = new MFManager_Cookie_Data_Table();
    $ct->ensure_table();
}

add_action('admin_menu', 'mf_manager_menu_page');
add_action('admin_init', 'mfmanager_api_settings_init');

function mf_manager_menu_page()
{
    add_menu_page(
        'MF Manager Settings',
        'MF Manager',
        'manage_options',
        'mfmanager_settings_page',
        'mfmanager_load_settings',
        'dashicons-shield'
    );
    add_submenu_page(
        'mfmanager_settings_page',
        'Run update',
        'Run Sync',
        'manage_options',
        'mfmanager_run',
        'mfmanager_run'
    );
    add_submenu_page(
        'mfmanager_settings_page',
        'Security Scan',
        'Security Scan',
        'manage_options',
        'mfmanager_security_scan',
        'mfmanager_security_scan_page'
    );
    add_submenu_page(
        'mfmanager_settings_page',
        'Cookie Compliance Scan',
        'Cookie Scan',
        'manage_options',
        'mfmanager_cookie_scan',
        'mfmanager_cookie_scan_page'
    );
}

function mfmanager_load_settings()
{
    include(plugin_dir_path(__FILE__) . 'views/settings.php');
}

function mfmanager_run()
{
    echo '<div class="wrap">';
    echo '<h1>Running Site Sync...</h1>';
    mfmanager_cron_exec();
    echo '<div class="notice notice-success"><p>Site sync completed successfully!</p></div>';
    echo '<p><a href="' . admin_url('admin.php?page=mfmanager_settings_page') . '" class="button">Back to Settings</a></p>';
    echo '</div>';
}

function mfmanager_security_scan_page()
{
    echo '<div class="wrap">';
    echo '<h1>Security Scan</h1>';

    $api_key = get_option('mfmanager_api_settings', '');

    if (empty($api_key)) {
        echo '<div class="notice notice-error"><p>MF Manager API key not configured. Please add it in the settings page first.</p></div>';
        echo '<p><a href="' . admin_url('admin.php?page=mfmanager_settings_page') . '" class="button button-primary">Go to Settings</a></p>';
        echo '</div>';
        return;
    }

    // Try to get WPScan token
    $wpscan_token = mfmanager_get_wpscan_token();

    if (empty($wpscan_token)) {
        echo '<div class="notice notice-warning"><p>Could not retrieve WPScan API token from server. Make sure your API key is valid.</p></div>';
        echo '<p><a href="' . admin_url('admin.php?page=mfmanager_settings_page') . '" class="button">Check Settings</a></p>';
        echo '</div>';
        return;
    }

    echo '<div class="notice notice-info"><p>WPScan token loaded from management server.</p></div>';

    if (isset($_POST['run_security_scan']) && wp_verify_nonce($_POST['_wpnonce'], 'mfmanager_security_scan')) {
        echo '<h2>Running Security Scan...</h2>';
        $results = mfmanager_run_security_scan();

        if (!empty($results['vulnerabilities'])) {
            echo '<div class="notice notice-warning"><p>Found <strong>' . count($results['vulnerabilities']) . '</strong> potential vulnerabilities.</p></div>';
            echo '<table class="wp-list-table widefat fixed striped">';
            echo '<thead><tr><th>Component</th><th>Type</th><th>Vulnerability</th><th>Severity</th><th>Fixed In</th></tr></thead>';
            echo '<tbody>';
            foreach ($results['vulnerabilities'] as $vuln) {
                $severity_class = '';
                switch ($vuln['severity']) {
                    case 'critical':
                        $severity_class = 'style="color: #dc3545; font-weight: bold;"';
                        break;
                    case 'high':
                        $severity_class = 'style="color: #fd7e14; font-weight: bold;"';
                        break;
                    case 'medium':
                        $severity_class = 'style="color: #ffc107;"';
                        break;
                }
                echo '<tr>';
                echo '<td>' . esc_html($vuln['component_name']) . ' (' . esc_html($vuln['component_version']) . ')</td>';
                echo '<td>' . esc_html(ucfirst($vuln['component_type'])) . '</td>';
                echo '<td>' . esc_html($vuln['title']) . '</td>';
                echo '<td ' . $severity_class . '>' . esc_html(ucfirst($vuln['severity'])) . '</td>';
                echo '<td>' . esc_html($vuln['fixed_in'] ?: 'N/A') . '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
        } else {
            echo '<div class="notice notice-success"><p>No vulnerabilities found! Your site appears to be secure.</p></div>';
        }

        // Send to remote server
        echo '<h3>Sending report to management server...</h3>';
        $send_result = mfmanager_send_security_report($results);
        if ($send_result === true) {
            echo '<div class="notice notice-success"><p>Security report sent successfully!</p></div>';
        } else {
            echo '<div class="notice notice-error"><p>Failed to send report: ' . esc_html($send_result) . '</p></div>';
        }
    }

    echo '<form method="post">';
    wp_nonce_field('mfmanager_security_scan');
    echo '<p><input type="submit" name="run_security_scan" class="button button-primary" value="Run Security Scan"></p>';
    echo '</form>';
    echo '</div>';
}

function mfmanager_api_settings_init()
{
    register_setting('mfmanager_settings', 'mfmanager_api_settings');
    register_setting('mfmanager_settings', 'mfmanager_cron_mode');

    add_settings_section(
        'mfmanager_key_section',
        'MF Manager API Settings',
        'mfmanager_settings_section_callback',
        'mfmanager_settings'
    );

    add_settings_field(
        'mfmanager_key',
        'MF Manager Key',
        'mfmanager_field_html',
        'mfmanager_settings',
        'mfmanager_key_section'
    );

    add_settings_field(
        'mfmanager_cron_mode_field',
        'Cron Mode',
        'mfmanager_cron_mode_field_html',
        'mfmanager_settings',
        'mfmanager_key_section'
    );
}

function mfmanager_settings_section_callback()
{
    echo '<p>Enter your MF Manager API key. The WPScan token will be automatically fetched from the server.</p>';
}

function mfmanager_field_html()
{
    $options = get_option('mfmanager_api_settings');
?>
    <input type="text" value="<?php echo esc_attr($options); ?>" name="mfmanager_api_settings" class="regular-text">
    <p class="description">Your MF Manager API key for site synchronization and security scanning.</p>
    <?php
    // Show connection status
    if (!empty($options)) {
        $token = mfmanager_get_wpscan_token(true); // Force refresh
        if ($token) {
            echo '<p class="description" style="color: green;"><span class="dashicons dashicons-yes"></span> Connected - WPScan token loaded from server.</p>';
        } else {
            echo '<p class="description" style="color: red;"><span class="dashicons dashicons-no"></span> Could not connect to server or invalid API key.</p>';
        }
    }
    ?>
<?php
}

/**
 * Render the Cron Mode settings field.
 *
 * When 'system_cron' is selected, MFManager tasks are unscheduled from WP-Cron
 * and run via a dedicated endpoint that system cron calls. This does NOT require
 * DISABLE_WP_CRON, so other plugins' cron tasks remain unaffected.
 */
function mfmanager_cron_mode_field_html()
{
    $mode = get_option('mfmanager_cron_mode', 'wp_cron');
    $cron_key = get_option('mfmanager_cron_key');
    if (empty($cron_key)) {
        $cron_key = wp_generate_password(32, false);
        update_option('mfmanager_cron_key', $cron_key, false);
    }
    $cron_url = add_query_arg('mfmanager_cron', $cron_key, site_url('/'));
?>
    <fieldset>
        <label>
            <input type="radio" name="mfmanager_cron_mode" value="wp_cron" <?php checked($mode, 'wp_cron'); ?>>
            <strong>WP-Cron</strong> &mdash; WordPress handles cron internally (default, triggered by visitor requests)
        </label>
        <br><br>
        <label>
            <input type="radio" name="mfmanager_cron_mode" value="system_cron" <?php checked($mode, 'system_cron'); ?>>
            <strong>System Cron (recommended)</strong> &mdash; Run via server crontab for better performance
        </label>
    </fieldset>

    <?php if ($mode === 'system_cron') : ?>
        <div style="margin-top: 15px; padding: 12px 16px; background: #f0f0f1; border-left: 4px solid #2271b1; font-family: monospace; font-size: 13px;">
            <p style="margin: 0 0 8px; font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-weight: 600;">
                Add this line to your server crontab (<code>crontab -e</code>):
            </p>
            <code style="display: block; padding: 6px 10px; background: #fff; border: 1px solid #c3c4c7; margin-bottom: 8px;">
                0 2 * * * /usr/bin/curl -s '<?php echo esc_url($cron_url); ?>' > /dev/null 2>&1
            </code>

            <p style="margin: 8px 0 4px; font-family: -apple-system, BlinkMacSystemFont, sans-serif; color: #50575e; font-size: 12px;">
                <span class="dashicons dashicons-info" style="color: #2271b1;"></span>
                This runs MFManager tasks at 2:00 AM daily. WP-Cron for other plugins remains unaffected.
                The URL includes a secret key for security.
            </p>
        </div>
    <?php else : ?>
        <p class="description" style="margin-top: 8px;">
            <span class="dashicons dashicons-warning" style="color: #dba617;"></span>
            WP-Cron is triggered by visitor requests, which can add latency and may not fire reliably on low-traffic sites.
            Switching to <strong>System Cron</strong> is recommended for production.
        </p>
    <?php endif; ?>
<?php
}

/**
 * Manage MFManager cron events based on selected mode.
 * Called when cron mode setting is updated.
 */
function mfmanager_manage_cron_events()
{
    $mode = get_option('mfmanager_cron_mode', 'wp_cron');
    
    $events = array(
        'mfmanager_cron_hook',
        'mfmanager_security_cron_hook',
        'mfmanager_cookie_cron_hook',
        'mfmanager_pageview_cron_hook',
        'mfmanager_audit_cron_hook',
        'mfmanager_cookie_data_cron_hook'
    );
    
    if ($mode === 'system_cron') {
        // Unschedule all MFManager WP-Cron events
        foreach ($events as $hook) {
            $timestamp = wp_next_scheduled($hook);
            if ($timestamp) {
                wp_unschedule_event($timestamp, $hook);
            }
        }
    } else {
        // Re-schedule events in WP-Cron (wp_cron mode)
        mfmanager_schedule_wp_cron_events();
    }
}

/**
 * Schedule all MFManager events in WP-Cron.
 */
function mfmanager_schedule_wp_cron_events()
{
    // Daily main cron (1:00 AM)
    if (!wp_next_scheduled('mfmanager_cron_hook')) {
        $next_1am = strtotime('tomorrow 01:00', current_time('timestamp'));
        wp_schedule_event($next_1am, 'daily', 'mfmanager_cron_hook');
    }
    
    // Weekly security scan (Sundays at 2:00 AM)
    if (!wp_next_scheduled('mfmanager_security_cron_hook')) {
        $next_sunday_2am = strtotime('next Sunday 02:00', current_time('timestamp'));
        wp_schedule_event($next_sunday_2am, 'weekly', 'mfmanager_security_cron_hook');
    }
    
    // Daily cookie scan (1:30 AM)
    if (!wp_next_scheduled('mfmanager_cookie_cron_hook')) {
        $next_130am = strtotime('tomorrow 01:30', current_time('timestamp'));
        wp_schedule_event($next_130am, 'daily', 'mfmanager_cookie_cron_hook');
    }
    
    // Daily pageview sync (2:05 AM)
    if (!wp_next_scheduled('mfmanager_pageview_cron_hook')) {
        $tomorrow_205 = strtotime('tomorrow 02:05', current_time('timestamp'));
        wp_schedule_event($tomorrow_205, 'daily', 'mfmanager_pageview_cron_hook');
    }
    
    // Daily audit log sync (2:10 AM)
    if (!wp_next_scheduled('mfmanager_audit_cron_hook')) {
        $tomorrow_audit = strtotime('tomorrow 02:10', current_time('timestamp'));
        wp_schedule_event($tomorrow_audit, 'daily', 'mfmanager_audit_cron_hook');
    }
    
    // Daily cookie data sync (2:30 AM)
    if (!wp_next_scheduled('mfmanager_cookie_data_cron_hook')) {
        $tomorrow_cookie_data = strtotime('tomorrow 02:30', current_time('timestamp'));
        wp_schedule_event($tomorrow_cookie_data, 'daily', 'mfmanager_cookie_data_cron_hook');
    }
}

/**
 * Handle system cron endpoint requests.
 * URL format: /?mfmanager_cron=SECRET_KEY
 */
function mfmanager_handle_cron_endpoint()
{
    if (!isset($_GET['mfmanager_cron'])) {
        return;
    }
    
    $provided_key = sanitize_text_field($_GET['mfmanager_cron']);
    $stored_key = get_option('mfmanager_cron_key');
    
    // Verify the secret key
    if (empty($stored_key) || !hash_equals($stored_key, $provided_key)) {
        status_header(403);
        die('Invalid cron key');
    }
    
    // Only run in system_cron mode
    $mode = get_option('mfmanager_cron_mode', 'wp_cron');
    if ($mode !== 'system_cron') {
        status_header(200);
        die('System cron mode is not enabled');
    }
    
    // Execute all MFManager cron tasks
    mfmanager_cron_exec();
    mfmanager_security_cron_exec();
    mfmanager_cookie_cron_exec();
    mfmanager_pageview_cron_exec();
    mfmanager_audit_cron_exec();
    mfmanager_cookie_data_cron_exec();
    
    status_header(200);
    die('MFManager cron tasks executed successfully');
}
add_action('init', 'mfmanager_handle_cron_endpoint', 1);

/**
 * Update cron events when cron mode setting changes.
 */
function mfmanager_update_cron_mode($old_value, $value, $option)
{
    if ($option === 'mfmanager_cron_mode') {
        mfmanager_manage_cron_events();
    }
}
add_action('update_option_mfmanager_cron_mode', 'mfmanager_update_cron_mode', 10, 3);

// Add weekly schedule if not exists
add_filter('cron_schedules', 'mfmanager_add_weekly_schedule');

add_action('mfmanager_cron_hook', 'mfmanager_cron_exec', 100);
add_action('mfmanager_security_cron_hook', 'mfmanager_security_cron_exec', 100);
add_action('mfmanager_cookie_cron_hook', 'mfmanager_cookie_cron_exec', 100);
add_action('mfmanager_pageview_cron_hook', 'mfmanager_pageview_cron_exec', 100);
add_action('mfmanager_audit_cron_hook', 'mfmanager_audit_cron_exec', 100);
add_action('mfmanager_cookie_data_cron_hook', 'mfmanager_cookie_data_cron_exec', 100);

// ── Schedule cron events only when in wp_cron mode ──
// When system_cron mode is active, these events are unscheduled
$cron_mode = get_option('mfmanager_cron_mode', 'wp_cron');
if ($cron_mode === 'wp_cron') {
    mfmanager_schedule_wp_cron_events();

// Track front-end page views on template_redirect (early, no output yet)
add_action('template_redirect', 'mfmanager_track_pageview');
function mfmanager_track_pageview()
{
    $tracker = new MFManager_Pageview_Tracker();
    $tracker->track();
}
}

// Register audit logger hooks — admin context only
// Almost all auditable actions (post edits, plugin changes, option updates)
// occur in wp-admin. Excluding front-end avoids unnecessary hook overhead.
if (is_admin() || (defined('DOING_CRON') && DOING_CRON) || (defined('WP_CLI') && WP_CLI)) {
    $mfm_audit_logger = new MFManager_Audit_Logger();
    $mfm_audit_logger->register_hooks();
}
function mfmanager_add_weekly_schedule($schedules)
{
    if (!isset($schedules['weekly'])) {
        $schedules['weekly'] = array(
            'interval' => 604800,
            'display' => __('Once Weekly')
        );
    }
    return $schedules;
}

/**
 * Get WPScan token from server (with caching)
 */
function mfmanager_get_wpscan_token($force_refresh = false)
{
    $cache_key = 'mfmanager_wpscan_token';
    $cached_token = get_transient($cache_key);

    if (!$force_refresh && $cached_token !== false) {
        return $cached_token;
    }

    $api_key = get_option('mfmanager_api_settings', '');

    if (empty($api_key)) {
        return null;
    }

    $response = wp_remote_post(
        MFMANAGER_API_URL . 'getConfig',
        array(
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'body' => wp_json_encode(array(
                'key' => $api_key,
                'url' => get_bloginfo('url')
            )),
            'timeout' => 15,
        )
    );

    if (is_wp_error($response)) {
        error_log('MF Manager: Failed to get config - ' . $response->get_error_message());
        return null;
    }

    $code = wp_remote_retrieve_response_code($response);
    if ($code !== 200) {
        error_log('MF Manager: Failed to get config - HTTP ' . $code);
        return null;
    }

    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if (empty($data['wpscan_token'])) {
        error_log('MF Manager: No WPScan token in response');
        return null;
    }

    // Cache for 24 hours
    set_transient($cache_key, $data['wpscan_token'], DAY_IN_SECONDS);

    return $data['wpscan_token'];
}

function mfmanager_security_cron_exec()
{
    if (!mfmanager_should_run_security_scan()) {
        error_log('MF Manager: Weekly security scan skipped (last scan too recent)');
        return;
    }

    $wpscan_token = mfmanager_get_wpscan_token();

    if (empty($wpscan_token)) {
        error_log('MF Manager: Could not get WPScan token, skipping security scan');
        return;
    }

    $results = mfmanager_run_security_scan();
    $send_result = mfmanager_send_security_report($results);

    if ($send_result === true) {
        update_option('mfmanager_last_security_scan', time());
    }
}

function mfmanager_should_run_security_scan()
{
    $last_scan = (int) get_option('mfmanager_last_security_scan', 0);
    if ($last_scan <= 0) {
        return true;
    }

    return (time() - $last_scan) >= WEEK_IN_SECONDS;
}

function mfmanager_run_security_scan()
{
    $wpscan_token = mfmanager_get_wpscan_token();

    if (empty($wpscan_token)) {
        return array(
            'scan_date' => current_time('mysql'),
            'wp_version' => get_bloginfo('version'),
            'vulnerabilities' => array(),
            'error' => 'Could not retrieve WPScan token from server'
        );
    }

    $scanner = new MFManager_Security_Scanner($wpscan_token);
    return $scanner->run_scan();
}

function mfmanager_send_security_report($results)
{
    $info = array(
        'url' => get_bloginfo('url'),
        'key' => get_option('mfmanager_api_settings'),
        'security_report' => $results
    );

    $response = wp_remote_post(
        MFMANAGER_API_URL . 'securityReport',
        array(
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'body'    => wp_json_encode($info),
            'timeout' => 30,
        )
    );

    if (is_wp_error($response)) {
        error_log('MF Manager security report error: ' . $response->get_error_message());
        return $response->get_error_message();
    }

    if (wp_remote_retrieve_response_code($response) >= 400) {
        $error = wp_remote_retrieve_body($response);
        error_log('MF Manager security report error: ' . $error);
        return $error;
    }

    return true;
}

function mfmanager_get_site_name()
{
    $name = get_bloginfo('name');
    if (empty($name)) {
        $name = get_option('blogname');
    }

    if (empty($name)) {
        $url = get_bloginfo('url');
        $host = parse_url($url, PHP_URL_HOST);
        if (!empty($host)) {
            $host = preg_replace('/^www\./i', '', $host);
            $parts = explode('.', $host);
            $primary = isset($parts[0]) ? $parts[0] : $host;
            $primary = trim(str_replace(array('-', '_'), ' ', $primary));
            $primary = ucwords($primary);
            $name = $primary !== '' ? $primary : $host;
        }
    }

    return (string) $name;
}

function mfmanager_cron_exec()
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    require_once ABSPATH . 'wp-admin/includes/file.php';

    wp_update_plugins();
    wp_update_themes();

    $info = array();
    $info['name'] = mfmanager_get_site_name();
    $info['version']  = get_bloginfo('version');
    $info['url'] = get_bloginfo('url');
    $info['template'] = get_bloginfo('template_url');
    $info['path'] = get_home_path();
    $info['ip'] = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
    $info['key'] = get_option('mfmanager_api_settings');
    $info['php_version'] = phpversion();
    $info['plugin_version'] = '9.2.0';

    // WordPress core update status
    $core_updates = get_site_transient('update_core');
    $core_update_info = array(
        'current_version' => get_bloginfo('version'),
        'status' => 'up_to_date',
        'latest_version' => null,
        'update_type' => null,
        'checked_at' => current_time('mysql')
    );

    if ($core_updates && !empty($core_updates->updates)) {
        foreach ($core_updates->updates as $update) {
            if ($update->response === 'upgrade') {
                $core_update_info['status'] = 'update_available';
                $core_update_info['latest_version'] = $update->version;
                $core_update_info['package'] = isset($update->package) ? $update->package : null;

                // Determine update type
                $current_parts = explode('.', get_bloginfo('version'));
                $new_parts = explode('.', $update->version);

                if ((int)$current_parts[0] < (int)$new_parts[0]) {
                    $core_update_info['update_type'] = 'major';
                } elseif (isset($current_parts[1], $new_parts[1]) && (int)$current_parts[1] < (int)$new_parts[1]) {
                    $core_update_info['update_type'] = 'minor';
                } else {
                    $core_update_info['update_type'] = 'patch';
                }
                break;
            }
        }
    }
    $info['core_updates'] = $core_update_info;

    // Theme information
    $theme = wp_get_theme();
    $theme_updates = get_site_transient('update_themes');
    $theme_slug = $theme->get_stylesheet();
    $theme_update = null;

    if ($theme_updates && !empty($theme_updates->response) && isset($theme_updates->response[$theme_slug])) {
        $theme_update = $theme_updates->response[$theme_slug];
    }

    $info['theme'] = array(
        'name'             => $theme->get('Name'),
        'version'          => $theme->get('Version'),
        'stylesheet'       => $theme->get_stylesheet(),
        'template'         => $theme->get_template(),
        'slug'             => $theme_slug,
        'author'           => $theme->get('Author'),
        'description'      => substr($theme->get('Description'), 0, 500),
        'update_available' => !empty($theme_update),
        'new_version'      => $theme_update ? $theme_update['new_version'] : null,
        'package'          => $theme_update ? $theme_update['package'] : null,
    );

    // Parent theme info if using child theme
    if ($theme->parent()) {
        $parent = $theme->parent();
        $parent_slug = $parent->get_stylesheet();
        $parent_update = null;

        if ($theme_updates && !empty($theme_updates->response) && isset($theme_updates->response[$parent_slug])) {
            $parent_update = $theme_updates->response[$parent_slug];
        }

        $info['parent_theme'] = array(
            'name'             => $parent->get('Name'),
            'version'          => $parent->get('Version'),
            'slug'             => $parent_slug,
            'update_available' => !empty($parent_update),
            'new_version'      => $parent_update ? $parent_update['new_version'] : null,
        );
    }

    // Plugin information with slugs
    $plugins = get_plugins();
    $plugin_updates = get_site_transient('update_plugins');
    $active_plugins = get_option('active_plugins', array());
    $plugins_info = array();

    foreach ($plugins as $plugin_file => $plugin_data) {
        $update = null;

        if ($plugin_updates && isset($plugin_updates->response[$plugin_file])) {
            $update = $plugin_updates->response[$plugin_file];
        }

        // Extract slug from plugin file path
        $slug = mfmanager_get_plugin_slug($plugin_file);

        $plugins_info[] = array(
            'name'             => $plugin_data['Name'],
            'version'          => $plugin_data['Version'],
            'plugin_file'      => $plugin_file,
            'slug'             => $slug,
            'active'           => in_array($plugin_file, $active_plugins) ? 1 : 0,
            'update_available' => !empty($update),
            'new_version'      => $update ? $update->new_version : null,
            'package'          => $update ? (isset($update->package) ? $update->package : null) : null,
            'author'           => isset($plugin_data['Author']) ? $plugin_data['Author'] : null,
            'plugin_uri'       => isset($plugin_data['PluginURI']) ? $plugin_data['PluginURI'] : null,
        );
    }

    $info['plugins'] = $plugins_info;

    // Summary counts for quick overview
    $info['summary'] = array(
        'total_plugins' => count($plugins),
        'active_plugins' => count($active_plugins),
        'plugins_needing_update' => count(array_filter($plugins_info, function($p) { return $p['update_available']; })),
        'theme_needs_update' => !empty($theme_update) ? 1 : 0,
        'core_needs_update' => $core_update_info['status'] === 'update_available' ? 1 : 0,
    );

    $response = wp_remote_post(
        MFMANAGER_API_URL . 'updateSite',
        array(
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'body'    => wp_json_encode($info),
            'timeout' => 30,
        )
    );

    if (is_wp_error($response)) {
        error_log('MF Manager error: ' . $response->get_error_message());
        return;
    }

    if (wp_remote_retrieve_response_code($response) >= 400) {
        error_log('MF Manager error: ' . wp_remote_retrieve_body($response));
    }
}

/**
 * Extract plugin slug from plugin file path
 */
function mfmanager_get_plugin_slug($plugin_file)
{
    $parts = explode('/', $plugin_file);

    if (count($parts) > 1) {
        return sanitize_title($parts[0]);
    }

    // Single file plugin
    return sanitize_title(str_replace('.php', '', $plugin_file));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cookie Compliance Scanner — Integration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Enqueue the lightweight cookie monitor JS on every front-end page.
 *
 * Runs for ALL visitors (logged-in and anonymous). Does NOT load in wp-admin.
 * The script uses sendBeacon() to report via a lightweight custom endpoint
 * that bypasses admin-ajax.php entirely (no full WP-admin bootstrap).
 */
add_action('wp_enqueue_scripts', 'mfmanager_enqueue_cookie_monitor');
function mfmanager_enqueue_cookie_monitor()
{
    // Never in admin
    if (is_admin()) {
        return;
    }

    wp_enqueue_script(
        'mfmanager-cookie-monitor',
        plugin_dir_url(__FILE__) . 'js/cookie-monitor.js',
        [],
        '9.2.0',
        true // in footer
    );

    // Lightweight custom endpoint — avoids full admin-ajax.php bootstrap
    wp_localize_script('mfmanager-cookie-monitor', 'mfmCM', [
        'e' => home_url('/?mfm_cookie_report=1'),
    ]);
}

/**
 * Register the lightweight cookie report query var.
 */
add_filter('query_vars', 'mfmanager_cookie_report_query_vars');
function mfmanager_cookie_report_query_vars($vars)
{
    $vars[] = 'mfm_cookie_report';
    return $vars;
}

/**
 * Lightweight cookie report endpoint.
 *
 * Intercepts requests at /?mfm_cookie_report=1 via parse_request.
 * This fires much earlier than admin-ajax.php, skipping the full admin
 * bootstrap, theme loading, and most plugin hooks. Responds with JSON
 * and exits immediately.
 *
 * Rate-limited to 20 reports per IP per minute via transient.
 */
add_action('parse_request', 'mfmanager_handle_cookie_report_lightweight');
function mfmanager_handle_cookie_report_lightweight($wp)
{
    if (empty($wp->query_vars['mfm_cookie_report'])) {
        return;
    }

    // Set JSON header early
    header('Content-Type: application/json; charset=utf-8');

    // Read raw POST body
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    if (empty($data) || empty($data['c'])) {
        echo wp_json_encode(['status' => 'ignored']);
        exit;
    }

    // Rate limit: 20 reports per IP per minute
    $ip       = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $rate_key = 'mfm_cr_' . md5($ip);
    $count    = (int) get_transient($rate_key);
    if ($count >= 20) {
        http_response_code(429);
        echo wp_json_encode(['status' => 'rate_limited']);
        exit;
    }
    set_transient($rate_key, $count + 1, 60);

    // Extract consent info
    $consent = isset($data['cs']) ? $data['cs'] : [];
    $non_essential = array_map('sanitize_text_field', (array) ($data['n'] ?? []));
    $path = isset($data['p']) ? sanitize_text_field($data['p']) : '/';

    // Write each non-essential cookie directly to the custom table
    $cookie_table = new MFManager_Cookie_Data_Table();

    foreach ($non_essential as $cookie_name) {
        $cookie_name = sanitize_text_field($cookie_name);
        if (empty($cookie_name)) {
            continue;
        }

        $classification = MFManager_Cookie_Compliance::classify($cookie_name);
        $seen_without_consent = !empty($consent) && empty($consent['consented']) ? 1 : 0;
        $seen_essential_only  = (!empty($consent['consented']) && empty($consent['statistics']) && empty($consent['marketing'])) ? 1 : 0;

        $cookie_table->upsert([
            'cookie_name'          => $cookie_name,
            'category'             => $classification['category'],
            'source'               => $classification['source'],
            'description'          => $classification['description'],
            'lifetime'             => $classification['lifetime'],
            'detection'            => 'javascript',
            'classification'       => 'frontend',
            'consent_plugin'       => sanitize_text_field($consent['plugin'] ?? 'none'),
            'seen_without_consent' => $seen_without_consent,
            'seen_essential_only'  => $seen_essential_only,
            'pages_seen_on'        => $path,
            'times_seen'           => 1,
        ]);
    }

    echo wp_json_encode(['status' => 'ok']);
    exit;
}

/**
 * Daily cron: crunch yesterday's page views, report to server, purge old rows.
 */
function mfmanager_pageview_cron_exec()
{
    $tracker = new MFManager_Pageview_Tracker();
    $result  = $tracker->daily_crunch();

    if ($result['sent'] === true) {
        error_log(sprintf(
            'MF Manager: Pageview report sent — %s = %d views, %d rows purged.',
            $result['date'], $result['views'], $result['purged']
        ));
    } else {
        error_log('MF Manager: Pageview report failed — ' . $result['sent']);
    }
}

/**
 * Daily cron: send audit log entries to CodeIgniter and clear table.
 */
function mfmanager_audit_cron_exec()
{
    $logger = new MFManager_Audit_Logger();
    $result = $logger->daily_send();

    if ($result['sent'] === true) {
        error_log(sprintf(
            'MF Manager: Audit log sent — %d entries, %d cleared.',
            $result['entries'], $result['cleared']
        ));
    } else {
        error_log('MF Manager: Audit log send failed — ' . $result['sent']);
    }
}

/**
 * Daily cron: run the cookie scan, save results to custom table, send report.
 */
function mfmanager_cookie_cron_exec()
{
    $api_key = get_option('mfmanager_api_settings', '');
    if (empty($api_key)) {
        error_log('MF Manager: Cookie scan skipped — no API key configured.');
        return;
    }

    $scanner = new MFManager_Cookie_Scanner();
    $report  = $scanner->run_full_scan();

    // Write scanned cookies into the custom mfm_cookies table
    if (!empty($report['cookies'])) {
        $cookie_table = new MFManager_Cookie_Data_Table();
        $summary = $cookie_table->bulk_upsert($report['cookies']);
        error_log(sprintf(
            'MF Manager: Cookie table sync — %d inserted, %d updated, %d unchanged.',
            $summary['inserted'], $summary['updated'], $summary['unchanged']
        ));
    }

    // Send to central server
    mfmanager_send_cookie_report($report);
}

/**
 * Send the cookie compliance report to the central dashboard.
 *
 * @param array $report Full scan report.
 * @return true|string True on success, error message on failure.
 */
function mfmanager_send_cookie_report($report)
{
    $info = [
        'url'           => get_bloginfo('url'),
        'key'           => get_option('mfmanager_api_settings'),
        'cookie_report' => $report,
    ];

    $response = wp_remote_post(
        MFMANAGER_API_URL . 'cookieReport',
        [
            'headers' => ['Content-Type' => 'application/json'],
            'body'    => wp_json_encode($info),
            'timeout' => 30,
        ]
    );

    if (is_wp_error($response)) {
        error_log('MF Manager cookie report error: ' . $response->get_error_message());
        return $response->get_error_message();
    }

    if (wp_remote_retrieve_response_code($response) >= 400) {
        $error = wp_remote_retrieve_body($response);
        error_log('MF Manager cookie report error: ' . $error);
        return $error;
    }

    return true;
}

/**
 * Daily cron: sync Complianz settings to custom cookie table, then send
 * the full cookie table data to the CodeIgniter dashboard.
 */
function mfmanager_cookie_data_cron_exec()
{
    $cookie_table = new MFManager_Cookie_Data_Table();

    // 1. Sync Complianz declarations into the cookie table
    $complianz_updated = $cookie_table->sync_complianz();
    if ($complianz_updated > 0) {
        error_log(sprintf('MF Manager: Complianz sync — %d cookie rows updated.', $complianz_updated));
    }

    // 2. Send the full cookie table to CodeIgniter
    $result = $cookie_table->send_to_server();
    if ($result === true) {
        error_log('MF Manager: Cookie data sent to dashboard.');
    } else {
        error_log('MF Manager: Cookie data send failed — ' . $result);
    }
}

/**
 * Admin page callback for the Cookie Scan submenu.
 */
function mfmanager_cookie_scan_page()
{
    $scan_message      = '';
    $scan_message_type = 'info';

    // Handle form submissions
    if (isset($_POST['mfm_cookie_nonce']) && wp_verify_nonce($_POST['mfm_cookie_nonce'], 'mfmanager_cookie_action')) {

        if (isset($_POST['run_cookie_scan'])) {
            $scanner = new MFManager_Cookie_Scanner();
            $report  = $scanner->run_full_scan();

            $v = $report['summary']['violations'] ?? 0;
            $w = $report['summary']['warnings'] ?? 0;

            if ($v > 0) {
                $scan_message      = sprintf('Scan complete. Found %d violation(s) and %d warning(s).', $v, $w);
                $scan_message_type = 'error';
            } elseif ($w > 0) {
                $scan_message      = sprintf('Scan complete. No violations, but %d warning(s) found.', $w);
                $scan_message_type = 'warning';
            } else {
                $scan_message      = 'Scan complete. All cookies are compliant!';
                $scan_message_type = 'success';
            }

            // Also send to central server
            $api_key = get_option('mfmanager_api_settings', '');
            if (!empty($api_key)) {
                mfmanager_send_cookie_report($report);
            }
        }

        if (isset($_POST['run_page_discovery'])) {
            $discovery    = new MFManager_Cookie_Page_Discovery();
            $sample_pages = $discovery->discover(true); // Force refresh from admin UI
            $count        = count($sample_pages);
            $scan_message      = sprintf('Page discovery complete. Found %d content type(s) with sample pages.', $count);
            $scan_message_type = 'success';
        }
    }

    // Load data for the view
    $last_scan    = get_option('mfmanager_cookie_last_scan', null);
    $sample_pages = get_option('mfmanager_cookie_sample_pages', []);

    include plugin_dir_path(__FILE__) . 'views/cookie-scan.php';
}

/**
 * Clean up cron events on plugin deactivation.
 */
register_deactivation_hook(__FILE__, 'mfmanager_deactivation_cleanup');
function mfmanager_deactivation_cleanup()
{
    wp_clear_scheduled_hook('mfmanager_cron_hook');
    wp_clear_scheduled_hook('mfmanager_security_cron_hook');
    wp_clear_scheduled_hook('mfmanager_cookie_cron_hook');
    wp_clear_scheduled_hook('mfmanager_pageview_cron_hook');
    wp_clear_scheduled_hook('mfmanager_audit_cron_hook');
    wp_clear_scheduled_hook('mfmanager_cookie_data_cron_hook');

    // Drop custom tables
    $pv = new MFManager_Pageview_Tracker();
    $pv->drop_table();

    $al = new MFManager_Audit_Logger();
    $al->drop_table();

    $ct = new MFManager_Cookie_Data_Table();
    $ct->drop_table();

    // Clean up old options that are no longer used
    delete_option('mfm_pageviews_table_created');
    delete_option('mfm_audit_table_created');
    delete_option('mfmanager_cookie_js_reports');

    // Clean up transients
    delete_transient('mfmanager_wpscan_token');
    delete_transient('mfmanager_cookie_discovery');
}
