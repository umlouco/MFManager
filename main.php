<?php

/**
 * Plugin Name:       MF Manager
 * Plugin URI:        https://www.mario-flores.com/mf-manager/
 * Description:       Connector for the MF website manager dashboard with security scanning.
 * Version:           7.1.0
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

add_action('mfmanager_cron_hook', 'mfmanager_cron_exec', 100);
add_action('mfmanager_security_cron_hook', 'mfmanager_security_cron_exec', 100);

if (!wp_next_scheduled('mfmanager_cron_hook')) {
    wp_schedule_event(time(), 'daily', 'mfmanager_cron_hook');
}

// Schedule weekly security scan
if (!wp_next_scheduled('mfmanager_security_cron_hook')) {
    wp_schedule_event(time(), 'weekly', 'mfmanager_security_cron_hook');
}

// Add weekly schedule if not exists
add_filter('cron_schedules', 'mfmanager_add_weekly_schedule');
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
    $wpscan_token = mfmanager_get_wpscan_token();

    if (empty($wpscan_token)) {
        error_log('MF Manager: Could not get WPScan token, skipping security scan');
        return;
    }

    $results = mfmanager_run_security_scan();
    mfmanager_send_security_report($results);
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

function mfmanager_cron_exec()
{
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    require_once ABSPATH . 'wp-admin/includes/file.php';

    wp_update_plugins();
    wp_update_themes();

    $info = array();
    $info['name'] = get_bloginfo('name');
    $info['version']  = get_bloginfo('version');
    $info['url'] = get_bloginfo('url');
    $info['template'] = get_bloginfo('template_url');
    $info['path'] = get_home_path();
    $info['ip'] = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
    $info['key'] = get_option('mfmanager_api_settings');

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
        'update_available' => !empty($theme_update),
        'new_version'      => $theme_update ? $theme_update['new_version'] : null,
        'package'          => $theme_update ? $theme_update['package'] : null,
    );

    $plugins = get_plugins();
    $plugin_updates = get_site_transient('update_plugins');
    $active_plugins = get_option('active_plugins', array());
    $plugins_info = array();

    foreach ($plugins as $plugin_file => $plugin_data) {
        $update = null;

        if ($plugin_updates && isset($plugin_updates->response[$plugin_file])) {
            $update = $plugin_updates->response[$plugin_file];
        }

        $plugins_info[] = array(
            'name'             => $plugin_data['Name'],
            'version'          => $plugin_data['Version'],
            'plugin_file'      => $plugin_file,
            'active'           => in_array($plugin_file, $active_plugins) ? 1 : 0,
            'update_available' => !empty($update),
            'new_version'      => $update ? $update->new_version : null,
            'package'          => $update ? $update->package : null,
        );
    }

    $info['plugins'] = $plugins_info;

    $response = wp_remote_post(
        MFMANAGER_API_URL . 'updateSite',
        array(
            'headers' => array(
                'Content-Type' => 'application/json',
            ),
            'body'    => wp_json_encode($info),
            'timeout' => 20,
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
