<?php

/**
 * Plugin Name:       MF Manager
 * Plugin URI:        https://www.mario-flores.com/mf-manager/
 * Description:       Connector for the MF website manager dashboard.
 * Version:           4.0.0
 * Requires at least: 5.2
 * Requires PHP:      5.6
 * Author:            Mario Flores
 * Author URI:        https://mario-flores.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mf_manager
 * Domain Path:       /languages
 */
add_action('admin_menu', 'mf_manager_menu_page');
add_action('admin_init', 'mfmanager_api_settings_init');
function mf_manager_menu_page()
{
    add_menu_page(
        'MF Manager Settings',
        'MF Manager',
        'manage_options',
        'mfmanager_settings_page',
        'mfmanager_load_settings'
    );
    add_submenu_page(
        'mfmanager_settings_page',
        'Run update',
        'Run',
        'manage_options',
        'mfmanager_run',
        'mfmanager_run'
    );
}

function mfmanager_load_settings()
{
    include(plugin_dir_path(__FILE__) . 'views/settings.php');
}

function mfmanager_run(){
    mfmanager_cron_exec(); 
}

function mfmanager_api_settings_init()
{
    register_setting('mfmanager_settings', 'mfmanager_api_settings');
    add_settings_section(
        'mfmanager_key_section',
        'MF Manager API Settings',
        '',
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

function mfmanager_field_html()
{
    $options = get_option('mfmanager_api_settings');
?>
    <input type="text" value="<?php echo $options; ?>" name="mfmanager_api_settings">
<?php
}

add_action('mfmanager_cron_hook', 'mfmanager_cron_exec', 100);

if (!wp_next_scheduled('mfmanager_cron_hook')) {
    wp_schedule_event(time(), 'daily', 'mfmanager_cron_hook');
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
            'update_available' => !empty($update),
            'new_version'      => $update ? $update->new_version : null,
            'package'          => $update ? $update->package : null,
        );
    }

    $info['plugins'] = $plugins_info;

    $response = wp_remote_post(
        'https://office.mario-flores.com/api/updateSite',
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
