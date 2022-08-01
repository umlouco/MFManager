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
    $theme = wp_get_theme(); 
    $info = array();
    $info['name'] = get_bloginfo('name');
    $info['version']  = get_bloginfo('version');
    $info['plugins'] = get_plugin_updates();
    $info['url'] = get_bloginfo('url');
    $info['template'] = get_bloginfo('template_url');
    $info['path'] = get_home_path();
    $info['ip'] = $_SERVER['SERVER_ADDR'];
    $info['key'] =  get_option('mfmanager_api_settings');
    $info['theme_version'] = $theme->Version; 
    $data_string = json_encode($info);
    $curl = curl_init();
    try {
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://office.mario-flores.com/api/updateSite',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $data_string,
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json'
            ),
        ));

        $response = curl_exec($curl);

        echo $response;
    } catch (\Exception $ex) {
        echo $ex->getMessage();
    }
    curl_close($curl);
}
