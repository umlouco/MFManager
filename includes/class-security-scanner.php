<?php
/**
 * Security Scanner - Checks for vulnerabilities using WPScan API
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Security_Scanner
{
    /**
     * WPScan API base URL
     */
    const WPSCAN_API_URL = 'https://wpscan.com/api/v3/';

    /**
     * API token for WPScan
     */
    private $api_token;

    /**
     * Constructor
     */
    public function __construct($api_token = null)
    {
        $this->api_token = $api_token;
    }

    /**
     * Set API token
     */
    public function set_api_token($token)
    {
        $this->api_token = $token;
    }

    /**
     * Run full security scan
     */
    public function run_scan()
    {
        $results = array(
            'scan_date' => current_time('mysql'),
            'wp_version' => get_bloginfo('version'),
            'vulnerabilities' => array(),
            'scan_summary' => array(
                'total' => 0,
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0
            )
        );

        // Scan WordPress core
        $core_vulns = $this->scan_wordpress_core();
        if (!empty($core_vulns)) {
            $results['vulnerabilities'] = array_merge($results['vulnerabilities'], $core_vulns);
        }

        // Scan plugins
        $plugin_vulns = $this->scan_plugins();
        if (!empty($plugin_vulns)) {
            $results['vulnerabilities'] = array_merge($results['vulnerabilities'], $plugin_vulns);
        }

        // Scan theme
        $theme_vulns = $this->scan_theme();
        if (!empty($theme_vulns)) {
            $results['vulnerabilities'] = array_merge($results['vulnerabilities'], $theme_vulns);
        }

        // Update summary counts
        foreach ($results['vulnerabilities'] as $vuln) {
            $results['scan_summary']['total']++;
            $severity = isset($vuln['severity']) ? strtolower($vuln['severity']) : 'medium';
            if (isset($results['scan_summary'][$severity])) {
                $results['scan_summary'][$severity]++;
            }
        }

        return $results;
    }

    /**
     * Scan WordPress core for vulnerabilities
     */
    public function scan_wordpress_core()
    {
        $vulnerabilities = array();
        $wp_version = get_bloginfo('version');

        if (empty($this->api_token)) {
            return $vulnerabilities;
        }

        $response = $this->api_request('wordpresses/' . str_replace('.', '', $wp_version));

        if (is_wp_error($response) || empty($response)) {
            return $vulnerabilities;
        }

        // Parse vulnerabilities from response
        $version_key = $wp_version;
        if (isset($response[$version_key]['vulnerabilities'])) {
            foreach ($response[$version_key]['vulnerabilities'] as $vuln) {
                $vulnerabilities[] = $this->format_vulnerability($vuln, 'WordPress Core', $wp_version, 'core');
            }
        }

        return $vulnerabilities;
    }

    /**
     * Scan all active plugins for vulnerabilities
     */
    public function scan_plugins()
    {
        $vulnerabilities = array();

        if (empty($this->api_token)) {
            return $vulnerabilities;
        }

        require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugins = get_plugins();
        $active_plugins = get_option('active_plugins', array());

        foreach ($plugins as $plugin_file => $plugin_data) {
            // Get plugin slug from file path
            $slug = $this->get_plugin_slug($plugin_file);

            if (empty($slug)) {
                continue;
            }

            $response = $this->api_request('plugins/' . $slug);

            if (is_wp_error($response) || empty($response)) {
                continue;
            }

            // Check if plugin exists in WPScan database
            if (isset($response[$slug]['vulnerabilities'])) {
                $plugin_version = isset($plugin_data['Version']) ? $plugin_data['Version'] : null;
                $is_active = in_array($plugin_file, $active_plugins);

                foreach ($response[$slug]['vulnerabilities'] as $vuln) {
                    // Check if vulnerability affects this version
                    if ($this->vulnerability_affects_version($vuln, $plugin_version)) {
                        $formatted = $this->format_vulnerability(
                            $vuln,
                            $plugin_data['Name'],
                            $plugin_version,
                            'plugin'
                        );
                        $formatted['plugin_file'] = $plugin_file;
                        $formatted['is_active'] = $is_active;
                        $vulnerabilities[] = $formatted;
                    }
                }
            }

            // Add small delay to avoid rate limiting
            usleep(200000); // 200ms
        }

        return $vulnerabilities;
    }

    /**
     * Scan current theme for vulnerabilities
     */
    public function scan_theme()
    {
        $vulnerabilities = array();

        if (empty($this->api_token)) {
            return $vulnerabilities;
        }

        $theme = wp_get_theme();
        $slug = $theme->get_stylesheet();
        $version = $theme->get('Version');

        $response = $this->api_request('themes/' . $slug);

        if (is_wp_error($response) || empty($response)) {
            return $vulnerabilities;
        }

        if (isset($response[$slug]['vulnerabilities'])) {
            foreach ($response[$slug]['vulnerabilities'] as $vuln) {
                if ($this->vulnerability_affects_version($vuln, $version)) {
                    $vulnerabilities[] = $this->format_vulnerability(
                        $vuln,
                        $theme->get('Name'),
                        $version,
                        'theme'
                    );
                }
            }
        }

        return $vulnerabilities;
    }

    /**
     * Make API request to WPScan
     */
    private function api_request($endpoint)
    {
        $url = self::WPSCAN_API_URL . $endpoint;

        $response = wp_remote_get($url, array(
            'timeout' => 15,
            'headers' => array(
                'Authorization' => 'Token token=' . $this->api_token,
                'Accept' => 'application/json'
            )
        ));

        if (is_wp_error($response)) {
            error_log('MFManager Security: API error - ' . $response->get_error_message());
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code === 404) {
            // Not found in database - not an error
            return array();
        }

        if ($code !== 200) {
            error_log('MFManager Security: API returned code ' . $code);
            return new WP_Error('api_error', 'API returned code ' . $code);
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return new WP_Error('json_error', 'Failed to parse API response');
        }

        return $data;
    }

    /**
     * Get plugin slug from plugin file path
     */
    private function get_plugin_slug($plugin_file)
    {
        // Plugin file format: plugin-slug/plugin-file.php or plugin-file.php
        $parts = explode('/', $plugin_file);

        if (count($parts) > 1) {
            return sanitize_title($parts[0]);
        }

        // Single file plugin
        return sanitize_title(str_replace('.php', '', $plugin_file));
    }

    /**
     * Check if vulnerability affects a specific version
     */
    private function vulnerability_affects_version($vuln, $installed_version)
    {
        if (empty($installed_version)) {
            return true; // Can't determine, assume vulnerable
        }

        // If no fixed_in version, always vulnerable
        if (empty($vuln['fixed_in'])) {
            return true;
        }

        // Compare versions - vulnerable if installed version is less than fixed_in
        return version_compare($installed_version, $vuln['fixed_in'], '<');
    }

    /**
     * Format vulnerability data for storage
     */
    private function format_vulnerability($vuln, $component_name, $component_version, $component_type)
    {
        $severity = $this->determine_severity($vuln);

        return array(
            'component_type' => $component_type,
            'component_name' => $component_name,
            'component_version' => $component_version,
            'title' => isset($vuln['title']) ? $vuln['title'] : 'Unknown vulnerability',
            'description' => isset($vuln['description']) ? $vuln['description'] : null,
            'vuln_type' => isset($vuln['vuln_type']) ? $vuln['vuln_type'] : null,
            'severity' => $severity,
            'cvss_score' => isset($vuln['cvss']['score']) ? floatval($vuln['cvss']['score']) : null,
            'fixed_in' => isset($vuln['fixed_in']) ? $vuln['fixed_in'] : null,
            'references' => isset($vuln['references']) ? $vuln['references'] : null,
            'wpvulndb_id' => isset($vuln['id']) ? $vuln['id'] : null,
            'published_date' => isset($vuln['published_date']) ? $vuln['published_date'] : null,
            'is_fixed' => $this->is_vulnerability_fixed($vuln, $component_version) ? 1 : 0
        );
    }

    /**
     * Determine severity from vulnerability data
     */
    private function determine_severity($vuln)
    {
        // Try CVSS score first
        if (isset($vuln['cvss']['score'])) {
            $score = floatval($vuln['cvss']['score']);
            if ($score >= 9.0) return 'critical';
            if ($score >= 7.0) return 'high';
            if ($score >= 4.0) return 'medium';
            return 'low';
        }

        // Try severity field
        if (isset($vuln['severity'])) {
            $severity = strtolower($vuln['severity']);
            if (in_array($severity, array('critical', 'high', 'medium', 'low'))) {
                return $severity;
            }
        }

        // Default to medium
        return 'medium';
    }

    /**
     * Check if vulnerability is fixed in installed version
     */
    private function is_vulnerability_fixed($vuln, $installed_version)
    {
        if (empty($vuln['fixed_in']) || empty($installed_version)) {
            return false;
        }

        return version_compare($installed_version, $vuln['fixed_in'], '>=');
    }
}
