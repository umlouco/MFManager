<?php
/**
 * MFManager Cookie Data Table
 *
 * Custom database table for cookie data. Stores one row per unique cookie
 * name with all relevant metadata. Rows are only updated when data changes.
 *
 * A daily cron reads Complianz settings and writes them here, and sends
 * the full table contents to the CodeIgniter dashboard.
 *
 * @package MFManager
 * @since   9.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Cookie_Data_Table
{
    /** @var string WordPress table name (with prefix) */
    private $table;

    public function __construct()
    {
        global $wpdb;
        $this->table = $wpdb->prefix . 'mfm_cookies';
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Table management
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Create the cookies table if it doesn't exist.
     * Called on plugin activation.
     */
    public function ensure_table()
    {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            cookie_name VARCHAR(255) NOT NULL,
            category VARCHAR(50) NOT NULL DEFAULT 'unknown',
            source VARCHAR(100) NOT NULL DEFAULT 'Unknown',
            description TEXT DEFAULT NULL,
            lifetime VARCHAR(50) DEFAULT NULL,
            lifetime_seconds INT UNSIGNED DEFAULT NULL,
            is_third_party TINYINT(1) NOT NULL DEFAULT 0,
            domain VARCHAR(255) DEFAULT NULL,
            secure TINYINT(1) NOT NULL DEFAULT 0,
            httponly TINYINT(1) NOT NULL DEFAULT 0,
            samesite VARCHAR(10) DEFAULT NULL,
            detection VARCHAR(20) NOT NULL DEFAULT 'unknown',
            classification VARCHAR(20) NOT NULL DEFAULT 'unknown',
            consent_plugin VARCHAR(50) DEFAULT NULL,
            seen_without_consent TINYINT(1) NOT NULL DEFAULT 0,
            seen_essential_only TINYINT(1) NOT NULL DEFAULT 0,
            compliance_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
            compliance_issues TEXT DEFAULT NULL,
            complianz_declared TINYINT(1) NOT NULL DEFAULT 0,
            complianz_description TEXT DEFAULT NULL,
            complianz_purpose TEXT DEFAULT NULL,
            complianz_category VARCHAR(100) DEFAULT NULL,
            complianz_service VARCHAR(100) DEFAULT NULL,
            pages_seen_on TEXT DEFAULT NULL,
            times_seen INT UNSIGNED NOT NULL DEFAULT 0,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_changed DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            data_hash VARCHAR(64) NOT NULL DEFAULT '',
            UNIQUE KEY idx_cookie_name (cookie_name),
            INDEX idx_category (category),
            INDEX idx_compliance (compliance_status),
            INDEX idx_last_changed (last_changed)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Upsert: insert or update only when data changed
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Insert or update a cookie row. Only writes if data has changed.
     *
     * @param array $cookie_data Associative array of cookie fields.
     * @return string 'inserted', 'updated', or 'unchanged'.
     */
    public function upsert($cookie_data)
    {
        global $wpdb;

        $name = isset($cookie_data['cookie_name']) ? $cookie_data['cookie_name'] : '';
        if (empty($name)) {
            return 'skipped';
        }

        // Build the data hash (excludes times_seen, first_seen, last_seen, last_changed)
        $hash_data = $cookie_data;
        unset($hash_data['times_seen'], $hash_data['first_seen'], $hash_data['last_seen'], $hash_data['last_changed']);
        $new_hash = hash('sha256', wp_json_encode($hash_data));

        // Check existing row
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT id, data_hash, times_seen FROM {$this->table} WHERE cookie_name = %s",
            $name
        ));

        $now = current_time('mysql');

        if (!$existing) {
            // New cookie — insert
            $cookie_data['data_hash']  = $new_hash;
            $cookie_data['first_seen'] = $now;
            $cookie_data['last_seen']  = $now;
            $cookie_data['last_changed'] = $now;
            if (!isset($cookie_data['times_seen'])) {
                $cookie_data['times_seen'] = 1;
            }

            // Serialize arrays for TEXT columns
            $cookie_data = $this->serialize_arrays($cookie_data);

            $wpdb->insert($this->table, $cookie_data);
            return 'inserted';
        }

        // Existing cookie — update only if hash differs
        $times_seen = (int) $existing->times_seen + (isset($cookie_data['times_seen']) ? (int) $cookie_data['times_seen'] : 1);

        if ($existing->data_hash === $new_hash) {
            // Data hasn't changed, just bump times_seen and last_seen
            $wpdb->update(
                $this->table,
                array('times_seen' => $times_seen, 'last_seen' => $now),
                array('id' => $existing->id),
                array('%d', '%s'),
                array('%d')
            );
            return 'unchanged';
        }

        // Data changed — full update
        $cookie_data['data_hash']    = $new_hash;
        $cookie_data['last_seen']    = $now;
        $cookie_data['last_changed'] = $now;
        $cookie_data['times_seen']   = $times_seen;

        // Don't overwrite first_seen
        unset($cookie_data['first_seen']);

        $cookie_data = $this->serialize_arrays($cookie_data);

        $wpdb->update(
            $this->table,
            $cookie_data,
            array('id' => $existing->id)
        );
        return 'updated';
    }

    /**
     * Bulk upsert from a cookie scan result array.
     *
     * @param array $cookies Array of cookie data from the scanner.
     * @return array Summary counts: inserted, updated, unchanged.
     */
    public function bulk_upsert($cookies)
    {
        $summary = array('inserted' => 0, 'updated' => 0, 'unchanged' => 0, 'skipped' => 0);

        foreach ($cookies as $cookie) {
            $row = $this->normalize_cookie($cookie);
            $result = $this->upsert($row);
            if (isset($summary[$result])) {
                $summary[$result]++;
            }
        }

        return $summary;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Complianz sync — daily cron writes Complianz settings here
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Read Complianz cookie declarations and update the table.
     *
     * @return int Number of rows updated from Complianz.
     */
    public function sync_complianz()
    {
        $scanner = new MFManager_Cookie_Scanner();
        $config  = $scanner->get_complianz_config();

        if (empty($config['installed']) || empty($config['cookies'])) {
            return 0;
        }

        global $wpdb;
        $updated = 0;

        foreach ($config['cookies'] as $declared) {
            $declared_name = '';
            if (isset($declared['name'])) {
                $declared_name = $declared['name'];
            } elseif (isset($declared['cookie_name'])) {
                $declared_name = $declared['cookie_name'];
            }
            if (empty($declared_name)) {
                continue;
            }

            // If this is a wildcard, try to match against existing cookies
            if (strpos($declared_name, '*') !== false) {
                $regex_like = str_replace('*', '%', $declared_name);
                $matches = $wpdb->get_col($wpdb->prepare(
                    "SELECT cookie_name FROM {$this->table} WHERE cookie_name LIKE %s",
                    $regex_like
                ));
            } else {
                $matches = array($declared_name);
            }

            $purpose = isset($declared['purpose']) ? $declared['purpose'] : null;
            if (empty($purpose)) {
                $purpose = isset($declared['cookieFunction']) ? $declared['cookieFunction'] : null;
            }
            $category = isset($declared['service']) ? $declared['service'] : null;
            if (empty($category)) {
                $category = isset($declared['category']) ? $declared['category'] : null;
            }

            // Resolve service name
            $service_name = null;
            if (isset($declared['serviceID']) && !empty($config['services'])) {
                foreach ($config['services'] as $svc) {
                    if (isset($svc['ID']) && $svc['ID'] == $declared['serviceID']) {
                        $service_name = isset($svc['name']) ? $svc['name'] : null;
                        break;
                    }
                }
            }
            if (empty($service_name) && isset($declared['service'])) {
                $service_name = $declared['service'];
            }

            foreach ($matches as $cookie_name) {
                $wpdb->query($wpdb->prepare(
                    "UPDATE {$this->table} SET
                        complianz_declared = 1,
                        complianz_description = %s,
                        complianz_purpose = %s,
                        complianz_category = %s,
                        complianz_service = %s,
                        last_changed = %s
                     WHERE cookie_name = %s
                       AND (complianz_declared = 0
                            OR complianz_description != %s
                            OR complianz_purpose != %s
                            OR complianz_category != %s
                            OR complianz_service != %s)",
                    $purpose, $purpose, $category, $service_name, current_time('mysql'),
                    $cookie_name,
                    $purpose, $purpose, $category, $service_name
                ));
                if ($wpdb->rows_affected > 0) {
                    $updated++;
                }
            }
        }

        return $updated;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Send to CodeIgniter
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Send the full cookie table to the central CodeIgniter dashboard.
     *
     * @return true|string True on success, error message on failure.
     */
    public function send_to_server()
    {
        global $wpdb;

        $api_key = get_option('mfmanager_api_settings', '');
        if (empty($api_key)) {
            return 'No API key configured';
        }

        $rows = $wpdb->get_results(
            "SELECT * FROM {$this->table} ORDER BY cookie_name ASC",
            ARRAY_A
        );

        $payload = array(
            'url'     => get_bloginfo('url'),
            'key'     => $api_key,
            'cookies' => $rows,
        );

        $response = wp_remote_post(
            MFMANAGER_API_URL . 'cookieData',
            array(
                'headers' => array('Content-Type' => 'application/json'),
                'body'    => wp_json_encode($payload),
                'timeout' => 30,
            )
        );

        if (is_wp_error($response)) {
            error_log('MF Manager cookie data error: ' . $response->get_error_message());
            return $response->get_error_message();
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 400) {
            $body = wp_remote_retrieve_body($response);
            error_log('MF Manager cookie data error: HTTP ' . $code . ' — ' . $body);
            return 'HTTP ' . $code;
        }

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Read
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Get all cookie rows.
     *
     * @return array
     */
    public function get_all()
    {
        global $wpdb;
        return $wpdb->get_results(
            "SELECT * FROM {$this->table} ORDER BY cookie_name ASC",
            ARRAY_A
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Normalize a scanner cookie array into our table columns.
     *
     * @param array $cookie Raw cookie from scanner.
     * @return array Normalized for upsert.
     */
    private function normalize_cookie($cookie)
    {
        $compliance = isset($cookie['compliance']) ? $cookie['compliance'] : array();

        return array(
            'cookie_name'           => isset($cookie['name']) ? substr($cookie['name'], 0, 255) : '',
            'category'              => isset($compliance['category']) ? $compliance['category'] : (isset($cookie['category']) ? $cookie['category'] : 'unknown'),
            'source'                => isset($compliance['source']) ? $compliance['source'] : (isset($cookie['source']) ? $cookie['source'] : 'Unknown'),
            'description'           => isset($compliance['description']) ? $compliance['description'] : null,
            'lifetime'              => isset($cookie['lifetime']) ? $cookie['lifetime'] : null,
            'lifetime_seconds'      => isset($cookie['lifetime_seconds']) ? (int) $cookie['lifetime_seconds'] : null,
            'is_third_party'        => !empty($cookie['is_third_party']) ? 1 : 0,
            'domain'                => isset($cookie['domain']) ? $cookie['domain'] : null,
            'secure'                => !empty($cookie['secure']) ? 1 : 0,
            'httponly'              => !empty($cookie['httponly']) ? 1 : 0,
            'samesite'              => isset($cookie['samesite']) ? $cookie['samesite'] : null,
            'detection'             => isset($cookie['detection']) ? $cookie['detection'] : 'unknown',
            'classification'        => isset($cookie['classification']) ? $cookie['classification'] : 'unknown',
            'consent_plugin'        => isset($cookie['consent_plugin']) ? $cookie['consent_plugin'] : null,
            'seen_without_consent'  => !empty($cookie['set_before_consent']) ? 1 : 0,
            'seen_essential_only'   => !empty($cookie['consent_was_essential_only']) ? 1 : 0,
            'compliance_status'     => isset($compliance['status']) ? $compliance['status'] : 'unknown',
            'compliance_issues'     => !empty($compliance['issues']) ? wp_json_encode($compliance['issues']) : null,
            'complianz_declared'    => !empty($cookie['complianz_declared']) ? 1 : 0,
            'complianz_description' => isset($cookie['complianz_description']) ? $cookie['complianz_description'] : null,
            'complianz_purpose'     => isset($cookie['complianz_purpose']) ? $cookie['complianz_purpose'] : null,
            'complianz_category'    => isset($cookie['complianz_category']) ? $cookie['complianz_category'] : null,
            'complianz_service'     => isset($cookie['complianz_service']) ? $cookie['complianz_service'] : null,
            'pages_seen_on'         => isset($cookie['found_on']) ? (is_array($cookie['found_on']) ? implode(',', $cookie['found_on']) : $cookie['found_on']) : null,
            'times_seen'            => isset($cookie['times_seen']) ? (int) $cookie['times_seen'] : 1,
        );
    }

    /**
     * Convert array/object values in data to JSON strings for TEXT columns.
     *
     * @param array $data Row data.
     * @return array
     */
    private function serialize_arrays($data)
    {
        $text_cols = array('compliance_issues', 'pages_seen_on');
        foreach ($text_cols as $col) {
            if (isset($data[$col]) && is_array($data[$col])) {
                $data[$col] = wp_json_encode($data[$col]);
            }
        }
        return $data;
    }

    /**
     * Drop the table (deactivation).
     */
    public function drop_table()
    {
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$this->table}");
    }
}
