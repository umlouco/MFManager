<?php
/**
 * MFManager Page View Tracker
 *
 * Lightweight front-end page view counter. Creates a local MySQL table
 * that stores only timestamps (one row per hit). A daily cron crunches
 * the numbers, sends the total to the CodeIgniter dashboard, and then
 * purges the raw rows to keep the table small.
 *
 * Only counts full front-end page loads. Excludes:
 *  - wp-admin / admin pages
 *  - AJAX / admin-ajax.php / admin-post.php requests
 *  - REST API requests
 *  - WP-Cron requests
 *  - CLI (WP-CLI)
 *  - Robots / crawlers with common bot user-agents
 *  - Asset requests (CSS/JS/images)
 *
 * @package MFManager
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Pageview_Tracker
{
    /** @var string WordPress table name (with prefix) */
    private $table;

    public function __construct()
    {
        global $wpdb;
        $this->table = $wpdb->prefix . 'mfm_pageviews';
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Table management
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Create the hits table if it doesn't exist.
     * Called on plugin activation and lazily on first track().
     */
    public function ensure_table()
    {
        global $wpdb;

        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            hit_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_hit_at (hit_at)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Track a page view
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Record a single front-end page hit.
     *
     * Instead of inserting a row immediately, we increment a request-local
     * counter and register a shutdown callback that flushes **one** INSERT
     * at the very end of the PHP process.  This keeps the critical path
     * DB-write-free and is safe under concurrent requests because each
     * PHP process has its own counter.
     */
    public function track()
    {
        if (!$this->should_count()) {
            return;
        }

        // Flag this request for a write at shutdown (only register once)
        if (empty($GLOBALS['_mfm_pv_pending'])) {
            $GLOBALS['_mfm_pv_pending'] = true;
            $table = $this->table;
            register_shutdown_function(function () use ($table) {
                global $wpdb;
                $wpdb->insert($table, array(
                    'hit_at' => current_time('mysql'),
                ), array('%s'));
            });
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Cron: crunch, send, purge
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Daily cron job.
     *
     * 1. Count yesterday's page views.
     * 2. Send the number to CodeIgniter.
     * 3. Delete all rows older than today (keep today's running count).
     *
     * @return array  Summary with 'date', 'views', 'sent', 'purged'.
     */
    public function daily_crunch()
    {
        global $wpdb;

        $yesterday = date('Y-m-d', strtotime('-1 day'));

        // 1. Count yesterday
        $views = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE DATE(hit_at) = %s",
            $yesterday
        ));

        // 2. Send to CodeIgniter
        $sent = $this->send_to_server($yesterday, $views);

        // 3. Purge everything up to and including yesterday
        $purged = (int) $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->table} WHERE hit_at < %s",
            date('Y-m-d 00:00:00') // start of today
        ));

        return array(
            'date'   => $yesterday,
            'views'  => $views,
            'sent'   => $sent,
            'purged' => $purged,
        );
    }

    /**
     * Send a single day's count to the central CodeIgniter dashboard.
     *
     * @param string $date  Y-m-d date string.
     * @param int    $views Number of page views for that date.
     * @return true|string  True on success, error message on failure.
     */
    public function send_to_server($date, $views)
    {
        $api_key = get_option('mfmanager_api_settings', '');
        if (empty($api_key)) {
            return 'No API key configured';
        }

        $payload = array(
            'url' => get_bloginfo('url'),
            'key' => $api_key,
            'pageviews' => array(
                array(
                    'date'  => $date,
                    'views' => $views,
                ),
            ),
        );

        $response = wp_remote_post(
            MFMANAGER_API_URL . 'pageViews',
            array(
                'headers' => array('Content-Type' => 'application/json'),
                'body'    => wp_json_encode($payload),
                'timeout' => 15,
            )
        );

        if (is_wp_error($response)) {
            error_log('MF Manager pageview report error: ' . $response->get_error_message());
            return $response->get_error_message();
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 400) {
            $body = wp_remote_retrieve_body($response);
            error_log('MF Manager pageview report error: HTTP ' . $code . ' — ' . $body);
            return 'HTTP ' . $code;
        }

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Should this request be counted as a page view?
     */
    private function should_count()
    {
        // CLI
        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }

        // WP-Cron
        if (defined('DOING_CRON') && DOING_CRON) {
            return false;
        }

        // AJAX
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return false;
        }

        // REST API
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return false;
        }

        // Admin pages
        if (is_admin()) {
            return false;
        }

        // admin-ajax.php or admin-post.php in request URI
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        if (strpos($uri, 'admin-ajax.php') !== false || strpos($uri, 'admin-post.php') !== false) {
            return false;
        }

        // wp-cron.php
        if (strpos($uri, 'wp-cron.php') !== false) {
            return false;
        }

        // xmlrpc.php
        if (strpos($uri, 'xmlrpc.php') !== false) {
            return false;
        }

        // Only count GET requests (not POST/PUT forms, etc.)
        if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== 'GET') {
            return false;
        }

        // Skip common bot user agents
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
        if (empty($ua)) {
            return false; // no user-agent = likely bot
        }
        $bots = array('bot', 'crawl', 'spider', 'slurp', 'facebookexternalhit',
                       'mediapartners', 'semrush', 'ahrefs', 'mj12bot', 'dotbot',
                       'petalbot', 'yandex', 'bingpreview', 'lighthouse', 'pagespeed',
                       'headlesschrome', 'wget', 'curl');
        foreach ($bots as $bot) {
            if (strpos($ua, $bot) !== false) {
                return false;
            }
        }

        // Skip asset requests (shouldn't reach PHP normally, but just in case)
        $ext = pathinfo(parse_url($uri, PHP_URL_PATH), PATHINFO_EXTENSION);
        if (in_array(strtolower($ext), array('css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'map'), true)) {
            return false;
        }

        return true;
    }

    /**
     * Drop the table. Used on plugin deactivation/uninstall.
     */
    public function drop_table()
    {
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$this->table}");
    }
}
