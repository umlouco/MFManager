<?php

/**
 * Cookie Scanner
 *
 * Orchestrates the full cookie scan process:
 *   1. Discovers pages with cookie-setting content (Google Maps, YouTube, etc.)
 *   2. Visits each page via HTTP as an anonymous visitor — captures Set-Cookie headers
 *   3. Parses HTML for third-party iframes/scripts that would set cookies in a browser
 *   4. Aggregates JavaScript-reported cookies from the front-end monitor
 *   5. Reads the Complianz plugin configuration for declared cookies
 *   6. Runs EU compliance checks on every detected cookie
 *   7. Builds a complete report and sends it to the central server
 *
 * @package MFManager
 * @since   9.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Cookie_Scanner
{
    /** @var string Site home URL */
    private $site_url;

    /** @var string Site domain (without www) */
    private $site_domain;

    public function __construct()
    {
        $this->site_url    = home_url('/');
        $this->site_domain = parse_url($this->site_url, PHP_URL_HOST);
    }

    // ─────────────────────────────────────────────────────────────
    //  Public API
    // ─────────────────────────────────────────────────────────────

    /**
     * Run a complete cookie scan.
     *
     * @return array Full scan report.
     */
    public function run_full_scan()
    {
        // 1 — Discover pages with cookie-triggering content (uses 7-day cache)
        $discovery    = new MFManager_Cookie_Page_Discovery();
        $sample_pages = $discovery->discover(); // Uses cache; refreshed weekly

        // 2 — Build URL list: homepage + sample pages + random page
        $urls = $this->build_scan_urls($sample_pages);

        // 3 — HTTP-scan each URL as an anonymous visitor
        $http_results = [];
        foreach ($urls as $url_info) {
            $result               = $this->scan_url($url_info['url']);
            $result['page_type']  = $url_info['type'];
            $result['page_label'] = $url_info['label'];
            $http_results[]       = $result;
        }

        // 4 — Collect JavaScript-reported cookies from the custom table
        $js_reports = $this->get_js_reports();

        // 5 — Merge HTTP and JS results, deduplicate
        $all_cookies = $this->merge_results($http_results, $js_reports);

        // 6 — Read Complianz configuration
        $complianz_config = $this->get_complianz_config();

        // 7 — Cross-reference with Complianz cookie descriptions
        foreach ($all_cookies as &$cookie) {
            $cookie = $this->enrich_with_complianz($cookie, $complianz_config);
        }
        unset($cookie);

        // 8 — Run compliance checks
        foreach ($all_cookies as &$cookie) {
            $cookie['compliance'] = MFManager_Cookie_Compliance::check_compliance(
                $cookie,
                $complianz_config
            );
        }
        unset($cookie);

        // 9 — Build final report
        $report = $this->build_report(
            $all_cookies,
            $sample_pages,
            $http_results,
            $js_reports,
            $complianz_config
        );

        // 10 — Persist locally for the admin UI
        update_option('mfmanager_cookie_last_scan', $report, false);

        return $report;
    }

    // ─────────────────────────────────────────────────────────────
    //  URL building
    // ─────────────────────────────────────────────────────────────

    /**
     * Build the list of URLs to scan.
     *
     * @param array $sample_pages Discovered sample pages.
     * @return array List of URL info arrays.
     */
    private function build_scan_urls($sample_pages)
    {
        $urls = [];

        // Always scan homepage
        $urls[] = [
            'url'   => home_url('/'),
            'type'  => 'homepage',
            'label' => 'Homepage',
        ];

        // Add one sample page per discovered content type
        foreach ($sample_pages as $type => $page) {
            if (empty($page['url'])) {
                continue;
            }
            // Skip homepage duplicates (some plugin-only discoveries fall back to /)
            if (rtrim($page['url'], '/') === rtrim(home_url('/'), '/')) {
                continue;
            }
            $urls[] = [
                'url'   => $page['url'],
                'type'  => $type,
                'label' => $page['content_type'] . ': ' . $page['title'],
            ];
        }

        // Add a random published page for broader coverage
        $exclude_ids = array_filter(array_column($sample_pages, 'post_id'));
        $random_page = get_posts([
            'post_type'   => 'page',
            'post_status' => 'publish',
            'numberposts' => 1,
            'orderby'     => 'rand',
            'exclude'     => $exclude_ids,
        ]);
        if (!empty($random_page)) {
            $urls[] = [
                'url'   => get_permalink($random_page[0]->ID),
                'type'  => 'random_page',
                'label' => 'Random page: ' . $random_page[0]->post_title,
            ];
        }

        return $urls;
    }

    // ─────────────────────────────────────────────────────────────
    //  HTTP scanning
    // ─────────────────────────────────────────────────────────────

    /**
     * Make an anonymous HTTP GET to a URL and capture cookies + third-party resources.
     *
     * @param string $url URL to scan.
     * @return array Scan result.
     */
    public function scan_url($url)
    {
        // Cache-busting query parameter
        $scan_url = add_query_arg('mfm_nocache', time(), $url);

        $response = wp_remote_get($scan_url, [
            'timeout'     => 30,
            'redirection' => 3,
            'cookies'     => [],            // no cookies = anonymous visitor
            'sslverify'   => false,         // same-server may have self-signed cert
            'headers'     => [
                'User-Agent'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language' => 'en-US,en;q=0.5',
            ],
        ]);

        $result = [
            'url'                    => $url,
            'status'                 => 'error',
            'cookies'                => [],
            'third_party_resources'  => [],
        ];

        if (is_wp_error($response)) {
            $result['error'] = $response->get_error_message();
            return $result;
        }

        $result['status']    = 'ok';
        $result['http_code'] = wp_remote_retrieve_response_code($response);

        // ── Parse Set-Cookie headers ──
        $headers = wp_remote_retrieve_headers($response);
        if (isset($headers['set-cookie'])) {
            $raw_cookies = is_array($headers['set-cookie'])
                ? $headers['set-cookie']
                : [$headers['set-cookie']];

            foreach ($raw_cookies as $raw) {
                $parsed = $this->parse_set_cookie_header($raw);
                if ($parsed) {
                    $parsed['detection']     = 'http_header';
                    $parsed['found_on']      = $url;
                    $parsed['is_third_party'] = !$this->is_same_domain(
                        $parsed['domain'] ?: $this->site_domain,
                        $this->site_domain
                    );
                    $parsed['from_https'] = (strpos($url, 'https://') === 0);
                    $result['cookies'][]  = $parsed;
                }
            }
        }

        // ── Parse HTML body for third-party resources ──
        $body = wp_remote_retrieve_body($response);
        if (!empty($body)) {
            $result['third_party_resources'] = $this->detect_third_party_resources($body);
        }

        return $result;
    }

    /**
     * Parse a raw Set-Cookie header into a structured array.
     *
     * @param string $header Raw Set-Cookie value.
     * @return array|null Parsed cookie or null if invalid.
     */
    private function parse_set_cookie_header($header)
    {
        $parts = explode(';', $header);
        $main  = explode('=', array_shift($parts), 2);
        $name  = trim($main[0]);

        if ($name === '') {
            return null;
        }

        $cookie = [
            'name'             => $name,
            'value_hash'       => md5(isset($main[1]) ? $main[1] : ''),
            'secure'           => false,
            'httponly'          => false,
            'samesite'         => null,
            'domain'           => null,
            'path'             => '/',
            'expires'          => null,
            'lifetime_seconds' => null,
        ];

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            $kv  = explode('=', $part, 2);
            $key = strtolower(trim($kv[0]));
            $val = isset($kv[1]) ? trim($kv[1]) : '';

            switch ($key) {
                case 'secure':
                    $cookie['secure'] = true;
                    break;
                case 'httponly':
                    $cookie['httponly'] = true;
                    break;
                case 'samesite':
                    $cookie['samesite'] = ucfirst(strtolower($val));
                    break;
                case 'domain':
                    $cookie['domain'] = ltrim($val, '.');
                    break;
                case 'path':
                    $cookie['path'] = $val;
                    break;
                case 'expires':
                    $cookie['expires'] = $val;
                    break;
                case 'max-age':
                    $cookie['lifetime_seconds'] = abs((int) $val);
                    break;
            }
        }

        // Derive lifetime from Expires when Max-Age is absent
        if (is_null($cookie['lifetime_seconds']) && $cookie['expires']) {
            $exp_time = strtotime($cookie['expires']);
            if ($exp_time !== false) {
                $cookie['lifetime_seconds'] = max(0, $exp_time - time());
            }
        }

        return $cookie;
    }

    // ─────────────────────────────────────────────────────────────
    //  HTML analysis
    // ─────────────────────────────────────────────────────────────

    /**
     * Detect third-party iframes, scripts, and inline tracking in HTML.
     *
     * These resources are likely to set cookies in a real browser but won't
     * appear as Set-Cookie headers in a server-side HTTP request.
     *
     * @param string $html Page HTML.
     * @return array Detected third-party resources.
     */
    private function detect_third_party_resources($html)
    {
        $resources = [];

        // ── Third-party iframes ──
        if (preg_match_all('/<iframe[^>]+src=["\']([^"\']+)["\'][^>]*>/i', $html, $matches)) {
            foreach ($matches[1] as $src) {
                $host = parse_url($src, PHP_URL_HOST);
                if ($host && !$this->is_same_domain($host, $this->site_domain)) {
                    $resources[] = [
                        'type'   => 'iframe',
                        'url'    => $src,
                        'domain' => $host,
                        'label'  => $this->identify_service($host),
                    ];
                }
            }
        }

        // ── Third-party scripts ──
        if (preg_match_all('/<script[^>]+src=["\']([^"\']+)["\'][^>]*>/i', $html, $matches)) {
            foreach ($matches[1] as $src) {
                $host = parse_url($src, PHP_URL_HOST);
                if ($host && !$this->is_same_domain($host, $this->site_domain)) {
                    $resources[] = [
                        'type'   => 'script',
                        'url'    => $src,
                        'domain' => $host,
                        'label'  => $this->identify_service($host),
                    ];
                }
            }
        }

        // ── Known inline tracking patterns ──
        $inline_patterns = [
            'google-analytics.com'    => 'Google Analytics',
            'googletagmanager.com'    => 'Google Tag Manager',
            'gtag('                   => 'Google gtag.js',
            'fbq('                    => 'Facebook Pixel',
            'hotjar.com'              => 'Hotjar',
            '_paq.push'               => 'Matomo / Piwik',
            'clarity.ms'              => 'Microsoft Clarity',
            'connect.facebook.net'    => 'Facebook SDK',
            'platform.twitter.com'    => 'Twitter / X',
            'snap.licdn.com'          => 'LinkedIn Insight Tag',
            'analytics.tiktok.com'    => 'TikTok Pixel',
            'maps.googleapis.com'     => 'Google Maps API',
            'js.hs-scripts.com'       => 'HubSpot',
            'cdn.amplitude.com'       => 'Amplitude',
        ];

        foreach ($inline_patterns as $pattern => $label) {
            if (stripos($html, $pattern) !== false) {
                $resources[] = [
                    'type'    => 'inline_tracking',
                    'pattern' => $pattern,
                    'label'   => $label,
                ];
            }
        }

        return $resources;
    }

    /**
     * Map a domain to a known service name.
     *
     * @param string $domain Domain to identify.
     * @return string Service label or the raw domain.
     */
    private function identify_service($domain)
    {
        $map = [
            'youtube.com'              => 'YouTube',
            'youtube-nocookie.com'     => 'YouTube (privacy mode)',
            'youtu.be'                 => 'YouTube',
            'vimeo.com'                => 'Vimeo',
            'player.vimeo.com'         => 'Vimeo',
            'maps.google.com'          => 'Google Maps',
            'maps.googleapis.com'      => 'Google Maps',
            'www.google.com'           => 'Google',
            'google-analytics.com'     => 'Google Analytics',
            'www.googletagmanager.com' => 'Google Tag Manager',
            'googletagmanager.com'     => 'Google Tag Manager',
            'connect.facebook.net'     => 'Facebook',
            'www.facebook.com'         => 'Facebook',
            'platform.twitter.com'     => 'Twitter / X',
            'cdn.linkedin.com'         => 'LinkedIn',
            'snap.licdn.com'           => 'LinkedIn',
            'js.hs-scripts.com'        => 'HubSpot',
            'js.hs-analytics.net'      => 'HubSpot',
            'static.hotjar.com'        => 'Hotjar',
            'cdn.matomo.cloud'         => 'Matomo',
            'www.clarity.ms'           => 'Microsoft Clarity',
            'analytics.tiktok.com'     => 'TikTok',
            'open.spotify.com'         => 'Spotify',
            'w.soundcloud.com'         => 'SoundCloud',
        ];

        foreach ($map as $pattern => $label) {
            if ($domain === $pattern || substr($domain, -(strlen($pattern) + 1)) === '.' . $pattern) {
                return $label;
            }
        }

        return $domain;
    }

    /**
     * Check whether two domains are the same or subdomains of each other.
     *
     * @param string $d1 First domain.
     * @param string $d2 Second domain.
     * @return bool
     */
    private function is_same_domain($d1, $d2)
    {
        $d1 = strtolower(preg_replace('/^www\./', '', $d1));
        $d2 = strtolower(preg_replace('/^www\./', '', $d2));

        return $d1 === $d2
            || substr($d1, -(strlen($d2) + 1)) === '.' . $d2
            || substr($d2, -(strlen($d1) + 1)) === '.' . $d1;
    }

    // ─────────────────────────────────────────────────────────────
    //  JavaScript report aggregation
    // ─────────────────────────────────────────────────────────────

    /**
     * Retrieve and aggregate JS-reported cookies.
     *
     * The front-end cookie-monitor.js writes cookies directly to the
     * custom mfm_cookies table. This method reads JS-detected cookies
     * from that table for merging with HTTP scan results.
     *
     * @return array Aggregated JS cookie data.
     */
    private function get_js_reports()
    {
        global $wpdb;
        $table = $wpdb->prefix . 'mfm_cookies';

        // Check table exists
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table)) !== $table) {
            return [];
        }

        $rows = $wpdb->get_results(
            "SELECT cookie_name, category, source, description, detection,
                    pages_seen_on, times_seen, seen_without_consent, seen_essential_only
             FROM {$table}
             WHERE detection = 'javascript'
             ORDER BY cookie_name ASC",
            ARRAY_A
        );

        if (empty($rows)) {
            return [];
        }

        $aggregated = [];
        foreach ($rows as $row) {
            $pages = isset($row['pages_seen_on']) ? explode(',', $row['pages_seen_on']) : [];

            $aggregated[] = [
                'name'                     => $row['cookie_name'],
                'detection'                => 'javascript',
                'pages_seen_on'            => $pages,
                'times_seen'               => (int) $row['times_seen'],
                'seen_without_consent'     => !empty($row['seen_without_consent']),
                'seen_with_essential_only' => !empty($row['seen_essential_only']),
                'seen_logged_in'           => false,
                'seen_logged_out'          => true,
            ];
        }

        return $aggregated;
    }

    // ─────────────────────────────────────────────────────────────
    //  Complianz configuration reader
    // ─────────────────────────────────────────────────────────────

    /**
     * Read the Complianz plugin configuration from the database.
     *
     * Works with both Complianz free and premium. Falls back gracefully
     * when Complianz is not installed.
     *
     * @return array Complianz configuration.
     */
    public function get_complianz_config()
    {
        global $wpdb;

        $config = [
            'installed'   => false,
            'cookies'     => [],
            'services'    => [],
            'settings'    => [],
            'banner'      => [],
            'config_hash' => null,
        ];

        // Check if Complianz is active
        $active_plugins = get_option('active_plugins', []);
        $has_complianz  = false;
        foreach ($active_plugins as $plugin) {
            if (strpos($plugin, 'complianz') !== false) {
                $has_complianz = true;
                break;
            }
        }

        if (!$has_complianz) {
            return $config;
        }

        $config['installed'] = true;

        // Main options
        $cmplz_options = get_option('cmplz_options', []);
        if (!empty($cmplz_options)) {
            $config['settings'] = is_array($cmplz_options) ? $cmplz_options : [];
        }

        // Cookie declarations from Complianz tables
        $cookies_table = $wpdb->prefix . 'cmplz_cookies';
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $cookies_table)) === $cookies_table) {
            $cookies = $wpdb->get_results("SELECT * FROM `{$cookies_table}`", ARRAY_A);
            if ($cookies) {
                $config['cookies'] = $cookies;
            }
        }

        // Declared services
        $services_table = $wpdb->prefix . 'cmplz_services';
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $services_table)) === $services_table) {
            $services = $wpdb->get_results("SELECT * FROM `{$services_table}`", ARRAY_A);
            if ($services) {
                $config['services'] = $services;
            }
        }

        // Banner settings
        $banners_table = $wpdb->prefix . 'cmplz_cookiebanners';
        if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $banners_table)) === $banners_table) {
            $banners = $wpdb->get_results("SELECT * FROM `{$banners_table}`", ARRAY_A);
            if ($banners) {
                $config['banner'] = $banners;
            }
        }

        // Hash for change detection (used by central server for staging diffs)
        $config['config_hash'] = hash('sha256', wp_json_encode([
            $config['cookies'],
            $config['services'],
            $config['settings'],
        ]));

        return $config;
    }

    // ─────────────────────────────────────────────────────────────
    //  Complianz cross-referencing
    // ─────────────────────────────────────────────────────────────

    /**
     * Enrich a cookie with Complianz's own description, purpose, and category.
     *
     * When Complianz declares a cookie, it provides a human-readable description
     * and a purpose/category. We attach these directly to the cookie so the
     * CodeIgniter dashboard can show them alongside our own classification.
     *
     * @param array $cookie         Cookie data.
     * @param array $complianz_config Complianz configuration.
     * @return array Enriched cookie.
     */
    private function enrich_with_complianz($cookie, $complianz_config)
    {
        $cookie['complianz_declared'] = false;
        $cookie['complianz_description'] = null;
        $cookie['complianz_purpose'] = null;
        $cookie['complianz_category'] = null;
        $cookie['complianz_service'] = null;

        if (empty($complianz_config['installed']) || empty($complianz_config['cookies'])) {
            return $cookie;
        }

        $name = isset($cookie['name']) ? $cookie['name'] : '';

        foreach ($complianz_config['cookies'] as $declared) {
            $declared_name = '';
            if (isset($declared['name'])) {
                $declared_name = $declared['name'];
            } elseif (isset($declared['cookie_name'])) {
                $declared_name = $declared['cookie_name'];
            }
            if (empty($declared_name)) {
                continue;
            }

            $matched = false;
            if ($declared_name === $name) {
                $matched = true;
            } elseif (strpos($declared_name, '*') !== false) {
                $regex = '/^' . str_replace('\\*', '.*', preg_quote($declared_name, '/')) . '$/';
                $matched = (bool) preg_match($regex, $name);
            }

            if ($matched) {
                $cookie['complianz_declared'] = true;
                $cookie['complianz_description'] = isset($declared['purpose']) ? $declared['purpose'] : null;
                if (empty($cookie['complianz_description'])) {
                    $cookie['complianz_description'] = isset($declared['cookieFunction']) ? $declared['cookieFunction'] : null;
                }
                $cookie['complianz_purpose'] = isset($declared['purpose']) ? $declared['purpose'] : null;
                $cookie['complianz_category'] = isset($declared['service']) ? $declared['service'] : null;
                if (empty($cookie['complianz_category'])) {
                    $cookie['complianz_category'] = isset($declared['category']) ? $declared['category'] : null;
                }
                // Resolve service name from services list
                if (isset($declared['serviceID']) && !empty($complianz_config['services'])) {
                    foreach ($complianz_config['services'] as $svc) {
                        if (isset($svc['ID']) && $svc['ID'] == $declared['serviceID']) {
                            $cookie['complianz_service'] = isset($svc['name']) ? $svc['name'] : null;
                            break;
                        }
                    }
                }
                if (empty($cookie['complianz_service']) && isset($declared['service'])) {
                    $cookie['complianz_service'] = $declared['service'];
                }
                break;
            }
        }

        return $cookie;
    }

    // ─────────────────────────────────────────────────────────────
    //  Result merging
    // ─────────────────────────────────────────────────────────────

    /**
     * Merge HTTP-detected cookies with JS-reported cookies into a unified list.
     *
     * When the same cookie name appears in both, flags from JS (consent
     * violations, pages seen, etc.) are merged into the HTTP record.
     *
     * @param array $http_results Results from scan_url() calls.
     * @param array $js_reports   Aggregated JS reports.
     * @return array Unified cookie list.
     */
    private function merge_results($http_results, $js_reports)
    {
        $cookies    = [];
        $seen_names = [];

        // ── HTTP-detected cookies ──
        foreach ($http_results as $result) {
            foreach ($result['cookies'] as $cookie) {
                $name = $cookie['name'];
                if (!isset($seen_names[$name])) {
                    $cookie['classification'] = $this->classify_frontend_backend($cookie, $result);
                    $cookies[]                = $cookie;
                    $seen_names[$name]        = count($cookies) - 1;
                } else {
                    // Already seen on another page — merge found_on
                    $idx = $seen_names[$name];
                    $existing = $cookies[$idx]['found_on'];
                    if (is_string($existing)) {
                        $cookies[$idx]['found_on'] = [$existing, $cookie['found_on']];
                    } elseif (is_array($existing) && !in_array($cookie['found_on'], $existing, true)) {
                        $cookies[$idx]['found_on'][] = $cookie['found_on'];
                    }
                }
            }
        }

        // ── JS-reported cookies ──
        foreach ($js_reports as $js_cookie) {
            $name = $js_cookie['name'];
            if (!isset($seen_names[$name])) {
                // New cookie only seen by JS
                $js_cookie['classification'] = 'frontend'; // JS always runs on front-end
                $js_cookie['found_on']       = isset($js_cookie['pages_seen_on']) ? $js_cookie['pages_seen_on'] : ['/'];

                if (!empty($js_cookie['seen_without_consent'])) {
                    $js_cookie['set_before_consent'] = true;
                }
                if (!empty($js_cookie['seen_with_essential_only'])) {
                    $js_cookie['consent_was_essential_only'] = true;
                }

                $cookies[]             = $js_cookie;
                $seen_names[$name]     = count($cookies) - 1;
            } else {
                // Merge JS signals into existing HTTP-detected cookie
                $idx = $seen_names[$name];
                $cookies[$idx]['also_detected_by_js'] = true;

                if (!empty($js_cookie['seen_without_consent'])) {
                    $cookies[$idx]['set_before_consent'] = true;
                }
                if (!empty($js_cookie['seen_with_essential_only'])) {
                    $cookies[$idx]['consent_was_essential_only'] = true;
                }
                if (!empty($js_cookie['pages_seen_on'])) {
                    $cookies[$idx]['js_pages'] = $js_cookie['pages_seen_on'];
                }
            }
        }

        return $cookies;
    }

    /**
     * Classify a cookie as front-end or back-end.
     *
     * Cookies found during an anonymous HTTP scan of a front-end page are
     * front-end — unless they match a known back-end-only pattern.
     *
     * @param array $cookie      Parsed cookie.
     * @param array $scan_result Scan context.
     * @return string 'frontend', 'backend', or 'unknown'.
     */
    private function classify_frontend_backend($cookie, $scan_result)
    {
        // Known back-end-only cookies (should never appear on anonymous front-end)
        $backend_patterns = [
            '/^wordpress_logged_in_/',
            '/^wordpress_sec_/',
            '/^wp-settings-time-/',
            '/^wp-settings-\d/',
        ];

        foreach ($backend_patterns as $pattern) {
            if (preg_match($pattern, $cookie['name'])) {
                return 'backend';
            }
        }

        // Came from a front-end page scan → front-end
        $frontend_types = [
            'homepage', 'random_page',
            'google_maps', 'youtube', 'vimeo', 'recaptcha',
            'facebook_embed', 'twitter_embed', 'instagram_embed',
            'tiktok_embed', 'spotify_embed', 'soundcloud_embed',
            'hubspot', 'woocommerce',
        ];

        if (in_array($scan_result['page_type'] ?? '', $frontend_types, true)) {
            return 'frontend';
        }

        return 'unknown';
    }

    // ─────────────────────────────────────────────────────────────
    //  Report building
    // ─────────────────────────────────────────────────────────────

    /**
     * Assemble the final scan report.
     *
     * @param array $cookies         Unified cookie list with compliance data.
     * @param array $sample_pages    Discovered sample pages.
     * @param array $http_results    Raw HTTP scan results.
     * @param array $js_reports      Aggregated JS reports.
     * @param array $complianz_config Complianz config snapshot.
     * @return array Complete report.
     */
    private function build_report($cookies, $sample_pages, $http_results, $js_reports, $complianz_config)
    {
        $frontend_cookies = array_filter($cookies, function ($c) {
            return ($c['classification'] ?? 'unknown') === 'frontend';
        });

        $violations = 0;
        $warnings   = 0;
        $compliant  = 0;

        foreach ($cookies as $cookie) {
            $status = isset($cookie['compliance']['status']) ? $cookie['compliance']['status'] : 'unknown';
            if ($status === 'violation') {
                $violations++;
            } elseif ($status === 'warning') {
                $warnings++;
            } elseif ($status === 'compliant') {
                $compliant++;
            }
        }

        // Collect third-party resources across all pages
        $third_party = [];
        foreach ($http_results as $result) {
            foreach (($result['third_party_resources'] ?? []) as $resource) {
                $key = ($resource['domain'] ?? $resource['pattern'] ?? '') . '|' . ($resource['label'] ?? '');
                if (!isset($third_party[$key])) {
                    $third_party[$key]             = $resource;
                    $third_party[$key]['found_on']  = [$result['url']];
                } else {
                    if (!in_array($result['url'], $third_party[$key]['found_on'], true)) {
                        $third_party[$key]['found_on'][] = $result['url'];
                    }
                }
            }
        }

        // Build consent violation list for dedicated card on CodeIgniter side
        $consent_violations = [];
        foreach ($cookies as $cookie) {
            $issues = isset($cookie['compliance']['issues']) ? $cookie['compliance']['issues'] : [];
            foreach ($issues as $issue) {
                if (in_array($issue['rule'], ['cookies_before_consent', 'consent_ignored'], true)) {
                    $consent_violations[] = [
                        'cookie_name'  => $cookie['name'],
                        'rule'         => $issue['rule'],
                        'severity'     => $issue['severity'],
                        'detail'       => $issue['detail'],
                        'found_on'     => $cookie['found_on'] ?? null,
                        'source'       => $cookie['compliance']['source'] ?? 'Unknown',
                        'category'     => $cookie['compliance']['category'] ?? 'unknown',
                    ];
                    break; // one entry per cookie
                }
            }
        }

        return [
            'scan_date'              => current_time('mysql'),
            'site_url'               => $this->site_url,
            'cookies'                => $cookies,
            'consent_violations'     => $consent_violations,
            'sample_pages'           => $sample_pages,
            'third_party_resources'  => array_values($third_party),
            'complianz'              => $complianz_config,
            'js_reports_processed'   => count($js_reports),
            'pages_scanned'          => count($http_results),
            'summary'                => [
                'total_cookies'         => count($cookies),
                'frontend_cookies'      => count($frontend_cookies),
                'backend_cookies'       => count($cookies) - count($frontend_cookies),
                'compliant'             => $compliant,
                'warnings'              => $warnings,
                'violations'            => $violations,
                'consent_violations'    => count($consent_violations),
                'third_party_services'  => count($third_party),
                'complianz_installed'   => $complianz_config['installed'],
                'complianz_config_hash' => $complianz_config['config_hash'] ?? null,
            ],
        ];
    }
}
