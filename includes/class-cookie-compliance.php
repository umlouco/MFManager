<?php

/**
 * Cookie Compliance Engine
 *
 * Known cookie database and EU compliance rules.
 * Classifies cookies by category and checks against ePrivacy Directive,
 * GDPR, and EDPB/CNIL guidelines.
 *
 * @package MFManager
 * @since   9.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Cookie_Compliance
{
    /**
     * Known cookies organized by category.
     * Pattern can be an exact string or a regex (prefixed with /).
     */
    private static $known_cookies = [
        'essential' => [
            ['pattern' => '/^wordpress_logged_in_/',   'source' => 'WordPress',   'desc' => 'Authentication session'],
            ['pattern' => '/^wordpress_sec_/',          'source' => 'WordPress',   'desc' => 'Authentication (secure)'],
            ['pattern' => '/^wp-settings-/',            'source' => 'WordPress',   'desc' => 'Admin UI preferences'],
            ['pattern' => '/^wp-settings-time-/',       'source' => 'WordPress',   'desc' => 'Admin settings timestamp'],
            ['pattern' => 'wordpress_test_cookie',      'source' => 'WordPress',   'desc' => 'Cookie support test'],
            ['pattern' => 'PHPSESSID',                  'source' => 'PHP',         'desc' => 'Server session identifier'],
            ['pattern' => '/^wp_woocommerce_session_/', 'source' => 'WooCommerce', 'desc' => 'Customer session'],
            ['pattern' => 'woocommerce_cart_hash',      'source' => 'WooCommerce', 'desc' => 'Cart contents hash'],
            ['pattern' => 'woocommerce_items_in_cart',  'source' => 'WooCommerce', 'desc' => 'Cart item indicator'],
            ['pattern' => '/^wc_cart_hash/',             'source' => 'WooCommerce', 'desc' => 'Cart hash'],
            ['pattern' => '/^wc_fragments_/',            'source' => 'WooCommerce', 'desc' => 'Ajax cart fragments cache'],
            ['pattern' => '/^comment_author_/',          'source' => 'WordPress',   'desc' => 'Comment form autofill'],
        ],
        'functional' => [
            ['pattern' => '/^cmplz_/',          'source' => 'Complianz',            'desc' => 'Cookie consent state'],
            ['pattern' => '/^complianz/',       'source' => 'Complianz',            'desc' => 'Cookie consent'],
            ['pattern' => '/^cookielawinfo/',   'source' => 'GDPR Cookie Consent',  'desc' => 'Consent preferences'],
            ['pattern' => 'moove_gdpr_popup',   'source' => 'Moove GDPR',           'desc' => 'Consent popup state'],
            ['pattern' => '/^borlabs-cookie/',  'source' => 'Borlabs Cookie',       'desc' => 'Consent preferences'],
            ['pattern' => 'viewed_cookie_policy', 'source' => 'GDPR Cookie Consent', 'desc' => 'Banner dismissed'],
            ['pattern' => 'pll_language',       'source' => 'Polylang',             'desc' => 'Language preference'],
            ['pattern' => '/^qtrans_/',         'source' => 'qTranslate',           'desc' => 'Language preference'],
            ['pattern' => 'icl_current_language', 'source' => 'WPML',              'desc' => 'Language preference'],
            ['pattern' => 'wp-wpml_current_language', 'source' => 'WPML',          'desc' => 'Language preference'],
            ['pattern' => '/^tk_/',             'source' => 'Jetpack',              'desc' => 'Tracking opt-out'],
        ],
        'analytics' => [
            ['pattern' => '/^_ga$/',    'source' => 'Google Analytics',         'desc' => 'User distinction',              'lifetime' => '2 years'],
            ['pattern' => '/^_ga_/',    'source' => 'Google Analytics 4',       'desc' => 'Session state',                 'lifetime' => '2 years'],
            ['pattern' => '_gid',       'source' => 'Google Analytics',         'desc' => 'User distinction (24h)',        'lifetime' => '24 hours'],
            ['pattern' => '/^_gat/',    'source' => 'Google Analytics',         'desc' => 'Request rate throttling',       'lifetime' => '1 minute'],
            ['pattern' => '/^__utm/',   'source' => 'Google Analytics (legacy)','desc' => 'Campaign/session tracking',     'lifetime' => 'varies'],
            ['pattern' => '/^_pk_id/',  'source' => 'Matomo',                   'desc' => 'Visitor ID',                    'lifetime' => '13 months'],
            ['pattern' => '/^_pk_ses/', 'source' => 'Matomo',                   'desc' => 'Session tracking',              'lifetime' => '30 minutes'],
            ['pattern' => '/^_pk_ref/', 'source' => 'Matomo',                   'desc' => 'Referral attribution',          'lifetime' => '6 months'],
            ['pattern' => '/^_hj/',     'source' => 'Hotjar',                   'desc' => 'Session analytics/heatmaps',    'lifetime' => '1 year'],
            ['pattern' => '_clck',      'source' => 'Microsoft Clarity',        'desc' => 'Visitor ID',                    'lifetime' => '1 year'],
            ['pattern' => '_clsk',      'source' => 'Microsoft Clarity',        'desc' => 'Session aggregation',           'lifetime' => '1 day'],
            ['pattern' => 'ai_user',    'source' => 'Azure App Insights',       'desc' => 'User tracking',                 'lifetime' => '1 year'],
            ['pattern' => 'ai_session', 'source' => 'Azure App Insights',       'desc' => 'Session tracking',              'lifetime' => '30 minutes'],
        ],
        'marketing' => [
            ['pattern' => '_fbp',             'source' => 'Facebook Pixel',       'desc' => 'Browser identification',       'lifetime' => '3 months'],
            ['pattern' => '_fbc',             'source' => 'Facebook',             'desc' => 'Click identifier',             'lifetime' => '3 months'],
            ['pattern' => '_gcl_au',          'source' => 'Google Ads',           'desc' => 'Conversion linker',            'lifetime' => '3 months'],
            ['pattern' => '_gcl_aw',          'source' => 'Google Ads',           'desc' => 'Ad click identifier',          'lifetime' => '3 months'],
            ['pattern' => 'IDE',              'source' => 'DoubleClick/Google',   'desc' => 'Ad serving and retargeting',   'lifetime' => '1 year'],
            ['pattern' => 'DSID',             'source' => 'DoubleClick/Google',   'desc' => 'Ad synchronization',           'lifetime' => '2 weeks'],
            ['pattern' => 'test_cookie',      'source' => 'DoubleClick/Google',   'desc' => 'Cookie support check',         'lifetime' => '15 minutes'],
            ['pattern' => 'fr',               'source' => 'Facebook',             'desc' => 'Ad delivery/measurement',      'lifetime' => '3 months'],
            ['pattern' => '_pin_unauth',      'source' => 'Pinterest',            'desc' => 'User tracking',                'lifetime' => '1 year'],
            ['pattern' => 'li_sugr',          'source' => 'LinkedIn',             'desc' => 'Browser identification',       'lifetime' => '3 months'],
            ['pattern' => 'bcookie',          'source' => 'LinkedIn',             'desc' => 'Browser identifier',           'lifetime' => '1 year'],
            ['pattern' => 'lidc',             'source' => 'LinkedIn',             'desc' => 'Data center routing',          'lifetime' => '1 day'],
            ['pattern' => '_tt_enable_cookie','source' => 'TikTok',              'desc' => 'Cookie support check',          'lifetime' => '13 months'],
            ['pattern' => '_ttp',             'source' => 'TikTok',              'desc' => 'Visitor tracking',              'lifetime' => '13 months'],
            ['pattern' => 'YSC',              'source' => 'YouTube',             'desc' => 'Video session tracking',        'lifetime' => 'session'],
            ['pattern' => 'VISITOR_INFO1_LIVE','source' => 'YouTube',            'desc' => 'Bandwidth estimation',          'lifetime' => '6 months'],
            ['pattern' => 'GPS',              'source' => 'YouTube',             'desc' => 'Geolocation on mobile',         'lifetime' => '30 minutes'],
            ['pattern' => 'PREF',             'source' => 'YouTube/Google',      'desc' => 'User preferences',              'lifetime' => '2 years'],
            ['pattern' => 'vuid',             'source' => 'Vimeo',              'desc' => 'Viewer analytics',               'lifetime' => '2 years'],
            ['pattern' => 'player',           'source' => 'Vimeo',              'desc' => 'Video player settings',          'lifetime' => '1 year'],
            ['pattern' => 'NID',              'source' => 'Google',              'desc' => 'Ad preferences/personalization', 'lifetime' => '6 months'],
            ['pattern' => '1P_JAR',           'source' => 'Google',              'desc' => 'Ad optimization',               'lifetime' => '1 month'],
            ['pattern' => 'CONSENT',          'source' => 'Google',              'desc' => 'Google consent state',           'lifetime' => '20 years'],
            ['pattern' => 'ANID',             'source' => 'Google',              'desc' => 'Advertising identifier',         'lifetime' => '2 years'],
            ['pattern' => '_GRECAPTCHA',      'source' => 'Google reCAPTCHA',    'desc' => 'Bot protection risk analysis',   'lifetime' => '6 months'],
            ['pattern' => 'SIDCC',            'source' => 'Google',              'desc' => 'Security cookie',                'lifetime' => '1 year'],
            ['pattern' => '/^__Secure-/',     'source' => 'Google',              'desc' => 'Secure authentication',          'lifetime' => '2 years'],
        ],
    ];

    /**
     * Classify a cookie name into a category.
     *
     * @param string $cookie_name Cookie name to classify.
     * @return array Category info: category, source, description, lifetime.
     */
    public static function classify($cookie_name)
    {
        foreach (self::$known_cookies as $category => $cookies) {
            foreach ($cookies as $entry) {
                if (self::matches($cookie_name, $entry['pattern'])) {
                    return [
                        'category'    => $category,
                        'source'      => $entry['source'],
                        'description' => $entry['desc'],
                        'lifetime'    => isset($entry['lifetime']) ? $entry['lifetime'] : null,
                    ];
                }
            }
        }
        return [
            'category'    => 'unknown',
            'source'      => 'Unknown',
            'description' => 'Unrecognized cookie — manual review needed',
            'lifetime'    => null,
        ];
    }

    /**
     * Match a cookie name against an exact string or regex pattern.
     *
     * @param string $name    Cookie name.
     * @param string $pattern Exact string or regex (starts with /).
     * @return bool
     */
    private static function matches($name, $pattern)
    {
        if ($pattern[0] === '/') {
            return (bool) preg_match($pattern, $name);
        }
        return $name === $pattern;
    }

    /**
     * Check if a cookie is strictly necessary (no consent required).
     *
     * @param string $cookie_name Cookie name.
     * @return bool
     */
    public static function is_essential($cookie_name)
    {
        $info = self::classify($cookie_name);
        return in_array($info['category'], ['essential', 'functional'], true);
    }

    /**
     * Check EU compliance for a single cookie.
     *
     * Applies rules from ePrivacy Directive, GDPR, and EDPB/CNIL guidelines.
     *
     * @param array      $cookie          Cookie data array.
     * @param array|null $complianz_config Complianz configuration (if available).
     * @return array Compliance result: status, category, source, issues.
     */
    public static function check_compliance($cookie, $complianz_config = null)
    {
        $issues = [];
        $name = isset($cookie['name']) ? $cookie['name'] : '';
        $info = self::classify($name);
        $is_essential = in_array($info['category'], ['essential', 'functional'], true);

        // ── Rule 1: Non-essential cookie set before/without consent ──
        // ePrivacy Directive Art. 5(3), GDPR Art. 7
        if (!$is_essential && !empty($cookie['set_before_consent'])) {
            $issues[] = [
                'severity' => 'violation',
                'rule'     => 'cookies_before_consent',
                'detail'   => 'Non-essential cookie set without user consent (ePrivacy Art. 5(3), GDPR Art. 7)',
            ];
        }

        // ── Rule 2: Cookie set despite user choosing essential-only ──
        // GDPR Art. 7 — consent must be respected
        if (!$is_essential && !empty($cookie['consent_was_essential_only'])) {
            $issues[] = [
                'severity' => 'violation',
                'rule'     => 'consent_ignored',
                'detail'   => 'Non-essential cookie active despite user choosing essential-only consent (GDPR Art. 7)',
            ];
        }

        // ── Rule 3: Cookie lifetime exceeds 13 months ──
        // EDPB Guidelines 2/2023 + CNIL recommendation
        if (!$is_essential && isset($cookie['lifetime_seconds']) && $cookie['lifetime_seconds'] > 0) {
            $thirteen_months = 13 * 30 * 86400; // ~390 days
            if ($cookie['lifetime_seconds'] > $thirteen_months) {
                $issues[] = [
                    'severity' => 'warning',
                    'rule'     => 'excessive_lifetime',
                    'detail'   => sprintf(
                        'Cookie lifetime (%d days) exceeds EDPB recommended maximum of 13 months',
                        round($cookie['lifetime_seconds'] / 86400)
                    ),
                ];
            }
        }

        // ── Rule 4: Not declared in consent banner ──
        // GDPR Art. 13 — transparency obligation
        if ($complianz_config && !empty($complianz_config['installed']) && !$is_essential) {
            $declared = self::is_declared_in_complianz($name, $complianz_config);
            if (!$declared) {
                $issues[] = [
                    'severity' => 'warning',
                    'rule'     => 'undeclared_cookie',
                    'detail'   => 'Cookie not declared in Complianz cookie consent banner (GDPR Art. 13)',
                ];
            }
        }

        // ── Rule 5: Missing Secure flag on HTTPS site ──
        // GDPR Art. 32 — appropriate security measures
        if (!$is_essential && !empty($cookie['from_https']) && empty($cookie['secure'])) {
            $issues[] = [
                'severity' => 'warning',
                'rule'     => 'missing_secure_flag',
                'detail'   => 'Cookie served over HTTPS without Secure flag (GDPR Art. 32)',
            ];
        }

        // ── Rule 6: Undeclared third-party cookie ──
        // GDPR Art. 13-14 — third party data sharing disclosure
        if (!$is_essential && !empty($cookie['is_third_party'])) {
            $declared = false;
            if ($complianz_config && !empty($complianz_config['installed'])) {
                $declared = self::is_declared_in_complianz($name, $complianz_config);
            }
            if (!$declared) {
                $issues[] = [
                    'severity' => 'warning',
                    'rule'     => 'undeclared_third_party',
                    'detail'   => sprintf(
                        'Third-party cookie from %s not declared in consent banner (GDPR Art. 13-14)',
                        isset($cookie['domain']) ? $cookie['domain'] : 'unknown domain'
                    ),
                ];
            }
        }

        // ── Rule 7: Completely unrecognized cookie ──
        if ($info['category'] === 'unknown') {
            $issues[] = [
                'severity' => 'warning',
                'rule'     => 'unrecognized_cookie',
                'detail'   => 'Cookie not in known database — manual review recommended',
            ];
        }

        // Determine overall status
        $status = 'compliant';
        foreach ($issues as $issue) {
            if ($issue['severity'] === 'violation') {
                $status = 'violation';
                break;
            }
            if ($issue['severity'] === 'warning') {
                $status = 'warning';
            }
        }

        return [
            'status'      => $status,
            'category'    => $info['category'],
            'source'      => $info['source'],
            'description' => $info['description'],
            'issues'      => $issues,
        ];
    }

    /**
     * Check if a cookie is declared in the Complianz configuration.
     *
     * Supports exact match and Complianz wildcard (*) patterns.
     *
     * @param string $cookie_name Cookie name.
     * @param array  $config      Complianz config array.
     * @return bool
     */
    private static function is_declared_in_complianz($cookie_name, $config)
    {
        if (empty($config['cookies'])) {
            return false;
        }

        foreach ($config['cookies'] as $declared) {
            // Complianz stores cookie name in 'name' or 'cookie_name' depending on version
            $declared_name = '';
            if (isset($declared['name'])) {
                $declared_name = $declared['name'];
            } elseif (isset($declared['cookie_name'])) {
                $declared_name = $declared['cookie_name'];
            }
            if (empty($declared_name)) {
                continue;
            }

            // Exact match
            if ($declared_name === $cookie_name) {
                return true;
            }

            // Wildcard match (Complianz uses * as wildcard)
            if (strpos($declared_name, '*') !== false) {
                $regex = '/^' . str_replace('\\*', '.*', preg_quote($declared_name, '/')) . '$/';
                if (preg_match($regex, $cookie_name)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get all known cookies for reference/display.
     *
     * @return array
     */
    public static function get_known_cookies()
    {
        return self::$known_cookies;
    }
}
