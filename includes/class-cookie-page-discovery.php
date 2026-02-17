<?php

/**
 * Cookie Page Discovery
 *
 * Discovers published pages/posts containing embeds and third-party content
 * that trigger cookies only when that specific page is visited (Google Maps,
 * YouTube, Vimeo, reCAPTCHA / Contact Form 7, etc.).
 *
 * Stores one sample page per content type in wp_options so the cookie scanner
 * can test them during its daily cron.
 *
 * @package MFManager
 * @since   9.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Cookie_Page_Discovery
{
    /**
     * Content types that may set cookies only when their page is visited.
     *
     * Each entry contains:
     *   label           – Human-readable name
     *   patterns        – Strings to search for in post_content (LIKE %pattern%)
     *   plugin_slugs    – Active plugin slugs that indicate this content exists
     *   expected_cookies – Cookie names commonly set by this content
     */
    private $content_types = [
        'google_maps' => [
            'label'    => 'Google Maps',
            'patterns' => [
                'maps.google.com',
                'google.com/maps',
                'maps.googleapis.com',
                'www.google.com/maps',
                '[wpgmza',
                'wp-block-jetstyle-map',
                'data-google-maps',
                'class="gmap',
                'wp:google-maps',
            ],
            'plugin_slugs'    => ['wp-google-maps', 'maps-widget-google-maps', 'jetstyle-google-maps'],
            'expected_cookies' => ['NID', '1P_JAR', 'CONSENT', 'SIDCC', 'ANID'],
        ],
        'youtube' => [
            'label'    => 'YouTube',
            'patterns' => [
                'youtube.com/embed',
                'youtube.com/watch',
                'youtu.be/',
                'youtube-nocookie.com',
                'wp-block-embed-youtube',
                '[youtube',
                'wp:core-embed/youtube',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => ['YSC', 'VISITOR_INFO1_LIVE', 'GPS', 'PREF', 'IDE'],
        ],
        'vimeo' => [
            'label'    => 'Vimeo',
            'patterns' => [
                'player.vimeo.com',
                'vimeo.com/video',
                'wp-block-embed-vimeo',
                '[vimeo',
                'wp:core-embed/vimeo',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => ['vuid', 'player'],
        ],
        'recaptcha' => [
            'label'    => 'reCAPTCHA (Contact Forms)',
            'patterns' => [
                '[contact-form-7',
                '[contact-form',
                'g-recaptcha',
                'google.com/recaptcha',
                'grecaptcha',
                '[gravityform',
                '[wpforms',
                '[ninja_form',
                'elementor-form',
                'class="wpcf7',
            ],
            'plugin_slugs'    => [
                'contact-form-7',
                'gravityforms',
                'wpforms-lite', 'wpforms',
                'ninja-forms',
                'formidable',
                'google-captcha',
            ],
            'expected_cookies' => ['_GRECAPTCHA'],
        ],
        'facebook_embed' => [
            'label'    => 'Facebook Embed',
            'patterns' => [
                'facebook.com/plugins',
                'facebook.com/video',
                'fb-video',
                'fb-page',
                'fb-post',
                'connect.facebook.net',
                'wp:core-embed/facebook',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => ['fr', '_fbp', '_fbc'],
        ],
        'twitter_embed' => [
            'label'    => 'Twitter/X Embed',
            'patterns' => [
                'platform.twitter.com',
                'twitter-timeline',
                'twitter-tweet',
                'wp:core-embed/twitter',
                'twitter.com/intent',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => [],
        ],
        'instagram_embed' => [
            'label'    => 'Instagram Embed',
            'patterns' => [
                'instagram.com/embed',
                'instagram.com/p/',
                'wp:core-embed/instagram',
                'instagr.am',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => [],
        ],
        'tiktok_embed' => [
            'label'    => 'TikTok Embed',
            'patterns' => [
                'tiktok.com/embed',
                'tiktok.com/@',
                'wp:core-embed/tiktok',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => ['_tt_enable_cookie', '_ttp'],
        ],
        'spotify_embed' => [
            'label'    => 'Spotify Embed',
            'patterns' => [
                'open.spotify.com/embed',
                'spotify.com/embed',
                'wp:core-embed/spotify',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => [],
        ],
        'soundcloud_embed' => [
            'label'    => 'SoundCloud Embed',
            'patterns' => [
                'soundcloud.com/player',
                'w.soundcloud.com',
                'wp:core-embed/soundcloud',
                '[soundcloud',
            ],
            'plugin_slugs'    => [],
            'expected_cookies' => [],
        ],
        'hubspot' => [
            'label'    => 'HubSpot',
            'patterns' => [
                'js.hs-scripts.com',
                'js.hs-analytics.net',
                'hbspt.forms.create',
                'hubspot-form',
            ],
            'plugin_slugs'    => ['leadin', 'hubspot-all-in-one-marketing'],
            'expected_cookies' => ['__hssc', '__hssrc', '__hstc', 'hubspotutk'],
        ],
        'woocommerce' => [
            'label'    => 'WooCommerce (Shop/Cart/Checkout)',
            'patterns' => [
                '[woocommerce_cart]',
                '[woocommerce_checkout]',
                '[woocommerce_my_account]',
                'wp:woocommerce/cart',
                'wp:woocommerce/checkout',
                'class="woocommerce',
            ],
            'plugin_slugs'    => ['woocommerce'],
            'expected_cookies' => ['woocommerce_cart_hash', 'woocommerce_items_in_cart', 'wp_woocommerce_session_'],
        ],
    ];

    /** @var int Cache duration for discovery results (7 days in seconds) */
    const CACHE_TTL = 604800;

    /**
     * Run page discovery and store results.
     *
     * Results are cached for 7 days since embed patterns in post content
     * rarely change. Use discover(true) to force a fresh scan.
     *
     * Uses a single SQL query with CASE WHEN to match all content types at
     * once, instead of running 12 separate queries. Only published posts/pages
     * are searched. The query is limited to the 2000 most recently modified
     * posts to avoid full-table scans on large sites.
     *
     * @param bool $force_refresh Bypass cache and run a fresh discovery.
     * @return array Discovered sample pages keyed by content type.
     */
    public function discover($force_refresh = false)
    {
        // Return cached results if still fresh
        if (!$force_refresh) {
            $cached = get_transient('mfmanager_cookie_discovery');
            if ($cached !== false && is_array($cached)) {
                return $cached;
            }
        }
        global $wpdb;

        $sample_pages   = [];
        $active_plugins = get_option('active_plugins', []);
        $active_slugs   = array_map(function ($p) {
            $parts = explode('/', $p);
            return sanitize_title($parts[0]);
        }, $active_plugins);

        // ── Build a single query that tags each row with its content type ──
        // For each content type we create a CASE WHEN clause that checks all
        // its patterns. The first match wins (ORDER BY + GROUP BY).
        $case_parts  = [];
        $like_clauses = [];

        foreach ($this->content_types as $type => $config) {
            $type_likes = [];
            foreach ($config['patterns'] as $pattern) {
                $escaped = '%' . $wpdb->esc_like($pattern) . '%';
                $type_likes[]  = $wpdb->prepare("post_content LIKE %s", $escaped);
                $like_clauses[] = $wpdb->prepare("post_content LIKE %s", $escaped);
            }
            // CASE WHEN (pattern1 OR pattern2 …) THEN 'type'
            $case_parts[] = sprintf(
                "WHEN (%s) THEN '%s'",
                implode(' OR ', $type_likes),
                esc_sql($type)
            );
        }

        if (empty($case_parts)) {
            update_option('mfmanager_cookie_sample_pages', $sample_pages, false);
            return $sample_pages;
        }

        // Limit to the 2000 most recently modified posts/pages to avoid
        // a full-table scan on large sites. Embeds on very old, unmodified
        // content are unlikely to change and will be caught on the next
        // cache refresh after they are edited.
        $sql = sprintf(
            "SELECT
                ID, post_title, post_name, post_type,
                CASE %s ELSE NULL END AS content_type_key
             FROM {$wpdb->posts}
             WHERE post_status = 'publish'
               AND post_type IN ('post', 'page')
               AND (%s)
             ORDER BY post_modified DESC, post_type ASC
             LIMIT 2000",
            implode(' ', $case_parts),
            implode(' OR ', array_unique($like_clauses))
        );

        $results = $wpdb->get_results($sql);

        // Pick the first (newest) match per content type
        $seen_types = [];
        foreach ($results as $row) {
            $type = $row->content_type_key;
            if ($type === null || isset($seen_types[$type])) {
                continue;
            }
            $seen_types[$type] = true;
            $config = $this->content_types[$type];

            $sample_pages[$type] = [
                'post_id'          => (int) $row->ID,
                'url'              => get_permalink($row->ID),
                'title'            => $row->post_title,
                'post_type'        => $row->post_type,
                'content_type'     => $config['label'],
                'expected_cookies' => $config['expected_cookies'],
                'discovered_at'    => current_time('mysql'),
                'match_method'     => 'content_search',
            ];
        }

        // ── Fallback: check active plugins for types with no content match ──
        foreach ($this->content_types as $type => $config) {
            if (isset($sample_pages[$type])) {
                continue; // Already found via content search
            }
            if (!empty($config['plugin_slugs'])) {
                $has_plugin = array_intersect($config['plugin_slugs'], $active_slugs);
                if (!empty($has_plugin)) {
                    $plugin_slug = reset($has_plugin);
                    $sample_pages[$type] = [
                        'post_id'          => 0,
                        'url'              => home_url('/'),
                        'title'            => '(homepage — plugin "' . $plugin_slug . '" active, no dedicated page found)',
                        'post_type'        => 'n/a',
                        'content_type'     => $config['label'],
                        'expected_cookies' => $config['expected_cookies'],
                        'discovered_at'    => current_time('mysql'),
                        'match_method'     => 'active_plugin',
                    ];
                }
            }
        }

        // Persist results and cache for 7 days
        update_option('mfmanager_cookie_sample_pages', $sample_pages, false);
        set_transient('mfmanager_cookie_discovery', $sample_pages, self::CACHE_TTL);

        return $sample_pages;
    }

    /**
     * Get previously discovered sample pages from the database.
     *
     * @return array
     */
    public function get_cached()
    {
        return get_option('mfmanager_cookie_sample_pages', []);
    }

    /**
     * Get the list of all content types this discovery checks for.
     *
     * @return array
     */
    public function get_content_types()
    {
        return $this->content_types;
    }
}
