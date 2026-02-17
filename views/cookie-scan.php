<?php
/**
 * Cookie Compliance Scan — Admin View
 *
 * Displayed under MF Manager > Cookie Scan in the WordPress admin.
 * Expects: $last_scan, $sample_pages (set by the page callback in main.php).
 *
 * @package MFManager
 * @since   9.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1>Cookie Compliance Scan</h1>

    <form method="post" style="margin-bottom: 20px;">
        <?php wp_nonce_field('mfmanager_cookie_action', 'mfm_cookie_nonce'); ?>
        <input type="submit" name="run_cookie_scan" class="button button-primary" value="Run Full Cookie Scan">
        <input type="submit" name="run_page_discovery" class="button" value="Discover Pages Only">
    </form>

    <?php if (!empty($scan_message)) : ?>
        <div class="notice notice-<?php echo esc_attr($scan_message_type); ?> is-dismissible">
            <p><?php echo esc_html($scan_message); ?></p>
        </div>
    <?php endif; ?>

    <?php
    // ── JS reports pending ──
    $pending_js = get_option('mfmanager_cookie_js_reports', []);
    $pending_count = is_array($pending_js) ? count($pending_js) : 0;
    ?>
    <div class="card" style="max-width: 100%; margin-bottom: 20px; padding: 12px 20px;">
        <strong>Front-end JS monitor:</strong>
        <?php echo esc_html($pending_count); ?> cookie reports queued since last scan.
        <br><small>Reports are collected from real visitors and processed during the next scan.</small>
    </div>

    <?php // ── Discovered Sample Pages ── ?>
    <?php if (!empty($sample_pages)) : ?>
        <h2>Discovered Pages with Cookie-Setting Content</h2>
        <p class="description">One sample page per content type. These pages are scanned during each cookie scan.</p>
        <table class="widefat striped" style="margin-bottom: 30px;">
            <thead>
                <tr>
                    <th>Content Type</th>
                    <th>Page</th>
                    <th>Detection Method</th>
                    <th>Expected Cookies</th>
                    <th>Discovered</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($sample_pages as $type => $page) : ?>
                    <tr>
                        <td><strong><?php echo esc_html($page['content_type']); ?></strong></td>
                        <td>
                            <?php if (!empty($page['url'])) : ?>
                                <a href="<?php echo esc_url($page['url']); ?>" target="_blank" rel="noopener">
                                    <?php echo esc_html($page['title']); ?>
                                </a>
                            <?php else : ?>
                                <?php echo esc_html($page['title']); ?>
                            <?php endif; ?>
                        </td>
                        <td>
                            <code><?php echo esc_html($page['match_method'] ?? 'content_search'); ?></code>
                        </td>
                        <td>
                            <?php if (!empty($page['expected_cookies'])) : ?>
                                <small><?php echo esc_html(implode(', ', $page['expected_cookies'])); ?></small>
                            <?php else : ?>
                                <small style="color: #999;">—</small>
                            <?php endif; ?>
                        </td>
                        <td><small><?php echo esc_html($page['discovered_at'] ?? '—'); ?></small></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else : ?>
        <div class="notice notice-info">
            <p>No sample pages discovered yet. Click <strong>Discover Pages Only</strong> or <strong>Run Full Cookie Scan</strong> to find pages with embeds.</p>
        </div>
    <?php endif; ?>

    <?php // ── Last Scan Results ── ?>
    <?php if (!empty($last_scan)) : ?>
        <h2>Last Scan Results — <?php echo esc_html($last_scan['scan_date']); ?></h2>

        <?php
        $s = $last_scan['summary'];
        $has_violations = ($s['violations'] ?? 0) > 0;
        $has_warnings   = ($s['warnings'] ?? 0) > 0;
        ?>

        <div class="card" style="max-width: 100%; margin-bottom: 20px; padding: 12px 20px;">
            <table style="border-collapse: collapse;">
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>Pages scanned:</strong></td>
                    <td><?php echo (int) ($last_scan['pages_scanned'] ?? 0); ?></td>
                </tr>
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>Total cookies:</strong></td>
                    <td><?php echo (int) ($s['total_cookies'] ?? 0); ?></td>
                </tr>
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>Front-end cookies:</strong></td>
                    <td><?php echo (int) ($s['frontend_cookies'] ?? 0); ?></td>
                </tr>
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>Back-end cookies:</strong></td>
                    <td><?php echo (int) ($s['backend_cookies'] ?? 0); ?></td>
                </tr>
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>Third-party services:</strong></td>
                    <td><?php echo (int) ($s['third_party_services'] ?? 0); ?></td>
                </tr>
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>Complianz installed:</strong></td>
                    <td><?php echo !empty($s['complianz_installed']) ? 'Yes' : 'No'; ?></td>
                </tr>
                <tr>
                    <td style="padding: 4px 20px 4px 0;"><strong>JS reports processed:</strong></td>
                    <td><?php echo (int) ($last_scan['js_reports_processed'] ?? 0); ?></td>
                </tr>
            </table>
            <hr style="margin: 10px 0;">
            <span style="font-size: 14px;">
                <span style="color: #46b450; margin-right: 16px;">&#x2714; Compliant: <strong><?php echo (int) ($s['compliant'] ?? 0); ?></strong></span>
                <span style="color: #ffb900; margin-right: 16px;">&#x26A0; Warnings: <strong><?php echo (int) ($s['warnings'] ?? 0); ?></strong></span>
                <span style="color: #dc3232;">&#x2716; Violations: <strong><?php echo (int) ($s['violations'] ?? 0); ?></strong></span>
            </span>
        </div>

        <?php // ── Cookie Inventory Table ── ?>
        <?php if (!empty($last_scan['cookies'])) : ?>
            <h3>Cookie Inventory</h3>
            <table class="widefat striped" style="margin-bottom: 30px;">
                <thead>
                    <tr>
                        <th>Cookie Name</th>
                        <th>Source</th>
                        <th>Category</th>
                        <th>Front/Back</th>
                        <th>Detection</th>
                        <th>Found On</th>
                        <th>Lifetime</th>
                        <th>Flags</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($last_scan['cookies'] as $cookie) :
                        $comp   = isset($cookie['compliance']) ? $cookie['compliance'] : [];
                        $status = isset($comp['status']) ? $comp['status'] : 'unknown';

                        $status_color = '#999';
                        $status_icon  = '?';
                        if ($status === 'compliant') {
                            $status_color = '#46b450';
                            $status_icon  = '&#x2714;';
                        } elseif ($status === 'warning') {
                            $status_color = '#ffb900';
                            $status_icon  = '&#x26A0;';
                        } elseif ($status === 'violation') {
                            $status_color = '#dc3232';
                            $status_icon  = '&#x2716;';
                        }

                        $found_on = isset($cookie['found_on']) ? $cookie['found_on'] : '—';
                        if (is_array($found_on)) {
                            $found_on = implode(', ', array_map(function ($u) {
                                return wp_parse_url($u, PHP_URL_PATH) ?: $u;
                            }, $found_on));
                        } else {
                            $path = wp_parse_url($found_on, PHP_URL_PATH);
                            $found_on = $path ?: $found_on;
                        }

                        $lifetime = '—';
                        if (isset($cookie['lifetime_seconds']) && $cookie['lifetime_seconds'] !== null) {
                            $days = round($cookie['lifetime_seconds'] / 86400);
                            if ($days > 365) {
                                $lifetime = round($days / 365, 1) . ' yr';
                            } elseif ($days > 30) {
                                $lifetime = round($days / 30) . ' mo';
                            } elseif ($days > 0) {
                                $lifetime = $days . ' d';
                            } else {
                                $lifetime = 'session';
                            }
                        }

                        $flags = [];
                        if (!empty($cookie['secure']))                     $flags[] = 'Secure';
                        if (!empty($cookie['httponly']))                    $flags[] = 'HttpOnly';
                        if (!empty($cookie['samesite']))                   $flags[] = 'SameSite=' . $cookie['samesite'];
                        if (!empty($cookie['is_third_party']))             $flags[] = '<em>3rd-party</em>';
                        if (!empty($cookie['also_detected_by_js']))        $flags[] = '<em>+JS</em>';
                        if (!empty($cookie['set_before_consent']))         $flags[] = '<strong style="color:#dc3232">Pre-consent!</strong>';
                        if (!empty($cookie['consent_was_essential_only'])) $flags[] = '<strong style="color:#dc3232">Essential-only ignored!</strong>';
                    ?>
                        <tr>
                            <td><code><?php echo esc_html($cookie['name']); ?></code></td>
                            <td><?php echo esc_html($comp['source'] ?? '—'); ?></td>
                            <td><?php echo esc_html($comp['category'] ?? '—'); ?></td>
                            <td><?php echo esc_html($cookie['classification'] ?? 'unknown'); ?></td>
                            <td><?php echo esc_html($cookie['detection'] ?? '—'); ?></td>
                            <td><small><?php echo esc_html($found_on); ?></small></td>
                            <td><?php echo esc_html($lifetime); ?></td>
                            <td><small><?php echo implode(', ', $flags); ?></small></td>
                            <td style="color: <?php echo $status_color; ?>; font-weight: bold;">
                                <?php echo $status_icon; ?> <?php echo esc_html(ucfirst($status)); ?>
                            </td>
                        </tr>
                        <?php if (!empty($comp['issues'])) : ?>
                            <tr>
                                <td colspan="9" style="padding: 4px 20px 12px; background: #fef7f1;">
                                    <?php foreach ($comp['issues'] as $issue) : ?>
                                        <small style="color: <?php echo $issue['severity'] === 'violation' ? '#dc3232' : '#ffb900'; ?>;">
                                            &#x2022; <?php echo esc_html($issue['detail']); ?>
                                            <em>(<?php echo esc_html($issue['rule']); ?>)</em>
                                        </small><br>
                                    <?php endforeach; ?>
                                </td>
                            </tr>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <?php // ── Third-Party Resources ── ?>
        <?php if (!empty($last_scan['third_party_resources'])) : ?>
            <h3>Third-Party Resources Detected in HTML</h3>
            <p class="description">These external resources were found in page HTML. They typically set cookies via JavaScript in the visitor's browser.</p>
            <table class="widefat striped" style="margin-bottom: 30px;">
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Type</th>
                        <th>Domain / Pattern</th>
                        <th>Found On</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($last_scan['third_party_resources'] as $resource) : ?>
                        <tr>
                            <td><strong><?php echo esc_html($resource['label'] ?? '—'); ?></strong></td>
                            <td><?php echo esc_html($resource['type'] ?? '—'); ?></td>
                            <td><code><?php echo esc_html($resource['domain'] ?? ($resource['pattern'] ?? '—')); ?></code></td>
                            <td>
                                <small>
                                <?php
                                $pages = isset($resource['found_on']) ? (array) $resource['found_on'] : [];
                                echo esc_html(implode(', ', array_map(function ($u) {
                                    return wp_parse_url($u, PHP_URL_PATH) ?: $u;
                                }, $pages)));
                                ?>
                                </small>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <?php // ── Complianz Config ── ?>
        <?php if (!empty($last_scan['complianz']['installed'])) : ?>
            <h3>Complianz Configuration Snapshot</h3>
            <div class="card" style="max-width: 100%; margin-bottom: 20px; padding: 12px 20px;">
                <p><strong>Config hash:</strong> <code><?php echo esc_html($last_scan['complianz']['config_hash'] ?? '—'); ?></code></p>
                <p><strong>Declared cookies:</strong> <?php echo count($last_scan['complianz']['cookies'] ?? []); ?></p>
                <p><strong>Declared services:</strong> <?php echo count($last_scan['complianz']['services'] ?? []); ?></p>
                <?php if (!empty($last_scan['complianz']['cookies'])) : ?>
                    <details style="margin-top: 10px;">
                        <summary style="cursor: pointer;"><strong>View declared cookies</strong></summary>
                        <table class="widefat striped" style="margin-top: 10px;">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Service</th>
                                    <th>Purpose</th>
                                    <th>Personal Data</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($last_scan['complianz']['cookies'] as $dc) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html($dc['name'] ?? ($dc['cookie_name'] ?? '—')); ?></code></td>
                                        <td><?php echo esc_html($dc['service'] ?? ($dc['serviceID'] ?? '—')); ?></td>
                                        <td><?php echo esc_html($dc['purpose'] ?? '—'); ?></td>
                                        <td><?php echo !empty($dc['isPersonalData']) ? 'Yes' : 'No'; ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </details>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    <?php else : ?>
        <div class="notice notice-info">
            <p>No scan results yet. Click <strong>Run Full Cookie Scan</strong> to start the first scan.</p>
        </div>
    <?php endif; ?>

    <hr>
    <p class="description">
        <strong>How it works:</strong> The scanner visits your pages as an anonymous visitor (HTTP) to capture server-set cookies.
        A lightweight JavaScript monitor runs on every front-end page load for all visitors, detecting JS-set cookies and
        checking them against the user's consent level. Results are merged and checked against EU regulations
        (ePrivacy Directive, GDPR, EDPB/CNIL guidelines). Reports are sent to the central dashboard daily.
    </p>
</div>
