/**
 * MFManager Cookie Monitor — Front-End
 *
 * Lightweight cookie compliance detector. Fires once per visitor,
 * 8 seconds after page load. Reports to a custom lightweight endpoint
 * (no full REST API bootstrap).
 *
 * Design constraints:
 *   - No dependencies (no jQuery, no external libs)
 *   - ~1.5 KB minified
 *   - Non-blocking: uses navigator.sendBeacon()
 *   - No DOM manipulation, no visible UI
 *   - Runs only on front-end (never wp-admin)
 *   - Fires exactly once per visitor per SESSION (sessionStorage dedup)
 *
 * @package MFManager
 * @since   9.2.0
 */
(function () {
    'use strict';

    // Bail if the localized config object is missing
    if (typeof window.mfmCM === 'undefined' || !window.mfmCM.e) {
        return;
    }

    // ── Session deduplication ──
    // Only report once per browser session to reduce server load.
    // Uses sessionStorage so it resets when the tab/browser is closed.
    var DEDUP_KEY = 'mfm_cr_sent';
    try {
        if (window.sessionStorage && sessionStorage.getItem(DEDUP_KEY)) {
            return; // Already reported this session
        }
    } catch (e) { /* sessionStorage blocked (e.g. Safari private) — continue */ }

    // ── Essential / functional cookie patterns ──
    // These NEVER require consent under ePrivacy Directive Art. 5(3) recital 66.
    var ESSENTIAL = [
        /^wordpress_/,
        /^wp-settings/,
        /^wp-/,
        /^PHPSESSID$/,
        /^cmplz_/,
        /^complianz/,
        /^cookielawinfo/,
        /^moove_gdpr/,
        /^borlabs-cookie/,
        /^viewed_cookie/,
        /^woocommerce_/,
        /^wc_/,
        /^pll_/,
        /^icl_/,
        /^comment_author/,
        /^tk_/
    ];

    function isEssential(name) {
        for (var i = 0; i < ESSENTIAL.length; i++) {
            if (ESSENTIAL[i].test(name)) return true;
        }
        return false;
    }

    /**
     * Parse document.cookie into { name: value } map.
     */
    function parseCookies() {
        var result = {};
        if (!document.cookie) return result;
        var parts = document.cookie.split(';');
        for (var i = 0; i < parts.length; i++) {
            var kv = parts[i].trim().split('=');
            if (kv[0]) {
                result[kv[0]] = kv.slice(1).join('=');
            }
        }
        return result;
    }

    /**
     * Detect which consent plugin is active and what consent level was given.
     * Supports Complianz, CookieYes/GDPR Cookie Consent, Borlabs Cookie.
     */
    function getConsentLevel(cookies) {
        // ── Complianz ──
        if (cookies.cmplz_consent_status !== undefined || cookies.cmplz_banner_status !== undefined) {
            return {
                plugin: 'complianz',
                consented: true,
                statistics: cookies.cmplz_statistics === 'allow',
                marketing: cookies.cmplz_marketing === 'allow',
                preferences: cookies.cmplz_preferences === 'allow'
            };
        }

        // ── CookieYes / GDPR Cookie Consent plugin ──
        if (cookies['cookielawinfo-checkbox-necessary'] !== undefined) {
            return {
                plugin: 'cookielawinfo',
                consented: true,
                statistics: cookies['cookielawinfo-checkbox-analytics'] === 'yes',
                marketing: cookies['cookielawinfo-checkbox-advertisement'] === 'yes',
                preferences: cookies['cookielawinfo-checkbox-functional'] === 'yes'
            };
        }

        // ── Borlabs Cookie ──
        if (cookies['borlabs-cookie']) {
            try {
                var bc = JSON.parse(decodeURIComponent(cookies['borlabs-cookie']));
                return {
                    plugin: 'borlabs',
                    consented: true,
                    statistics: !!(bc.statistics || bc.s),
                    marketing: !!(bc.marketing || bc.m),
                    preferences: true
                };
            } catch (e) { /* malformed cookie, treat as no consent */ }
        }

        // ── No consent plugin detected or no consent given yet ──
        return {
            plugin: 'none',
            consented: false,
            statistics: false,
            marketing: false,
            preferences: false
        };
    }

    /**
     * Perform a single scan and report via sendBeacon.
     * Fires exactly once, 8 seconds after page load.
     */
    function scan() {
        var cookies = parseCookies();
        var names = [];
        for (var k in cookies) {
            if (cookies.hasOwnProperty(k)) names.push(k);
        }

        var consent = getConsentLevel(cookies);
        var nonEssential = [];
        for (var i = 0; i < names.length; i++) {
            if (!isEssential(names[i])) {
                nonEssential.push(names[i]);
            }
        }

        // Only report when non-essential cookies exist (no noise)
        if (nonEssential.length === 0) return;

        var payload = {
            p: location.pathname,
            c: names,
            n: nonEssential,
            cs: consent,
            li: document.body && document.body.classList.contains('logged-in') ? 1 : 0,
            t: Math.floor(Date.now() / 1000)
        };

        try {
            var blob = new Blob(
                [JSON.stringify(payload)],
                { type: 'application/json' }
            );
            navigator.sendBeacon(window.mfmCM.e, blob);

            // Mark this session as reported
            try {
                if (window.sessionStorage) {
                    sessionStorage.setItem(DEDUP_KEY, '1');
                }
            } catch (s) { /* ignore */ }
        } catch (x) {
            /* silently fail — monitor must never break the site */
        }
    }

    // ── Single scan at 8 seconds after page load ──
    function init() {
        setTimeout(scan, 8000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
