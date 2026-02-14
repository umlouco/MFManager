<?php
/**
 * MFManager Audit Logger
 *
 * Hooks into WordPress actions to log every meaningful database write
 * (insert, update, delete) with a timestamp, the acting user, and a
 * short text identifier describing the action.
 *
 * Stores rows in a local wp_mfm_audit_log table. A daily cron ships
 * the entries to CodeIgniter and purges the table.
 *
 * @package MFManager
 */

if (!defined('ABSPATH')) {
    exit;
}

class MFManager_Audit_Logger
{
    /** @var string WordPress table name (with prefix) */
    private $table;

    public function __construct()
    {
        global $wpdb;
        $this->table = $wpdb->prefix . 'mfm_audit_log';
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Table management
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Create the audit log table if it doesn't exist.
     */
    public function ensure_table()
    {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            event_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user VARCHAR(100) NOT NULL DEFAULT 'system',
            action VARCHAR(255) NOT NULL,
            INDEX idx_event_date (event_date)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Core logging
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Insert an audit row.
     *
     * @param string $action  Short text identifier, e.g. "post.update.page"
     * @param string|null $user  Username override. Defaults to current WP user.
     */
    public function log($action, $user = null)
    {
        global $wpdb;

        if ($user === null) {
            $user = $this->current_user();
        }

        // Buffer audit entries in memory, flush once at shutdown
        if (!isset($GLOBALS['_mfm_audit_buffer'])) {
            $GLOBALS['_mfm_audit_buffer'] = [];
            $table = $this->table;
            register_shutdown_function(function () use ($table) {
                global $wpdb;
                if (empty($GLOBALS['_mfm_audit_buffer'])) {
                    return;
                }
                
                // Check if table exists before attempting to insert
                $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$table}'") === $table;
                if (!$table_exists) {
                    return; // Silently skip logging if table doesn't exist yet
                }
                
                foreach ($GLOBALS['_mfm_audit_buffer'] as $row) {
                    $wpdb->insert($table, $row, array('%s', '%s', '%s'));
                }
            });
        }

        $GLOBALS['_mfm_audit_buffer'][] = array(
            'event_date' => current_time('mysql'),
            'user'       => substr($user, 0, 100),
            'action'     => substr($action, 0, 255),
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Register all WordPress hooks
    // ─────────────────────────────────────────────────────────────────────

    public function register_hooks()
    {
        // ── Posts / Pages / CPT ──────────────────────────────────────────
        add_action('save_post',   array($this, 'on_save_post'), 99, 3);
        add_action('before_delete_post', array($this, 'on_delete_post'), 99, 1);
        add_action('wp_trash_post', array($this, 'on_trash_post'), 99, 1);
        add_action('untrash_post',  array($this, 'on_untrash_post'), 99, 1);

        // ── Comments ─────────────────────────────────────────────────────
        add_action('wp_insert_comment',  array($this, 'on_insert_comment'), 99, 2);
        add_action('edit_comment',       array($this, 'on_edit_comment'), 99, 2);
        add_action('delete_comment',     array($this, 'on_delete_comment'), 99, 2);
        add_action('spam_comment',       array($this, 'on_spam_comment'), 99, 2);

        // ── Users ────────────────────────────────────────────────────────
        add_action('user_register',      array($this, 'on_user_register'), 99, 1);
        add_action('profile_update',     array($this, 'on_profile_update'), 99, 2);
        add_action('delete_user',        array($this, 'on_delete_user'), 99, 1);

        // ── Terms / Taxonomies ───────────────────────────────────────────
        add_action('created_term', array($this, 'on_created_term'), 99, 3);
        add_action('edited_term',  array($this, 'on_edited_term'), 99, 3);
        add_action('delete_term',  array($this, 'on_delete_term'), 99, 4);

        // ── Options ──────────────────────────────────────────────────────
        add_action('updated_option', array($this, 'on_updated_option'), 99, 3);
        add_action('added_option',   array($this, 'on_added_option'), 99, 2);
        add_action('deleted_option', array($this, 'on_deleted_option'), 99, 1);

        // ── Plugins / Themes ─────────────────────────────────────────────
        add_action('activated_plugin',   array($this, 'on_activated_plugin'), 99, 2);
        add_action('deactivated_plugin', array($this, 'on_deactivated_plugin'), 99, 2);
        add_action('switch_theme',       array($this, 'on_switch_theme'), 99, 3);
        add_action('upgrader_process_complete', array($this, 'on_upgrade'), 99, 2);

        // ── Attachments (media) ──────────────────────────────────────────
        add_action('add_attachment',    array($this, 'on_add_attachment'), 99, 1);
        add_action('edit_attachment',   array($this, 'on_edit_attachment'), 99, 1);
        add_action('delete_attachment', array($this, 'on_delete_attachment'), 99, 1);

        // ── Menus ────────────────────────────────────────────────────────
        add_action('wp_update_nav_menu', array($this, 'on_update_menu'), 99, 2);
        add_action('wp_delete_nav_menu', array($this, 'on_delete_menu'), 99, 1);

        // ── Widgets ──────────────────────────────────────────────────────
        add_action('update_option_sidebars_widgets', array($this, 'on_widgets_update'), 99, 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Hook callbacks
    // ─────────────────────────────────────────────────────────────────────

    // Posts
    public function on_save_post($post_id, $post, $update)
    {
        if (wp_is_post_revision($post_id) || wp_is_post_autosave($post_id)) {
            return;
        }
        $type = $post->post_type;
        $op   = $update ? 'update' : 'insert';
        $this->log("post.{$op}.{$type}");
    }

    public function on_delete_post($post_id)
    {
        $post = get_post($post_id);
        $type = $post ? $post->post_type : 'unknown';
        $this->log("post.delete.{$type}");
    }

    public function on_trash_post($post_id)
    {
        $post = get_post($post_id);
        $type = $post ? $post->post_type : 'unknown';
        $this->log("post.trash.{$type}");
    }

    public function on_untrash_post($post_id)
    {
        $post = get_post($post_id);
        $type = $post ? $post->post_type : 'unknown';
        $this->log("post.untrash.{$type}");
    }

    // Comments
    public function on_insert_comment($id, $comment)
    {
        $this->log('comment.insert');
    }

    public function on_edit_comment($id, $data)
    {
        $this->log('comment.update');
    }

    public function on_delete_comment($id, $comment)
    {
        $this->log('comment.delete');
    }

    public function on_spam_comment($id, $comment)
    {
        $this->log('comment.spam');
    }

    // Users
    public function on_user_register($user_id)
    {
        $u = get_userdata($user_id);
        $this->log('user.insert', $u ? $u->user_login : 'unknown');
    }

    public function on_profile_update($user_id, $old_data)
    {
        $u = get_userdata($user_id);
        $this->log('user.update', $u ? $u->user_login : 'unknown');
    }

    public function on_delete_user($user_id)
    {
        $u = get_userdata($user_id);
        $this->log('user.delete', $u ? $u->user_login : 'unknown');
    }

    // Terms
    public function on_created_term($term_id, $tt_id, $taxonomy)
    {
        $this->log("term.insert.{$taxonomy}");
    }

    public function on_edited_term($term_id, $tt_id, $taxonomy)
    {
        $this->log("term.update.{$taxonomy}");
    }

    public function on_delete_term($term_id, $tt_id, $taxonomy, $deleted_term)
    {
        $this->log("term.delete.{$taxonomy}");
    }

    // Options — skip noisy transients and cron entries
    private $skip_options = array(
        '_transient_', '_site_transient_', 'cron', 'rewrite_rules',
        'auto_updater', 'recently_edited', 'action_scheduler',
        'mfm_', 'mfmanager_',
    );

    private function should_log_option($option)
    {
        foreach ($this->skip_options as $prefix) {
            if (strpos($option, $prefix) === 0) {
                return false;
            }
        }
        return true;
    }

    public function on_updated_option($option, $old, $new)
    {
        if ($this->should_log_option($option)) {
            $this->log('option.update.' . substr($option, 0, 80));
        }
    }

    public function on_added_option($option, $value)
    {
        if ($this->should_log_option($option)) {
            $this->log('option.insert.' . substr($option, 0, 80));
        }
    }

    public function on_deleted_option($option)
    {
        if ($this->should_log_option($option)) {
            $this->log('option.delete.' . substr($option, 0, 80));
        }
    }

    // Plugins / Themes
    public function on_activated_plugin($plugin, $network)
    {
        $slug = dirname($plugin) ?: $plugin;
        $this->log("plugin.activate.{$slug}");
    }

    public function on_deactivated_plugin($plugin, $network)
    {
        $slug = dirname($plugin) ?: $plugin;
        $this->log("plugin.deactivate.{$slug}");
    }

    public function on_switch_theme($new_name, $new_theme, $old_theme)
    {
        $this->log("theme.switch.{$new_name}");
    }

    public function on_upgrade($upgrader, $options)
    {
        $type = isset($options['type']) ? $options['type'] : 'unknown';
        $action = isset($options['action']) ? $options['action'] : 'update';
        $this->log("upgrade.{$action}.{$type}");
    }

    // Attachments
    public function on_add_attachment($post_id)
    {
        $this->log('attachment.insert');
    }

    public function on_edit_attachment($post_id)
    {
        $this->log('attachment.update');
    }

    public function on_delete_attachment($post_id)
    {
        $this->log('attachment.delete');
    }

    // Menus
    public function on_update_menu($menu_id, $data = null)
    {
        $this->log('menu.update');
    }

    public function on_delete_menu($menu_id)
    {
        $this->log('menu.delete');
    }

    // Widgets
    public function on_widgets_update($old, $new)
    {
        $this->log('widgets.update');
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Cron: ship to CodeIgniter and clear
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Daily cron: fetch all log entries, send to CI, truncate.
     *
     * @return array Summary.
     */
    public function daily_send()
    {
        global $wpdb;

        $rows = $wpdb->get_results(
            "SELECT event_date, user, action FROM {$this->table} ORDER BY event_date ASC",
            ARRAY_A
        );

        $count = count($rows);

        if ($count === 0) {
            return array('entries' => 0, 'sent' => true, 'cleared' => 0);
        }

        $sent = $this->send_to_server($rows);

        $cleared = 0;
        if ($sent === true) {
            $cleared = (int) $wpdb->query("TRUNCATE TABLE {$this->table}");
            // TRUNCATE returns 0 on success, use count instead
            $cleared = $count;
        }

        return array(
            'entries' => $count,
            'sent'    => $sent,
            'cleared' => $cleared,
        );
    }

    /**
     * Send log entries to CodeIgniter.
     *
     * @param array $rows
     * @return true|string
     */
    private function send_to_server($rows)
    {
        $api_key = get_option('mfmanager_api_settings', '');
        if (empty($api_key)) {
            return 'No API key configured';
        }

        $payload = array(
            'url'       => get_bloginfo('url'),
            'key'       => $api_key,
            'audit_log' => $rows,
        );

        $response = wp_remote_post(
            MFMANAGER_API_URL . 'auditLog',
            array(
                'headers' => array('Content-Type' => 'application/json'),
                'body'    => wp_json_encode($payload),
                'timeout' => 30,
            )
        );

        if (is_wp_error($response)) {
            error_log('MF Manager audit log error: ' . $response->get_error_message());
            return $response->get_error_message();
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code >= 400) {
            $body = wp_remote_retrieve_body($response);
            error_log('MF Manager audit log error: HTTP ' . $code . ' — ' . $body);
            return 'HTTP ' . $code;
        }

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Get the current WordPress user login, or 'system' if none.
     */
    private function current_user()
    {
        if (function_exists('wp_get_current_user')) {
            $user = wp_get_current_user();
            if ($user && $user->ID > 0) {
                return $user->user_login;
            }
        }

        // WP-Cron or CLI
        if (defined('DOING_CRON') && DOING_CRON) {
            return 'wp-cron';
        }
        if (defined('WP_CLI') && WP_CLI) {
            return 'wp-cli';
        }

        return 'system';
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
