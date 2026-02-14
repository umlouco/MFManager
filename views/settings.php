<div class="wrapper">
    <h1>MF Manager Settings</h1>
    <form action='options.php' method='post'>
        <?php
        settings_fields('mfmanager_settings');
        do_settings_sections('mfmanager_settings');
        submit_button();
        ?>
    </form>
</div>
<form action="<?php echo esc_url( admin_url('admin.php?page=mfmanager_settings_page') ); ?>" method="post">
    <?php wp_nonce_field('mfmanager_runcron_action', 'mfmanager_runcron_nonce'); ?>
    <input type="submit" name="mfmanager_runcron" value="Send site info">
</form>
<?php

if (!empty($_POST['mfmanager_runcron'])) {
    // Verify nonce for CSRF protection
    if (!isset($_POST['mfmanager_runcron_nonce']) || 
        !wp_verify_nonce($_POST['mfmanager_runcron_nonce'], 'mfmanager_runcron_action')) {
        wp_die('Security check failed. Please try again.');
    }
    
    // Check user permissions
    if (!current_user_can('manage_options')) {
        wp_die('You do not have permission to perform this action.');
    }
    
    mfmanager_cron_exec();
}

?>
