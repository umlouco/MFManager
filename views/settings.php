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
<form action="<?php echo $_SERVER['REQUEST_URI']; ?>" method="post">
    <input type="submit" name="mfmanager_runcron" value="Send site info">
</form>
<?php

if (!empty($_POST['mfmanager_runcron'])) {
    mfmanager_cron_exec();
}

?>