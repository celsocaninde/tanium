<?php

use GlpiPlugin\Tanium\Api as TaniumApi;
use GlpiPlugin\Tanium\Config as TaniumConfig;
use GlpiPlugin\Tanium\Notification as TaniumNotification;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasConfigUpdateRight() && !Session::haveRight('config', UPDATE)) { Html::displayRightError(); }

$config = new TaniumConfig();

if (isset($_POST['regen_kiosk_token'])) {
    TaniumConfig::saveConfig(['kiosk_token' => bin2hex(random_bytes(16))]);
    Session::addMessageAfterRedirect(__('New kiosk link generated — the previous link no longer works.', 'tanium'), true, INFO);
    Html::redirect('config.form.php');
}

if (isset($_POST['save'])) {

    // Kiosk: generate the access token the first time the mode is enabled
    $kioskToken = [];
    if (isset($_POST['kiosk_enabled']) && empty(TaniumConfig::getConfig()['kiosk_token'])) {
        $kioskToken['kiosk_token'] = bin2hex(random_bytes(16));
    }

    TaniumConfig::saveConfig($kioskToken + [
        'kiosk_enabled'        => isset($_POST['kiosk_enabled']) ? 1 : 0,
        'api_url'              => trim($_POST['api_url']   ?? ''),
        'api_token'            => trim($_POST['api_token'] ?? ''),
        'sync_computers'       => isset($_POST['sync_computers'])       ? 1 : 0,
        'sync_software'        => isset($_POST['sync_software'])        ? 1 : 0,
        'sync_vulnerabilities' => isset($_POST['sync_vulnerabilities']) ? 1 : 0,
        'sync_hardware'        => isset($_POST['sync_hardware'])        ? 1 : 0,
        'sync_network'         => isset($_POST['sync_network'])         ? 1 : 0,
        'sync_os_details'      => isset($_POST['sync_os_details'])      ? 1 : 0,
        'sync_patches'         => isset($_POST['sync_patches'])         ? 1 : 0,
        'sync_incremental'     => isset($_POST['sync_incremental'])     ? 1 : 0,
        'cron_frequency'       => max(1, (int)($_POST['cron_frequency'] ?? 24)),
        'import_limit'         => min(500, max(10, (int)($_POST['import_limit'] ?? 500))),
        'webhook_enabled'      => isset($_POST['webhook_enabled'])      ? 1 : 0,
        'webhook_url'          => trim($_POST['webhook_url']   ?? ''),
        'notify_critical'      => isset($_POST['notify_critical'])      ? 1 : 0,
        'notify_email'         => trim($_POST['notify_email'] ?? ''),
        'notify_users'         => implode(',', array_filter(array_map('intval', (array)($_POST['notify_users'] ?? [])))),
        'sla_critical_days'    => max(1, (int)($_POST['sla_critical_days'] ?? 7)),
        'sla_high_days'        => max(1, (int)($_POST['sla_high_days']     ?? 30)),
        'sla_medium_days'      => max(1, (int)($_POST['sla_medium_days']   ?? 90)),
        'patch_limiting_group_id' => max(0, (int)($_POST['patch_limiting_group_id'] ?? 0)),
        'ticket_entity_id'        => max(0, (int)($_POST['ticket_entity_id'] ?? 0)),
        'ticket_requester_id'     => max(0, (int)($_POST['ticket_requester_id'] ?? 0)),
        'default_entity_id'       => max(0, (int)($_POST['default_entity_id'] ?? 0)),
        'sync_group_membership'   => isset($_POST['sync_group_membership']) ? 1 : 0,
        'agent_stale_days'        => max(1, (int)($_POST['agent_stale_days'] ?? 7)),
        'agent_health_ticket'     => isset($_POST['agent_health_ticket']) ? 1 : 0,
        'sync_compliance'         => isset($_POST['sync_compliance']) ? 1 : 0,
        'sync_threats'            => isset($_POST['sync_threats']) ? 1 : 0,
        'threat_ticket'           => isset($_POST['threat_ticket']) ? 1 : 0,
        'threat_min_severity'     => in_array($_POST['threat_min_severity'] ?? '', ['info', 'low', 'medium', 'high', 'critical'])
            ? $_POST['threat_min_severity'] : 'high',
        'webhook_sla'             => isset($_POST['webhook_sla']) ? 1 : 0,
        'webhook_deploy'          => isset($_POST['webhook_deploy']) ? 1 : 0,
        'auto_ticket_critical'    => isset($_POST['auto_ticket_critical']) ? 1 : 0,
        'quarantine_package'      => trim($_POST['quarantine_package'] ?? ''),
        'restart_package'         => trim($_POST['restart_package'] ?? ''),
        'token_expires_at'        => preg_match('/^\d{4}-\d{2}-\d{2}$/', $_POST['token_expires_at'] ?? '')
            ? $_POST['token_expires_at'] : null,
        'retention_days'          => max(30, (int)($_POST['retention_days'] ?? 365)),
        'custom_sensors'          => trim($_POST['custom_sensors'] ?? ''),
        'auto_deploy_kev'         => isset($_POST['auto_deploy_kev']) ? 1 : 0,
        'report_day'              => max(0, min(6, (int)($_POST['report_day'] ?? 1))),
        'report_hour'             => max(0, min(23, (int)($_POST['report_hour'] ?? 8))),
        'auto_close_cves'         => isset($_POST['auto_close_cves']) ? 1 : 0,
        'notify_remediation'      => isset($_POST['notify_remediation']) ? 1 : 0,
        'monthly_report_day'      => max(1, min(28, (int)($_POST['monthly_report_day'] ?? 1))),
    ]);

    Session::addMessageAfterRedirect(__('Tanium configuration saved.', 'tanium'), true, INFO);

    // Surface picked users that will silently receive nothing
    $noEmail = TaniumConfig::usersWithoutEmail((array)($_POST['notify_users'] ?? []));
    if ($noEmail !== []) {
        Session::addMessageAfterRedirect(
            sprintf(
                __('Warning: these users have no email registered in GLPI and will NOT receive alerts or reports: %s', 'tanium'),
                implode(', ', $noEmail)
            ),
            true, WARNING
        );
    }

    Html::redirect('config.form.php');
}

if (isset($_POST['test_email'])) {

    // Test with the values currently typed in the form (fall back to saved
    // config when the form fields come in empty).
    $saved  = TaniumConfig::getConfig();
    $config = [
        'notify_email' => trim($_POST['notify_email'] ?? '') !== '' ? trim($_POST['notify_email']) : ($saved['notify_email'] ?? ''),
        'notify_users' => implode(',', array_filter(array_map('intval', (array)($_POST['notify_users'] ?? []))))
            ?: ($saved['notify_users'] ?? ''),
    ];

    $recipients = TaniumConfig::resolveNotifyRecipients($config);
    $noEmail    = TaniumConfig::usersWithoutEmail(array_filter(array_map('intval', explode(',', $config['notify_users']))));

    if ($noEmail !== []) {
        Session::addMessageAfterRedirect(
            sprintf(
                __('Warning: these users have no email registered in GLPI and will NOT receive alerts or reports: %s', 'tanium'),
                implode(', ', $noEmail)
            ),
            true, WARNING
        );
    }

    if ($recipients === []) {
        Session::addMessageAfterRedirect(__('No email recipient configured. Pick GLPI users or type extra emails first.', 'tanium'), true, ERROR);
    } else {
        $subject = __('[Tanium] Test email', 'tanium') . ' — ' . date('d/m/Y H:i');
        $body    = '<div style="font-family:Segoe UI,Arial,sans-serif">'
                 . '<h2 style="color:#e8212a">Tanium + GLPI</h2>'
                 . '<p>' . __('This is a test email from the Tanium plugin. If you can read this, email notifications are working.', 'tanium') . '</p>'
                 . '<p style="color:#6b7280;font-size:12px">' . date('d/m/Y H:i:s') . '</p></div>';

        $ok = 0;
        $fail = [];
        foreach ($recipients as $to) {
            if (TaniumNotification::sendEmail($to, $subject, $body)) {
                $ok++;
            } else {
                $fail[] = $to;
            }
        }

        if ($ok > 0) {
            Session::addMessageAfterRedirect(
                sprintf(__('Test email queued for %d recipient(s): %s', 'tanium'), $ok, implode(', ', array_diff($recipients, $fail))),
                true, INFO
            );
        }
        if ($fail !== []) {
            Session::addMessageAfterRedirect(
                sprintf(__('Test email FAILED for: %s — check tanium.log and the email settings in Setup > Notifications.', 'tanium'), implode(', ', $fail)),
                true, ERROR
            );
        }
    }

    Html::redirect('config.form.php');
}

if (isset($_POST['send_report'])) {

    $sent = \GlpiPlugin\Tanium\WeeklyReport::send();
    if ($sent > 0) {
        Session::addMessageAfterRedirect(
            sprintf(__('Weekly report sent now to %d recipient(s).', 'tanium'), $sent),
            true, INFO
        );
    } else {
        Session::addMessageAfterRedirect(
            __('Weekly report was NOT sent — no valid recipient configured (or every send failed; check tanium.log).', 'tanium'),
            true, ERROR
        );
    }

    Html::redirect('config.form.php');
}

if (isset($_POST['send_monthly_report'])) {

    $sent = \GlpiPlugin\Tanium\MonthlyReport::send();
    if ($sent > 0) {
        Session::addMessageAfterRedirect(
            sprintf(__('Monthly report sent now to %d recipient(s).', 'tanium'), $sent),
            true, INFO
        );
    } else {
        Session::addMessageAfterRedirect(
            __('Monthly report was NOT sent — no valid recipient configured (or every send failed; check tanium.log).', 'tanium'),
            true, ERROR
        );
    }

    Html::redirect('config.form.php');
}

if (isset($_POST['test'])) {


    $apiUrl   = trim($_POST['api_url']   ?? '');
    $apiToken = trim($_POST['api_token'] ?? '');

    if (empty($apiToken)) {
        $stored   = TaniumConfig::getConfig();
        $apiToken = $stored['api_token'] ?? '';
    }

    if (empty($apiUrl) || empty($apiToken)) {
        Session::addMessageAfterRedirect(
            __('Please enter the API URL and token before testing.', 'tanium'),
            true, ERROR
        );
    } else {
        $api    = new TaniumApi($apiUrl, $apiToken);
        $result = $api->testConnection();
        Session::addMessageAfterRedirect($result['message'], true, $result['ok'] ? INFO : ERROR);
    }

    Html::redirect('config.form.php');
}

if (isset($_POST['test_webhook'])) {


    $url = trim($_POST['webhook_url'] ?? TaniumConfig::getConfig()['webhook_url'] ?? '');
    if (empty($url)) {
        Session::addMessageAfterRedirect(__('No webhook URL configured.', 'tanium'), true, ERROR);
    } else {
        $payload = TaniumNotification::buildSyncPayload(
            ['total' => 0, 'created' => 0, 'updated' => 0, 'errors' => 0, 'message' => ''],
            0
        );
        $payload['text']  = '✅ Test webhook from GLPI Tanium Plugin — ' . date('d/m/Y H:i');
        $payload['title'] = 'Test webhook';
        foreach ($payload['attachments'] as &$a) {
            $a['title'] = 'Test webhook';
            $a['text']  = 'Este é um teste de webhook enviado pelo plugin Tanium para GLPI.';
            $a['color'] = '#1a6dff';
        }

        $ok = TaniumNotification::sendWebhook($url, $payload);
        Session::addMessageAfterRedirect(
            $ok ? __('Webhook test sent successfully!', 'tanium') : __('Webhook test failed. Check the URL and your server logs.', 'tanium'),
            true,
            $ok ? INFO : ERROR
        );
    }

    Html::redirect('config.form.php');
}

Html::header(__('Tanium — Configuration', 'tanium'), $_SERVER['PHP_SELF'], 'config', 'plugins');
echo <<<'CSS'
<style>
.container-xl,.container-lg{max-width:100%!important}
/* Entity (select2) dropdown — legível no tema escuro do plugin.
   O popup do select2 é montado no <body>, então as regras não podem ficar
   sob .tanium-page-wrap; este <style> é local desta página, sem vazar para o GLPI. */
.select2-container--default .select2-dropdown,
.select2-dropdown{background:#0f1e33!important;border:1px solid #1e2d44!important}
.select2-container--default .select2-results__option{color:#e8edf5!important;background:#0f1e33!important}
.select2-container--default .select2-results__option--highlighted,
.select2-container--default .select2-results__option--highlighted[aria-selected]{background:#e8212a!important;color:#fff!important}
.select2-container--default .select2-results__option[aria-selected=true]{background:#1e2d44!important;color:#e8edf5!important}
.select2-container--default .select2-results__group{color:#7a8da8!important}
.select2-container--default .select2-search--dropdown .select2-search__field{background:#0a1628!important;border:1px solid #1e2d44!important;color:#e8edf5!important}
.select2-container--default .select2-selection--single{background:#0a1628!important;border:1px solid #1e2d44!important}
.select2-container--default .select2-selection--single .select2-selection__rendered{color:#e8edf5!important}
</style>
CSS;
echo "<div class='tanium-page-wrap'>";
$config->showConfigForm();
echo "</div>";
Html::footer();
