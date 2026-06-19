<?php

use GlpiPlugin\Tanium\Api as TaniumApi;
use GlpiPlugin\Tanium\Config as TaniumConfig;
use GlpiPlugin\Tanium\Notification as TaniumNotification;

include('../../../inc/includes.php');

Session::checkRight('config', UPDATE);

$config = new TaniumConfig();

if (isset($_POST['save'])) {


    TaniumConfig::saveConfig([
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
        'sla_critical_days'    => max(1, (int)($_POST['sla_critical_days'] ?? 7)),
        'sla_high_days'        => max(1, (int)($_POST['sla_high_days']     ?? 30)),
        'sla_medium_days'      => max(1, (int)($_POST['sla_medium_days']   ?? 90)),
        'patch_limiting_group_id' => max(0, (int)($_POST['patch_limiting_group_id'] ?? 0)),
    ]);

    Session::addMessageAfterRedirect(__('Tanium configuration saved.', 'tanium'), true, INFO);
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
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
echo "<div class='tanium-page-wrap'>";
$config->showConfigForm();
echo "</div>";
Html::footer();
