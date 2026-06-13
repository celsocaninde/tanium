<?php

namespace GlpiPlugin\Tanium;

use Toolbox;

class Notification {

    // ── Webhook (Slack / Teams / generic JSON) ────────────────────────────

    public static function sendWebhook(string $url, array $payload): bool {
        if (empty($url)) {
            return false;
        }

        $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Content-Length: ' . strlen($body)],
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($error) {
            Toolbox::logError('[Tanium] Webhook error: ' . $error);
            return false;
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            Toolbox::logError("[Tanium] Webhook HTTP {$httpCode}: " . substr((string)$response, 0, 200));
            return false;
        }

        return true;
    }

    // ── Build payloads for Slack / Teams / generic ────────────────────────

    public static function buildSyncPayload(array $result, int $newCritical): array {
        $color   = $result['errors'] > 0 ? '#e8212a' : ($newCritical > 0 ? '#f97316' : '#1eb464');
        $status  = $result['errors'] > 0 ? '❌ Erro' : ($newCritical > 0 ? '⚠️ Novos CVEs críticos' : '✅ Sucesso');
        $summary = "Sync Tanium concluído: {$result['total']} endpoints, {$result['created']} criados, {$result['updated']} atualizados.";

        if ($newCritical > 0) {
            $summary .= " **{$newCritical} novos CVEs críticos** detectados!";
        }

        // Slack-compatible
        return [
            'username'    => 'Tanium + GLPI',
            'icon_emoji'  => ':shield:',
            'attachments' => [[
                'color'  => $color,
                'title'  => "Tanium Sync — {$status}",
                'text'   => $summary,
                'fields' => [
                    ['title' => 'Endpoints',    'value' => (string)$result['total'],   'short' => true],
                    ['title' => 'Criados',       'value' => (string)$result['created'], 'short' => true],
                    ['title' => 'Atualizados',   'value' => (string)$result['updated'], 'short' => true],
                    ['title' => 'CVEs críticos', 'value' => (string)$newCritical,        'short' => true],
                ],
                'footer' => 'GLPI Tanium Plugin • ' . date('d/m/Y H:i'),
            ]],
            // MS Teams compatible (also accepts 'text' at root for generic webhooks)
            'text'  => $summary,
            'title' => "Tanium Sync — {$status}",
        ];
    }

    public static function buildCriticalCVEPayload(string $cveId, string $endpointName, float $cvss): array {
        $summary = "🚨 CVE crítico detectado: *{$cveId}* (CVSS {$cvss}) no endpoint *{$endpointName}*";

        return [
            'username'    => 'Tanium + GLPI',
            'icon_emoji'  => ':rotating_light:',
            'attachments' => [[
                'color'  => '#e8212a',
                'title'  => "🚨 Novo CVE Crítico: {$cveId}",
                'text'   => $summary,
                'fields' => [
                    ['title' => 'CVE ID',    'value' => $cveId,        'short' => true],
                    ['title' => 'CVSS',      'value' => (string)$cvss, 'short' => true],
                    ['title' => 'Endpoint',  'value' => $endpointName, 'short' => true],
                    ['title' => 'NVD',       'value' => "https://nvd.nist.gov/vuln/detail/{$cveId}", 'short' => false],
                ],
                'footer' => 'GLPI Tanium Plugin • ' . date('d/m/Y H:i'),
            ]],
            'text'  => $summary,
            'title' => "Novo CVE Crítico: {$cveId}",
        ];
    }

    // ── GLPI internal email notification ──────────────────────────────────

    public static function sendEmail(string $to, string $subject, string $body): bool {
        if (empty($to)) {
            return false;
        }

        // Use GLPI's mail system if available
        if (class_exists('NotificationMailing') || function_exists('sendMailWithErrorHandling')) {
            return self::sendViaGLPI($to, $subject, $body);
        }

        // Fallback: PHP mail()
        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-type: text/html; charset=UTF-8\r\n";
        $headers .= "From: GLPI Tanium Plugin <noreply@glpi>\r\n";

        return @mail($to, $subject, $body, $headers);
    }

    private static function sendViaGLPI(string $to, string $subject, string $body): bool {
        try {
            $mailing = new \NotificationMailing();
            return $mailing->sendNotification($to, $subject, $body);
        } catch (\Throwable $e) {
            Toolbox::logError('[Tanium] Email send failed: ' . $e->getMessage());
            return false;
        }
    }

    public static function buildCriticalEmailBody(int $newCritical, array $criticalCves, string $glpiUrl): string {
        $rows = '';
        foreach (array_slice($criticalCves, 0, 20) as $cve) {
            $rows .= "<tr>
                <td style='padding:6px 12px;border-bottom:1px solid #eee;font-family:monospace'>{$cve['cve_id']}</td>
                <td style='padding:6px 12px;border-bottom:1px solid #eee'>{$cve['endpoint']}</td>
                <td style='padding:6px 12px;border-bottom:1px solid #eee;color:#e8212a;font-weight:bold'>{$cve['cvss']}</td>
            </tr>";
        }

        return "<!DOCTYPE html><html><body style='font-family:Segoe UI,Arial,sans-serif;color:#1a1a2e;background:#f5f5f5'>
<div style='max-width:600px;margin:24px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)'>
  <div style='background:#e8212a;padding:20px 24px;color:#fff'>
    <h1 style='margin:0;font-size:18px'>🚨 {$newCritical} novo(s) CVE(s) crítico(s) detectado(s)</h1>
    <p style='margin:8px 0 0;opacity:.85;font-size:13px'>GLPI Tanium Plugin — " . date('d/m/Y H:i') . "</p>
  </div>
  <div style='padding:20px 24px'>
    <p>O Tanium detectou <strong>{$newCritical} novo(s) CVE(s) crítico(s)</strong> durante a última sincronização.</p>
    <table style='width:100%;border-collapse:collapse;margin:16px 0;font-size:13px'>
      <thead><tr style='background:#f9fafb'>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>CVE ID</th>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>Endpoint</th>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>CVSS</th>
      </tr></thead>
      <tbody>{$rows}</tbody>
    </table>
    <a href='{$glpiUrl}' style='display:inline-block;background:#e8212a;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold;margin-top:8px'>
      Ver no GLPI
    </a>
  </div>
  <div style='background:#f9fafb;padding:14px 24px;font-size:11px;color:#9ca3af;border-top:1px solid #eee'>
    Gerado automaticamente pelo plugin Tanium para GLPI
  </div>
</div></body></html>";
    }
}
