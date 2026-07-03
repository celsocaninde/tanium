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
            Toolbox::logInFile('tanium','[Tanium] Webhook error: ' . $error);
            return false;
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            Toolbox::logInFile('tanium',"[Tanium] Webhook HTTP {$httpCode}: " . substr((string)$response, 0, 200));
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

    /**
     * @param array<int,array{filename:string,content:string,mime?:string}> $attachments
     *        Only honoured on the GLPIMailer path -- the mail() fallback sends
     *        the HTML body only.
     */
    public static function sendEmail(string $to, string $subject, string $body, array $attachments = []): bool {
        if (empty($to)) {
            return false;
        }

        // Prefer GLPI's own mailer (respects the configured SMTP transport)
        if (class_exists('GLPIMailer')) {
            return self::sendViaGLPI($to, $subject, $body, $attachments);
        }

        // Fallback: PHP mail()
        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-type: text/html; charset=UTF-8\r\n";
        $headers .= "From: GLPI Tanium Plugin <noreply@glpi>\r\n";

        return @mail($to, $subject, $body, $headers);
    }

    /**
     * Send a one-off HTML email through GLPI's configured mail transport
     * (GLPIMailer wraps Symfony Mailer and uses the SMTP settings from
     * Configuração → Notificações). Returns false and logs a clear reason
     * on failure (invalid address, transport error, etc.).
     *
     * @param array<int,array{filename:string,content:string,mime?:string}> $attachments
     */
    private static function sendViaGLPI(string $to, string $subject, string $body, array $attachments = []): bool {
        global $CFG_GLPI;

        $from     = (string) ($CFG_GLPI['admin_email'] ?? '');
        $fromName = (string) ($CFG_GLPI['admin_email_name'] ?? 'GLPI');

        if ($from === '' || !\GLPIMailer::validateAddress($from)) {
            Toolbox::logInFile('tanium', '[Tanium] Remetente inválido. Defina o "E-mail do administrador" em Configurar → Notificações → Configurações de e-mail.');
            return false;
        }
        if (!\GLPIMailer::validateAddress($to)) {
            Toolbox::logInFile('tanium', "[Tanium] Endereço de destino inválido: {$to}");
            return false;
        }

        try {
            $mailer = new \GLPIMailer();
            $email  = $mailer->getEmail();
            $email->from(new \Symfony\Component\Mime\Address($from, $fromName));
            $email->to($to);
            $email->subject($subject);
            $email->html($body);
            $email->text(trim(strip_tags(str_replace(['<br>', '<br/>', '<br />', '</p>', '</tr>'], "\n", $body))));

            foreach ($attachments as $attachment) {
                $content = (string) ($attachment['content'] ?? '');
                if ($content === '') {
                    continue;
                }
                $email->attach($content, (string) ($attachment['filename'] ?? 'anexo.pdf'), (string) ($attachment['mime'] ?? 'application/pdf'));
            }

            if (!$mailer->send()) {
                Toolbox::logInFile('tanium', '[Tanium] Falha no envio do e-mail para ' . $to . ': ' . ($mailer->getError() ?? 'erro desconhecido'));
                return false;
            }
            return true;
        } catch (\Throwable $e) {
            Toolbox::logInFile('tanium', '[Tanium] Exceção no envio do e-mail: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * @param array<int,array{cve_id:string,endpoint:string,cvss:mixed,ip?:string,os_name?:string,title?:string,affected_count?:int}> $criticalCves
     */
    public static function buildCriticalEmailBody(int $newCritical, array $criticalCves, string $glpiUrl): string {
        $rows = '';
        $cvssSum = 0.0;
        $cvssCount = 0;
        foreach (array_slice($criticalCves, 0, 20) as $cve) {
            $cveId    = htmlspecialchars((string)($cve['cve_id'] ?? ''));
            $endpoint = htmlspecialchars((string)($cve['endpoint'] ?? ''));
            $ip       = trim((string)($cve['ip'] ?? ''));
            $osName   = trim((string)($cve['os_name'] ?? ''));
            $title    = htmlspecialchars(self::short((string)($cve['title'] ?? ''), 90));
            $affected = (int)($cve['affected_count'] ?? 0);
            $cvss     = $cve['cvss'] ?? null;
            if ($cvss !== null && $cvss !== '') {
                $cvssSum += (float)$cvss;
                $cvssCount++;
            }

            $endpointMeta = '';
            if ($ip !== '' || $osName !== '') {
                $endpointMeta = "<br><span style='color:#9ca3af;font-size:11px'>" . htmlspecialchars(trim($ip . ($ip !== '' && $osName !== '' ? ' · ' : '') . $osName)) . '</span>';
            }

            $nvdLink = $cve['cve_id'] ?? ''
                ? "<a href='https://nvd.nist.gov/vuln/detail/" . rawurlencode((string)$cve['cve_id']) . "' style='color:#e8212a;text-decoration:none;font-weight:bold'>{$cveId}</a>"
                : $cveId;

            $rows .= "<tr>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;font-family:monospace;vertical-align:top'>{$nvdLink}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top;color:#4a5568'>{$title}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top'>{$endpoint}{$endpointMeta}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;color:#e8212a;font-weight:bold;vertical-align:top'>" . htmlspecialchars((string)($cve['cvss'] ?? '-')) . "</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top;color:#4a5568'>" . ($affected > 0 ? $affected : '-') . "</td>
            </tr>";
        }

        $avgCvss = $cvssCount > 0 ? number_format($cvssSum / $cvssCount, 1) : '-';

        return "<!DOCTYPE html><html><body style='font-family:Segoe UI,Arial,sans-serif;color:#1a1a2e;background:#f5f5f5'>
<div style='max-width:680px;margin:24px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)'>
  <div style='background:linear-gradient(120deg,#7a0d1f 0%,#e8212a 100%);padding:20px 24px;color:#fff'>
    <table style='border-collapse:collapse;margin-bottom:10px'><tr>
      <td style='width:34px;height:34px;border-radius:50%;background:rgba(255,255,255,.18);color:#fff;font-weight:900;font-size:17px;text-align:center;vertical-align:middle'>T</td>
      <td style='padding-left:10px;font-size:18px;font-weight:800;letter-spacing:2px;vertical-align:middle'>TANIUM</td>
    </tr></table>
    <h1 style='margin:0;font-size:18px'>🚨 {$newCritical} novo(s) CVE(s) crítico(s) detectado(s)</h1>
    <p style='margin:8px 0 0;opacity:.85;font-size:13px'>GLPI Tanium Plugin — " . date('d/m/Y H:i') . "</p>
  </div>
  <div style='background:#f9fafb;padding:12px 24px;border-bottom:1px solid #eee;display:flex;gap:24px;font-size:12px;color:#4a5568'>
    <span>CVSS médio: <strong style='color:#1a1a2e'>{$avgCvss}</strong></span>
    <span>Endpoints afetados: <strong style='color:#1a1a2e'>" . count(array_unique(array_column($criticalCves, 'endpoint'))) . "</strong></span>
  </div>
  <div style='padding:20px 24px'>
    <p>O Tanium detectou <strong>{$newCritical} novo(s) CVE(s) crítico(s)</strong> durante a última sincronização.</p>
    <table style='width:100%;border-collapse:collapse;margin:16px 0;font-size:13px'>
      <thead><tr style='background:#f9fafb'>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>CVE ID</th>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>Título</th>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>Endpoint</th>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>CVSS</th>
        <th style='padding:8px 12px;text-align:left;border-bottom:2px solid #e8212a'>Afetados</th>
      </tr></thead>
      <tbody>{$rows}</tbody>
    </table>
    <a href='{$glpiUrl}' style='display:inline-block;background:#e8212a;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold;margin-top:8px'>
      Ver no GLPI
    </a>
  </div>
  <div style='background:#f9fafb;padding:14px 24px;font-size:11px;color:#9ca3af;border-top:1px solid #eee'>
    Gerado automaticamente pelo plugin Tanium para GLPI. Relatório completo em anexo (PDF).
  </div>
</div></body></html>";
    }

    private static function short(string $value, int $length): string {
        if ($value === '') {
            return '';
        }
        if (function_exists('mb_strlen') && mb_strlen($value) <= $length) {
            return $value;
        }
        if (!function_exists('mb_strlen') && strlen($value) <= $length) {
            return $value;
        }

        return function_exists('mb_substr') ? mb_substr($value, 0, $length - 1) . '…' : substr($value, 0, $length - 1) . '…';
    }
}
