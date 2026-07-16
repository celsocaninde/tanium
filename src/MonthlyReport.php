<?php

namespace GlpiPlugin\Tanium;

use CronTask;

/**
 * Monthly security report by email: 30-day remediation trend + how the
 * posture moved against ~30 days ago, on top of the current-state stats the
 * weekly report already gathers.
 */
class MonthlyReport {

    // ── GLPI cron entry point ─────────────────────────────────────────────

    /**
     * Runs hourly (see setup.php); sends on the configured day-of-month, from
     * the configured hour on, at most once a month.
     */
    public static function cronMonthlyreport(CronTask $task): int {
        $config = Config::getConfig();

        $emails = Config::resolveNotifyRecipients($config);
        if (empty($emails)) {
            $task->log('No notification email configured — skipping monthly report.');
            return 0;
        }

        $day  = max(1, min(28, (int)($config['monthly_report_day'] ?? 1)));
        $hour = max(0, min(23, (int)($config['report_hour'] ?? 8)));
        if ((int)date('j') !== $day || (int)date('G') < $hour) {
            return 0;
        }

        // Already sent this month? (25-day guard tolerates cron latency)
        $last = $config['last_monthly_report'] ?? null;
        if (!empty($last) && strtotime($last) > time() - 25 * DAY_TIMESTAMP) {
            return 0;
        }

        $sent = self::send();
        $task->addVolume($sent);
        $task->log("Monthly report sent to {$sent} recipient(s).");
        return $sent > 0 ? 1 : 0;
    }

    /**
     * Builds and emails the report right now (no schedule gate). Used by the
     * cron and by the "Send monthly report now" button.
     *
     * @return int number of recipients the email was sent to
     */
    public static function send(): int {
        global $CFG_GLPI, $DB;

        $config = Config::getConfig();
        $emails = Config::resolveNotifyRecipients($config);
        if (empty($emails)) {
            return 0;
        }

        $baseUrl = $CFG_GLPI['url_base'] ?? '';

        $stats   = self::gatherStats();
        $html    = self::buildHtml($stats);
        $subject = sprintf('[Tanium] Relatório Mensal de Segurança — %s', date('m/Y'));

        $attachments = [];
        $pdf = PdfReport::monthly($stats, $baseUrl);
        if ($pdf !== null) {
            $attachments[] = [
                'filename' => 'tanium-relatorio-mensal-' . date('Y-m') . '.pdf',
                'content'  => $pdf,
                'mime'     => 'application/pdf',
            ];
        }

        $sent = 0;
        foreach ($emails as $to) {
            if (Notification::sendEmail($to, $subject, $html, $attachments)) {
                $sent++;
            }
        }

        if ($sent > 0 && ($config['id'] ?? 0) > 0) {
            $DB->update('glpi_plugin_tanium_configs', [
                'last_monthly_report' => date('Y-m-d H:i:s'),
            ], ['id' => $config['id']]);
        }

        return $sent;
    }

    // ── Stat gathering ────────────────────────────────────────────────────

    private static function gatherStats(): array {
        global $DB;

        // Current posture — same base the weekly report uses
        $stats = WeeklyReport::gatherStats();

        // 30-day remediation trend
        $rem = Remediation::getStats(30);
        $stats['remediated_cves_30d']   = $rem['cves_remediated'];
        $stats['patches_installed_30d'] = $rem['patches_installed'];
        $stats['endpoints_fixed_30d']   = $rem['endpoints_touched'];
        $stats['mttr_30d']              = Sla::getMttr(30)['overall'];
        $stats['top_remediators']       = array_slice(Remediation::getByEndpoint(30, 5), 0, 5);

        // New findings that appeared in the month
        $row = $DB->doQuery("
            SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_cve_history
            WHERE old_status IS NULL
              AND changed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        ")->fetch_assoc();
        $stats['new_findings_30d'] = (int)($row['cpt'] ?? 0);

        // Posture ~30 days ago from the risk-history snapshots (closest one at
        // or before the 30-day mark; falls back to the oldest snapshot).
        $baseline = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_risk_history',
            'WHERE' => ['recorded_at' => ['<=', date('Y-m-d H:i:s', time() - 30 * DAY_TIMESTAMP)]],
            'ORDER' => 'recorded_at DESC',
            'LIMIT' => 1,
        ])->current();
        if ($baseline === null) {
            $baseline = $DB->request([
                'FROM'  => 'glpi_plugin_tanium_risk_history',
                'ORDER' => 'recorded_at ASC',
                'LIMIT' => 1,
            ])->current();
        }
        $stats['baseline'] = $baseline; // null when no history at all

        return $stats;
    }

    // ── HTML email builder ────────────────────────────────────────────────

    private static function buildHtml(array $s): string {
        global $CFG_GLPI;
        $baseUrl   = $CFG_GLPI['url_base'] ?? '';
        $pluginUrl = $baseUrl . '/plugins/tanium';

        $generatedAt = date('d/m/Y H:i');
        $monthLabel  = date('m/Y');

        // ── Remediation block ────────────────────────────────────────────
        $remCves    = (int)($s['remediated_cves_30d'] ?? 0);
        $remPatches = (int)($s['patches_installed_30d'] ?? 0);
        $mttr30     = $s['mttr_30d'] !== null ? number_format((float)$s['mttr_30d'], 1) . ' dias' : '—';

        $remRows = '';
        foreach (($s['top_remediators'] ?? []) as $ep) {
            $remRows .= "<tr>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;font-family:Consolas,monospace;font-size:12px;color:#1c2330'>" . htmlspecialchars((string)$ep['name']) . "</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#1a9c53;font-weight:700'>" . (int)$ep['cves_fixed'] . "</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#1a6dff;font-weight:700'>" . (int)$ep['patches_fixed'] . "</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#6b7280'>" . ($ep['avg_days'] !== null ? number_format((float)$ep['avg_days'], 1) . ' d' : '—') . "</td>
            </tr>";
        }
        $remTable = $remRows !== ''
            ? "<table style='width:100%;border-collapse:collapse;font-size:13px'>
                <thead><tr style='color:#6b7280'>
                    <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Endpoint</th>
                    <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>CVEs</th>
                    <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Patches</th>
                    <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Tempo médio</th>
                </tr></thead><tbody>{$remRows}</tbody></table>"
            : "<p style='font-size:12px;color:#6b7280;margin:0'>Nenhuma remediação registrada no período.</p>";

        // ── Posture delta vs baseline ────────────────────────────────────
        $deltaSection = '';
        $baseline = $s['baseline'] ?? null;
        if ($baseline !== null) {
            $deltaRow = static function (string $label, int $now, int $then): string {
                $diff  = $now - $then;
                $color = $diff > 0 ? '#d6336c' : ($diff < 0 ? '#1a9c53' : '#6b7280');
                $sign  = $diff > 0 ? '+' : '';
                return "<tr>
                    <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#4a5568'>{$label}</td>
                    <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#6b7280'>{$then}</td>
                    <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#1c2330;font-weight:700'>{$now}</td>
                    <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:{$color};font-weight:700'>{$sign}{$diff}</td>
                </tr>";
            };

            $baselineDate = date('d/m/Y', strtotime((string)$baseline['recorded_at']));
            $deltaSection = "
  <div style=\"background:#ffffff;padding:20px 28px;border-top:1px solid #eeeeee\">
    <div style=\"font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#e8212a;border-left:3px solid #e8212a;padding-left:8px;margin-bottom:12px\">Evolução da postura — vs {$baselineDate}</div>
    <table style='width:100%;border-collapse:collapse;font-size:13px'>
      <thead><tr style='color:#6b7280'>
        <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Indicador</th>
        <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Antes</th>
        <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Agora</th>
        <th style='padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase'>Δ</th>
      </tr></thead>
      <tbody>"
                . $deltaRow('Total de CVEs', (int)$s['total_cves'], (int)$baseline['total_cves'])
                . $deltaRow('CVEs críticos', (int)$s['critical_cves'], (int)$baseline['critical_cves'])
                . $deltaRow('Patches ausentes', (int)$s['patches_missing'], (int)$baseline['patches_missing'])
                . $deltaRow('Risco médio', (int)round((float)$s['avg_risk']), (int)round((float)$baseline['avg_risk']))
                . "</tbody>
    </table>
  </div>";
        }

        $compliance = $s['patch_compliance'] !== null ? $s['patch_compliance'] . '%' : 'N/A';
        $compColor  = $s['patch_compliance'] === null ? '#6b7280' : ($s['patch_compliance'] >= 90 ? '#1a9c53' : ($s['patch_compliance'] >= 70 ? '#c2860a' : '#d6336c'));
        $slaColor   = $s['sla_breaches'] > 0 ? '#d6336c' : '#1a9c53';

        return <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:24px 0;background:#f1f3f7;font-family:'Segoe UI',Arial,sans-serif;color:#1c2330">
<div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #e3e1ee;border-radius:12px;overflow:hidden">

  <!-- Header -->
  <div style="background:linear-gradient(120deg,#7a0d1f 0%,#e8212a 100%);padding:24px 28px">
    <table style="border-collapse:collapse;margin-bottom:6px"><tr>
      <td style="width:34px;height:34px;border-radius:50%;background:rgba(255,255,255,.18);color:#fff;font-weight:900;font-size:17px;text-align:center;vertical-align:middle">T</td>
      <td style="padding-left:10px;font-size:20px;font-weight:800;color:#fff;letter-spacing:2px;vertical-align:middle">TANIUM</td>
    </tr></table>
    <div style="color:rgba(255,255,255,.85);font-size:13px">Relatório Mensal de Segurança — {$monthLabel}</div>
    <div style="color:rgba(255,255,255,.75);font-size:12px;margin-top:4px">{$s['total_endpoints']} endpoints monitorados · Gerado em {$generatedAt}</div>
  </div>

  <!-- Remediation of the month (headline) -->
  <div style="background:#f0faf4;padding:20px 28px;border-bottom:1px solid #d3ecdc">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#1a9c53;border-left:3px solid #1a9c53;padding-left:8px;margin-bottom:12px">Remediação nos últimos 30 dias</div>
    <div style="display:flex;gap:0;margin-bottom:14px">
      <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #d3ecdc">
        <div style="font-size:26px;font-weight:800;color:#1a9c53">{$remCves}</div>
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">CVEs Remediados</div>
      </div>
      <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #d3ecdc">
        <div style="font-size:26px;font-weight:800;color:#1a6dff">{$remPatches}</div>
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Patches Instalados</div>
      </div>
      <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #d3ecdc">
        <div style="font-size:26px;font-weight:800;color:#1c2330">{$s['endpoints_fixed_30d']}</div>
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Endpoints Corrigidos</div>
      </div>
      <div style="flex:1;text-align:center;padding:0 12px">
        <div style="font-size:26px;font-weight:800;color:#1c2330">{$mttr30}</div>
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">MTTR do Mês</div>
      </div>
    </div>
    {$remTable}
  </div>

  {$deltaSection}

  <!-- Current posture -->
  <div style="background:#f9fafb;padding:20px 28px;display:flex;gap:0;border-top:1px solid #eeeeee;border-bottom:1px solid #eeeeee">
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:22px;font-weight:800;color:#d6336c">{$s['critical_cves']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">CVEs Críticos Abertos</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:22px;font-weight:800;color:#c2860a">{$s['new_findings_30d']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Novos Findings (30d)</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:22px;font-weight:800;color:{$compColor}">{$compliance}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Patch Compliance</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px">
      <div style="font-size:22px;font-weight:800;color:{$slaColor}">{$s['sla_breaches']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">SLA Breaches</div>
    </div>
  </div>

  <!-- CTA -->
  <div style="background:#f9fafb;padding:20px 28px;text-align:center;border-top:1px solid #eeeeee">
    <a href="{$pluginUrl}/front/remediation.php" style="background:#1a9c53;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;font-size:13px">
      Tendência de Remediação
    </a>
    &nbsp;&nbsp;
    <a href="{$pluginUrl}/front/dashboard.php" style="background:#e8212a;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;font-size:13px">
      Dashboard
    </a>
  </div>

  <div style="background:#ffffff;padding:14px 28px;font-size:11px;color:#9ca3af;border-top:1px solid #eee">
    Gerado automaticamente pelo plugin Tanium para GLPI. Relatório completo em anexo (PDF).
  </div>

</div>
</body>
</html>
HTML;
    }
}
