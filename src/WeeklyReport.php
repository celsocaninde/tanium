<?php

namespace GlpiPlugin\Tanium;

use CronTask;
use Plugin;
use Toolbox;

class WeeklyReport {

    // ── GLPI cron entry point ─────────────────────────────────────────────

    /**
     * Runs hourly (see setup.php); only sends on the configured day-of-week
     * and from the configured hour on, at most once per week.
     */
    public static function cronWeeklyreport(CronTask $task): int {
        $config = Config::getConfig();

        $emails = Config::resolveNotifyRecipients($config);
        if (empty($emails)) {
            $task->log('No notification email configured — skipping weekly report.');
            return 0;
        }

        $day  = max(0, min(6, (int)($config['report_day'] ?? 1)));   // 0=Sunday … 6=Saturday
        $hour = max(0, min(23, (int)($config['report_hour'] ?? 8)));
        if ((int)date('w') !== $day || (int)date('G') < $hour) {
            return 0;
        }

        // Already sent this week? (6-day guard tolerates cron latency)
        $last = $config['last_weekly_report'] ?? null;
        if (!empty($last) && strtotime($last) > time() - 6 * DAY_TIMESTAMP) {
            return 0;
        }

        $sent = self::send();
        $task->addVolume($sent);
        $task->log("Weekly report sent to {$sent} recipient(s).");
        return $sent > 0 ? 1 : 0;
    }

    /**
     * Builds and emails the report to every configured recipient, right now
     * (no schedule gate). Used by the cron and by the "Send report now"
     * button in the configuration page.
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
        $subject = sprintf('[Tanium] Weekly Security Report — %s', date('d/m/Y'));

        $attachments = [];
        $pdf = PdfReport::weekly($stats, $baseUrl);
        if ($pdf !== null) {
            $attachments[] = [
                'filename' => 'tanium-relatorio-semanal-' . date('Y-m-d') . '.pdf',
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
                'last_weekly_report' => date('Y-m-d H:i:s'),
            ], ['id' => $config['id']]);
        }

        return $sent;
    }

    // ── Stat gathering ────────────────────────────────────────────────────

    /** Also consumed by MonthlyReport as the "current posture" baseline. */
    public static function gatherStats(): array {
        global $DB;

        $stats = [
            'total_endpoints'    => 0,
            'critical_endpoints' => 0,
            'total_cves'         => 0,
            'critical_cves'      => 0,
            'high_cves'          => 0,
            'patches_missing'    => 0,
            'patch_compliance'   => null,
            'avg_risk'           => 0,
            'top_endpoints'      => [],
            'top_cves'           => [],
            'recent_syncs'       => [],
            'sla_breaches'       => 0,
            'new_assignments'    => 0,
            'open_exceptions'    => 0,
            'expired_exceptions' => 0,
        ];

        // Endpoint counts
        $row = $DB->doQuery("SELECT COUNT(*) AS cnt, ROUND(AVG(risk_score),1) AS avg_risk,
                                    COUNT(CASE WHEN risk_score >= 70 THEN 1 END) AS crit
                             FROM glpi_plugin_tanium_assets")->fetch_assoc();
        $stats['total_endpoints']    = (int)($row['cnt']      ?? 0);
        $stats['avg_risk']           = (float)($row['avg_risk'] ?? 0);
        $stats['critical_endpoints'] = (int)($row['crit']     ?? 0);

        // CVE counts
        $cveRow = $DB->doQuery("SELECT COUNT(*) AS total,
                                       COUNT(CASE WHEN severity='critical' THEN 1 END) AS crit,
                                       COUNT(CASE WHEN severity='high' THEN 1 END) AS hi
                                FROM glpi_plugin_tanium_vulnerabilities")->fetch_assoc();
        $stats['total_cves']    = (int)($cveRow['total'] ?? 0);
        $stats['critical_cves'] = (int)($cveRow['crit']  ?? 0);
        $stats['high_cves']     = (int)($cveRow['hi']    ?? 0);

        // Patch compliance
        $pRow = $DB->doQuery("SELECT COUNT(*) AS total, COUNT(CASE WHEN status='missing' THEN 1 END) AS missing FROM glpi_plugin_tanium_patches")->fetch_assoc();
        $stats['patches_missing'] = (int)($pRow['missing'] ?? 0);
        if (($pRow['total'] ?? 0) > 0) {
            $stats['patch_compliance'] = (int)round((1 - $pRow['missing'] / $pRow['total']) * 100);
        }

        // Top 5 risky endpoints
        foreach ($DB->doQuery("SELECT tanium_name, ip_address, os_name, risk_score FROM glpi_plugin_tanium_assets ORDER BY risk_score DESC LIMIT 5") as $r) {
            $stats['top_endpoints'][] = $r;
        }

        // Top 5 CVEs by CVSS
        foreach ($DB->doQuery("SELECT cve_id, severity, cvss_score, title, affected_count FROM glpi_plugin_tanium_vulnerabilities ORDER BY cvss_score DESC LIMIT 5") as $r) {
            $stats['top_cves'][] = $r;
        }

        // Recent syncs
        foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_sync_logs', 'ORDER' => 'started_at DESC', 'LIMIT' => 3]) as $r) {
            $stats['recent_syncs'][] = $r;
        }

        // SLA breaches (open CVEs detected > SLA days ago)
        $config  = Config::getConfig();
        $critDays = (int)($config['sla_critical_days'] ?? 7);
        $highDays = (int)($config['sla_high_days']     ?? 30);
        $medDays  = (int)($config['sla_medium_days']   ?? 90);
        $slaRow = $DB->doQuery("
            SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
            " . Sla::activeExceptionJoin() . "
            WHERE ec.status != 'remediated'
            AND ex.id IS NULL
            AND (
                (v.severity = 'critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$critDays} DAY))
                OR (v.severity = 'high'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$highDays} DAY))
                OR (v.severity = 'medium' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$medDays} DAY))
            )
        ")->fetch_assoc();
        $stats['sla_breaches'] = (int)($slaRow['cnt'] ?? 0);

        // Open assignments
        $aRow = $DB->request(['FROM' => 'glpi_plugin_tanium_cve_assignments', 'WHERE' => ['status' => ['!=', 'resolved']], 'COUNT' => 'cpt'])->current();
        $stats['new_assignments'] = (int)($aRow['cpt'] ?? 0);

        // MTTR (90-day window) for the executive summary line
        $stats['mttr_overall'] = Sla::getMttr(90)['overall'];

        // Remediation over the report week (cve_history + patch_history)
        $rem = Remediation::getStats(7);
        $stats['remediated_cves_7d']   = $rem['cves_remediated'];
        $stats['patches_installed_7d'] = $rem['patches_installed'];
        $stats['endpoints_fixed_7d']   = $rem['endpoints_touched'];
        $stats['top_remediators']      = array_slice(Remediation::getByEndpoint(7, 5), 0, 5);

        // Open (active) exceptions — expired ones no longer suppress risk
        $eRow = $DB->doQuery("
            SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_cve_exceptions
            WHERE expires_at IS NULL OR expires_at > NOW()
        ")->fetch_assoc();
        $stats['open_exceptions'] = (int)($eRow['cpt'] ?? 0);

        // Expired exceptions — risk acceptances that lapsed and need review
        $xRow = $DB->doQuery("
            SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_cve_exceptions
            WHERE expires_at IS NOT NULL AND expires_at <= NOW()
        ")->fetch_assoc();
        $stats['expired_exceptions'] = (int)($xRow['cpt'] ?? 0);

        return $stats;
    }

    // ── HTML email builder ────────────────────────────────────────────────

    private static function buildHtml(array $s): string {
        global $CFG_GLPI;
        $baseUrl    = $CFG_GLPI['url_base'] ?? '';
        $pluginUrl  = $baseUrl . '/plugins/tanium';
        $compliance = $s['patch_compliance'] !== null ? $s['patch_compliance'] . '%' : 'N/A';
        $compColor  = $s['patch_compliance'] === null ? '#6b7280' : ($s['patch_compliance'] >= 90 ? '#1a9c53' : ($s['patch_compliance'] >= 70 ? '#c2860a' : '#d6336c'));
        $slaColor   = $s['sla_breaches'] > 0 ? '#d6336c' : '#1a9c53';

        $mttrLabel = isset($s['mttr_overall']) && $s['mttr_overall'] !== null
            ? $s['mttr_overall'] . ' dias'
            : '—';

        $expiredEx      = (int)($s['expired_exceptions'] ?? 0);
        $expiredExColor = $expiredEx > 0 ? '#d6336c' : '#1c2330';
        $expiredExBanner = '';
        if ($expiredEx > 0) {
            $expiredExBanner = "
  <div style=\"background:#fdecef;border-left:4px solid #e8212a;margin:0 28px 16px;padding:12px 16px;font-size:12px;color:#8a1f28\">
    ⚠️ <strong>{$expiredEx}</strong> exceção(ões) de risco expiraram e os CVEs voltaram a contar no SLA. Revise em <em>CVE Exceptions</em>.
  </div>";
        }
        $generatedAt = date('d/m/Y H:i');

        $topEpRows = '';
        foreach ($s['top_endpoints'] as $ep) {
            $rs = (int)$ep['risk_score'];
            $c  = $rs >= 70 ? '#d6336c' : ($rs >= 40 ? '#e8590c' : ($rs >= 15 ? '#c2860a' : '#1a9c53'));
            $topEpRows .= "<tr>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;font-family:Consolas,monospace;font-size:12px;color:#1c2330'>{$ep['tanium_name']}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#6b7280'>{$ep['ip_address']}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:{$c};font-weight:700'>{$rs}</td>
            </tr>";
        }

        $remCves     = (int)($s['remediated_cves_7d'] ?? 0);
        $remPatches  = (int)($s['patches_installed_7d'] ?? 0);
        $remSection  = '';
        if ($remCves + $remPatches > 0) {
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
                : '';
            $remSection = "
  <!-- Remediation of the week -->
  <div style=\"background:#f0faf4;padding:20px 28px;border-top:1px solid #d3ecdc\">
    <div style=\"font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#1a9c53;border-left:3px solid #1a9c53;padding-left:8px;margin-bottom:12px\">Remediação nos últimos 7 dias</div>
    <div style=\"display:flex;gap:0;margin-bottom:12px\">
      <div style=\"flex:1;text-align:center;padding:0 12px;border-right:1px solid #d3ecdc\">
        <div style=\"font-size:22px;font-weight:800;color:#1a9c53\">{$remCves}</div>
        <div style=\"font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em\">CVEs Remediados</div>
      </div>
      <div style=\"flex:1;text-align:center;padding:0 12px;border-right:1px solid #d3ecdc\">
        <div style=\"font-size:22px;font-weight:800;color:#1a6dff\">{$remPatches}</div>
        <div style=\"font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em\">Patches Instalados</div>
      </div>
      <div style=\"flex:1;text-align:center;padding:0 12px\">
        <div style=\"font-size:22px;font-weight:800;color:#1c2330\">" . (int)($s['endpoints_fixed_7d'] ?? 0) . "</div>
        <div style=\"font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em\">Endpoints Corrigidos</div>
      </div>
    </div>
    {$remTable}
  </div>";
        } else {
            $remSection = "
  <div style=\"background:#f9fafb;padding:14px 28px;border-top:1px solid #eeeeee;font-size:12px;color:#6b7280\">
    Nenhuma remediação registrada nos últimos 7 dias.
  </div>";
        }

        $topCveRows = '';
        foreach ($s['top_cves'] as $cve) {
            $sc = strtolower($cve['severity']);
            $c  = match($sc) { 'critical' => '#d6336c', 'high' => '#e8590c', 'medium' => '#c2860a', default => '#1a9c53' };
            $cveIdEsc = htmlspecialchars($cve['cve_id']);
            $title    = htmlspecialchars(self::short((string)($cve['title'] ?? ''), 70));
            $nvdLink  = "<a href='https://nvd.nist.gov/vuln/detail/" . rawurlencode($cve['cve_id']) . "' style='color:#1c2330;text-decoration:none;font-weight:700'>{$cveIdEsc}</a>";
            $topCveRows .= "<tr>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;font-family:Consolas,monospace;font-size:12px;color:#1c2330'>{$nvdLink}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#4a5568;font-size:12px'>{$title}</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:{$c};font-weight:700'>" . ucfirst($cve['severity']) . "</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#6b7280'>" . ($cve['cvss_score'] ?? '—') . "</td>
                <td style='padding:8px 12px;border-bottom:1px solid #eeeeee;color:#6b7280'>" . (int)$cve['affected_count'] . " endpoints</td>
            </tr>";
        }

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
    <div style="color:rgba(255,255,255,.85);font-size:13px">Weekly Security Report — {$baseUrl}</div>
    <div style="color:rgba(255,255,255,.75);font-size:12px;margin-top:4px">{$s['total_endpoints']} endpoints monitorados · Gerado em {$generatedAt}</div>
  </div>

  <!-- KPIs -->
  <div style="background:#f9fafb;padding:20px 28px;display:flex;gap:0;border-bottom:1px solid #eeeeee">
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:26px;font-weight:800;color:#d6336c">{$s['critical_endpoints']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Critical Endpoints</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:26px;font-weight:800;color:#d6336c">{$s['critical_cves']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Critical CVEs</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:26px;font-weight:800;color:{$compColor}">{$compliance}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Patch Compliance</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px">
      <div style="font-size:26px;font-weight:800;color:{$slaColor}">{$s['sla_breaches']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">SLA Breaches</div>
    </div>
  </div>

  <!-- KPIs (linha 2) -->
  <div style="background:#ffffff;padding:14px 28px;display:flex;gap:0;border-bottom:1px solid #eeeeee">
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:20px;font-weight:800;color:#e8590c">{$s['high_cves']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">CVEs Altos</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:20px;font-weight:800;color:#c2860a">{$s['patches_missing']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Patches Ausentes</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #e5e7eb">
      <div style="font-size:20px;font-weight:800;color:#1c2330">{$s['total_cves']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Total de CVEs</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px">
      <div style="font-size:20px;font-weight:800;color:#1c2330">{$s['avg_risk']}</div>
      <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Risco Médio</div>
    </div>
  </div>

  <!-- Top endpoints -->
  <div style="background:#ffffff;padding:20px 28px">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#e8212a;border-left:3px solid #e8212a;padding-left:8px;margin-bottom:12px">Top Risk Endpoints</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="color:#6b7280">
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">Name</th>
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">IP</th>
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">Risk</th>
      </tr></thead>
      <tbody>{$topEpRows}</tbody>
    </table>
  </div>

  <!-- Top CVEs -->
  <div style="background:#f9fafb;padding:20px 28px;border-top:1px solid #eeeeee">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#e8212a;border-left:3px solid #e8212a;padding-left:8px;margin-bottom:12px">Top CVEs by CVSS</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="color:#6b7280">
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">CVE ID</th>
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">Título</th>
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">Severity</th>
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">CVSS</th>
        <th style="padding:4px 12px;text-align:left;font-size:11px;text-transform:uppercase">Affected</th>
      </tr></thead>
      <tbody>{$topCveRows}</tbody>
    </table>
  </div>

  {$remSection}

  <!-- Summary line -->
  <div style="background:#ffffff;padding:16px 28px;border-top:1px solid #eeeeee;font-size:12px;color:#6b7280;display:flex;justify-content:space-between">
    <span>Atribuições abertas: <strong style="color:#1c2330">{$s['new_assignments']}</strong></span>
    <span>Exceções ativas: <strong style="color:#1c2330">{$s['open_exceptions']}</strong></span>
    <span>Exceções expiradas: <strong style="color:{$expiredExColor}">{$expiredEx}</strong></span>
    <span>MTTR 90d: <strong style="color:#1c2330">{$mttrLabel}</strong></span>
  </div>
  {$expiredExBanner}

  <!-- CTA -->
  <div style="background:#f9fafb;padding:20px 28px;text-align:center;border-top:1px solid #eeeeee">
    <a href="{$pluginUrl}/front/dashboard.php" style="background:#e8212a;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;font-size:13px">
      View Dashboard
    </a>
    &nbsp;&nbsp;
    <a href="{$pluginUrl}/front/report.php" style="background:#1a6dff;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;font-size:13px">
      Full Report
    </a>
  </div>

</div>
</body>
</html>
HTML;
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
