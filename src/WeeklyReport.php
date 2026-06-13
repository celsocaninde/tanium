<?php

namespace GlpiPlugin\Tanium;

use CronTask;
use Plugin;
use Toolbox;

class WeeklyReport {

    // ── GLPI cron entry point ─────────────────────────────────────────────

    public static function cronWeeklyreport(CronTask $task): int {
        $config = Config::getConfig();

        $emails = array_filter(array_map('trim', explode(',', $config['notify_email'] ?? '')));
        if (empty($emails)) {
            $task->log('No notification email configured — skipping weekly report.');
            return 0;
        }

        $stats  = self::gatherStats();
        $html   = self::buildHtml($stats);
        $subject = sprintf('[Tanium] Weekly Security Report — %s', date('d/m/Y'));

        $sent = 0;
        foreach ($emails as $to) {
            if (Notification::sendEmail($to, $subject, $html)) {
                $sent++;
            }
        }

        $task->addVolume($sent);
        $task->log("Weekly report sent to {$sent} recipient(s).");
        return $sent > 0 ? 1 : 0;
    }

    // ── Stat gathering ────────────────────────────────────────────────────

    private static function gatherStats(): array {
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
        ];

        // Endpoint counts
        $row = $DB->doQuery("SELECT COUNT(*) AS cnt, ROUND(AVG(risk_score),1) AS avg_risk,
                                    COUNT(CASE WHEN risk_score >= 70 THEN 1 END) AS crit
                             FROM glpi_plugin_tanium_assets")->current();
        $stats['total_endpoints']    = (int)($row['cnt']      ?? 0);
        $stats['avg_risk']           = (float)($row['avg_risk'] ?? 0);
        $stats['critical_endpoints'] = (int)($row['crit']     ?? 0);

        // CVE counts
        $cveRow = $DB->doQuery("SELECT COUNT(*) AS total,
                                       COUNT(CASE WHEN severity='critical' THEN 1 END) AS crit,
                                       COUNT(CASE WHEN severity='high' THEN 1 END) AS hi
                                FROM glpi_plugin_tanium_vulnerabilities")->current();
        $stats['total_cves']    = (int)($cveRow['total'] ?? 0);
        $stats['critical_cves'] = (int)($cveRow['crit']  ?? 0);
        $stats['high_cves']     = (int)($cveRow['hi']    ?? 0);

        // Patch compliance
        $pRow = $DB->doQuery("SELECT COUNT(*) AS total, COUNT(CASE WHEN status='missing' THEN 1 END) AS missing FROM glpi_plugin_tanium_patches")->current();
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
            WHERE ec.status != 'remediated'
            AND (
                (v.severity = 'critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$critDays} DAY))
                OR (v.severity = 'high'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$highDays} DAY))
                OR (v.severity = 'medium' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$medDays} DAY))
            )
        ")->current();
        $stats['sla_breaches'] = (int)($slaRow['cnt'] ?? 0);

        // Open assignments
        $aRow = $DB->request(['FROM' => 'glpi_plugin_tanium_cve_assignments', 'WHERE' => ['status' => ['!=', 'resolved']], 'COUNT' => 'id'])->current();
        $stats['new_assignments'] = (int)($aRow['cpt'] ?? 0);

        // Open exceptions
        $eRow = $DB->request(['FROM' => 'glpi_plugin_tanium_cve_exceptions', 'COUNT' => 'id'])->current();
        $stats['open_exceptions'] = (int)($eRow['cpt'] ?? 0);

        return $stats;
    }

    // ── HTML email builder ────────────────────────────────────────────────

    private static function buildHtml(array $s): string {
        global $CFG_GLPI;
        $baseUrl    = $CFG_GLPI['url_base'] ?? '';
        $pluginUrl  = $baseUrl . '/plugins/tanium';
        $compliance = $s['patch_compliance'] !== null ? $s['patch_compliance'] . '%' : 'N/A';
        $compColor  = $s['patch_compliance'] === null ? '#7a8da8' : ($s['patch_compliance'] >= 90 ? '#1eb464' : ($s['patch_compliance'] >= 70 ? '#e8c42a' : '#e8212a'));
        $slaColor   = $s['sla_breaches'] > 0 ? '#e8212a' : '#1eb464';

        $topEpRows = '';
        foreach ($s['top_endpoints'] as $ep) {
            $rs = (int)$ep['risk_score'];
            $c  = $rs >= 70 ? '#e8212a' : ($rs >= 40 ? '#f97316' : ($rs >= 15 ? '#f59e0b' : '#1eb464'));
            $topEpRows .= "<tr>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;font-family:monospace;color:#ccd6f6'>{$ep['tanium_name']}</td>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;color:#7a8da8'>{$ep['ip_address']}</td>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;color:{$c};font-weight:700'>{$rs}</td>
            </tr>";
        }

        $topCveRows = '';
        foreach ($s['top_cves'] as $cve) {
            $sc = strtolower($cve['severity']);
            $c  = match($sc) { 'critical' => '#e8212a', 'high' => '#f97316', 'medium' => '#f59e0b', default => '#1eb464' };
            $topCveRows .= "<tr>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;font-family:monospace;color:#ccd6f6'>" . htmlspecialchars($cve['cve_id']) . "</td>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;color:{$c};font-weight:700'>" . ucfirst($cve['severity']) . "</td>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;color:#7a8da8'>" . ($cve['cvss_score'] ?? '—') . "</td>
                <td style='padding:6px 12px;border-bottom:1px solid #2a2a3e;color:#7a8da8'>" . (int)$cve['affected_count'] . " endpoints</td>
            </tr>";
        }

        return <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0e0e1a;font-family:Segoe UI,Arial,sans-serif;color:#ccd6f6">
<div style="max-width:640px;margin:24px auto">

  <!-- Header -->
  <div style="background:#e8212a;padding:24px 28px;border-radius:10px 10px 0 0">
    <div style="display:flex;align-items:center;gap:12px">
      <div style="font-size:22px;font-weight:800;color:#fff;letter-spacing:-.5px">TANIUM</div>
      <div style="color:rgba(255,255,255,.7);font-size:13px">Weekly Security Report — {$baseUrl}</div>
    </div>
    <div style="color:rgba(255,255,255,.6);font-size:12px;margin-top:4px">{$s['total_endpoints']} endpoints monitored · Generated {date('d/m/Y H:i')}</div>
  </div>

  <!-- KPIs -->
  <div style="background:#16162a;padding:20px 28px;display:flex;gap:0;border-bottom:1px solid #2a2a3e">
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #2a2a3e">
      <div style="font-size:26px;font-weight:800;color:#e8212a">{$s['critical_endpoints']}</div>
      <div style="font-size:11px;color:#7a8da8;text-transform:uppercase;letter-spacing:.06em">Critical Endpoints</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #2a2a3e">
      <div style="font-size:26px;font-weight:800;color:#e8212a">{$s['critical_cves']}</div>
      <div style="font-size:11px;color:#7a8da8;text-transform:uppercase;letter-spacing:.06em">Critical CVEs</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px;border-right:1px solid #2a2a3e">
      <div style="font-size:26px;font-weight:800;color:{$compColor}">{$compliance}</div>
      <div style="font-size:11px;color:#7a8da8;text-transform:uppercase;letter-spacing:.06em">Patch Compliance</div>
    </div>
    <div style="flex:1;text-align:center;padding:0 12px">
      <div style="font-size:26px;font-weight:800;color:{$slaColor}">{$s['sla_breaches']}</div>
      <div style="font-size:11px;color:#7a8da8;text-transform:uppercase;letter-spacing:.06em">SLA Breaches</div>
    </div>
  </div>

  <!-- Top endpoints -->
  <div style="background:#1a1a2e;padding:20px 28px">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#e8212a;border-left:3px solid #e8212a;padding-left:8px;margin-bottom:12px">Top Risk Endpoints</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="color:#7a8da8">
        <th style="padding:4px 12px;text-align:left">Name</th>
        <th style="padding:4px 12px;text-align:left">IP</th>
        <th style="padding:4px 12px;text-align:left">Risk</th>
      </tr></thead>
      <tbody>{$topEpRows}</tbody>
    </table>
  </div>

  <!-- Top CVEs -->
  <div style="background:#16162a;padding:20px 28px">
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#e8212a;border-left:3px solid #e8212a;padding-left:8px;margin-bottom:12px">Top CVEs by CVSS</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="color:#7a8da8">
        <th style="padding:4px 12px;text-align:left">CVE ID</th>
        <th style="padding:4px 12px;text-align:left">Severity</th>
        <th style="padding:4px 12px;text-align:left">CVSS</th>
        <th style="padding:4px 12px;text-align:left">Affected</th>
      </tr></thead>
      <tbody>{$topCveRows}</tbody>
    </table>
  </div>

  <!-- Summary line -->
  <div style="background:#1a1a2e;padding:16px 28px;border-top:1px solid #2a2a3e;font-size:12px;color:#7a8da8;display:flex;justify-content:space-between">
    <span>Avg risk score: <strong style="color:#ccd6f6">{$s['avg_risk']}</strong></span>
    <span>Open assignments: <strong style="color:#ccd6f6">{$s['new_assignments']}</strong></span>
    <span>Active exceptions: <strong style="color:#ccd6f6">{$s['open_exceptions']}</strong></span>
  </div>

  <!-- CTA -->
  <div style="background:#0e0e1a;padding:20px 28px;text-align:center;border-radius:0 0 10px 10px;border-top:1px solid #2a2a3e">
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
}
