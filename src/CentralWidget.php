<?php

namespace GlpiPlugin\Tanium;

use CommonGLPI;
use Plugin;
use Session;

class CentralWidget extends CommonGLPI {

    public static $rightname = 'plugin_tanium_sync';

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string {
        if ($item instanceof \Central) {
            return __('Tanium Security', 'tanium');
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool {
        if ($item instanceof \Central) {
            self::showWidget();
            return true;
        }
        return false;
    }

    public static function showWidget(): void {
        global $DB;

        if (!Session::haveRight('config', READ)) {
            return;
        }

        $webDir = Plugin::getWebDir('tanium');

        // Quick stats
        $epRow = $DB->doQuery("SELECT COUNT(*) AS total, COUNT(CASE WHEN risk_score >= 70 THEN 1 END) AS crit, ROUND(AVG(risk_score),1) AS avg_risk FROM glpi_plugin_tanium_assets")->current();
        $cveRow = $DB->doQuery("SELECT COUNT(CASE WHEN severity='critical' AND status!='remediated' THEN 1 END) AS crit_cves FROM glpi_plugin_tanium_endpoint_cves")->current();
        $slaRow = $DB->doQuery("
            SELECT COUNT(*) AS breaches FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
            WHERE ec.status != 'remediated'
            AND (
                (v.severity='critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL 7 DAY))
                OR (v.severity='high'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL 30 DAY))
                OR (v.severity='medium' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL 90 DAY))
            )
        ")->current();

        $total     = (int)($epRow['total']     ?? 0);
        $critical  = (int)($epRow['crit']      ?? 0);
        $avgRisk   = (float)($epRow['avg_risk'] ?? 0);
        $critCves  = (int)($cveRow['crit_cves'] ?? 0);
        $breaches  = (int)($slaRow['breaches']  ?? 0);

        // Top 5 risky endpoints
        $top = [];
        foreach ($DB->doQuery("SELECT tanium_name, ip_address, risk_score, tanium_eid FROM glpi_plugin_tanium_assets ORDER BY risk_score DESC LIMIT 5") as $r) {
            $top[] = $r;
        }

        $topRows = '';
        foreach ($top as $ep) {
            $rs = (int)$ep['risk_score'];
            $c  = $rs >= 70 ? '#e8212a' : ($rs >= 40 ? '#f97316' : ($rs >= 15 ? '#f59e0b' : '#1eb464'));
            $topRows .= "<tr>
                <td style='padding:5px 8px'><a href='{$webDir}/front/endpoint.php?eid=" . urlencode($ep['tanium_eid']) . "' style='color:#1a6dff;text-decoration:none'>" . htmlspecialchars($ep['tanium_name']) . "</a></td>
                <td style='padding:5px 8px;color:#7a8da8;font-size:.8rem'>" . htmlspecialchars($ep['ip_address'] ?? '') . "</td>
                <td style='padding:5px 8px;text-align:right;color:{$c};font-weight:700'>{$rs}</td>
            </tr>";
        }

        ?>
        <div class="tanium-widget" style="margin-bottom:16px">
            <div class="tanium-widget-header">
                <span style="font-size:.85rem;font-weight:700;color:#e8212a;text-transform:uppercase;letter-spacing:.06em">&#128202; Tanium Security</span>
                <a href="<?= $webDir ?>/front/dashboard.php" style="font-size:.75rem;color:#7a8da8;text-decoration:none;margin-left:auto">
                    <?= __('Full dashboard →', 'tanium') ?>
                </a>
            </div>
            <div class="tanium-widget-kpis">
                <div class="tanium-widget-kpi">
                    <div class="tanium-widget-kpi-val" style="color:#1a6dff"><?= $total ?></div>
                    <div class="tanium-widget-kpi-lbl"><?= __('Endpoints', 'tanium') ?></div>
                </div>
                <div class="tanium-widget-kpi">
                    <div class="tanium-widget-kpi-val" style="color:#e8212a"><?= $critical ?></div>
                    <div class="tanium-widget-kpi-lbl"><?= __('Critical risk', 'tanium') ?></div>
                </div>
                <div class="tanium-widget-kpi">
                    <div class="tanium-widget-kpi-val" style="color:#e8212a"><?= $critCves ?></div>
                    <div class="tanium-widget-kpi-lbl"><?= __('Critical CVEs', 'tanium') ?></div>
                </div>
                <div class="tanium-widget-kpi">
                    <div class="tanium-widget-kpi-val" style="color:<?= $breaches > 0 ? '#e8212a' : '#1eb464' ?>"><?= $breaches ?></div>
                    <div class="tanium-widget-kpi-lbl"><?= __('SLA breaches', 'tanium') ?></div>
                </div>
            </div>
            <?php if (!empty($top)): ?>
            <div class="tanium-widget-table">
                <table style="width:100%;border-collapse:collapse;font-size:.82rem">
                    <thead><tr style="color:#7a8da8;border-bottom:1px solid #2a2a3e">
                        <th style="padding:4px 8px;text-align:left"><?= __('Endpoint', 'tanium') ?></th>
                        <th style="padding:4px 8px;text-align:left">IP</th>
                        <th style="padding:4px 8px;text-align:right"><?= __('Risk', 'tanium') ?></th>
                    </tr></thead>
                    <tbody><?= $topRows ?></tbody>
                </table>
            </div>
            <?php endif; ?>
            <div style="padding:8px 12px;border-top:1px solid #2a2a3e;display:flex;gap:8px">
                <a href="<?= $webDir ?>/front/vulnerabilities.php?severity=critical" class="tanium-btn tanium-btn-sm" style="background:#e8212a22;color:#e8212a;border:1px solid #e8212a44;border-radius:4px;padding:4px 10px;font-size:.75rem;text-decoration:none">
                    <?= __('Critical CVEs', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/assignments.php" class="tanium-btn tanium-btn-sm" style="background:#1a6dff22;color:#1a6dff;border:1px solid #1a6dff44;border-radius:4px;padding:4px 10px;font-size:.75rem;text-decoration:none">
                    <?= __('Assignments', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/report.php" target="_blank" class="tanium-btn tanium-btn-sm" style="background:#1eb46422;color:#1eb464;border:1px solid #1eb46444;border-radius:4px;padding:4px 10px;font-size:.75rem;text-decoration:none">
                    <?= __('Report', 'tanium') ?>
                </a>
            </div>
        </div>
        <?php
    }
}
