<?php

namespace GlpiPlugin\Tanium;

use Html;
use Plugin;

/**
 * SLA compliance intelligence.
 *
 * Computes how the open (unremediated, non-excepted) CVE findings stand against
 * the remediation deadlines configured in the plugin settings:
 *   - critical → sla_critical_days
 *   - high     → sla_high_days
 *   - medium   → sla_medium_days
 *
 * Low/unknown severities have no configured deadline, so they are not tracked.
 * A finding is "breached" once (detected_at + sla_days) is in the past.
 */
class Sla {

    /** Severities that have an SLA deadline (in display order). */
    private const TRACKED = ['critical', 'high', 'medium'];

    public static function days(): array {
        $c = Config::getConfig();
        return [
            'critical' => (int) ($c['sla_critical_days'] ?? 7),
            'high'     => (int) ($c['sla_high_days']     ?? 30),
            'medium'   => (int) ($c['sla_medium_days']   ?? 90),
        ];
    }

    /**
     * Shared SQL fragment: open findings that count toward SLA (not remediated,
     * not excepted, severity has a deadline). $alias is the endpoint_cves alias.
     */
    private static function openFindingsJoin(): string {
        return "
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
            LEFT JOIN glpi_plugin_tanium_cve_exceptions ex
                   ON ex.tanium_eid = ec.tanium_eid AND ex.cve_id = ec.cve_id
            WHERE ec.status != 'remediated'
              AND ex.id IS NULL
              AND ec.detected_at IS NOT NULL
              AND v.severity IN ('critical','high','medium')";
    }

    /** Per-severity + overall: tracked, breached, due-soon, within, compliance %. */
    public static function getStats(int $dueSoonDays = 3): array {
        global $DB;

        $d    = self::days();
        $crit = $d['critical'];
        $high = $d['high'];
        $med  = $d['medium'];
        $soon = max(1, $dueSoonDays);

        // One pass: classify each open finding as breached / due-soon / within.
        $sql = "
            SELECT v.severity AS severity,
                   COUNT(*) AS tracked,
                   SUM(CASE
                       WHEN (v.severity='critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$crit} DAY))
                         OR (v.severity='high'     AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$high} DAY))
                         OR (v.severity='medium'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$med}  DAY))
                       THEN 1 ELSE 0 END) AS breached,
                   SUM(CASE
                       WHEN (v.severity='critical' AND ec.detected_at >= DATE_SUB(NOW(), INTERVAL {$crit} DAY)
                             AND ec.detected_at < DATE_SUB(NOW(), INTERVAL " . ($crit - $soon) . " DAY))
                         OR (v.severity='high'     AND ec.detected_at >= DATE_SUB(NOW(), INTERVAL {$high} DAY)
                             AND ec.detected_at < DATE_SUB(NOW(), INTERVAL " . ($high - $soon) . " DAY))
                         OR (v.severity='medium'   AND ec.detected_at >= DATE_SUB(NOW(), INTERVAL {$med}  DAY)
                             AND ec.detected_at < DATE_SUB(NOW(), INTERVAL " . ($med - $soon) . " DAY))
                       THEN 1 ELSE 0 END) AS due_soon
            " . self::openFindingsJoin() . "
            GROUP BY v.severity
        ";

        $bySeverity = [];
        foreach (self::TRACKED as $s) {
            $bySeverity[$s] = ['tracked' => 0, 'breached' => 0, 'due_soon' => 0, 'within' => 0, 'compliance' => null, 'days' => $d[$s]];
        }

        $totTracked = 0; $totBreached = 0; $totSoon = 0;
        foreach ($DB->doQuery($sql) as $r) {
            $sev = strtolower($r['severity']);
            if (!isset($bySeverity[$sev])) {
                continue;
            }
            $tracked  = (int) $r['tracked'];
            $breached = (int) $r['breached'];
            $soonN    = (int) $r['due_soon'];
            $within   = $tracked - $breached;

            $bySeverity[$sev]['tracked']    = $tracked;
            $bySeverity[$sev]['breached']   = $breached;
            $bySeverity[$sev]['due_soon']   = $soonN;
            $bySeverity[$sev]['within']     = $within;
            $bySeverity[$sev]['compliance'] = $tracked > 0 ? (int) round($within / $tracked * 100) : null;

            $totTracked  += $tracked;
            $totBreached += $breached;
            $totSoon     += $soonN;
        }

        $totWithin = $totTracked - $totBreached;

        return [
            'by_severity'   => $bySeverity,
            'tracked'       => $totTracked,
            'breached'      => $totBreached,
            'due_soon'      => $totSoon,
            'within'        => $totWithin,
            'compliance'    => $totTracked > 0 ? (int) round($totWithin / $totTracked * 100) : null,
            'due_soon_days' => $soon,
        ];
    }

    /** Endpoints with the most SLA-breached findings (worst offenders first). */
    public static function getTopBreachedEndpoints(int $limit = 10): array {
        global $DB;

        $d     = self::days();
        $crit  = $d['critical']; $high = $d['high']; $med = $d['medium'];
        $limit = max(1, $limit);

        $sql = "
            SELECT a.tanium_eid, a.tanium_name, a.ip_address, a.os_name, a.computers_id,
                   a.risk_score,
                   COUNT(*) AS breached,
                   SUM(CASE WHEN v.severity='critical' THEN 1 ELSE 0 END) AS crit_breached,
                   MIN(ec.detected_at) AS oldest_detected
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = ec.tanium_eid
            JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
            LEFT JOIN glpi_plugin_tanium_cve_exceptions ex
                   ON ex.tanium_eid = ec.tanium_eid AND ex.cve_id = ec.cve_id
            WHERE ec.status != 'remediated'
              AND ex.id IS NULL
              AND ec.detected_at IS NOT NULL
              AND v.severity IN ('critical','high','medium')
              AND (
                  (v.severity='critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$crit} DAY))
               OR (v.severity='high'     AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$high} DAY))
               OR (v.severity='medium'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$med}  DAY))
              )
            GROUP BY a.tanium_eid
            ORDER BY crit_breached DESC, breached DESC
            LIMIT {$limit}
        ";

        $rows = [];
        foreach ($DB->doQuery($sql) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    /** The individual findings that are most overdue (longest past deadline). */
    public static function getMostOverdue(int $limit = 10): array {
        global $DB;

        $d     = self::days();
        $crit  = $d['critical']; $high = $d['high']; $med = $d['medium'];
        $limit = max(1, $limit);

        // days_overdue = how many days past the deadline this finding already is.
        $sql = "
            SELECT ec.cve_id, ec.severity, ec.cvss_score, ec.detected_at,
                   a.tanium_eid, a.tanium_name, a.computers_id,
                   DATEDIFF(NOW(), DATE_ADD(ec.detected_at, INTERVAL
                       CASE v.severity
                           WHEN 'critical' THEN {$crit}
                           WHEN 'high'     THEN {$high}
                           WHEN 'medium'   THEN {$med}
                       END DAY)) AS days_overdue
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
            JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = ec.tanium_eid
            LEFT JOIN glpi_plugin_tanium_cve_exceptions ex
                   ON ex.tanium_eid = ec.tanium_eid AND ex.cve_id = ec.cve_id
            WHERE ec.status != 'remediated'
              AND ex.id IS NULL
              AND ec.detected_at IS NOT NULL
              AND v.severity IN ('critical','high','medium')
              AND (
                  (v.severity='critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$crit} DAY))
               OR (v.severity='high'     AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$high} DAY))
               OR (v.severity='medium'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$med}  DAY))
              )
            ORDER BY days_overdue DESC
            LIMIT {$limit}
        ";

        $rows = [];
        foreach ($DB->doQuery($sql) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    // ── Page render ────────────────────────────────────────────────────────

    public static function showPage(): void {
        $stats     = self::getStats();
        $topBreach = self::getTopBreachedEndpoints(10);
        $overdue   = self::getMostOverdue(10);
        $d         = self::days();
        $config    = Config::getConfig();
        $webDir    = Plugin::getWebDir('tanium');
        $logoUrl   = $webDir . '/public/img/tanium-logo.svg';

        $comp      = $stats['compliance'];
        $compColor = $comp === null ? '#7a8da8' : ($comp >= 90 ? '#1eb464' : ($comp >= 70 ? '#e8c42a' : '#e8212a'));
        ?>
        <div class="tanium-page-wrap">

        <!-- Hero header -->
        <div class="tanium-dashboard-hero">
            <div class="tanium-hero-brand">
                <img src="<?= $logoUrl ?>" alt="Tanium" class="tanium-hero-logo"/>
                <div>
                    <div class="tanium-hero-title"><?= __('SLA Compliance', 'tanium') ?></div>
                    <div class="tanium-hero-sub">
                        <?= __('Open CVEs measured against your remediation deadlines', 'tanium') ?>
                        <?php if (!empty($config['last_sync'])): ?>
                            &nbsp;·&nbsp;<?= __('Last sync', 'tanium') ?>: <?= Html::convDateTime($config['last_sync']) ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="tanium-hero-actions">
                <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary" title="<?= __('Back', 'tanium') ?>">
                    <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/vulnerabilities.php" class="tanium-btn tanium-btn-secondary">
                    &#9762; <?= __('Vulnerabilities', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/config.form.php" class="tanium-btn tanium-btn-secondary">
                    &#9881; <?= __('SLA settings', 'tanium') ?>
                </a>
            </div>
        </div>

        <?php if ($stats['tracked'] === 0): ?>
            <div class="tanium-card">
                <div class="tanium-card-body">
                    <p class="tanium-empty">
                        <?= __('No open CVEs to measure yet. Enable "Vulnerabilities" sync (Tanium Comply) and run a sync.', 'tanium') ?>
                    </p>
                </div>
            </div>
            </div>
            <?php
            return;
        endif; ?>

        <!-- KPI cards -->
        <div class="tanium-kpi-grid">
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:<?= $compColor ?>22;color:<?= $compColor ?>">&#127919;</div>
                <div class="tanium-kpi-value" style="color:<?= $compColor ?>"><?= $comp === null ? '—' : $comp . '%' ?></div>
                <div class="tanium-kpi-label"><?= __('Overall SLA compliance', 'tanium') ?></div>
                <span class="tanium-kpi-link tanium-muted" style="font-size:.75rem"><?= number_format($stats['tracked']) ?> <?= __('findings tracked', 'tanium') ?></span>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-green" style="background:rgba(30,180,100,.15);color:#1eb464">&#10003;</div>
                <div class="tanium-kpi-value" style="color:#1eb464"><?= number_format($stats['within']) ?></div>
                <div class="tanium-kpi-label"><?= __('Within SLA', 'tanium') ?></div>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-orange" style="background:rgba(240,160,48,.15);color:#f0a030">&#9201;</div>
                <div class="tanium-kpi-value" style="color:#f0a030"><?= number_format($stats['due_soon']) ?></div>
                <div class="tanium-kpi-label"><?= sprintf(__('Due within %d days', 'tanium'), $stats['due_soon_days']) ?></div>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-red" style="background:rgba(232,33,42,.15);color:#e8212a">&#9888;</div>
                <div class="tanium-kpi-value tanium-text-red"><?= number_format($stats['breached']) ?></div>
                <div class="tanium-kpi-label"><?= __('SLA breached (overdue)', 'tanium') ?></div>
            </div>
        </div>

        <!-- Per-severity compliance -->
        <div class="tanium-card" style="margin-bottom:16px">
            <div class="tanium-card-header">
                <span>&#128202; <?= __('Compliance by severity', 'tanium') ?></span>
                <span class="tanium-muted" style="margin-left:auto;font-size:.78rem">
                    <?= __('Deadlines', 'tanium') ?>:
                    <?= sprintf(__('Critical %dd · High %dd · Medium %dd', 'tanium'), $d['critical'], $d['high'], $d['medium']) ?>
                </span>
            </div>
            <div class="tanium-card-body">
                <?php foreach (self::TRACKED as $sev):
                    $row = $stats['by_severity'][$sev];
                    if ($row['tracked'] === 0) continue;
                    $pct      = $row['compliance'];
                    $sevColor = $sev === 'critical' ? '#e8212a' : ($sev === 'high' ? '#f0a030' : '#e8c42a');
                    $barColor = $pct >= 90 ? '#1eb464' : ($pct >= 70 ? '#e8c42a' : '#e8212a');
                ?>
                <div class="tanium-sla-row">
                    <div class="tanium-sla-row-head">
                        <span class="tanium-badge <?= Vulnerability::sevClass($sev) ?>"><?= ucfirst($sev) ?></span>
                        <span class="tanium-sla-row-deadline"><?= sprintf(__('%d-day deadline', 'tanium'), $row['days']) ?></span>
                        <span class="tanium-sla-row-pct" style="color:<?= $barColor ?>"><?= $pct ?>%</span>
                    </div>
                    <div class="tanium-sla-track">
                        <div class="tanium-sla-fill" style="width:<?= $pct ?>%;background:<?= $barColor ?>"></div>
                    </div>
                    <div class="tanium-sla-row-foot">
                        <span class="tanium-sla-chip tanium-sla-chip-ok"><?= number_format($row['within']) ?> <?= __('within', 'tanium') ?></span>
                        <?php if ($row['due_soon'] > 0): ?>
                        <span class="tanium-sla-chip tanium-sla-chip-soon"><?= number_format($row['due_soon']) ?> <?= __('due soon', 'tanium') ?></span>
                        <?php endif; ?>
                        <span class="tanium-sla-chip tanium-sla-chip-bad"><?= number_format($row['breached']) ?> <?= __('breached', 'tanium') ?></span>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="tanium-sla-grid">
            <!-- Worst-offender endpoints -->
            <div class="tanium-card">
                <div class="tanium-card-header">
                    <span>&#128421; <?= __('Endpoints breaching SLA', 'tanium') ?></span>
                </div>
                <div class="tanium-card-body tanium-p0">
                    <?php if (empty($topBreach)): ?>
                        <p class="tanium-empty"><?= __('No endpoints currently breaching SLA. 🎉', 'tanium') ?></p>
                    <?php else: ?>
                    <table class="tanium-table">
                        <thead>
                            <tr>
                                <th><?= __('Endpoint', 'tanium') ?></th>
                                <th class="tanium-center"><?= __('Critical', 'tanium') ?></th>
                                <th class="tanium-center"><?= __('Total overdue', 'tanium') ?></th>
                                <th><?= __('Oldest', 'tanium') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($topBreach as $ep): ?>
                            <tr>
                                <td>
                                    <?php if (!empty($ep['computers_id'])): ?>
                                        <a href="<?= $webDir ?>/front/endpoint.php?id=<?= (int)$ep['computers_id'] ?>" class="tanium-link"><?= htmlspecialchars($ep['tanium_name'] ?: $ep['tanium_eid']) ?></a>
                                    <?php else: ?>
                                        <?= htmlspecialchars($ep['tanium_name'] ?: $ep['tanium_eid']) ?>
                                    <?php endif; ?>
                                    <div class="tanium-small tanium-muted"><?= htmlspecialchars($ep['ip_address'] ?? '') ?> <?= htmlspecialchars($ep['os_name'] ? '· ' . $ep['os_name'] : '') ?></div>
                                </td>
                                <td class="tanium-center">
                                    <?php if ((int)$ep['crit_breached'] > 0): ?>
                                        <span class="tanium-badge tanium-badge-critical"><?= (int)$ep['crit_breached'] ?></span>
                                    <?php else: ?>—<?php endif; ?>
                                </td>
                                <td class="tanium-center"><span class="tanium-badge tanium-badge-error"><?= (int)$ep['breached'] ?></span></td>
                                <td class="tanium-small"><?= $ep['oldest_detected'] ? Html::convDateTime($ep['oldest_detected']) : '—' ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Most overdue findings -->
            <div class="tanium-card">
                <div class="tanium-card-header">
                    <span>&#9203; <?= __('Most overdue findings', 'tanium') ?></span>
                </div>
                <div class="tanium-card-body tanium-p0">
                    <?php if (empty($overdue)): ?>
                        <p class="tanium-empty"><?= __('Nothing overdue. 🎉', 'tanium') ?></p>
                    <?php else: ?>
                    <table class="tanium-table">
                        <thead>
                            <tr>
                                <th><?= __('CVE', 'tanium') ?></th>
                                <th><?= __('Severity', 'tanium') ?></th>
                                <th class="tanium-center"><?= __('Days overdue', 'tanium') ?></th>
                                <th><?= __('Endpoint', 'tanium') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($overdue as $f): ?>
                            <tr>
                                <td class="tanium-mono">
                                    <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($f['cve_id']) ?>" target="_blank" class="tanium-link"><?= htmlspecialchars($f['cve_id']) ?></a>
                                </td>
                                <td><span class="tanium-badge <?= Vulnerability::sevClass($f['severity']) ?>"><?= ucfirst($f['severity']) ?></span></td>
                                <td class="tanium-center"><span class="tanium-sla-overdue"><?= (int)$f['days_overdue'] ?>d</span></td>
                                <td class="tanium-small">
                                    <?php if (!empty($f['computers_id'])): ?>
                                        <a href="<?= $webDir ?>/front/endpoint.php?id=<?= (int)$f['computers_id'] ?>" class="tanium-link"><?= htmlspecialchars($f['tanium_name'] ?: $f['tanium_eid']) ?></a>
                                    <?php else: ?>
                                        <?= htmlspecialchars($f['tanium_name'] ?: $f['tanium_eid']) ?>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        </div>
        <?php
    }
}
