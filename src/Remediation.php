<?php

namespace GlpiPlugin\Tanium;

use Html;
use Plugin;

/**
 * Remediation trend: what got FIXED, per endpoint and over time, from the
 * status transitions recorded in cve_history (new_status = remediated) and
 * patch_history (missing → installed/remediated).
 */
class Remediation {

    // ── Data layer ────────────────────────────────────────────────────────

    /**
     * Headline numbers for the trailing window.
     *
     * @return array{cves_remediated:int,patches_installed:int,endpoints_touched:int,mttr:?float}
     */
    public static function getStats(int $windowDays = 30): array {
        global $DB;

        $windowDays = max(1, $windowDays);

        $cveRow = $DB->doQuery("
            SELECT COUNT(*) AS cpt, COUNT(DISTINCT tanium_eid) AS eids
            FROM glpi_plugin_tanium_cve_history
            WHERE new_status = 'remediated'
              AND changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
        ")->fetch_assoc();

        $patchRow = $DB->doQuery("
            SELECT COUNT(*) AS cpt, COUNT(DISTINCT tanium_eid) AS eids
            FROM glpi_plugin_tanium_patch_history
            WHERE new_status IN ('installed', 'remediated')
              AND changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
        ")->fetch_assoc();

        $eidRow = $DB->doQuery("
            SELECT COUNT(DISTINCT eid) AS cpt FROM (
                SELECT tanium_eid AS eid FROM glpi_plugin_tanium_cve_history
                WHERE new_status = 'remediated' AND changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
                UNION
                SELECT tanium_eid AS eid FROM glpi_plugin_tanium_patch_history
                WHERE new_status IN ('installed', 'remediated') AND changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
            ) t
        ")->fetch_assoc();

        return [
            'cves_remediated'   => (int)($cveRow['cpt'] ?? 0),
            'patches_installed' => (int)($patchRow['cpt'] ?? 0),
            'endpoints_touched' => (int)($eidRow['cpt'] ?? 0),
            'mttr'              => Sla::getMttr($windowDays)['overall'],
        ];
    }

    /**
     * Remediations per ISO week for the chart, zero-filled so quiet weeks
     * still appear. Oldest first.
     *
     * @return array<int,array{label:string,cves:int,patches:int}>
     */
    public static function getWeeklySeries(int $weeks = 12): array {
        global $DB;

        $weeks = max(2, $weeks);
        $days  = $weeks * 7;

        $byWeek = [];
        foreach ($DB->doQuery("
            SELECT YEARWEEK(changed_at, 3) AS yw, COUNT(*) AS cpt
            FROM glpi_plugin_tanium_cve_history
            WHERE new_status = 'remediated' AND changed_at >= DATE_SUB(NOW(), INTERVAL {$days} DAY)
            GROUP BY yw
        ") as $r) {
            $byWeek[(int)$r['yw']]['cves'] = (int)$r['cpt'];
        }
        foreach ($DB->doQuery("
            SELECT YEARWEEK(changed_at, 3) AS yw, COUNT(*) AS cpt
            FROM glpi_plugin_tanium_patch_history
            WHERE new_status IN ('installed', 'remediated') AND changed_at >= DATE_SUB(NOW(), INTERVAL {$days} DAY)
            GROUP BY yw
        ") as $r) {
            $byWeek[(int)$r['yw']]['patches'] = (int)$r['cpt'];
        }

        $series = [];
        for ($i = $weeks - 1; $i >= 0; $i--) {
            $monday = strtotime("monday this week -{$i} weeks");
            $yw     = (int)date('oW', $monday);
            $series[] = [
                'label'   => date('d/m', $monday),
                'cves'    => (int)($byWeek[$yw]['cves']    ?? 0),
                'patches' => (int)($byWeek[$yw]['patches'] ?? 0),
            ];
        }
        return $series;
    }

    /**
     * Per-endpoint remediation summary for the trailing window, most-fixed
     * first: how many CVEs/patches were fixed, average days-to-fix, last fix
     * and how many findings remain open.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function getByEndpoint(int $windowDays = 30, int $limit = 100): array {
        global $DB;

        $windowDays = max(1, $windowDays);
        $rows       = [];

        foreach ($DB->doQuery("
            SELECT h.tanium_eid,
                   COUNT(*) AS cves_fixed,
                   ROUND(AVG(GREATEST(0, DATEDIFF(h.changed_at, ec.detected_at))), 1) AS avg_days,
                   MAX(h.changed_at) AS last_fix
            FROM glpi_plugin_tanium_cve_history h
            LEFT JOIN glpi_plugin_tanium_endpoint_cves ec
                   ON ec.tanium_eid = h.tanium_eid AND ec.cve_id = h.cve_id
            WHERE h.new_status = 'remediated'
              AND h.changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
            GROUP BY h.tanium_eid
        ") as $r) {
            $rows[$r['tanium_eid']] = [
                'tanium_eid'    => $r['tanium_eid'],
                'cves_fixed'    => (int)$r['cves_fixed'],
                'patches_fixed' => 0,
                'avg_days'      => $r['avg_days'] !== null ? (float)$r['avg_days'] : null,
                'last_fix'      => $r['last_fix'],
            ];
        }

        foreach ($DB->doQuery("
            SELECT tanium_eid, COUNT(*) AS patches_fixed, MAX(changed_at) AS last_fix
            FROM glpi_plugin_tanium_patch_history
            WHERE new_status IN ('installed', 'remediated')
              AND changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
            GROUP BY tanium_eid
        ") as $r) {
            $eid = $r['tanium_eid'];
            if (!isset($rows[$eid])) {
                $rows[$eid] = [
                    'tanium_eid'    => $eid,
                    'cves_fixed'    => 0,
                    'patches_fixed' => 0,
                    'avg_days'      => null,
                    'last_fix'      => null,
                ];
            }
            $rows[$eid]['patches_fixed'] = (int)$r['patches_fixed'];
            if ($rows[$eid]['last_fix'] === null || $r['last_fix'] > $rows[$eid]['last_fix']) {
                $rows[$eid]['last_fix'] = $r['last_fix'];
            }
        }

        if ($rows === []) {
            return [];
        }

        // Endpoint names + open findings still pending, for the same eids
        $eids   = array_keys($rows);
        $quoted = implode(',', array_map(static fn($e) => "'" . $DB->escape($e) . "'", $eids));

        foreach ($DB->doQuery("SELECT tanium_eid, tanium_name, os_name FROM glpi_plugin_tanium_assets WHERE tanium_eid IN ({$quoted})") as $r) {
            $rows[$r['tanium_eid']]['name'] = $r['tanium_name'];
            $rows[$r['tanium_eid']]['os']   = $r['os_name'];
        }
        foreach ($DB->doQuery("
            SELECT tanium_eid, COUNT(*) AS still_open
            FROM glpi_plugin_tanium_endpoint_cves
            WHERE status != 'remediated' AND tanium_eid IN ({$quoted})
            GROUP BY tanium_eid
        ") as $r) {
            $rows[$r['tanium_eid']]['still_open'] = (int)$r['still_open'];
        }

        foreach ($rows as &$row) {
            $row['name']       = $row['name'] ?? $row['tanium_eid'];
            $row['os']         = $row['os'] ?? '';
            $row['still_open'] = $row['still_open'] ?? 0;
            $row['total']      = $row['cves_fixed'] + $row['patches_fixed'];
        }
        unset($row);

        usort($rows, static fn(array $a, array $b): int => $b['total'] <=> $a['total']);
        return array_slice(array_values($rows), 0, $limit);
    }

    /**
     * Most recent individual remediation events (CVE + patch merged),
     * newest first.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function getRecent(int $windowDays = 30, int $limit = 200): array {
        global $DB;

        $windowDays = max(1, $windowDays);
        $events     = [];

        foreach ($DB->doQuery("
            SELECT h.tanium_eid, h.cve_id AS ref, h.changed_at, a.tanium_name,
                   ec.severity, ec.cvss_score,
                   GREATEST(0, DATEDIFF(h.changed_at, ec.detected_at)) AS days_open
            FROM glpi_plugin_tanium_cve_history h
            LEFT JOIN glpi_plugin_tanium_endpoint_cves ec
                   ON ec.tanium_eid = h.tanium_eid AND ec.cve_id = h.cve_id
            LEFT JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = h.tanium_eid
            WHERE h.new_status = 'remediated'
              AND h.changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
            ORDER BY h.changed_at DESC
            LIMIT {$limit}
        ") as $r) {
            $events[] = [
                'type'      => 'cve',
                'ref'       => $r['ref'],
                'endpoint'  => $r['tanium_name'] ?: $r['tanium_eid'],
                'severity'  => strtolower((string)($r['severity'] ?? 'unknown')),
                'cvss'      => $r['cvss_score'],
                'days_open' => $r['days_open'] !== null ? (int)$r['days_open'] : null,
                'fixed_at'  => $r['changed_at'],
            ];
        }

        foreach ($DB->doQuery("
            SELECT h.tanium_eid, h.patch_title, h.patch_id, h.severity, h.changed_at, a.tanium_name
            FROM glpi_plugin_tanium_patch_history h
            LEFT JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = h.tanium_eid
            WHERE h.new_status IN ('installed', 'remediated')
              AND h.changed_at >= DATE_SUB(NOW(), INTERVAL {$windowDays} DAY)
            ORDER BY h.changed_at DESC
            LIMIT {$limit}
        ") as $r) {
            $events[] = [
                'type'      => 'patch',
                'ref'       => $r['patch_title'] !== '' ? $r['patch_title'] : $r['patch_id'],
                'endpoint'  => $r['tanium_name'] ?: $r['tanium_eid'],
                'severity'  => strtolower((string)($r['severity'] ?? 'unknown')),
                'cvss'      => null,
                'days_open' => null,
                'fixed_at'  => $r['changed_at'],
            ];
        }

        usort($events, static fn(array $a, array $b): int => strcmp((string)$b['fixed_at'], (string)$a['fixed_at']));
        return array_slice($events, 0, $limit);
    }

    // ── CSV export ────────────────────────────────────────────────────────

    /** Streams the recent-events list as CSV and exits. */
    public static function exportEventsCsv(int $windowDays): void {
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="tanium-remediacao-eventos-' . date('Y-m-d') . '.csv"');

        $out = fopen('php://output', 'w');
        fwrite($out, "\xEF\xBB\xBF"); // BOM: Excel pt-BR
        fputcsv($out, ['tipo', 'referencia', 'endpoint', 'severidade', 'cvss', 'dias_aberto', 'corrigido_em'], ';');
        foreach (self::getRecent($windowDays, 10000) as $ev) {
            fputcsv($out, [
                $ev['type'],
                $ev['ref'],
                $ev['endpoint'],
                $ev['severity'],
                $ev['cvss'] ?? '',
                $ev['days_open'] ?? '',
                $ev['fixed_at'],
            ], ';');
        }
        fclose($out);
        exit;
    }

    /** Streams the per-endpoint summary as CSV and exits. */
    public static function exportEndpointsCsv(int $windowDays): void {
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="tanium-remediacao-endpoints-' . date('Y-m-d') . '.csv"');

        $out = fopen('php://output', 'w');
        fwrite($out, "\xEF\xBB\xBF");
        fputcsv($out, ['endpoint', 'os', 'cves_remediados', 'patches_instalados', 'total', 'dias_medio', 'ultima_correcao', 'ainda_abertos'], ';');
        foreach (self::getByEndpoint($windowDays, 10000) as $row) {
            fputcsv($out, [
                $row['name'],
                $row['os'],
                $row['cves_fixed'],
                $row['patches_fixed'],
                $row['total'],
                $row['avg_days'] ?? '',
                $row['last_fix'] ?? '',
                $row['still_open'],
            ], ';');
        }
        fclose($out);
        exit;
    }

    // ── Rendering ─────────────────────────────────────────────────────────

    private static function sevBadge(string $sev): string {
        $cls = match ($sev) {
            'critical' => 'tanium-badge-critical',
            'high'     => 'tanium-badge-error',
            'medium'   => 'tanium-badge-warning',
            default    => 'tanium-badge-muted',
        };
        return "<span class='tanium-badge {$cls}'>" . htmlspecialchars(ucfirst($sev)) . "</span>";
    }

    private static function renderChart(array $series): string {
        if (count($series) < 2) {
            return '';
        }

        $w = 100; $h = 70;
        $n = count($series);
        $stepX = $w / ($n - 1);
        $max   = max(1, max(array_map(static fn(array $s): int => max($s['cves'], $s['patches']), $series)));

        $cvePoints   = '';
        $patchPoints = '';
        $lastX = 0;
        foreach (array_values($series) as $i => $s) {
            $x = round($i * $stepX, 2);
            $cvePoints   .= $x . ',' . round($h - ($s['cves'] / $max * $h), 2) . ' ';
            $patchPoints .= $x . ',' . round($h - ($s['patches'] / $max * $h), 2) . ' ';
            $lastX = $x;
        }
        $cvePoints   = trim($cvePoints);
        $patchPoints = trim($patchPoints);
        $areaPoints  = "{$cvePoints} {$lastX},{$h} 0,{$h}";

        $labels = '';
        foreach ($series as $s) {
            $labels .= "<span style='flex:1 1 0;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'>{$s['label']}</span>";
        }

        return "
        <svg viewBox='0 0 {$w} {$h}' width='100%' height='130' preserveAspectRatio='none' style='display:block'>
            <defs>
                <linearGradient id='tremed1' x1='0' y1='0' x2='0' y2='1'>
                    <stop offset='0%' stop-color='#1eb464' stop-opacity='.28'/>
                    <stop offset='100%' stop-color='#1eb464' stop-opacity='0'/>
                </linearGradient>
            </defs>
            <polygon points='{$areaPoints}' fill='url(#tremed1)' stroke='none'/>
            <polyline points='{$cvePoints}' fill='none' stroke='#1eb464' stroke-width='2' vector-effect='non-scaling-stroke' stroke-linejoin='round' stroke-linecap='round'/>
            <polyline points='{$patchPoints}' fill='none' stroke='#1a6dff' stroke-width='1.5' vector-effect='non-scaling-stroke' stroke-dasharray='4,3' stroke-linejoin='round' stroke-linecap='round'/>
        </svg>
        <div style='display:flex;font-size:.68rem;color:var(--t-muted);margin-top:6px;padding:0 2px'>{$labels}</div>
        <div style='display:flex;gap:16px;font-size:.72rem;color:var(--t-muted);margin-top:6px'>
            <span style='color:#1eb464'>&#8212; " . __('CVEs remediated', 'tanium') . "</span>
            <span style='color:#1a6dff'>&#8943; " . __('Patches installed', 'tanium') . "</span>
        </div>";
    }

    public static function showPage(): void {
        $windowDays = (int)($_GET['days'] ?? 30);
        if (!in_array($windowDays, [7, 30, 90, 365], true)) {
            $windowDays = 30;
        }

        $webDir  = Plugin::getWebDir('tanium');
        $logoUrl = $webDir . '/public/img/tanium-logo.svg';
        $stats   = self::getStats($windowDays);
        $series  = self::getWeeklySeries(12);
        $byEp    = self::getByEndpoint($windowDays, 100);
        $recent  = self::getRecent($windowDays, 60);
        $config  = Config::getConfig();

        $windowBtns = '';
        foreach ([7 => __('7 days', 'tanium'), 30 => __('30 days', 'tanium'), 90 => __('90 days', 'tanium'), 365 => __('1 year', 'tanium')] as $d => $label) {
            $cls = $d === $windowDays ? 'tanium-btn-primary' : 'tanium-btn-secondary';
            $windowBtns .= "<a href='?days={$d}' class='tanium-btn {$cls}' style='padding:6px 14px'>{$label}</a> ";
        }
        ?>
        <div class="tanium-page-wrap">

        <div class="tanium-dashboard-hero">
            <div class="tanium-hero-brand">
                <img src="<?= $logoUrl ?>" alt="Tanium" class="tanium-hero-logo"/>
                <div>
                    <div class="tanium-hero-title"><?= __('Remediation', 'tanium') ?></div>
                    <div class="tanium-hero-sub"><?= __('What got fixed: remediated CVEs and installed patches, per endpoint', 'tanium') ?></div>
                </div>
            </div>
            <div class="tanium-hero-actions">
                <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary">
                    <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
                </a>
                <a href="?days=<?= $windowDays ?>&export=pdf" class="tanium-btn tanium-btn-secondary">
                    <span class="ti ti-file-type-pdf"></span> <?= __('PDF per endpoint', 'tanium') ?>
                </a>
                <a href="?days=<?= $windowDays ?>&export=endpoints" class="tanium-btn tanium-btn-secondary">
                    <span class="ti ti-download"></span> <?= __('CSV per endpoint', 'tanium') ?>
                </a>
                <a href="?days=<?= $windowDays ?>&export=events" class="tanium-btn tanium-btn-secondary">
                    <span class="ti ti-download"></span> <?= __('CSV events', 'tanium') ?>
                </a>
            </div>
        </div>

        <?php if (empty($config['auto_close_cves'])): ?>
        <div class="tanium-card" style="margin-bottom:16px;border-left:4px solid #e8c42a">
            <div class="tanium-card-body" style="font-size:.85rem">
                &#9888;&#65039; <?= __('The "mark vanished findings as remediated" option is OFF (Configuration). Without it, fixes are only recorded when Tanium explicitly reports them — this page may stay empty.', 'tanium') ?>
            </div>
        </div>
        <?php endif; ?>

        <div style="margin-bottom:16px"><?= $windowBtns ?></div>

        <!-- KPI cards -->
        <div class="tanium-kpi-grid">
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(30,180,100,.15);color:#1eb464">&#128737;</div>
                <div class="tanium-kpi-value" style="color:#1eb464"><?= number_format($stats['cves_remediated']) ?></div>
                <div class="tanium-kpi-label"><?= __('CVEs remediated', 'tanium') ?></div>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(26,109,255,.15);color:#1a6dff">&#128295;</div>
                <div class="tanium-kpi-value" style="color:#1a6dff"><?= number_format($stats['patches_installed']) ?></div>
                <div class="tanium-kpi-label"><?= __('Patches installed', 'tanium') ?></div>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(122,141,168,.15);color:#7a8da8">&#128421;</div>
                <div class="tanium-kpi-value"><?= number_format($stats['endpoints_touched']) ?></div>
                <div class="tanium-kpi-label"><?= __('Endpoints fixed', 'tanium') ?></div>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(240,160,48,.15);color:#f0a030">&#9201;</div>
                <div class="tanium-kpi-value"><?= $stats['mttr'] !== null ? number_format($stats['mttr'], 1) : '—' ?></div>
                <div class="tanium-kpi-label"><?= __('MTTR (days)', 'tanium') ?></div>
            </div>
        </div>

        <!-- Weekly chart -->
        <?php $chart = self::renderChart($series); if ($chart !== ''): ?>
        <div class="tanium-card" style="margin-bottom:16px">
            <div class="tanium-card-header">
                <span class="ti ti-chart-line"></span> <?= __('Remediations per week', 'tanium') ?>
                <span class="tanium-muted" style="margin-left:auto;font-size:.78rem"><?= sprintf(__('Last %d weeks', 'tanium'), count($series)) ?></span>
            </div>
            <div class="tanium-card-body" style="padding:16px 24px 8px">
                <?= $chart ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Per-endpoint table -->
        <div class="tanium-card" style="margin-bottom:16px">
            <div class="tanium-card-header">
                <span class="ti ti-devices"></span> <?= __('Remediation by endpoint', 'tanium') ?>
                <span class="tanium-muted" style="margin-left:auto;font-size:.78rem"><?= sprintf(__('Last %d days', 'tanium'), $windowDays) ?></span>
            </div>
            <div class="tanium-card-body" style="padding:0">
                <?php if ($byEp === []): ?>
                    <p class="tanium-empty" style="padding:18px 24px"><?= __('No remediation recorded in this window yet. Fixes appear here after a sync detects them.', 'tanium') ?></p>
                <?php else: ?>
                <table class="tanium-table">
                    <thead>
                        <tr>
                            <th><?= __('Endpoint', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('CVEs remediated', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Patches installed', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Avg. days to fix', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Last fix', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Still open', 'tanium') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($byEp as $row): ?>
                        <tr>
                            <td>
                                <span class="tanium-mono"><?= htmlspecialchars((string)$row['name']) ?></span>
                                <?php if ($row['os'] !== ''): ?><br><span class="tanium-muted" style="font-size:.75rem"><?= htmlspecialchars((string)$row['os']) ?></span><?php endif; ?>
                            </td>
                            <td class="tanium-center" style="color:#1eb464;font-weight:700"><?= (int)$row['cves_fixed'] ?></td>
                            <td class="tanium-center" style="color:#1a6dff;font-weight:700"><?= (int)$row['patches_fixed'] ?></td>
                            <td class="tanium-center"><?= $row['avg_days'] !== null ? number_format($row['avg_days'], 1) : '—' ?></td>
                            <td class="tanium-center tanium-small tanium-mono"><?= $row['last_fix'] !== null ? Html::convDateTime($row['last_fix']) : '—' ?></td>
                            <td class="tanium-center"><?= (int)$row['still_open'] > 0 ? "<span class='tanium-badge tanium-badge-error'>" . (int)$row['still_open'] . "</span>" : "<span class='tanium-badge tanium-badge-success'>0</span>" ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Recent events -->
        <div class="tanium-card">
            <div class="tanium-card-header">
                <span class="ti ti-history"></span> <?= __('Recent remediation events', 'tanium') ?>
            </div>
            <div class="tanium-card-body" style="padding:0">
                <?php if ($recent === []): ?>
                    <p class="tanium-empty" style="padding:18px 24px"><?= __('Nothing yet.', 'tanium') ?></p>
                <?php else: ?>
                <table class="tanium-table">
                    <thead>
                        <tr>
                            <th><?= __('Type', 'tanium') ?></th>
                            <th><?= __('CVE / Patch', 'tanium') ?></th>
                            <th><?= __('Endpoint', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Severity', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Days open', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Fixed at', 'tanium') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($recent as $ev): ?>
                        <tr>
                            <td><?= $ev['type'] === 'cve'
                                ? "<span class='tanium-badge tanium-badge-success'>CVE</span>"
                                : "<span class='tanium-badge' style='background:rgba(26,109,255,.15);color:#1a6dff'>PATCH</span>" ?></td>
                            <td class="tanium-mono tanium-small">
                                <?php if ($ev['type'] === 'cve'): ?>
                                    <a href="https://nvd.nist.gov/vuln/detail/<?= rawurlencode((string)$ev['ref']) ?>" target="_blank" rel="noopener" class="tanium-link"><?= htmlspecialchars((string)$ev['ref']) ?></a>
                                <?php else: ?>
                                    <?= htmlspecialchars(mb_strimwidth((string)$ev['ref'], 0, 80, '…')) ?>
                                <?php endif; ?>
                            </td>
                            <td><?= htmlspecialchars((string)$ev['endpoint']) ?></td>
                            <td class="tanium-center"><?= self::sevBadge((string)$ev['severity']) ?></td>
                            <td class="tanium-center"><?= $ev['days_open'] !== null ? (int)$ev['days_open'] : '—' ?></td>
                            <td class="tanium-center tanium-small tanium-mono"><?= Html::convDateTime($ev['fixed_at']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>

        </div><!-- .tanium-page-wrap -->
        <?php
    }
}
