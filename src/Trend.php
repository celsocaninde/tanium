<?php

namespace GlpiPlugin\Tanium;

use Html;
use Plugin;

/**
 * Sync-over-sync trend: how much the CVE posture moved since the previous
 * scan, using the snapshots Sync::run() already writes to risk_history.
 */
class Trend {

    /** Full snapshot history, oldest first (for the chart/table). */
    public static function getHistory(int $limit = 30): array {
        global $DB;

        $rows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_risk_history',
            'ORDER' => 'recorded_at DESC',
            'LIMIT' => $limit,
        ]) as $r) {
            $rows[] = $r;
        }
        return array_reverse($rows);
    }

    /**
     * % change of $current vs $previous. Null means "no baseline" (previous
     * was 0 and current isn't — can't express that as a percentage).
     */
    private static function pctDelta(int $current, int $previous): ?float {
        if ($previous === 0) {
            return $current === 0 ? 0.0 : null;
        }
        return round(($current - $previous) / $previous * 100, 1);
    }

    private static function trendChip(?float $pct, bool $higherIsWorse = true): string {
        if ($pct === null) {
            return '<span class="tanium-badge tanium-badge-muted">' . __('new', 'tanium') . '</span>';
        }
        if ($pct == 0.0) {
            return '<span class="tanium-badge tanium-badge-muted">' . __('no change', 'tanium') . '</span>';
        }
        $isIncrease = $pct > 0;
        $bad        = $higherIsWorse ? $isIncrease : !$isIncrease;
        $cls        = $bad ? 'tanium-badge-critical' : 'tanium-badge-success';
        $arrow      = $isIncrease ? '&#9650;' : '&#9660;';
        $sign       = $isIncrease ? '+' : '';
        return "<span class='tanium-badge {$cls}'>{$arrow} {$sign}{$pct}%</span>";
    }

    private static function renderChart(array $history): string {
        if (count($history) < 2) {
            return '';
        }

        $w = 100; $h = 70;
        $n = count($history);
        $stepX   = $w / ($n - 1);
        $maxCve  = max(1, max(array_column($history, 'total_cves')));
        $maxCrit = max(1, max(array_column($history, 'critical_cves')));

        $totalPoints = '';
        $critPoints  = '';
        $lastX = 0;
        foreach (array_values($history) as $i => $row) {
            $x = round($i * $stepX, 2);
            $totalPoints .= $x . ',' . round($h - ((int)$row['total_cves'] / $maxCve * $h), 2) . ' ';
            $critPoints  .= $x . ',' . round($h - ((int)$row['critical_cves'] / $maxCrit * $h), 2) . ' ';
            $lastX = $x;
        }
        $totalPoints = trim($totalPoints);
        $critPoints  = trim($critPoints);
        $areaPoints  = "{$totalPoints} {$lastX},{$h} 0,{$h}";

        $labels = '';
        foreach (array_values($history) as $row) {
            $lbl = date('d/m H:i', strtotime($row['recorded_at']));
            $labels .= "<span style='flex:1 1 0;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'>{$lbl}</span>";
        }

        return "
        <svg viewBox='0 0 {$w} {$h}' width='100%' height='130' preserveAspectRatio='none' style='display:block'>
            <defs>
                <linearGradient id='ttrend1' x1='0' y1='0' x2='0' y2='1'>
                    <stop offset='0%' stop-color='#e8212a' stop-opacity='.28'/>
                    <stop offset='100%' stop-color='#e8212a' stop-opacity='0'/>
                </linearGradient>
            </defs>
            <polygon points='{$areaPoints}' fill='url(#ttrend1)' stroke='none'/>
            <polyline points='{$totalPoints}' fill='none' stroke='#e8212a' stroke-width='2' vector-effect='non-scaling-stroke' stroke-linejoin='round' stroke-linecap='round'/>
            <polyline points='{$critPoints}' fill='none' stroke='#f97316' stroke-width='1.5' vector-effect='non-scaling-stroke' stroke-dasharray='4,3' stroke-linejoin='round' stroke-linecap='round'/>
        </svg>
        <div style='display:flex;font-size:.68rem;color:var(--t-muted);margin-top:6px;padding:0 2px'>{$labels}</div>
        <div style='display:flex;gap:16px;font-size:.72rem;color:var(--t-muted);margin-top:6px'>
            <span style='color:#e8212a'>&#8212; " . __('Total CVEs', 'tanium') . "</span>
            <span style='color:#f97316'>&#8943; " . __('Critical CVEs', 'tanium') . "</span>
        </div>";
    }

    public static function showPage(): void {
        $history = self::getHistory(30);
        $webDir  = Plugin::getWebDir('tanium');
        $logoUrl = $webDir . '/public/img/tanium-logo.svg';
        $current  = $history ? end($history) : null;
        $previous = count($history) >= 2 ? $history[count($history) - 2] : null;
        ?>
        <div class="tanium-page-wrap">

        <div class="tanium-dashboard-hero">
            <div class="tanium-hero-brand">
                <img src="<?= $logoUrl ?>" alt="Tanium" class="tanium-hero-logo"/>
                <div>
                    <div class="tanium-hero-title"><?= __('Trend', 'tanium') ?></div>
                    <div class="tanium-hero-sub"><?= __('How your CVE posture moved since the last scan', 'tanium') ?></div>
                </div>
            </div>
            <div class="tanium-hero-actions">
                <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary">
                    <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/sync.form.php" class="tanium-btn tanium-btn-primary">
                    &#9654; <?= __('Sync now', 'tanium') ?>
                </a>
            </div>
        </div>

        <?php if ($current === null): ?>
            <div class="tanium-card">
                <div class="tanium-card-body">
                    <p class="tanium-empty"><?= __('No sync history yet. Run a sync to start tracking trends.', 'tanium') ?></p>
                </div>
            </div>
            </div>
            <?php
            return;
        endif;

        if ($previous === null): ?>
            <div class="tanium-card" style="margin-bottom:16px">
                <div class="tanium-card-body">
                    <p class="tanium-empty"><?= __('Only one scan recorded so far. Run a second sync to see a trend.', 'tanium') ?></p>
                </div>
            </div>
        <?php endif;

        $totalPct = self::pctDelta((int)$current['total_cves'], $previous !== null ? (int)$previous['total_cves'] : 0);
        $critPct  = self::pctDelta((int)$current['critical_cves'], $previous !== null ? (int)$previous['critical_cves'] : 0);
        $riskPct  = $previous !== null ? self::pctDelta((int)round((float)$current['avg_risk']), (int)round((float)$previous['avg_risk'])) : null;
        $patchPct = self::pctDelta((int)$current['patches_missing'], $previous !== null ? (int)$previous['patches_missing'] : 0);
        ?>

        <!-- KPI cards: current value + trend vs the previous scan -->
        <div class="tanium-kpi-grid">
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(122,141,168,.15);color:#7a8da8">&#128202;</div>
                <div class="tanium-kpi-value"><?= number_format((int)$current['total_cves']) ?></div>
                <div class="tanium-kpi-label"><?= __('Total CVEs', 'tanium') ?></div>
                <?php if ($previous !== null): ?>
                <span class="tanium-kpi-link" style="font-size:.75rem"><?= self::trendChip($totalPct) ?> <?= __('vs last scan', 'tanium') ?></span>
                <?php endif; ?>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(232,33,42,.15);color:#e8212a">&#9762;</div>
                <div class="tanium-kpi-value tanium-text-red"><?= number_format((int)$current['critical_cves']) ?></div>
                <div class="tanium-kpi-label"><?= __('Critical CVEs', 'tanium') ?></div>
                <?php if ($previous !== null): ?>
                <span class="tanium-kpi-link" style="font-size:.75rem"><?= self::trendChip($critPct) ?> <?= __('vs last scan', 'tanium') ?></span>
                <?php endif; ?>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(240,160,48,.15);color:#f0a030">&#128200;</div>
                <div class="tanium-kpi-value"><?= number_format((float)$current['avg_risk'], 1) ?></div>
                <div class="tanium-kpi-label"><?= __('Average risk score', 'tanium') ?></div>
                <?php if ($previous !== null): ?>
                <span class="tanium-kpi-link" style="font-size:.75rem"><?= self::trendChip($riskPct) ?> <?= __('vs last scan', 'tanium') ?></span>
                <?php endif; ?>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(232,196,42,.15);color:#e8c42a">&#128295;</div>
                <div class="tanium-kpi-value"><?= number_format((int)$current['patches_missing']) ?></div>
                <div class="tanium-kpi-label"><?= __('Missing patches', 'tanium') ?></div>
                <?php if ($previous !== null): ?>
                <span class="tanium-kpi-link" style="font-size:.75rem"><?= self::trendChip($patchPct) ?> <?= __('vs last scan', 'tanium') ?></span>
                <?php endif; ?>
            </div>
        </div>

        <!-- Chart -->
        <?php if (count($history) >= 2): ?>
        <div class="tanium-card" style="margin-bottom:16px">
            <div class="tanium-card-header">
                <span class="ti ti-chart-line"></span> <?= __('CVE count over time', 'tanium') ?>
                <span class="tanium-muted" style="margin-left:auto;font-size:.78rem"><?= sprintf(__('Last %d syncs', 'tanium'), count($history)) ?></span>
            </div>
            <div class="tanium-card-body" style="padding:16px 24px 8px">
                <?= self::renderChart($history) ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Sync-over-sync history table -->
        <div class="tanium-card">
            <div class="tanium-card-header">
                <span class="ti ti-history"></span> <?= __('Scan-by-scan history', 'tanium') ?>
            </div>
            <div class="tanium-card-body" style="padding:0">
                <table class="tanium-table">
                    <thead>
                        <tr>
                            <th><?= __('Date', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Total CVEs', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Critical CVEs', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Avg. risk', 'tanium') ?></th>
                            <th class="tanium-center"><?= __('Missing patches', 'tanium') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php
                    $reversed = array_reverse($history);
                    foreach ($reversed as $i => $row):
                        $prevRow = $reversed[$i + 1] ?? null;
                        $tPct = $prevRow !== null ? self::pctDelta((int)$row['total_cves'], (int)$prevRow['total_cves']) : null;
                        $cPct = $prevRow !== null ? self::pctDelta((int)$row['critical_cves'], (int)$prevRow['critical_cves']) : null;
                        $rPct = $prevRow !== null ? self::pctDelta((int)round((float)$row['avg_risk']), (int)round((float)$prevRow['avg_risk'])) : null;
                        $pPct = $prevRow !== null ? self::pctDelta((int)$row['patches_missing'], (int)$prevRow['patches_missing']) : null;
                    ?>
                        <tr>
                            <td class="tanium-mono tanium-small"><?= Html::convDateTime($row['recorded_at']) ?></td>
                            <td class="tanium-center"><?= number_format((int)$row['total_cves']) ?> <?= $prevRow !== null ? self::trendChip($tPct) : '' ?></td>
                            <td class="tanium-center"><?= number_format((int)$row['critical_cves']) ?> <?= $prevRow !== null ? self::trendChip($cPct) : '' ?></td>
                            <td class="tanium-center"><?= number_format((float)$row['avg_risk'], 1) ?> <?= $prevRow !== null ? self::trendChip($rPct) : '' ?></td>
                            <td class="tanium-center"><?= number_format((int)$row['patches_missing']) ?> <?= $prevRow !== null ? self::trendChip($pPct) : '' ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        </div><!-- .tanium-page-wrap -->
        <?php
    }
}
