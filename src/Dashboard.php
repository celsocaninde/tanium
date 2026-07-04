<?php

namespace GlpiPlugin\Tanium;

use Html;
use Plugin;

class Dashboard {

    public static function getStats(): array {
        global $DB;

        $stats = [
            'total_endpoints'   => 0,
            'total_cves'        => 0,
            'cves_critical'     => 0,
            'cves_high'         => 0,
            'cves_medium'       => 0,
            'cves_low'          => 0,
            'patches_missing'   => 0,
            'patch_compliance'  => null,
            'endpoints_critical'=> 0,
            'endpoints_high'    => 0,
            'endpoints_medium'  => 0,
            'endpoints_low'     => 0,
            'last_sync'         => null,
            'last_sync_count'   => 0,
            'os_distribution'   => [],
            'sync_status'       => 'never',
        ];

        // Endpoint count
        $row = $DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'COUNT' => 'cpt'])->current();
        $stats['total_endpoints'] = (int) ($row['cpt'] ?? 0);

        // CVE counts by severity
        $cveRows = $DB->request(['FROM' => 'glpi_plugin_tanium_vulnerabilities']);
        foreach ($cveRows as $r) {
            $stats['total_cves']++;
            $sev = strtolower($r['severity']);
            if ($sev === 'critical') $stats['cves_critical']++;
            elseif ($sev === 'high')  $stats['cves_high']++;
            elseif ($sev === 'medium') $stats['cves_medium']++;
            elseif ($sev === 'low')   $stats['cves_low']++;
        }

        // Missing patches
        $pRow = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_patches',
            'WHERE' => ['status' => 'missing'],
            'COUNT' => 'cpt',
        ])->current();
        $stats['patches_missing'] = (int) ($pRow['cpt'] ?? 0);

        // Patch compliance %
        $totalPatches = (int) ($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'COUNT' => 'cpt'])->current()['cpt'] ?? 0);
        if ($totalPatches > 0) {
            $installed = $totalPatches - $stats['patches_missing'];
            $stats['patch_compliance'] = (int) round($installed / $totalPatches * 100);
        }

        // Endpoints by risk level
        foreach ($DB->request(['SELECT' => ['risk_score'], 'FROM' => 'glpi_plugin_tanium_assets']) as $r) {
            $rs = (int)$r['risk_score'];
            if ($rs >= 70)      $stats['endpoints_critical']++;
            elseif ($rs >= 40)  $stats['endpoints_high']++;
            elseif ($rs >= 15)  $stats['endpoints_medium']++;
            else                $stats['endpoints_low']++;
        }

        // OS distribution
        $osRows = $DB->request([
            'SELECT' => ['os_name', 'COUNT' => 'id AS cnt'],
            'FROM'   => 'glpi_plugin_tanium_assets',
            'WHERE'  => ['NOT' => ['os_name' => null]],
            'GROUPBY'=> 'os_name',
            'ORDER'  => 'cnt DESC',
            'LIMIT'  => 8,
        ]);
        foreach ($osRows as $r) {
            $stats['os_distribution'][$r['os_name']] = (int) $r['cnt'];
        }

        // Last sync info from config
        $config = Config::getConfig();
        $stats['last_sync']       = $config['last_sync'];
        $stats['last_sync_count'] = (int) $config['last_sync_count'];

        // Agent health: endpoints silent past the configured threshold
        $stats['agent_stale_days'] = (int)($config['agent_stale_days'] ?? 7);
        $stats['agents_stale']     = AgentHealth::countStale($stats['agent_stale_days']);

        // Hardening: fleet-wide Comply benchmark score (null = module not used)
        $stats['comply_score'] = Compliance::fleetScore();

        // Open Threat Response alerts
        $stats['threat_alerts'] = ThreatResponse::countOpen();

        // KEV exposure: open findings whose CVE has confirmed exploitation
        Enrichment::ensureTable();
        $kevRow = $DB->doQuery("
            SELECT COUNT(*) AS cpt
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_cve_enrichment e
                 ON e.cve_id = ec.cve_id AND e.is_kev = 1
            WHERE ec.status != 'remediated'
        ")->fetch_assoc();
        $stats['kev_findings'] = (int)($kevRow['cpt'] ?? 0);

        // Last sync status from logs
        $logRow = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_sync_logs',
            'WHERE' => ['NOT' => ['status' => 'running']],
            'ORDER' => 'started_at DESC',
            'LIMIT' => 1,
        ])->current();
        if ($logRow) {
            $stats['sync_status'] = $logRow['status'];
        }

        return $stats;
    }

    public static function getTopVulnerableEndpoints(int $limit = 10): array {
        global $DB;

        $limit = (int) $limit;
        $sql   = "
            SELECT
                a.tanium_eid, a.tanium_name, a.computers_id, a.ip_address, a.os_name,
                COUNT(ec.id) AS cve_count
            FROM glpi_plugin_tanium_assets AS a
            LEFT JOIN glpi_plugin_tanium_endpoint_cves AS ec
                ON a.tanium_eid = ec.tanium_eid
            GROUP BY a.tanium_eid
            ORDER BY cve_count DESC
            LIMIT {$limit}
        ";

        $result = [];
        foreach ($DB->doQuery($sql) as $r) {
            $result[] = $r;
        }
        return $result;
    }

    public static function getRecentSyncs(int $limit = 5): array {
        global $DB;

        $rows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_sync_logs',
            'ORDER' => 'started_at DESC',
            'LIMIT' => $limit,
        ]) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    public static function getRiskTimeline(int $limit = 12): array {
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

    private static function renderTimelineChart(array $timeline): string {
        if (empty($timeline)) {
            return '<p class="tanium-empty">' . __('No sync history yet. Risk timeline will appear after the first sync.', 'tanium') . '</p>';
        }

        $w = 100; $h = 80;
        $n = count($timeline);
        $stepX   = $n > 1 ? $w / ($n - 1) : 0;
        $maxCrit = max(1, max(array_column($timeline, 'critical_count')));

        $avgPoints  = '';
        $critPoints = '';
        $lastX      = 0;
        foreach (array_values($timeline) as $i => $row) {
            $x    = $n > 1 ? round($i * $stepX, 2) : ($w / 2);
            $yAvg = round($h - (max(0.0, min(100.0, (float)$row['avg_risk'])) / 100 * $h), 2);
            $yCrt = round($h - ((float)$row['critical_count'] / $maxCrit * $h), 2);
            $avgPoints  .= "{$x},{$yAvg} ";
            $critPoints .= "{$x},{$yCrt} ";
            $lastX = $x;
        }
        $avgPoints  = trim($avgPoints);
        $critPoints = trim($critPoints);

        // Filled area under the average-risk line (uses the gradient defined below).
        $areaPoints = "{$avgPoints} {$lastX},{$h} 0,{$h}";

        // X-axis labels are rendered as HTML *below* the SVG. Drawing <text> inside an
        // SVG that uses preserveAspectRatio='none' stretches glyphs ~10x horizontally —
        // that is what made the old timeline look garbled and overlapping.
        $labelCells = '';
        foreach (array_values($timeline) as $row) {
            $lbl = date('d/m H:i', strtotime($row['recorded_at']));
            $labelCells .= "<span style='flex:1 1 0;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'>{$lbl}</span>";
        }

        return "
        <svg viewBox='0 0 {$w} {$h}' width='100%' height='140' preserveAspectRatio='none' style='display:block'>
            <defs>
                <linearGradient id='tg1' x1='0' y1='0' x2='0' y2='1'>
                    <stop offset='0%' stop-color='#e8212a' stop-opacity='.28'/>
                    <stop offset='100%' stop-color='#e8212a' stop-opacity='0'/>
                </linearGradient>
            </defs>
            <polygon points='{$areaPoints}' fill='url(#tg1)' stroke='none'/>
            <polyline points='{$avgPoints}' fill='none' stroke='#e8212a' stroke-width='2' vector-effect='non-scaling-stroke' stroke-linejoin='round' stroke-linecap='round'/>
            <polyline points='{$critPoints}' fill='none' stroke='#f97316' stroke-width='1.5' vector-effect='non-scaling-stroke' stroke-dasharray='4,3' stroke-linejoin='round' stroke-linecap='round'/>
        </svg>
        <div style='display:flex;font-size:.68rem;color:var(--t-muted);margin-top:6px;padding:0 2px'>{$labelCells}</div>
        <div style='display:flex;gap:16px;font-size:.72rem;color:var(--t-muted);margin-top:6px'>
            <span style='color:#e8212a'>— Risk score médio</span>
            <span style='color:#f97316'>⋯ Endpoints críticos</span>
        </div>";
    }

    public static function show(): void {
        $stats      = self::getStats();
        $topVulnEps = self::getTopVulnerableEndpoints(8);
        $recentSync = self::getRecentSyncs(5);
        $slaStats   = Sla::getStats();
        $config     = Config::getConfig();
        $configured = !empty($config['api_url']) && !empty($config['api_token']);
        $logoUrl    = Plugin::getWebDir('tanium') . '/public/img/tanium-logo.svg';
        $webDir     = Plugin::getWebDir('tanium');

        ?>
        <div class="tanium-page-wrap">

        <?php if (!$configured): ?>
        <div class="tanium-alert tanium-alert-warn">
            &#9888; <?= __('Tanium plugin is not configured yet.', 'tanium') ?>
            <a href="<?= $webDir ?>/front/config.form.php" class="tanium-btn tanium-btn-primary tanium-btn-sm" style="margin-left:16px">
                <?= __('Configure now', 'tanium') ?>
            </a>
        </div>
        <?php endif; ?>

        <!-- Hero header -->
        <div class="tanium-dashboard-hero">
            <div class="tanium-hero-brand">
                <img src="<?= $logoUrl ?>" alt="Tanium" class="tanium-hero-logo"/>
                <div>
                    <div class="tanium-hero-title"><?= __('Security Dashboard', 'tanium') ?></div>
                    <div class="tanium-hero-sub">
                        <?php if ($stats['last_sync']): ?>
                            <?= __('Last sync', 'tanium') ?>: <?= Html::convDateTime($stats['last_sync']) ?>
                            &nbsp;<span class="tanium-badge tanium-badge-<?= $stats['sync_status'] === 'success' ? 'success' : 'error' ?>">
                                <?= htmlspecialchars($stats['sync_status']) ?>
                            </span>
                        <?php else: ?>
                            <?= __('No sync performed yet', 'tanium') ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="tanium-hero-actions">
                <a href="<?= $webDir ?>/front/sync.form.php" class="tanium-btn tanium-btn-primary">
                    &#9654; <?= __('Sync now', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/report.php" target="_blank" class="tanium-btn tanium-btn-secondary">
                    &#128438; <?= __('Report', 'tanium') ?>
                </a>
                <a href="<?= $webDir ?>/front/config.form.php" class="tanium-btn tanium-btn-secondary">
                    &#9881; <?= __('Settings', 'tanium') ?>
                </a>
            </div>
        </div>

        <!-- Sync progress widget (always visible) -->
        <?php
        $syncStatus  = $stats['sync_status'];   // 'never' | 'running' | 'success' | 'error'
        $isRunning   = ($syncStatus === 'running');
        $progressUrl = Plugin::getWebDir('tanium') . '/ajax/sync_progress.php';
        $lastCount   = (int) $stats['last_sync_count'];

        if ($syncStatus === 'running') {
            $spLabel    = __('Syncing endpoints...', 'tanium');
            $spPct      = 0;
            $spFillCls  = 'tanium-sync-fill';
            $spDot      = true;
            $spCounts   = '';
            $spTime     = '';
        } elseif ($syncStatus === 'success') {
            $spLabel    = __('Last sync completed successfully', 'tanium');
            $spPct      = 100;
            $spFillCls  = 'tanium-sync-fill tanium-sync-fill-success';
            $spDot      = false;
            $spCounts   = $lastCount . ' endpoints';
            $spTime     = $stats['last_sync'] ? Html::convDateTime($stats['last_sync']) : '';
        } elseif ($syncStatus === 'error') {
            $spLabel    = __('Last sync finished with errors', 'tanium');
            $spPct      = 100;
            $spFillCls  = 'tanium-sync-fill tanium-sync-fill-error';
            $spDot      = false;
            $spCounts   = $lastCount . ' endpoints';
            $spTime     = $stats['last_sync'] ? Html::convDateTime($stats['last_sync']) : '';
        } else {
            $spLabel    = __('No sync performed yet', 'tanium');
            $spPct      = 0;
            $spFillCls  = 'tanium-sync-fill';
            $spDot      = false;
            $spCounts   = __('Click "Sync now" to start the first synchronization', 'tanium');
            $spTime     = '';
        }
        ?>
        <div id="tanium-sync-progress" class="tanium-sync-progress">
            <div class="tanium-sync-progress-label">
                <span class="tanium-pulse-dot" id="tsp-dot" style="<?= $spDot ? '' : 'display:none' ?>"></span>
                <span id="tsp-label"><?= htmlspecialchars($spLabel) ?></span>
                <span class="tanium-sync-progress-pct" id="tsp-pct"><?= $spPct > 0 ? $spPct . '%' : '' ?></span>
            </div>
            <div class="tanium-sync-track">
                <div class="<?= $spFillCls ?>" id="tsp-fill" style="width:<?= $spPct ?>%"></div>
            </div>
            <div class="tanium-sync-footer">
                <span id="tsp-counts"><?= htmlspecialchars($spCounts) ?></span>
                <span id="tsp-time"><?= htmlspecialchars($spTime) ?></span>
            </div>
        </div>
        <script>
        (function () {
            var dot    = document.getElementById('tsp-dot');
            var label  = document.getElementById('tsp-label');
            var pct    = document.getElementById('tsp-pct');
            var fill   = document.getElementById('tsp-fill');
            var counts = document.getElementById('tsp-counts');
            var timeEl = document.getElementById('tsp-time');
            var url    = <?= json_encode($progressUrl) ?>;
            var timer  = null;
            var reloading  = false;
            var wasRunning = false;

            function fmt(n) { return Number(n).toLocaleString(); }

            function render(d, initial) {
                if (d.status === 'running') {
                    wasRunning = true;
                    var p = d.percent || 0;
                    dot.style.display  = 'inline-block';
                    label.textContent  = '<?= __('Syncing endpoints...', 'tanium') ?>';
                    pct.textContent    = p + '%';
                    fill.style.width   = p + '%';
                    fill.className     = 'tanium-sync-fill';
                    counts.textContent = fmt(d.processed) + (d.total > 0 ? ' / ' + fmt(d.total) + ' endpoints' : ' endpoints');
                    timeEl.textContent = d.started_at ? '<?= __('Started', 'tanium') ?>: ' + d.started_at : '';
                    timer = setTimeout(poll, 3000);

                } else if (d.status === 'success') {
                    clearTimeout(timer);
                    dot.style.display  = 'none';
                    label.textContent  = '<?= __('Last sync completed successfully', 'tanium') ?>';
                    pct.textContent    = '100%';
                    fill.style.width   = '100%';
                    fill.className     = 'tanium-sync-fill tanium-sync-fill-success';
                    counts.textContent = fmt(d.processed) + ' endpoints'
                                      + (d.errors > 0 ? ' — ' + d.errors + ' <?= __('errors', 'tanium') ?>' : '');
                    timeEl.textContent = d.finished_at || '';
                    if (!initial && wasRunning && !reloading) {
                        reloading = true;
                        setTimeout(function () { location.reload(); }, 3000);
                    }

                } else if (d.status === 'error') {
                    clearTimeout(timer);
                    dot.style.display  = 'none';
                    label.textContent  = '<?= __('Last sync finished with errors', 'tanium') ?>';
                    pct.textContent    = '';
                    fill.style.width   = '100%';
                    fill.className     = 'tanium-sync-fill tanium-sync-fill-error';
                    counts.textContent = d.errors + ' <?= __('errors', 'tanium') ?>';
                    timeEl.textContent = d.finished_at || '';
                    if (!initial && wasRunning && !reloading) {
                        reloading = true;
                        setTimeout(function () { location.reload(); }, 3000);
                    }
                }
                // 'never': keep the PHP-rendered placeholder
            }

            function poll() {
                clearTimeout(timer);
                fetch(url, { credentials: 'same-origin' })
                    .then(function (r) { return r.json(); })
                    .then(function (d) { render(d, false); })
                    .catch(function () { timer = setTimeout(poll, 5000); });
            }

            // On load: fetch once immediately to sync the bar with real DB state.
            // This corrects the PHP-rendered initial state (e.g. 'never' while DB has 'success').
            fetch(url, { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    render(d, true);
                    // Keep polling every 5 s when idle to detect sync started from cron or another tab
                    if (d.status !== 'running') {
                        setInterval(poll, 5000);
                    }
                })
                .catch(function () { setInterval(poll, 5000); });
        }());
        </script>

        <!-- KPI cards -->
        <div class="tanium-kpi-grid">
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-blue">&#128187;</div>
                <div class="tanium-kpi-value"><?= number_format($stats['total_endpoints']) ?></div>
                <div class="tanium-kpi-label"><?= __('Endpoints synced', 'tanium') ?></div>
                <a href="<?= $webDir ?>/front/endpoints.php" class="tanium-kpi-link"><?= __('View all', 'tanium') ?> →</a>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-red">&#9762;</div>
                <div class="tanium-kpi-value tanium-text-red"><?= number_format($stats['cves_critical']) ?></div>
                <div class="tanium-kpi-label"><?= __('Critical CVEs', 'tanium') ?></div>
                <a href="<?= $webDir ?>/front/vulnerabilities.php?severity=critical" class="tanium-kpi-link"><?= __('View', 'tanium') ?> →</a>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-orange">&#9888;</div>
                <div class="tanium-kpi-value" style="color:#f0a030"><?= number_format($stats['cves_high']) ?></div>
                <div class="tanium-kpi-label"><?= __('High severity CVEs', 'tanium') ?></div>
                <a href="<?= $webDir ?>/front/vulnerabilities.php?severity=high" class="tanium-kpi-link"><?= __('View', 'tanium') ?> →</a>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-yellow">&#128396;</div>
                <div class="tanium-kpi-value" style="color:#e8c42a"><?= number_format($stats['patches_missing']) ?></div>
                <div class="tanium-kpi-label"><?= __('Missing patches', 'tanium') ?></div>
                <a href="<?= $webDir ?>/front/patches.php" class="tanium-kpi-link"><?= __('View', 'tanium') ?> →</a>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon tanium-kpi-muted">&#128505;</div>
                <div class="tanium-kpi-value"><?= number_format($stats['total_cves']) ?></div>
                <div class="tanium-kpi-label"><?= __('Total unique CVEs', 'tanium') ?></div>
                <a href="<?= $webDir ?>/front/vulnerabilities.php" class="tanium-kpi-link"><?= __('View all', 'tanium') ?> →</a>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(232,33,42,.15);color:#e8212a">&#128293;</div>
                <div class="tanium-kpi-value <?= $stats['kev_findings'] > 0 ? 'tanium-text-red' : '' ?>"><?= number_format($stats['kev_findings']) ?></div>
                <div class="tanium-kpi-label" title="<?= __('Open findings on CVEs with confirmed exploitation (CISA KEV)', 'tanium') ?>"><?= __('KEV exposure', 'tanium') ?></div>
            </div>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(122,141,168,.15);color:#7a8da8">&#128263;</div>
                <div class="tanium-kpi-value" style="<?= $stats['agents_stale'] > 0 ? 'color:#f0a030' : '' ?>"><?= number_format($stats['agents_stale']) ?></div>
                <div class="tanium-kpi-label"><?= sprintf(__('Silent agents (> %d days)', 'tanium'), $stats['agent_stale_days']) ?></div>
            </div>
            <?php if ($stats['comply_score'] !== null):
                $csColor = $stats['comply_score'] >= 90 ? '#1eb464' : ($stats['comply_score'] >= 70 ? '#e8c42a' : '#e8212a');
            ?>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:<?= $csColor ?>22;color:<?= $csColor ?>">&#9989;</div>
                <div class="tanium-kpi-value" style="color:<?= $csColor ?>"><?= $stats['comply_score'] ?>%</div>
                <div class="tanium-kpi-label"><?= __('Benchmark compliance (Comply)', 'tanium') ?></div>
            </div>
            <?php endif; ?>
            <?php if ($stats['threat_alerts'] > 0): ?>
            <div class="tanium-kpi-card">
                <div class="tanium-kpi-icon" style="background:rgba(232,33,42,.15);color:#e8212a">&#128737;</div>
                <div class="tanium-kpi-value tanium-text-red"><?= number_format($stats['threat_alerts']) ?></div>
                <div class="tanium-kpi-label"><?= __('Open threat alerts (TR)', 'tanium') ?></div>
            </div>
            <?php endif; ?>
            <div class="tanium-kpi-card">
                <?php
                $compliance = $stats['patch_compliance'];
                if ($compliance === null) {
                    $compColor = '#7a8da8';
                    $compLabel = '—';
                } else {
                    $compColor = $compliance >= 90 ? '#1eb464' : ($compliance >= 70 ? '#e8c42a' : '#e8212a');
                    $compLabel = $compliance . '%';
                }
                ?>
                <div class="tanium-kpi-icon" style="background:<?= $compColor ?>22;color:<?= $compColor ?>">&#127919;</div>
                <div class="tanium-kpi-value" style="color:<?= $compColor ?>"><?= $compLabel ?></div>
                <div class="tanium-kpi-label"><?= __('Patch compliance', 'tanium') ?></div>
                <?php if ($compliance === null): ?>
                    <span class="tanium-kpi-link tanium-muted" style="font-size:.75rem"><?= !empty($config['sync_patches']) ? __('No patch data yet — run a sync', 'tanium') : __('Enable patch sync', 'tanium') ?></span>
                <?php else: ?>
                    <a href="<?= $webDir ?>/front/patches.php" class="tanium-kpi-link"><?= __('Details', 'tanium') ?> →</a>
                <?php endif; ?>
            </div>
            <div class="tanium-kpi-card">
                <?php
                $slaComp = $slaStats['compliance'];
                if ($slaComp === null) {
                    $slaColor = '#7a8da8';
                    $slaLabel = '—';
                } else {
                    $slaColor = $slaComp >= 90 ? '#1eb464' : ($slaComp >= 70 ? '#e8c42a' : '#e8212a');
                    $slaLabel = $slaComp . '%';
                }
                ?>
                <div class="tanium-kpi-icon" style="background:<?= $slaColor ?>22;color:<?= $slaColor ?>">&#9201;</div>
                <div class="tanium-kpi-value" style="color:<?= $slaColor ?>"><?= $slaLabel ?></div>
                <div class="tanium-kpi-label"><?= __('SLA compliance', 'tanium') ?></div>
                <?php if ($slaComp === null): ?>
                    <span class="tanium-kpi-link tanium-muted" style="font-size:.75rem"><?= __('No CVEs to measure yet', 'tanium') ?></span>
                <?php else: ?>
                    <a href="<?= $webDir ?>/front/sla.php" class="tanium-kpi-link"><?= number_format($slaStats['breached']) ?> <?= __('overdue', 'tanium') ?> →</a>
                <?php endif; ?>
            </div>
        </div>

        <!-- Risk distribution bar -->
        <?php if ($stats['total_endpoints'] > 0):
            $ep = $stats['total_endpoints'];
            $critPct   = round($stats['endpoints_critical'] / $ep * 100);
            $highPct   = round($stats['endpoints_high']     / $ep * 100);
            $medPct    = round($stats['endpoints_medium']   / $ep * 100);
            $lowPct    = 100 - $critPct - $highPct - $medPct;
        ?>
        <div class="tanium-risk-overview">
            <div class="tanium-risk-title"><?= __('Endpoint Risk Overview', 'tanium') ?></div>
            <div class="tanium-risk-stacked">
                <?php if ($critPct > 0): ?><div class="tanium-risk-seg tanium-risk-seg-critical" style="width:<?= $critPct ?>%" title="Critical: <?= $stats['endpoints_critical'] ?>"><?= $stats['endpoints_critical'] ?></div><?php endif; ?>
                <?php if ($highPct > 0): ?><div class="tanium-risk-seg tanium-risk-seg-high"     style="width:<?= $highPct ?>%"   title="High: <?= $stats['endpoints_high'] ?>"><?= $stats['endpoints_high'] ?></div><?php endif; ?>
                <?php if ($medPct  > 0): ?><div class="tanium-risk-seg tanium-risk-seg-medium"   style="width:<?= $medPct ?>%"    title="Medium: <?= $stats['endpoints_medium'] ?>"><?= $stats['endpoints_medium'] ?></div><?php endif; ?>
                <?php if ($lowPct  > 0): ?><div class="tanium-risk-seg tanium-risk-seg-low"      style="width:<?= max(1,$lowPct) ?>%" title="Low: <?= $stats['endpoints_low'] ?>"><?= $stats['endpoints_low'] ?></div><?php endif; ?>
            </div>
            <div class="tanium-risk-legend">
                <span class="tanium-rl-dot tanium-rl-critical"></span>Critical (<?= $stats['endpoints_critical'] ?>)
                <span class="tanium-rl-dot tanium-rl-high"    ></span>High (<?= $stats['endpoints_high'] ?>)
                <span class="tanium-rl-dot tanium-rl-medium"  ></span>Medium (<?= $stats['endpoints_medium'] ?>)
                <span class="tanium-rl-dot tanium-rl-low"     ></span>Low (<?= $stats['endpoints_low'] ?>)
            </div>
        </div>
        <?php endif; ?>

        <!-- Risk score timeline -->
        <?php $timeline = self::getRiskTimeline(12); ?>
        <div class="tanium-card" style="margin-bottom:16px">
            <div class="tanium-card-header">
                <span>&#128200; <?= __('Risk Score Timeline', 'tanium') ?></span>
                <span class="tanium-muted" style="margin-left:auto;font-size:.78rem"><?= sprintf(__('Last %d syncs', 'tanium'), min(12, count($timeline))) ?></span>
            </div>
            <div class="tanium-card-body" style="padding:16px 24px 8px">
                <?= self::renderTimelineChart($timeline) ?>
            </div>
        </div>

        <div class="tanium-dashboard-grid">

            <!-- CVE severity distribution -->
            <div class="tanium-card tanium-dashboard-panel">
                <div class="tanium-card-header">
                    <span>&#127914; <?= __('CVE Severity Distribution', 'tanium') ?></span>
                </div>
                <div class="tanium-card-body">
                    <?php
                    $sevData  = [
                        'critical' => [$stats['cves_critical'], '#e8212a'],
                        'high'     => [$stats['cves_high'],     '#f0a030'],
                        'medium'   => [$stats['cves_medium'],   '#e8c42a'],
                        'low'      => [$stats['cves_low'],      '#1eb464'],
                    ];
                    $maxCVE = max(1, $stats['total_cves']);
                    foreach ($sevData as $sev => [$cnt, $color]): ?>
                    <div class="tanium-bar-row">
                        <div class="tanium-bar-label">
                            <span class="tanium-sev-dot" style="background:<?= $color ?>"></span>
                            <?= ucfirst($sev) ?>
                        </div>
                        <div class="tanium-bar-track">
                            <div class="tanium-bar-fill" style="width:<?= min(100, round($cnt/$maxCVE*100)) ?>%;background:<?= $color ?>"></div>
                        </div>
                        <div class="tanium-bar-count"><?= $cnt ?></div>
                    </div>
                    <?php endforeach; ?>
                    <?php if ($stats['total_cves'] === 0): ?>
                        <p class="tanium-empty"><?= __('No CVE data. Enable "Vulnerabilities" sync and run a sync.', 'tanium') ?></p>
                    <?php endif; ?>
                </div>
            </div>

            <!-- OS distribution -->
            <div class="tanium-card tanium-dashboard-panel">
                <div class="tanium-card-header">
                    <span>&#128187; <?= __('OS Distribution', 'tanium') ?></span>
                </div>
                <div class="tanium-card-body">
                    <?php
                    $maxOS = max(1, max(array_values($stats['os_distribution']) ?: [1]));
                    $osColors = ['#e8212a','#f0a030','#1a6dff','#1eb464','#9b59b6','#e8c42a','#00bcd4','#7a8da8'];
                    $ci = 0;
                    foreach ($stats['os_distribution'] as $os => $cnt):
                        $color = $osColors[$ci++ % count($osColors)]; ?>
                    <div class="tanium-bar-row">
                        <div class="tanium-bar-label tanium-bar-label-sm"><?= htmlspecialchars($os) ?></div>
                        <div class="tanium-bar-track">
                            <div class="tanium-bar-fill" style="width:<?= min(100,round($cnt/$maxOS*100)) ?>%;background:<?= $color ?>"></div>
                        </div>
                        <div class="tanium-bar-count"><?= $cnt ?></div>
                    </div>
                    <?php endforeach; ?>
                    <?php if (empty($stats['os_distribution'])): ?>
                        <p class="tanium-empty"><?= __('No endpoint data yet.', 'tanium') ?></p>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Top vulnerable endpoints -->
            <div class="tanium-card tanium-dashboard-wide">
                <div class="tanium-card-header tanium-card-header-dark">
                    <span>&#127919; <?= __('Most Vulnerable Endpoints', 'tanium') ?></span>
                    <a href="<?= $webDir ?>/front/endpoints.php?risk=critical" class="tanium-btn tanium-btn-sm tanium-btn-secondary" style="margin-left:auto"><?= __('All endpoints', 'tanium') ?></a>
                </div>
                <div class="tanium-card-body tanium-p0">
                    <?php if (empty($topVulnEps)): ?>
                        <p class="tanium-empty"><?= __('No data yet. Run a sync with CVE scanning enabled.', 'tanium') ?></p>
                    <?php else: ?>
                    <table class="tanium-table">
                        <thead>
                            <tr>
                                <th><?= __('Endpoint', 'tanium') ?></th>
                                <th><?= __('IP Address', 'tanium') ?></th>
                                <th><?= __('OS', 'tanium') ?></th>
                                <th><?= __('CVEs found', 'tanium') ?></th>
                                <th><?= __('Actions', 'tanium') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($topVulnEps as $ep): ?>
                            <tr>
                                <td class="tanium-mono">
                                    <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ep['tanium_eid']) ?>" class="tanium-link">
                                        <?= htmlspecialchars($ep['tanium_name']) ?>
                                    </a>
                                </td>
                                <td class="tanium-mono"><?= htmlspecialchars($ep['ip_address'] ?? '—') ?></td>
                                <td><?= htmlspecialchars($ep['os_name'] ?? '—') ?></td>
                                <td class="tanium-center">
                                    <?php $cc = (int)$ep['cve_count']; ?>
                                    <span class="tanium-badge tanium-badge-<?= $cc > 0 ? 'error' : 'success' ?>"><?= $cc ?></span>
                                </td>
                                <td style="white-space:nowrap">
                                    <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ep['tanium_eid']) ?>" class="tanium-btn-xs tanium-btn-secondary" title="Detail">
                                        <span class="ti ti-eye"></span>
                                    </a>
                                    <a href="<?= $webDir ?>/front/report.php?eid=<?= urlencode($ep['tanium_eid']) ?>" target="_blank" class="tanium-btn-xs tanium-btn-secondary" title="Report">
                                        <span class="ti ti-printer"></span>
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Recent syncs -->
            <div class="tanium-card tanium-dashboard-wide">
                <div class="tanium-card-header tanium-card-header-dark">
                    <span>&#128336; <?= __('Recent Sync History', 'tanium') ?></span>
                    <a href="<?= $webDir ?>/front/sync.form.php" class="tanium-btn tanium-btn-sm tanium-btn-secondary" style="margin-left:auto"><?= __('Full history', 'tanium') ?></a>
                </div>
                <div class="tanium-card-body tanium-p0">
                    <?php if (empty($recentSync)): ?>
                        <p class="tanium-empty"><?= __('No sync runs yet.', 'tanium') ?></p>
                    <?php else: ?>
                    <table class="tanium-table">
                        <thead>
                            <tr>
                                <th><?= __('Started', 'tanium') ?></th>
                                <th><?= __('Duration', 'tanium') ?></th>
                                <th><?= __('Status', 'tanium') ?></th>
                                <th><?= __('Total', 'tanium') ?></th>
                                <th><?= __('Created', 'tanium') ?></th>
                                <th><?= __('Updated', 'tanium') ?></th>
                                <th><?= __('Errors', 'tanium') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($recentSync as $log):
                            $dur = '';
                            if ($log['finished_at'] && $log['started_at']) {
                                $secs = strtotime($log['finished_at']) - strtotime($log['started_at']);
                                $dur  = $secs < 60 ? "{$secs}s" : floor($secs/60) . 'm ' . ($secs%60) . 's';
                            }
                            $cls = $log['status'] === 'success' ? 'tanium-badge-success' : ($log['status'] === 'error' ? 'tanium-badge-error' : 'tanium-badge-warning');
                        ?>
                            <tr>
                                <td><?= Html::convDateTime($log['started_at']) ?></td>
                                <td class="tanium-mono"><?= $dur ?: '…' ?></td>
                                <td><span class="tanium-badge <?= $cls ?>"><?= htmlspecialchars($log['status']) ?></span></td>
                                <td class="tanium-center"><?= (int)$log['total'] ?></td>
                                <td class="tanium-center tanium-text-green"><?= (int)$log['created'] ?></td>
                                <td class="tanium-center tanium-text-blue"><?= (int)$log['updated'] ?></td>
                                <td class="tanium-center tanium-text-red"><?= (int)$log['errors'] ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                </div>
            </div>

        </div><!-- /.tanium-dashboard-grid -->
        </div><!-- /.tanium-page-wrap -->
        <?php
    }
}
