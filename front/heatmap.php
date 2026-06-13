<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);

global $DB;

$os      = $_GET['os']   ?? '';
$minRisk = max(0, (int)($_GET['min_risk'] ?? 0));
$webDir  = \Plugin::getWebDir('tanium');

// Build WHERE
$conds = ['1=1'];
if ($os)      $conds[] = "os_name = '" . $DB->escape($os) . "'";
if ($minRisk) $conds[] = "risk_score >= {$minRisk}";
$where = implode(' AND ', $conds);

$endpoints = [];
foreach ($DB->doQuery("SELECT tanium_eid, tanium_name, ip_address, os_name, risk_score, last_seen, sync_status FROM glpi_plugin_tanium_assets WHERE {$where} ORDER BY risk_score DESC, tanium_name ASC LIMIT 500") as $r) {
    $endpoints[] = $r;
}

// OS dropdown
$osRows = [];
foreach ($DB->request(['SELECT' => ['os_name'], 'FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['NOT' => ['os_name' => null]], 'GROUPBY' => 'os_name', 'ORDER' => 'os_name ASC']) as $r) {
    $osRows[] = $r['os_name'];
}

$riskColor = function(int $s): string {
    if ($s >= 70) return '#e8212a';
    if ($s >= 40) return '#f97316';
    if ($s >= 15) return '#f59e0b';
    return '#1eb464';
};
$riskClass = function(int $s): string {
    if ($s >= 70) return 'hm-critical';
    if ($s >= 40) return 'hm-high';
    if ($s >= 15) return 'hm-medium';
    return 'hm-low';
};

Html::header(__('Tanium — Risk Heatmap', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">
<div class="tanium-card">
    <div class="tanium-card-header">
        <span>&#127919; <?= __('Endpoint Risk Heatmap', 'tanium') ?></span>
        <span class="tanium-muted" style="margin-left:auto;font-size:.8rem"><?= count($endpoints) ?> <?= __('endpoints', 'tanium') ?></span>
    </div>

    <!-- Filter bar -->
    <div class="tanium-filter-bar">
        <form method="get" class="tanium-filter-form">
            <select name="os" class="tanium-input tanium-select">
                <option value=""><?= __('All OS', 'tanium') ?></option>
                <?php foreach ($osRows as $n): ?>
                <option value="<?= htmlspecialchars($n) ?>" <?= $os === $n ? 'selected' : '' ?>><?= htmlspecialchars($n) ?></option>
                <?php endforeach; ?>
            </select>
            <select name="min_risk" class="tanium-input tanium-select">
                <option value="0"  <?= $minRisk === 0  ? 'selected' : '' ?>><?= __('All risk levels', 'tanium') ?></option>
                <option value="15" <?= $minRisk === 15 ? 'selected' : '' ?>>≥ 15 (Médio+)</option>
                <option value="40" <?= $minRisk === 40 ? 'selected' : '' ?>>≥ 40 (Alto+)</option>
                <option value="70" <?= $minRisk === 70 ? 'selected' : '' ?>>≥ 70 (Crítico)</option>
            </select>
            <button type="submit" class="tanium-btn tanium-btn-primary"><?= __('Filter', 'tanium') ?></button>
            <?php if ($os || $minRisk): ?>
            <a href="<?= $webDir ?>/front/heatmap.php" class="tanium-btn tanium-btn-secondary"><?= __('Clear', 'tanium') ?></a>
            <?php endif; ?>
        </form>
        <!-- Legend -->
        <div class="hm-legend">
            <span class="hm-legend-dot hm-critical"></span> Crítico (≥70)
            <span class="hm-legend-dot hm-high"    ></span> Alto (40-69)
            <span class="hm-legend-dot hm-medium"  ></span> Médio (15-39)
            <span class="hm-legend-dot hm-low"     ></span> Baixo (<15)
        </div>
    </div>

    <div class="tanium-card-body">
        <?php if (empty($endpoints)): ?>
            <p class="tanium-empty"><?= __('No endpoints found. Run a sync first.', 'tanium') ?></p>
        <?php else: ?>
        <div class="hm-grid">
            <?php foreach ($endpoints as $ep):
                $rs    = (int)($ep['risk_score'] ?? 0);
                $cls   = $riskClass($rs);
                $color = $riskColor($rs);
                $ls    = $ep['last_seen'] ? strtotime($ep['last_seen']) : 0;
                $stale = $ls && (time() - $ls) > 86400 * 7;
                $tip   = htmlspecialchars($ep['tanium_name'] . "\nIP: " . ($ep['ip_address'] ?? '—') . "\nOS: " . ($ep['os_name'] ?? '—') . "\nRisk: {$rs}");
            ?>
            <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ep['tanium_eid']) ?>"
               class="hm-cell <?= $cls ?> <?= $stale ? 'hm-stale' : '' ?>"
               title="<?= $tip ?>">
                <span class="hm-score"><?= $rs ?></span>
                <span class="hm-name"><?= htmlspecialchars(mb_strimwidth($ep['tanium_name'], 0, 14, '…')) ?></span>
                <?php if ($stale): ?><span class="hm-stale-dot" title="<?= __('Not seen for >7 days', 'tanium') ?>">!</span><?php endif; ?>
            </a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>
</div>

<style>
.hm-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding: 4px;
}
.hm-cell {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 90px;
    height: 72px;
    border-radius: 8px;
    text-decoration: none;
    position: relative;
    transition: transform .15s, box-shadow .15s;
    border: 1px solid transparent;
    cursor: pointer;
}
.hm-cell:hover { transform: scale(1.08); box-shadow: 0 4px 16px rgba(0,0,0,.35); z-index: 2; }
.hm-critical { background: rgba(232,33,42,.22);  border-color: rgba(232,33,42,.5);  }
.hm-high     { background: rgba(249,115,22,.22); border-color: rgba(249,115,22,.5); }
.hm-medium   { background: rgba(245,158,11,.22); border-color: rgba(245,158,11,.5); }
.hm-low      { background: rgba(30,180,100,.18); border-color: rgba(30,180,100,.4); }
.hm-stale    { opacity: .55; }
.hm-score {
    font-size: 1.3rem;
    font-weight: 800;
    line-height: 1;
}
.hm-critical .hm-score { color: #e8212a; }
.hm-high     .hm-score { color: #f97316; }
.hm-medium   .hm-score { color: #f59e0b; }
.hm-low      .hm-score { color: #1eb464; }
.hm-name {
    font-size: .65rem;
    color: var(--t-muted);
    text-align: center;
    margin-top: 3px;
    word-break: break-all;
    line-height: 1.2;
    max-width: 80px;
}
.hm-stale-dot {
    position: absolute;
    top: 4px; right: 6px;
    font-size: .65rem;
    color: var(--t-orange);
    font-weight: 900;
}
.hm-legend {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: .78rem;
    color: var(--t-muted);
    margin-left: auto;
    flex-wrap: wrap;
}
.hm-legend-dot {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 50%;
    margin-right: 3px;
    vertical-align: middle;
}
.hm-legend-dot.hm-critical { background: #e8212a; }
.hm-legend-dot.hm-high     { background: #f97316; }
.hm-legend-dot.hm-medium   { background: #f59e0b; }
.hm-legend-dot.hm-low      { background: #1eb464; }
</style>

<?php Html::footer();
