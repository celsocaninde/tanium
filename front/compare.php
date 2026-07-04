<?php

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

global $DB;

$eid1   = $_GET['eid1'] ?? '';
$eid2   = $_GET['eid2'] ?? '';
$webDir = \Plugin::getWebDir('tanium');

// Load all endpoint names for selectors
$allEndpoints = [];
foreach ($DB->request(['SELECT' => ['tanium_eid', 'tanium_name'], 'FROM' => 'glpi_plugin_tanium_assets', 'ORDER' => 'tanium_name ASC', 'LIMIT' => 1000]) as $r) {
    $allEndpoints[] = $r;
}

$loadEndpoint = function(string $eid) use ($DB): ?array {
    if (!$eid) return null;
    $a = $DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();
    if (!$a) return null;

    $cves = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_endpoint_cves', 'WHERE' => ['tanium_eid' => $eid], 'ORDER' => 'cvss_score DESC', 'LIMIT' => 50]) as $r) { $cves[] = $r; }

    $patches = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'], 'ORDER' => ['severity ASC'], 'LIMIT' => 50]) as $r) { $patches[] = $r; }

    $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($cves as $c) { $s = strtolower($c['severity']); if (isset($sev[$s])) $sev[$s]++; }

    return ['asset' => $a, 'cves' => $cves, 'patches' => $patches, 'sev' => $sev, 'cve_ids' => array_column($cves, 'cve_id'), 'patch_ids' => array_column($patches, 'patch_id')];
};

$ep1 = $loadEndpoint($eid1);
$ep2 = $loadEndpoint($eid2);

// PDF export — must run before any HTML output
if (($_GET['export'] ?? '') === 'pdf' && $ep1 && $ep2) {
    $pdf = \GlpiPlugin\Tanium\PdfReport::compare($ep1, $ep2);
    if ($pdf !== null) {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="tanium-compare-' . date('Y-m-d') . '.pdf"');
        header('Content-Length: ' . strlen($pdf));
        echo $pdf;
        exit;
    }
    Session::addMessageAfterRedirect(__('PDF generation failed — check tanium.log.', 'tanium'), false, ERROR);
}

$sevClass = function(string $s): string {
    return match(strtolower($s)) { 'critical' => 'tanium-badge-critical', 'high' => 'tanium-badge-high', 'medium' => 'tanium-badge-warning', 'low' => 'tanium-badge-success', default => 'tanium-badge-muted' };
};

Html::header(__('Tanium — Compare Endpoints', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<div class="tanium-card" style="margin-bottom:16px">
    <div class="tanium-card-header"><span class="ti ti-git-compare"></span> <?= __('Compare Endpoints', 'tanium') ?></div>
    <div class="tanium-card-body">
        <form method="get" style="display:flex;gap:16px;align-items:flex-end;flex-wrap:wrap">
            <div>
                <label class="tanium-form-label"><?= __('Endpoint A', 'tanium') ?></label>
                <select name="eid1" class="tanium-input tanium-select" style="min-width:260px">
                    <option value=""><?= __('— select endpoint —', 'tanium') ?></option>
                    <?php foreach ($allEndpoints as $e): ?>
                    <option value="<?= htmlspecialchars($e['tanium_eid']) ?>" <?= $eid1 === $e['tanium_eid'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($e['tanium_name']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="tanium-form-label"><?= __('Endpoint B', 'tanium') ?></label>
                <select name="eid2" class="tanium-input tanium-select" style="min-width:260px">
                    <option value=""><?= __('— select endpoint —', 'tanium') ?></option>
                    <?php foreach ($allEndpoints as $e): ?>
                    <option value="<?= htmlspecialchars($e['tanium_eid']) ?>" <?= $eid2 === $e['tanium_eid'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($e['tanium_name']) ?>
                    </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit" class="tanium-btn tanium-btn-primary"><span class="ti ti-git-compare"></span> <?= __('Compare', 'tanium') ?></button>
            <?php if ($ep1 && $ep2): ?>
            <a href="?eid1=<?= urlencode($eid1) ?>&eid2=<?= urlencode($eid2) ?>&export=pdf" class="tanium-btn tanium-btn-secondary">
                <span class="ti ti-file-type-pdf"></span> <?= __('Export PDF', 'tanium') ?>
            </a>
            <?php endif; ?>
        </form>
    </div>
</div>

<?php if ($ep1 && $ep2): ?>

<!-- ── Side-by-side comparison ────────────────────────────────────────── -->
<div class="cmp-grid">

<?php
$renderSide = function(array $ep, string $side) use ($webDir, $sevClass, $ep1, $ep2): void {
    $a    = $ep['asset'];
    $rs   = (int)($a['risk_score'] ?? 0);
    $other = $side === 'A' ? ($ep2 ?? null) : ($ep1 ?? null);

    $riskColor = function(int $s): string {
        if ($s >= 70) return 'tanium-risk-critical';
        if ($s >= 40) return 'tanium-risk-high';
        if ($s >= 15) return 'tanium-risk-medium';
        return 'tanium-risk-low';
    };

    $diff = function(string $fieldA, string $fieldB, $va, $vb, string $side): string {
        if ((string)$va === (string)$vb) return '';
        return '<span class="cmp-diff" title="' . htmlspecialchars("Diferente do outro endpoint") . '">≠</span>';
    };

    $oa = $other ? $other['asset'] : [];
?>
    <div class="tanium-card cmp-side cmp-side-<?= strtolower($side) ?>">
        <div class="tanium-card-header cmp-header">
            <span class="cmp-label"><?= $side ?></span>
            <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($a['tanium_eid']) ?>" class="tanium-link tanium-mono" style="font-size:.9rem">
                <?= htmlspecialchars($a['tanium_name']) ?>
            </a>
            <div class="tanium-risk-gauge <?= $riskColor($rs) ?>" style="margin-left:auto;width:60px;height:60px;font-size:1.1rem">
                <div class="tanium-risk-score"><?= $rs ?></div>
                <div class="tanium-risk-sub">risk</div>
            </div>
        </div>
        <div class="tanium-card-body">

        <!-- Info -->
        <div class="cmp-section-title">Informações</div>
        <dl class="tanium-dl">
            <dt>IP</dt><dd><code><?= htmlspecialchars($a['ip_address'] ?? '—') ?></code>
                <?= $oa ? ($a['ip_address'] !== ($oa['ip_address'] ?? '') ? '<span class="cmp-diff">≠</span>' : '') : '' ?></dd>
            <dt>MAC</dt><dd><code><?= htmlspecialchars($a['mac_address'] ?? '—') ?></code></dd>
            <dt>OS</dt><dd><?= htmlspecialchars($a['os_name'] ?? '—') ?>
                <?= $oa ? ($a['os_name'] !== ($oa['os_name'] ?? '') ? '<span class="cmp-diff">≠</span>' : '') : '' ?></dd>
            <dt>Versão</dt><dd><code><?= htmlspecialchars($a['os_version'] ?? '—') ?></code>
                <?= $oa ? ($a['os_version'] !== ($oa['os_version'] ?? '') ? '<span class="cmp-diff">≠</span>' : '') : '' ?></dd>
            <dt>Build</dt><dd><code><?= htmlspecialchars($a['os_build'] ?? '—') ?></code></dd>
            <dt>Virtual</dt><dd><?= (int)($a['is_virtual'] ?? 0) ? 'Sim' : 'Não' ?></dd>
            <dt>Último acesso</dt><dd><?= $a['last_seen'] ? Html::convDateTime($a['last_seen']) : '—' ?></dd>
        </dl>

        <!-- CVE summary -->
        <div class="cmp-section-title" style="margin-top:14px">CVEs</div>
        <div class="tanium-tab-cve-grid">
            <div class="tanium-tab-cve-box tanium-sev-critical"><div class="tanium-cve-count"><?= $ep['sev']['critical'] ?></div><div class="tanium-cve-sev">Crítico</div></div>
            <div class="tanium-tab-cve-box tanium-sev-high">    <div class="tanium-cve-count"><?= $ep['sev']['high'] ?></div>    <div class="tanium-cve-sev">Alto</div></div>
            <div class="tanium-tab-cve-box tanium-sev-medium">  <div class="tanium-cve-count"><?= $ep['sev']['medium'] ?></div>  <div class="tanium-cve-sev">Médio</div></div>
            <div class="tanium-tab-cve-box tanium-sev-low">     <div class="tanium-cve-count"><?= $ep['sev']['low'] ?></div>     <div class="tanium-cve-sev">Baixo</div></div>
        </div>

        <!-- Top 10 CVEs -->
        <?php if (!empty($ep['cves'])):
            $otherCveIds = $other ? $other['cve_ids'] : [];
        ?>
        <table class="tanium-table" style="margin-top:8px">
            <thead><tr><th>CVE ID</th><th>Sev.</th><th>CVSS</th><th></th></tr></thead>
            <tbody>
            <?php foreach (array_slice($ep['cves'], 0, 10) as $cve):
                $inOther = in_array($cve['cve_id'], $otherCveIds, true);
            ?>
            <tr class="<?= $inOther ? 'cmp-shared' : 'cmp-unique' ?>">
                <td class="tanium-mono tanium-small">
                    <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($cve['cve_id']) ?>" target="_blank" class="tanium-link">
                        <?= htmlspecialchars($cve['cve_id']) ?>
                    </a>
                </td>
                <td><span class="tanium-badge <?= $sevClass($cve['severity']) ?>"><?= ucfirst($cve['severity']) ?></span></td>
                <td class="tanium-mono tanium-center"><?= $cve['cvss_score'] !== null ? number_format((float)$cve['cvss_score'],1) : '—' ?></td>
                <td class="tanium-center">
                    <?php if ($inOther): ?>
                        <span class="cmp-shared-badge" title="CVE em ambos os endpoints">⇌</span>
                    <?php else: ?>
                        <span class="cmp-unique-badge" title="CVE exclusivo deste endpoint">★</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php else: ?>
            <p class="tanium-empty" style="padding:12px 0"><?= __('No CVEs', 'tanium') ?></p>
        <?php endif; ?>

        <!-- Missing patches count -->
        <div class="cmp-section-title" style="margin-top:14px">Patches ausentes</div>
        <div style="font-size:2rem;font-weight:800;color:<?= count($ep['patches']) > 0 ? '#f97316' : '#1eb464' ?>">
            <?= count($ep['patches']) ?>
        </div>

        </div><!-- card-body -->
    </div><!-- cmp-side -->
<?php }; ?>

<?php $renderSide($ep1, 'A'); ?>
<?php $renderSide($ep2, 'B'); ?>

</div><!-- .cmp-grid -->

<!-- Legend -->
<div class="tanium-card" style="margin-top:14px">
    <div class="tanium-card-body" style="display:flex;gap:24px;flex-wrap:wrap;font-size:.83rem">
        <span><span class="cmp-shared-badge">⇌</span> CVE presente em ambos os endpoints</span>
        <span><span class="cmp-unique-badge">★</span> CVE exclusivo deste endpoint</span>
        <span><span class="cmp-diff">≠</span> Campo diferente entre os dois endpoints</span>
        <span style="background:rgba(26,109,255,.1);padding:2px 6px;border-radius:4px;color:#1a6dff">linha azul</span> = CVE compartilhado
        <span style="background:rgba(232,33,42,.08);padding:2px 6px;border-radius:4px;color:#e8212a">linha vermelha</span> = CVE exclusivo
    </div>
</div>

<?php elseif ($eid1 || $eid2): ?>
<p class="tanium-empty" style="padding:24px"><?= __('Select two endpoints to compare.', 'tanium') ?></p>
<?php endif; ?>

</div><!-- .tanium-page-wrap -->

<style>
.cmp-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 900px) { .cmp-grid { grid-template-columns: 1fr; } }
.cmp-header { gap: 10px; flex-wrap: wrap; }
.cmp-label { font-size: 1rem; font-weight: 800; color: var(--t-red); background: rgba(232,33,42,.15); width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.cmp-side-b .cmp-label { color: var(--t-blue); background: rgba(26,109,255,.15); }
.cmp-section-title { font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .07em; color: var(--t-red); border-left: 2px solid var(--t-red); padding-left: 6px; margin-bottom: 8px; }
.cmp-shared { background: rgba(26,109,255,.06) !important; }
.cmp-unique  { background: rgba(232,33,42,.06) !important; }
.cmp-shared-badge { color: var(--t-blue); font-weight: 700; font-size: .8rem; }
.cmp-unique-badge  { color: var(--t-red);  font-weight: 700; font-size: .8rem; }
.cmp-diff { font-size: .7rem; color: var(--t-orange); font-weight: 700; margin-left: 4px; cursor: help; }
</style>

<?php Html::footer();
