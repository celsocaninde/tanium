<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);

global $DB;

$q      = trim($_GET['q'] ?? '');
$type   = $_GET['type'] ?? 'all'; // all | endpoints | cves | patches
$webDir = \Plugin::getWebDir('tanium');

$results = ['endpoints' => [], 'cves' => [], 'patches' => []];

if (strlen($q) >= 2) {
    $esc = $DB->escape($q);

    if ($type === 'all' || $type === 'endpoints') {
        foreach ($DB->doQuery("
            SELECT tanium_eid, tanium_name, ip_address, os_name, risk_score, last_seen
            FROM glpi_plugin_tanium_assets
            WHERE tanium_name LIKE '%{$esc}%' OR ip_address LIKE '%{$esc}%' OR mac_address LIKE '%{$esc}%' OR tanium_eid LIKE '%{$esc}%'
            ORDER BY risk_score DESC LIMIT 30
        ") as $r) { $results['endpoints'][] = $r; }
    }

    if ($type === 'all' || $type === 'cves') {
        foreach ($DB->doQuery("
            SELECT cve_id, severity, cvss_score, title, affected_count, first_detected
            FROM glpi_plugin_tanium_vulnerabilities
            WHERE cve_id LIKE '%{$esc}%' OR title LIKE '%{$esc}%'
            ORDER BY cvss_score DESC LIMIT 30
        ") as $r) { $results['cves'][] = $r; }
    }

    if ($type === 'all' || $type === 'patches') {
        foreach ($DB->doQuery("
            SELECT DISTINCT p.patch_id, p.patch_title, p.severity, p.kb_id, a.tanium_name, a.tanium_eid
            FROM glpi_plugin_tanium_patches p
            JOIN glpi_plugin_tanium_assets a ON p.tanium_eid = a.tanium_eid
            WHERE p.patch_title LIKE '%{$esc}%' OR p.patch_id LIKE '%{$esc}%' OR p.kb_id LIKE '%{$esc}%'
            LIMIT 30
        ") as $r) { $results['patches'][] = $r; }
    }
}

$total = count($results['endpoints']) + count($results['cves']) + count($results['patches']);

$sevClass = function(string $s): string {
    return match (strtolower($s)) { 'critical' => 'tanium-badge-critical', 'high' => 'tanium-badge-high', 'medium' => 'tanium-badge-warning', 'low' => 'tanium-badge-success', default => 'tanium-badge-muted' };
};

Html::header(__('Tanium — Global Search', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<!-- Search form -->
<div class="tanium-search-hero">
    <form method="get" class="tanium-search-form">
        <div class="tanium-search-box">
            <span class="ti ti-search tanium-search-icon"></span>
            <input type="text" name="q" class="tanium-search-input" autofocus
                   placeholder="<?= __('Search endpoints, CVE IDs, patch titles, IPs…', 'tanium') ?>"
                   value="<?= htmlspecialchars($q) ?>"/>
            <button type="submit" class="tanium-btn tanium-btn-primary"><?= __('Search', 'tanium') ?></button>
        </div>
        <div class="tanium-search-types">
            <?php foreach (['all' => 'All', 'endpoints' => 'Endpoints', 'cves' => 'CVEs', 'patches' => 'Patches'] as $k => $l): ?>
            <label class="tanium-type-pill <?= $type === $k ? 'active' : '' ?>">
                <input type="radio" name="type" value="<?= $k ?>" <?= $type === $k ? 'checked' : '' ?> onchange="this.form.submit()" style="display:none">
                <?= $l ?>
            </label>
            <?php endforeach; ?>
        </div>
    </form>
</div>

<?php if ($q !== '' && strlen($q) < 2): ?>
<p class="tanium-empty"><?= __('Please enter at least 2 characters.', 'tanium') ?></p>
<?php elseif ($q !== ''): ?>
<p class="tanium-search-summary">
    <?php if ($total === 0): ?>
        <?= __('No results found for', 'tanium') ?> <strong>"<?= htmlspecialchars($q) ?>"</strong>
    <?php else: ?>
        <strong><?= $total ?></strong> <?= __('results for', 'tanium') ?> <strong>"<?= htmlspecialchars($q) ?>"</strong>
    <?php endif; ?>
</p>

<!-- Endpoints results -->
<?php if (!empty($results['endpoints'])): ?>
<div class="tanium-card" style="margin-bottom:14px">
    <div class="tanium-card-header">
        <span class="ti ti-devices"></span> <?= __('Endpoints', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:8px;font-size:.8rem">(<?= count($results['endpoints']) ?>)</span>
    </div>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead><tr>
            <th><?= __('Name', 'tanium') ?></th>
            <th><?= __('IP', 'tanium') ?></th>
            <th><?= __('OS', 'tanium') ?></th>
            <th><?= __('Risk Score', 'tanium') ?></th>
            <th><?= __('Last seen', 'tanium') ?></th>
        </tr></thead>
        <tbody>
        <?php foreach ($results['endpoints'] as $ep):
            $rs = (int)($ep['risk_score'] ?? 0);
        ?>
        <tr>
            <td class="tanium-mono">
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ep['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($ep['tanium_name']) ?>
                </a>
            </td>
            <td class="tanium-mono"><?= htmlspecialchars($ep['ip_address'] ?? '—') ?></td>
            <td><?= htmlspecialchars($ep['os_name'] ?? '—') ?></td>
            <td>
                <div class="tanium-riskmini <?= $rs >= 70 ? 'tanium-risk-critical' : ($rs >= 40 ? 'tanium-risk-high' : ($rs >= 15 ? 'tanium-risk-medium' : 'tanium-risk-low')) ?>">
                    <div class="tanium-riskmini-bar" style="width:<?= $rs ?>%"></div>
                    <span class="tanium-riskmini-val"><?= $rs ?></span>
                </div>
            </td>
            <td class="tanium-small"><?= $ep['last_seen'] ? Html::convDateTime($ep['last_seen']) : '—' ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>
<?php endif; ?>

<!-- CVE results -->
<?php if (!empty($results['cves'])): ?>
<div class="tanium-card" style="margin-bottom:14px">
    <div class="tanium-card-header">
        <span class="ti ti-shield-exclamation"></span> <?= __('CVEs / Vulnerabilities', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:8px;font-size:.8rem">(<?= count($results['cves']) ?>)</span>
    </div>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead><tr>
            <th>CVE ID</th><th><?= __('Severity', 'tanium') ?></th><th>CVSS</th>
            <th><?= __('Title', 'tanium') ?></th><th><?= __('Affected', 'tanium') ?></th><th><?= __('First seen', 'tanium') ?></th>
        </tr></thead>
        <tbody>
        <?php foreach ($results['cves'] as $cve): ?>
        <tr>
            <td class="tanium-mono">
                <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($cve['cve_id']) ?>" target="_blank" class="tanium-link">
                    <?= htmlspecialchars($cve['cve_id']) ?>
                </a>
            </td>
            <td><span class="tanium-badge <?= $sevClass($cve['severity']) ?>"><?= ucfirst($cve['severity']) ?></span></td>
            <td class="tanium-mono tanium-center"><?= $cve['cvss_score'] !== null ? number_format((float)$cve['cvss_score'],1) : '—' ?></td>
            <td class="tanium-small"><?= htmlspecialchars(substr($cve['title'],0,80)) ?></td>
            <td class="tanium-center"><?= (int)$cve['affected_count'] ?></td>
            <td class="tanium-small"><?= $cve['first_detected'] ? Html::convDateTime($cve['first_detected']) : '—' ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>
<?php endif; ?>

<!-- Patch results -->
<?php if (!empty($results['patches'])): ?>
<div class="tanium-card">
    <div class="tanium-card-header">
        <span class="ti ti-shield-check"></span> <?= __('Patches', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:8px;font-size:.8rem">(<?= count($results['patches']) ?>)</span>
    </div>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead><tr>
            <th><?= __('Patch ID', 'tanium') ?></th><th><?= __('Title', 'tanium') ?></th>
            <th>KB</th><th><?= __('Severity', 'tanium') ?></th><th><?= __('Endpoint', 'tanium') ?></th>
        </tr></thead>
        <tbody>
        <?php foreach ($results['patches'] as $p): ?>
        <tr>
            <td class="tanium-mono"><?= htmlspecialchars($p['patch_id']) ?></td>
            <td class="tanium-small"><?= htmlspecialchars(substr($p['patch_title'],0,70)) ?></td>
            <td class="tanium-mono tanium-small"><?= htmlspecialchars($p['kb_id'] ?? '—') ?></td>
            <td><span class="tanium-badge <?= $sevClass($p['severity']) ?>"><?= ucfirst($p['severity']) ?></span></td>
            <td class="tanium-mono">
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($p['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($p['tanium_name']) ?>
                </a>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>
<?php endif; ?>

<?php endif; /* $q !== '' */ ?>

</div><!-- .tanium-page-wrap -->
<?php Html::footer();
