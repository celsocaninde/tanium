<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);

global $DB;

$webDir = \Plugin::getWebDir('tanium');
$now    = time();

// Load all active exceptions with asset + user info
$exceptions = [];
foreach ($DB->doQuery("
    SELECT e.*,
           a.tanium_name, a.ip_address, a.os_name,
           v.cvss_score, v.severity, v.title AS cve_title,
           u.name AS accepted_by_name
    FROM glpi_plugin_tanium_cve_exceptions e
    LEFT JOIN glpi_plugin_tanium_assets a ON e.tanium_eid = a.tanium_eid
    LEFT JOIN glpi_plugin_tanium_vulnerabilities v ON e.cve_id = v.cve_id
    LEFT JOIN glpi_users u ON e.accepted_by = u.id
    ORDER BY e.created_at DESC
    LIMIT 500
") as $r) {
    $exceptions[] = $r;
}

$sevClass = function(string $s): string {
    return match (strtolower($s)) { 'critical' => 'tanium-badge-critical', 'high' => 'tanium-badge-high', 'medium' => 'tanium-badge-warning', 'low' => 'tanium-badge-success', default => 'tanium-badge-muted' };
};

Html::header(__('Tanium — CVE Exceptions', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<div class="tanium-card">
    <div class="tanium-card-header">
        <span class="ti ti-shield-off"></span> <?= __('CVE Exceptions (Accepted Risk)', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:8px;font-size:.8rem">(<?= count($exceptions) ?>)</span>
        <a href="<?= $webDir ?>/front/vulnerabilities.php" class="tanium-btn tanium-btn-secondary tanium-btn-sm" style="margin-left:auto">
            <span class="ti ti-arrow-left"></span> <?= __('Back to CVEs', 'tanium') ?>
        </a>
    </div>

    <?php if (empty($exceptions)): ?>
    <div class="tanium-card-body">
        <p class="tanium-empty"><?= __('No CVE exceptions defined yet. Use the "Accept Risk" button on a CVE to add one.', 'tanium') ?></p>
    </div>
    <?php else: ?>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead>
            <tr>
                <th>CVE ID</th>
                <th><?= __('Severity', 'tanium') ?></th>
                <th>CVSS</th>
                <th><?= __('Endpoint', 'tanium') ?></th>
                <th><?= __('Reason', 'tanium') ?></th>
                <th><?= __('Accepted by', 'tanium') ?></th>
                <th><?= __('Created', 'tanium') ?></th>
                <th><?= __('Expires', 'tanium') ?></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($exceptions as $ex):
            $expired = $ex['expires_at'] && strtotime($ex['expires_at']) < $now;
            $expiring = !$expired && $ex['expires_at'] && (strtotime($ex['expires_at']) - $now) < 86400 * 14;
        ?>
        <tr class="<?= $expired ? 'tanium-row-muted' : '' ?>">
            <td class="tanium-mono">
                <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($ex['cve_id']) ?>" target="_blank" class="tanium-link">
                    <?= htmlspecialchars($ex['cve_id']) ?>
                </a>
            </td>
            <td><span class="tanium-badge <?= $sevClass($ex['severity'] ?? '') ?>"><?= ucfirst($ex['severity'] ?? '—') ?></span></td>
            <td class="tanium-mono tanium-center"><?= $ex['cvss_score'] !== null ? number_format((float)$ex['cvss_score'],1) : '—' ?></td>
            <td class="tanium-mono">
                <?php if ($ex['tanium_name']): ?>
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ex['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($ex['tanium_name']) ?>
                </a>
                <?php else: ?>
                <span class="tanium-muted"><?= htmlspecialchars($ex['tanium_eid']) ?></span>
                <?php endif; ?>
            </td>
            <td class="tanium-small" style="max-width:260px"><?= htmlspecialchars($ex['reason']) ?></td>
            <td class="tanium-small"><?= htmlspecialchars($ex['accepted_by_name'] ?? '—') ?></td>
            <td class="tanium-small"><?= $ex['created_at'] ? Html::convDateTime($ex['created_at']) : '—' ?></td>
            <td>
                <?php if ($expired): ?>
                    <span class="tanium-badge tanium-badge-error"><?= __('Expired', 'tanium') ?></span>
                <?php elseif ($expiring): ?>
                    <span class="tanium-badge tanium-badge-warning"><?= __('Expiring soon', 'tanium') ?></span>
                <?php elseif ($ex['expires_at']): ?>
                    <span class="tanium-small"><?= Html::convDate($ex['expires_at']) ?></span>
                <?php else: ?>
                    <span class="tanium-muted tanium-small"><?= __('Never', 'tanium') ?></span>
                <?php endif; ?>
            </td>
            <td>
                <button class="tanium-btn-xs tanium-btn-danger" title="<?= __('Revoke exception', 'tanium') ?>"
                        onclick="revokeException(<?= (int)$ex['id'] ?>)">
                    <span class="ti ti-trash"></span>
                </button>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

</div><!-- .tanium-page-wrap -->

<script>
const _csrf = <?= json_encode(Session::getNewCSRFToken()) ?>;
function revokeException(id) {
    if (!confirm('<?= __('Revoke this exception? The CVE will become active again.', 'tanium') ?>')) return;
    fetch('<?= $webDir ?>/ajax/exception.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({action: 'delete', id: id})
    }).then(r => r.json()).then(d => {
        if (d.success) location.reload();
        else alert(d.error || 'Error');
    });
}
</script>

<?php Html::footer();
