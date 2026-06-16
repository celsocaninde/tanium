<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);

global $DB;

$webDir     = \Plugin::getWebDir('tanium');
$filterStatus = $_GET['status'] ?? 'open';

$statusWhere = $filterStatus === 'all' ? '' : "AND asgn.status = '" . $DB->escape($filterStatus) . "'";

$assignments = [];
foreach ($DB->doQuery("
    SELECT asgn.*,
           a.tanium_name, a.ip_address,
           v.cvss_score, v.severity, v.title AS cve_title,
           u.name AS assigned_to_name,
           ub.name AS assigned_by_name
    FROM glpi_plugin_tanium_cve_assignments asgn
    LEFT JOIN glpi_plugin_tanium_assets a ON asgn.tanium_eid = a.tanium_eid
    LEFT JOIN glpi_plugin_tanium_vulnerabilities v ON asgn.cve_id = v.cve_id
    LEFT JOIN glpi_users u ON asgn.assigned_to = u.id
    LEFT JOIN glpi_users ub ON asgn.assigned_by = ub.id
    WHERE 1=1 {$statusWhere}
    ORDER BY asgn.due_date ASC, v.cvss_score DESC
    LIMIT 500
") as $r) {
    $assignments[] = $r;
}

// Fetch all active users for filter
$users = [];
foreach ($DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_users', 'WHERE' => ['is_deleted' => 0, 'is_active' => 1], 'ORDER' => 'name ASC', 'LIMIT' => 500]) as $u) {
    $users[] = $u;
}

$sevClass = function(string $s): string {
    return match (strtolower($s)) { 'critical' => 'tanium-badge-critical', 'high' => 'tanium-badge-high', 'medium' => 'tanium-badge-warning', 'low' => 'tanium-badge-success', default => 'tanium-badge-muted' };
};

$statusClass = function(string $s): string {
    return match ($s) { 'resolved' => 'tanium-badge-success', 'in_progress' => 'tanium-badge-warning', default => 'tanium-badge-muted' };
};

$now = time();

Html::header(__('Tanium — CVE Assignments', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<div class="tanium-card">
    <div class="tanium-card-header">
        <span class="ti ti-user-check"></span> <?= __('CVE / Patch Assignments', 'tanium') ?>
        <div class="tanium-filter-bar" style="margin-left:auto;border:none;padding:0;background:none">
            <form method="get" style="display:flex;gap:8px;align-items:center">
                <select name="status" class="tanium-input tanium-select tanium-select-sm" onchange="this.form.submit()">
                    <option value="open"       <?= $filterStatus === 'open'        ? 'selected' : '' ?>><?= __('Open', 'tanium') ?></option>
                    <option value="in_progress"<?= $filterStatus === 'in_progress' ? 'selected' : '' ?>><?= __('In progress', 'tanium') ?></option>
                    <option value="resolved"   <?= $filterStatus === 'resolved'    ? 'selected' : '' ?>><?= __('Resolved', 'tanium') ?></option>
                    <option value="all"        <?= $filterStatus === 'all'         ? 'selected' : '' ?>><?= __('All', 'tanium') ?></option>
                </select>
            </form>
        </div>
    </div>

    <?php if (empty($assignments)): ?>
    <div class="tanium-card-body">
        <p class="tanium-empty"><?= __('No assignments found. Use the "Assign" button on a CVE or patch to create one.', 'tanium') ?></p>
    </div>
    <?php else: ?>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead>
            <tr>
                <th>CVE / Patch</th>
                <th><?= __('Severity', 'tanium') ?></th>
                <th><?= __('Endpoint', 'tanium') ?></th>
                <th><?= __('Assigned to', 'tanium') ?></th>
                <th><?= __('Due date', 'tanium') ?></th>
                <th><?= __('Status', 'tanium') ?></th>
                <th><?= __('Notes', 'tanium') ?></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($assignments as $asgn):
            $overdue = $asgn['due_date'] && strtotime($asgn['due_date']) < $now && $asgn['status'] !== 'resolved';
            $nearDue  = !$overdue && $asgn['due_date'] && (strtotime($asgn['due_date']) - $now) < 86400 * 3 && $asgn['status'] !== 'resolved';
        ?>
        <tr class="<?= $overdue ? 'tanium-row-overdue' : '' ?>">
            <td class="tanium-mono">
                <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($asgn['cve_id']) ?>" target="_blank" class="tanium-link">
                    <?= htmlspecialchars($asgn['cve_id']) ?>
                </a>
                <?php if ($asgn['cve_title']): ?>
                <div class="tanium-small tanium-muted"><?= htmlspecialchars(substr($asgn['cve_title'], 0, 60)) ?></div>
                <?php endif; ?>
            </td>
            <td><span class="tanium-badge <?= $sevClass($asgn['severity'] ?? '') ?>"><?= ucfirst($asgn['severity'] ?? '—') ?></span></td>
            <td class="tanium-mono">
                <?php if ($asgn['tanium_name']): ?>
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($asgn['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($asgn['tanium_name']) ?>
                </a>
                <?php else: ?>
                <span class="tanium-muted"><?= htmlspecialchars($asgn['tanium_eid']) ?></span>
                <?php endif; ?>
            </td>
            <td><?= htmlspecialchars($asgn['assigned_to_name'] ?? '—') ?></td>
            <td>
                <?php if ($asgn['due_date']): ?>
                <span class="<?= $overdue ? 'tanium-text-red' : ($nearDue ? 'tanium-text-orange' : '') ?>">
                    <?= Html::convDate($asgn['due_date']) ?>
                    <?= $overdue ? ' <span class="tanium-badge tanium-badge-error">' . __('Overdue', 'tanium') . '</span>' : '' ?>
                    <?= $nearDue  ? ' <span class="tanium-badge tanium-badge-warning">' . __('Due soon', 'tanium') . '</span>' : '' ?>
                </span>
                <?php else: ?>
                <span class="tanium-muted">—</span>
                <?php endif; ?>
            </td>
            <td>
                <select class="tanium-input tanium-select tanium-select-sm asgn-status-sel"
                        data-id="<?= (int)$asgn['id'] ?>"
                        onchange="updateAssignmentStatus(this)">
                    <?php foreach (['open' => __('Open','tanium'), 'in_progress' => __('In progress','tanium'), 'resolved' => __('Resolved','tanium')] as $sv => $sl): ?>
                    <option value="<?= $sv ?>" <?= $asgn['status'] === $sv ? 'selected' : '' ?>><?= $sl ?></option>
                    <?php endforeach; ?>
                </select>
            </td>
            <td class="tanium-small" style="max-width:200px"><?= htmlspecialchars($asgn['notes'] ?? '') ?></td>
            <td>
                <button class="tanium-btn-xs tanium-btn-danger" title="<?= __('Delete assignment', 'tanium') ?>"
                        onclick="deleteAssignment(<?= (int)$asgn['id'] ?>)">
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
function updateAssignmentStatus(sel) {
    fetch('<?= $webDir ?>/ajax/assign.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({action: 'update_status', id: parseInt(sel.dataset.id), status: sel.value})
    }).then(r => r.json()).then(d => { if (!d.success) alert(d.error || 'Error'); });
}
function deleteAssignment(id) {
    if (!confirm('<?= __('Delete this assignment?', 'tanium') ?>')) return;
    fetch('<?= $webDir ?>/ajax/assign.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({action: 'delete', id: id})
    }).then(r => r.json()).then(d => { if (d.success) location.reload(); else alert(d.error || 'Error'); });
}
</script>

<?php Html::footer();
