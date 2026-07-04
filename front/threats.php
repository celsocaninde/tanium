<?php

use GlpiPlugin\Tanium\ThreatResponse;
use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

global $DB;

ThreatResponse::ensureTable();

$severity = $_GET['severity'] ?? '';
$show     = $_GET['show']     ?? 'open';   // open (default) / all
$page     = max(1, (int)($_GET['page'] ?? 1));
$limit    = 50;
$offset   = ($page - 1) * $limit;

// ── Build WHERE ───────────────────────────────────────────────────────────────
$conditions = ['1=1'];
if ($show !== 'all') {
    // same criteria as ThreatResponse::countOpen (dashboard KPI)
    $conditions[] = "t.status NOT IN ('resolved', 'closed', 'suppressed')";
}
if ($severity) {
    $conditions[] = "t.severity = '" . $DB->escape($severity) . "'";
}
$whereSQL = implode(' AND ', $conditions);

// ── Data ──────────────────────────────────────────────────────────────────────
$rows = [];
$sql  = "SELECT t.*, a.tanium_name
         FROM `" . ThreatResponse::$table . "` t
         LEFT JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = t.tanium_eid
         WHERE {$whereSQL}
         ORDER BY t.detected_at DESC
         LIMIT {$limit} OFFSET {$offset}";
foreach ($DB->doQuery($sql) as $r) { $rows[] = $r; }

$cntRes = $DB->doQuery("SELECT COUNT(*) AS cnt FROM `" . ThreatResponse::$table . "` t WHERE {$whereSQL}");
$total  = (int)(($cntRes ? $cntRes->fetch_assoc() : [])['cnt'] ?? 0);
$pages  = (int)ceil($total / $limit);

$webDir = \Plugin::getWebDir('tanium');

$statusClass = function (string $s): string {
    return match (strtolower($s)) {
        'resolved', 'closed' => 'tanium-badge-success',
        'suppressed'         => 'tanium-badge-muted',
        default              => 'tanium-badge-error',
    };
};

// ── Render ───────────────────────────────────────────────────────────────────
Html::header(__('Tanium — Threat Alerts', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">
<div class="tanium-card">
    <div class="tanium-card-header">
        <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary" style="padding:4px 12px;font-size:.75rem;margin-right:12px" title="<?= __('Back', 'tanium') ?>">
            <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
        </a>
        <span>&#128737; <?= __('Threat Response Alerts', 'tanium') ?></span>
        <span class="tanium-muted" style="margin-left:auto;font-size:.8rem"><?= number_format($total) ?> <?= __('records', 'tanium') ?></span>
    </div>

    <!-- Filter bar -->
    <div class="tanium-filter-bar">
        <form method="get" class="tanium-filter-form">
            <select name="show" class="tanium-input tanium-select">
                <option value="open" <?= $show !== 'all' ? 'selected' : '' ?>><?= __('Open only', 'tanium') ?></option>
                <option value="all"  <?= $show === 'all' ? 'selected' : '' ?>><?= __('All statuses', 'tanium') ?></option>
            </select>
            <select name="severity" class="tanium-input tanium-select">
                <option value=""><?= __('All severities', 'tanium') ?></option>
                <?php foreach (['critical','high','medium','low','info'] as $s): ?>
                <option value="<?= $s ?>" <?= $severity === $s ? 'selected' : '' ?>><?= ucfirst($s) ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="tanium-btn tanium-btn-primary"><?= __('Filter', 'tanium') ?></button>
            <?php if ($severity || $show === 'all'): ?>
            <a href="<?= $webDir ?>/front/threats.php" class="tanium-btn tanium-btn-secondary"><?= __('Clear', 'tanium') ?></a>
            <?php endif; ?>
        </form>
    </div>

    <div class="tanium-card-body tanium-p0">
        <?php if (empty($rows)): ?>
            <p class="tanium-empty"><?= __('No threat alerts. Enable Threat Response sync in the plugin configuration.', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th><?= __('Detected', 'tanium') ?></th>
                    <th><?= __('Alert', 'tanium') ?></th>
                    <th><?= __('Severity', 'tanium') ?></th>
                    <th><?= __('Endpoint', 'tanium') ?></th>
                    <th><?= __('Status', 'tanium') ?></th>
                    <th><?= __('Ticket', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($rows as $al): ?>
                <tr>
                    <td class="tanium-small"><?= $al['detected_at'] ? Html::convDateTime($al['detected_at']) : '—' ?></td>
                    <td><?= htmlspecialchars(substr($al['title'], 0, 100)) ?><?= strlen($al['title']) > 100 ? '…' : '' ?></td>
                    <td><span class="tanium-badge <?= Vulnerability::sevClass($al['severity']) ?>"><?= ucfirst(htmlspecialchars($al['severity'])) ?></span></td>
                    <td>
                        <?php if ($al['tanium_eid']): ?>
                        <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($al['tanium_eid']) ?>" class="tanium-link tanium-mono">
                            <?= htmlspecialchars($al['tanium_name'] ?? $al['tanium_eid']) ?>
                        </a>
                        <?php else: ?>—<?php endif; ?>
                    </td>
                    <td><span class="tanium-badge <?= $statusClass($al['status']) ?>"><?= htmlspecialchars($al['status']) ?></span></td>
                    <td>
                        <?php if (!empty($al['tickets_id'])): ?>
                        <a href="/front/ticket.form.php?id=<?= (int)$al['tickets_id'] ?>" class="tanium-link">#<?= (int)$al['tickets_id'] ?></a>
                        <?php else: ?><span class="tanium-muted">—</span><?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($pages > 1): ?>
        <div class="tanium-pagination">
            <?php for ($p = 1; $p <= min($pages, 20); $p++): ?>
            <a href="?page=<?= $p ?>&show=<?= urlencode($show) ?>&severity=<?= urlencode($severity) ?>"
               class="tanium-page-btn <?= $p === $page ? 'active' : '' ?>"><?= $p ?></a>
            <?php endfor; ?>
        </div>
        <?php endif; ?>

        <?php endif; ?>
    </div>
</div>
</div>

<?php
Html::footer();
