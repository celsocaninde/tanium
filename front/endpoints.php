<?php

use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');

Session::checkRight('config', READ);

global $DB;

$search   = $_GET['search']   ?? '';
$os       = $_GET['os']       ?? '';
$risk     = $_GET['risk']     ?? '';   // low / medium / high / critical
$page     = max(1, (int)($_GET['page'] ?? 1));
$limit    = 50;
$offset   = ($page - 1) * $limit;

// ── Build WHERE ───────────────────────────────────────────────────────────────
$conditions = ['1=1'];
if ($search) {
    $s = $DB->escape($search);
    $conditions[] = "(tanium_name LIKE '%{$s}%' OR ip_address LIKE '%{$s}%' OR tanium_eid LIKE '%{$s}%')";
}
if ($os) {
    $conditions[] = "os_name = '" . $DB->escape($os) . "'";
}
switch ($risk) {
    case 'critical': $conditions[] = 'risk_score >= 70'; break;
    case 'high':     $conditions[] = 'risk_score >= 40 AND risk_score < 70'; break;
    case 'medium':   $conditions[] = 'risk_score >= 15 AND risk_score < 40'; break;
    case 'low':      $conditions[] = 'risk_score < 15'; break;
}
$whereSQL = implode(' AND ', $conditions);

// ── Data ──────────────────────────────────────────────────────────────────────
$rows = [];
$sql  = "SELECT * FROM glpi_plugin_tanium_assets WHERE {$whereSQL} ORDER BY risk_score DESC, last_seen DESC LIMIT {$limit} OFFSET {$offset}";
foreach ($DB->doQuery($sql) as $r) { $rows[] = $r; }

$cntRes = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_assets WHERE {$whereSQL}");
$total  = (int)(($cntRes ? $cntRes->fetch_assoc() : [])['cnt'] ?? 0);
$pages  = (int)ceil($total / $limit);

// OS dropdown
$osRows = [];
foreach ($DB->request([
    'SELECT'  => ['os_name'],
    'FROM'    => 'glpi_plugin_tanium_assets',
    'WHERE'   => ['NOT' => ['os_name' => null]],
    'GROUPBY' => 'os_name',
    'ORDER'   => 'os_name ASC',
]) as $r) { $osRows[] = $r['os_name']; }

$webDir = \Plugin::getWebDir('tanium');

// ── Risk helpers ──────────────────────────────────────────────────────────────
$riskClass = function(int $s): string {
    if ($s >= 70) return 'tanium-risk-critical';
    if ($s >= 40) return 'tanium-risk-high';
    if ($s >= 15) return 'tanium-risk-medium';
    return 'tanium-risk-low';
};
$riskLabel = function(int $s): string {
    if ($s >= 70) return 'Crítico';
    if ($s >= 40) return 'Alto';
    if ($s >= 15) return 'Médio';
    return 'Baixo';
};

// ── Render ───────────────────────────────────────────────────────────────────
Html::header(__('Tanium — Endpoints', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">
<div class="tanium-card">
    <div class="tanium-card-header">
        <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary" style="padding:4px 12px;font-size:.75rem;margin-right:12px" title="<?= __('Back', 'tanium') ?>">
            <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
        </a>
        <span>&#128187; <?= __('Synced Endpoints', 'tanium') ?></span>
        <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
            <span class="tanium-muted" style="font-size:.8rem"><?= number_format($total) ?> <?= __('endpoints', 'tanium') ?></span>
            <a href="<?= $webDir ?>/front/report.php" target="_blank" class="tanium-btn tanium-btn-secondary" style="padding:4px 12px;font-size:.75rem">
                <span class="ti ti-printer"></span> <?= __('Global Report', 'tanium') ?>
            </a>
        </div>
    </div>

    <!-- Filter bar -->
    <div class="tanium-filter-bar">
        <form method="get" class="tanium-filter-form" id="ep-filter-form">
            <input type="text" name="search" class="tanium-input tanium-input-filter"
                   placeholder="<?= __('Search by name, IP or EID...', 'tanium') ?>"
                   value="<?= htmlspecialchars($search) ?>"/>
            <select name="os" class="tanium-input tanium-select">
                <option value=""><?= __('All OS', 'tanium') ?></option>
                <?php foreach ($osRows as $osName): ?>
                <option value="<?= htmlspecialchars($osName) ?>" <?= $os === $osName ? 'selected' : '' ?>>
                    <?= htmlspecialchars($osName) ?>
                </option>
                <?php endforeach; ?>
            </select>
            <select name="risk" class="tanium-input tanium-select">
                <option value=""><?= __('All risk levels', 'tanium') ?></option>
                <option value="critical" <?= $risk === 'critical' ? 'selected' : '' ?>>&#128308; <?= __('Critical (≥70)', 'tanium') ?></option>
                <option value="high"     <?= $risk === 'high'     ? 'selected' : '' ?>>&#128992; <?= __('High (40-69)', 'tanium') ?></option>
                <option value="medium"   <?= $risk === 'medium'   ? 'selected' : '' ?>>&#128993; <?= __('Medium (15-39)', 'tanium') ?></option>
                <option value="low"      <?= $risk === 'low'      ? 'selected' : '' ?>>&#128994; <?= __('Low (<15)', 'tanium') ?></option>
            </select>
            <button type="submit" class="tanium-btn tanium-btn-primary"><?= __('Filter', 'tanium') ?></button>
            <?php if ($search || $os || $risk): ?>
            <a href="<?= $webDir ?>/front/endpoints.php" class="tanium-btn tanium-btn-secondary"><?= __('Clear', 'tanium') ?></a>
            <?php endif; ?>
            <button type="button" class="tanium-btn tanium-btn-secondary" onclick="saveCurrentFilter()" title="<?= __('Save this filter', 'tanium') ?>">
                <span class="ti ti-bookmark"></span>
            </button>
        </form>
    </div>

    <!-- Saved filters bar -->
    <div id="ep-saved-filters" style="display:none;padding:6px 16px;border-bottom:1px solid var(--t-border);gap:6px;flex-wrap:wrap"></div>

    <!-- Bulk actions bar (hidden until checkboxes selected) -->
    <div id="ep-bulk-bar" style="display:none;padding:8px 16px;border-bottom:1px solid var(--t-border);background:rgba(26,109,255,.07);align-items:center;gap:12px">
        <span id="ep-bulk-count" style="font-size:.85rem;font-weight:700;color:#1a6dff">0 selecionados</span>
        <button onclick="bulkOpenTicket()" class="tanium-btn tanium-btn-primary tanium-btn-sm">
            <span class="ti ti-ticket"></span> <?= __('Create ticket', 'tanium') ?>
        </button>
        <button onclick="bulkDeselect()" class="tanium-btn tanium-btn-secondary tanium-btn-sm">
            <?= __('Deselect all', 'tanium') ?>
        </button>
    </div>

    <div class="tanium-card-body tanium-p0">
        <?php if (empty($rows)): ?>
            <p class="tanium-empty"><?= __('No endpoints found. Run a sync first.', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th style="width:32px"><input type="checkbox" id="ep-check-all" onchange="toggleAllChecks(this)" style="cursor:pointer"></th>
                    <th><?= __('Endpoint', 'tanium') ?></th>
                    <th><?= __('IP Address', 'tanium') ?></th>
                    <th><?= __('Operating System', 'tanium') ?></th>
                    <th><?= __('Risk Score', 'tanium') ?></th>
                    <th><?= __('SLA', 'tanium') ?></th>
                    <th><?= __('Last seen', 'tanium') ?></th>
                    <th><?= __('Status', 'tanium') ?></th>
                    <th><?= __('Actions', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php
            // Load SLA config once
            $slaCfg  = \GlpiPlugin\Tanium\Config::getConfig();
            $critDays = (int)($slaCfg['sla_critical_days'] ?? 7);
            $highDays = (int)($slaCfg['sla_high_days']     ?? 30);
            $medDays  = (int)($slaCfg['sla_medium_days']   ?? 90);

            foreach ($rows as $ep):
                $lastSeen  = $ep['last_seen'] ? strtotime($ep['last_seen']) : 0;
                $isRecent  = $lastSeen && (time() - $lastSeen) < 86400 * 7;
                $rs        = (int)($ep['risk_score'] ?? 0);
                $rsClass   = $riskClass($rs);
                $rsLabel   = $riskLabel($rs);

                // SLA breach check: any unremediated CVE past SLA for this endpoint
                $slaBreachRow = $DB->doQuery("
                    SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_endpoint_cves ec
                    JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
                    LEFT JOIN glpi_plugin_tanium_cve_exceptions ex ON ex.tanium_eid = ec.tanium_eid AND ex.cve_id = ec.cve_id
                    WHERE ec.tanium_eid = '" . $DB->escape($ep['tanium_eid']) . "'
                    AND ec.status != 'remediated' AND ex.id IS NULL
                    AND (
                        (v.severity='critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$critDays} DAY))
                        OR (v.severity='high'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$highDays} DAY))
                        OR (v.severity='medium' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$medDays} DAY))
                    )
                ")->fetch_assoc();
                $slaBreaches = (int)($slaBreachRow['cnt'] ?? 0);
            ?>
                <tr>
                    <td><input type="checkbox" class="ep-check" data-eid="<?= htmlspecialchars($ep['tanium_eid']) ?>" onchange="updateBulkBar()" style="cursor:pointer"></td>
                    <td>
                        <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ep['tanium_eid']) ?>" class="tanium-link tanium-mono">
                            <?= htmlspecialchars($ep['tanium_name']) ?>
                        </a>
                    </td>
                    <td class="tanium-mono"><?= htmlspecialchars($ep['ip_address'] ?? '—') ?></td>
                    <td><?= htmlspecialchars($ep['os_name'] ?? '—') ?></td>
                    <td>
                        <div class="tanium-riskmini <?= $rsClass ?>">
                            <div class="tanium-riskmini-bar" style="width:<?= $rs ?>%"></div>
                            <span class="tanium-riskmini-val"><?= $rs ?> <small><?= $rsLabel ?></small></span>
                        </div>
                    </td>
                    <td>
                        <?php if ($slaBreaches > 0): ?>
                        <span class="tanium-badge tanium-badge-error" title="<?= $slaBreaches ?> CVE(s) com SLA ultrapassado">
                            <span class="ti ti-alarm"></span> <?= $slaBreaches ?>
                        </span>
                        <?php else: ?>
                        <span class="tanium-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td class="tanium-small">
                        <?php if ($ep['last_seen']): ?>
                            <span class="<?= $isRecent ? 'tanium-text-green' : '' ?>">
                                <?= Html::convDateTime($ep['last_seen']) ?>
                            </span>
                        <?php else: ?>—<?php endif; ?>
                    </td>
                    <td>
                        <span class="tanium-badge tanium-badge-<?= $ep['sync_status'] === 'ok' ? 'success' : 'error' ?>">
                            <?= htmlspecialchars($ep['sync_status']) ?>
                        </span>
                    </td>
                    <td style="white-space:nowrap">
                        <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($ep['tanium_eid']) ?>"
                           class="tanium-btn-xs tanium-btn-secondary" title="<?= __('Detail', 'tanium') ?>">
                            <span class="ti ti-eye"></span>
                        </a>
                        <a href="<?= $webDir ?>/front/report.php?eid=<?= urlencode($ep['tanium_eid']) ?>"
                           target="_blank" class="tanium-btn-xs tanium-btn-secondary" title="<?= __('Report', 'tanium') ?>">
                            <span class="ti ti-printer"></span>
                        </a>
                        <?php if ($ep['computers_id']): ?>
                        <a href="/front/computer.form.php?id=<?= (int)$ep['computers_id'] ?>"
                           class="tanium-btn-xs tanium-btn-secondary" title="<?= __('GLPI Computer', 'tanium') ?>">
                            <span class="ti ti-link"></span>
                        </a>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($pages > 1): ?>
        <div class="tanium-pagination">
            <?php for ($p = 1; $p <= min($pages, 20); $p++): ?>
            <a href="?page=<?= $p ?>&search=<?= urlencode($search) ?>&os=<?= urlencode($os) ?>&risk=<?= urlencode($risk) ?>"
               class="tanium-page-btn <?= $p === $page ? 'active' : '' ?>"><?= $p ?></a>
            <?php endfor; ?>
        </div>
        <?php endif; ?>

        <?php endif; ?>
    </div>
</div>
</div>

<!-- Bulk ticket modal -->
<div id="ep-bulk-modal" class="tanium-modal-overlay" style="display:none">
    <div class="tanium-modal">
        <div class="tanium-modal-header">
            <span class="ti ti-ticket"></span> <?= __('Create Bulk Ticket', 'tanium') ?>
            <button onclick="document.getElementById('ep-bulk-modal').style.display='none'" class="tanium-modal-close">✕</button>
        </div>
        <div class="tanium-modal-body">
            <p id="ep-bulk-summary" class="tanium-muted" style="margin:0 0 12px;font-size:.85rem"></p>
            <label class="tanium-form-label"><?= __('Ticket title', 'tanium') ?></label>
            <input type="text" id="ep-bulk-title" class="tanium-input" style="width:100%" placeholder="<?= __('[Tanium] Security findings...', 'tanium') ?>">
            <label class="tanium-form-label" style="margin-top:12px"><?= __('Priority', 'tanium') ?></label>
            <select id="ep-bulk-priority" class="tanium-input tanium-select" style="width:200px">
                <option value="5">5 — <?= __('Very High', 'tanium') ?></option>
                <option value="4">4 — <?= __('High', 'tanium') ?></option>
                <option value="3" selected>3 — <?= __('Medium', 'tanium') ?></option>
                <option value="2">2 — <?= __('Low', 'tanium') ?></option>
            </select>
            <label class="tanium-form-label" style="margin-top:12px"><?= __('Additional notes', 'tanium') ?></label>
            <textarea id="ep-bulk-notes" class="tanium-input" rows="3" style="width:100%"></textarea>
        </div>
        <div class="tanium-modal-footer">
            <button onclick="document.getElementById('ep-bulk-modal').style.display='none'" class="tanium-btn tanium-btn-secondary"><?= __('Cancel', 'tanium') ?></button>
            <button onclick="submitBulkTicket()" class="tanium-btn tanium-btn-primary">
                <span class="ti ti-send"></span> <?= __('Create ticket', 'tanium') ?>
            </button>
        </div>
    </div>
</div>

<script>
const _webDir = <?= json_encode($webDir) ?>;
const _csrf   = <?= json_encode(Session::getNewCSRFToken()) ?>;
const SAVED_FILTERS_KEY = 'tanium_ep_filters';

// ── Bulk checkboxes ───────────────────────────────────────────────────────
function toggleAllChecks(master) {
    document.querySelectorAll('.ep-check').forEach(c => c.checked = master.checked);
    updateBulkBar();
}
function updateBulkBar() {
    const checked = document.querySelectorAll('.ep-check:checked');
    const bar  = document.getElementById('ep-bulk-bar');
    const cnt  = document.getElementById('ep-bulk-count');
    bar.style.display  = checked.length ? 'flex' : 'none';
    cnt.textContent    = checked.length + ' selecionado(s)';
}
function bulkDeselect() {
    document.querySelectorAll('.ep-check').forEach(c => c.checked = false);
    document.getElementById('ep-check-all').checked = false;
    updateBulkBar();
}
function getSelectedEids() {
    return Array.from(document.querySelectorAll('.ep-check:checked')).map(c => c.dataset.eid);
}
function bulkOpenTicket() {
    const eids = getSelectedEids();
    if (!eids.length) return;
    document.getElementById('ep-bulk-summary').textContent = eids.length + ' endpoint(s) selecionado(s)';
    document.getElementById('ep-bulk-title').value = '';
    document.getElementById('ep-bulk-notes').value = '';
    document.getElementById('ep-bulk-modal').style.display = 'flex';
}
function submitBulkTicket() {
    const eids = getSelectedEids();
    if (!eids.length) return;
    fetch(_webDir + '/ajax/bulk_ticket.php', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({
            eids: eids,
            title: document.getElementById('ep-bulk-title').value,
            priority: parseInt(document.getElementById('ep-bulk-priority').value),
            content: document.getElementById('ep-bulk-notes').value
        })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            document.getElementById('ep-bulk-modal').style.display = 'none';
            bulkDeselect();
            if (confirm('Ticket #' + d.ticket_id + ' criado! Abrir ticket?')) window.open(d.ticket_url, '_blank');
        } else alert(d.error || 'Error');
    });
}

// ── Saved filters (localStorage) ─────────────────────────────────────────
function saveCurrentFilter() {
    const form    = document.getElementById('ep-filter-form');
    const search  = form.querySelector('[name=search]').value.trim();
    const os      = form.querySelector('[name=os]').value;
    const risk    = form.querySelector('[name=risk]').value;
    if (!search && !os && !risk) { alert('Nenhum filtro ativo para salvar.'); return; }
    const name    = prompt('Nome do filtro:');
    if (!name) return;
    const filters = JSON.parse(localStorage.getItem(SAVED_FILTERS_KEY) || '[]');
    filters.push({name, search, os, risk});
    localStorage.setItem(SAVED_FILTERS_KEY, JSON.stringify(filters));
    renderSavedFilters();
}
function renderSavedFilters() {
    const filters = JSON.parse(localStorage.getItem(SAVED_FILTERS_KEY) || '[]');
    const bar     = document.getElementById('ep-saved-filters');
    if (!filters.length) { bar.style.display = 'none'; return; }
    bar.style.display = 'flex';
    bar.innerHTML = '<span style="font-size:.75rem;color:var(--t-muted);margin-right:4px">Filtros:</span>' +
        filters.map((f, i) =>
            '<button class="tanium-saved-filter-btn" onclick="applyFilter(' + i + ')">' + f.name + '</button>' +
            '<button class="tanium-saved-filter-del" onclick="deleteFilter(' + i + ')" title="Remover">✕</button>'
        ).join('');
}
function applyFilter(idx) {
    const f = JSON.parse(localStorage.getItem(SAVED_FILTERS_KEY) || '[]')[idx];
    if (!f) return;
    const form = document.getElementById('ep-filter-form');
    form.querySelector('[name=search]').value = f.search || '';
    form.querySelector('[name=os]').value     = f.os     || '';
    form.querySelector('[name=risk]').value   = f.risk   || '';
    form.submit();
}
function deleteFilter(idx) {
    const filters = JSON.parse(localStorage.getItem(SAVED_FILTERS_KEY) || '[]');
    filters.splice(idx, 1);
    localStorage.setItem(SAVED_FILTERS_KEY, JSON.stringify(filters));
    renderSavedFilters();
}
document.addEventListener('DOMContentLoaded', renderSavedFilters);
</script>

<?php
Html::footer();
