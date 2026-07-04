<?php

/**
 * GLPI ↔ Tanium Coverage Analysis
 * Shows: computers with Tanium agent, without agent, and Tanium endpoints not in GLPI.
 */

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

global $DB;

$webDir = \Plugin::getWebDir('tanium');
$tab    = $_GET['tab'] ?? 'without_tanium';

// ── Summary counts ────────────────────────────────────────────────────────────
$totalGlpi = 0;
$res = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_computers WHERE is_deleted=0 AND is_template=0");
if ($res) $totalGlpi = (int)$res->fetch_assoc()['cnt'];

$withTanium = 0;
$res = $DB->doQuery(
    "SELECT COUNT(DISTINCT c.id) AS cnt
     FROM glpi_computers c
     INNER JOIN glpi_plugin_tanium_assets a ON c.id = a.computers_id
     WHERE c.is_deleted = 0 AND c.is_template = 0"
);
if ($res) $withTanium = (int)$res->fetch_assoc()['cnt'];

$withoutTanium = $totalGlpi - $withTanium;

$totalTanium = 0;
$res = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_assets");
if ($res) $totalTanium = (int)$res->fetch_assoc()['cnt'];

$taniumNotLinked = 0;
$res = $DB->doQuery(
    "SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_assets
     WHERE computers_id IS NULL OR computers_id NOT IN (SELECT id FROM glpi_computers WHERE is_deleted=0)"
);
if ($res) $taniumNotLinked = (int)$res->fetch_assoc()['cnt'];

$coveragePct = $totalGlpi > 0 ? round($withTanium / $totalGlpi * 100) : 0;

// ── Tab data ──────────────────────────────────────────────────────────────────
$search = trim($_GET['search'] ?? '');
$page   = max(1, (int)($_GET['page'] ?? 1));
$limit  = 100;
$offset = ($page - 1) * $limit;

$rows     = [];
$rowTotal = 0;

if ($tab === 'without_tanium') {
    // GLPI computers without Tanium agent
    $srchSql = $search ? "AND (c.name LIKE '%" . $DB->escape($search) . "%' OR c.serial LIKE '%" . $DB->escape($search) . "%')" : '';
    $rowRes  = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_computers c LEFT JOIN glpi_plugin_tanium_assets a ON c.id = a.computers_id WHERE c.is_deleted=0 AND c.is_template=0 AND a.computers_id IS NULL {$srchSql}");
    if ($rowRes) $rowTotal = (int)$rowRes->fetch_assoc()['cnt'];

    foreach ($DB->doQuery("
        SELECT c.id, c.name, c.serial, c.date_mod, c.date_creation,
               e.completename AS entity_name,
               l.completename AS location_name,
               s.name AS state_name,
               g.name AS group_name,
               u.name AS user_name
        FROM glpi_computers c
        LEFT JOIN glpi_plugin_tanium_assets a  ON c.id = a.computers_id
        LEFT JOIN glpi_entities e              ON c.entities_id = e.id
        LEFT JOIN glpi_locations l             ON c.locations_id = l.id
        LEFT JOIN glpi_states s                ON c.states_id = s.id
        LEFT JOIN glpi_groups g                ON g.id = (
            SELECT gi.groups_id FROM glpi_groups_items gi
            WHERE gi.itemtype = 'Computer' AND gi.items_id = c.id AND gi.type = 1
            LIMIT 1
        )
        LEFT JOIN glpi_users u                 ON c.users_id = u.id
        WHERE c.is_deleted=0 AND c.is_template=0 AND a.computers_id IS NULL
        {$srchSql}
        ORDER BY c.date_mod DESC
        LIMIT {$limit} OFFSET {$offset}
    ") as $r) {
        $rows[] = $r;
    }

} elseif ($tab === 'with_tanium') {
    // GLPI computers WITH Tanium agent
    $srchSql = $search ? "AND (c.name LIKE '%" . $DB->escape($search) . "%' OR a.ip_address LIKE '%" . $DB->escape($search) . "%')" : '';
    $rowRes  = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_computers c INNER JOIN glpi_plugin_tanium_assets a ON c.id = a.computers_id WHERE c.is_deleted=0 {$srchSql}");
    if ($rowRes) $rowTotal = (int)$rowRes->fetch_assoc()['cnt'];

    foreach ($DB->doQuery("
        SELECT c.id AS computers_id, c.name AS glpi_name, c.serial, c.date_mod,
               a.tanium_eid, a.tanium_name, a.ip_address, a.os_name,
               a.last_seen, a.risk_score, a.patch_compliance,
               e.completename AS entity_name
        FROM glpi_computers c
        INNER JOIN glpi_plugin_tanium_assets a ON c.id = a.computers_id
        LEFT JOIN glpi_entities e              ON c.entities_id = e.id
        WHERE c.is_deleted=0 {$srchSql}
        ORDER BY a.risk_score DESC
        LIMIT {$limit} OFFSET {$offset}
    ") as $r) {
        $rows[] = $r;
    }

} elseif ($tab === 'tanium_only') {
    // Tanium endpoints NOT linked to any GLPI computer
    $srchSql = $search ? "AND (a.tanium_name LIKE '%" . $DB->escape($search) . "%' OR a.ip_address LIKE '%" . $DB->escape($search) . "%')" : '';
    $rowRes  = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_assets a WHERE (a.computers_id IS NULL OR a.computers_id NOT IN (SELECT id FROM glpi_computers WHERE is_deleted=0)) {$srchSql}");
    if ($rowRes) $rowTotal = (int)$rowRes->fetch_assoc()['cnt'];

    foreach ($DB->doQuery("
        SELECT a.*
        FROM glpi_plugin_tanium_assets a
        WHERE (a.computers_id IS NULL OR a.computers_id NOT IN (SELECT id FROM glpi_computers WHERE is_deleted=0))
        {$srchSql}
        ORDER BY a.last_seen DESC
        LIMIT {$limit} OFFSET {$offset}
    ") as $r) {
        $rows[] = $r;
    }
}

$pages = (int)ceil($rowTotal / $limit);

$riskColor = function(float $score): string {
    if ($score >= 70) return '#e53e3e';
    if ($score >= 40) return '#ed8936';
    if ($score >= 20) return '#ecc94b';
    return '#68d391';
};

Html::header(__('Tanium — Coverage Analysis', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<!-- Coverage gauge header -->
<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:14px;margin-bottom:20px">
    <div class="tanium-card" style="padding:20px 24px">
        <div class="tanium-small tanium-muted" style="margin-bottom:4px"><?= __('GLPI Computers', 'tanium') ?></div>
        <div style="font-size:28px;font-weight:700;color:#e2e8f0"><?= number_format($totalGlpi) ?></div>
        <div class="tanium-small tanium-muted"><?= __('total active', 'tanium') ?></div>
    </div>
    <div class="tanium-card" style="padding:20px 24px">
        <div class="tanium-small tanium-muted" style="margin-bottom:4px"><?= __('Tanium Coverage', 'tanium') ?></div>
        <div style="font-size:28px;font-weight:700;color:<?= $coveragePct >= 90 ? '#68d391' : ($coveragePct >= 70 ? '#ecc94b' : '#e53e3e') ?>"><?= $coveragePct ?>%</div>
        <div style="margin-top:8px;background:#2d3748;border-radius:4px;height:6px;overflow:hidden">
            <div style="height:100%;width:<?= $coveragePct ?>%;background:<?= $coveragePct >= 90 ? '#68d391' : ($coveragePct >= 70 ? '#ecc94b' : '#e53e3e') ?>;transition:width .4s"></div>
        </div>
    </div>
    <div class="tanium-card" style="padding:20px 24px;border-left:3px solid #e53e3e">
        <div class="tanium-small tanium-muted" style="margin-bottom:4px"><?= __('Without Tanium Agent', 'tanium') ?></div>
        <div style="font-size:28px;font-weight:700;color:#e53e3e"><?= number_format($withoutTanium) ?></div>
        <div class="tanium-small tanium-muted"><?= __('GLPI computers not in Tanium', 'tanium') ?></div>
    </div>
    <div class="tanium-card" style="padding:20px 24px;border-left:3px solid #f6ad55">
        <div class="tanium-small tanium-muted" style="margin-bottom:4px"><?= __('Tanium Only', 'tanium') ?></div>
        <div style="font-size:28px;font-weight:700;color:#f6ad55"><?= number_format($taniumNotLinked) ?></div>
        <div class="tanium-small tanium-muted"><?= __('not matched in GLPI', 'tanium') ?></div>
    </div>
</div>

<!-- Tabs -->
<div class="tanium-card">
    <div class="tanium-card-header" style="padding:0;border-bottom:1px solid var(--tanium-border)">
        <?php
        $tabs = [
            'without_tanium' => ['label' => sprintf(__('⚠ Without Tanium (%s)', 'tanium'), number_format($withoutTanium)), 'clr' => '#e53e3e'],
            'with_tanium'    => ['label' => sprintf(__('✓ With Tanium (%s)',    'tanium'), number_format($withTanium)),     'clr' => '#68d391'],
            'tanium_only'    => ['label' => sprintf(__('◈ Tanium only (%s)',    'tanium'), number_format($taniumNotLinked)), 'clr' => '#f6ad55'],
        ];
        foreach ($tabs as $key => $t):
            $active = $tab === $key;
        ?>
        <a href="?tab=<?= $key ?>"
           style="display:inline-flex;align-items:center;padding:14px 22px;font-size:13px;font-weight:600;text-decoration:none;
                  color:<?= $active ? $t['clr'] : 'var(--tanium-muted)' ?>;
                  border-bottom:<?= $active ? '3px solid '.$t['clr'] : '3px solid transparent' ?>;
                  margin-bottom:-1px">
            <?= $t['label'] ?>
        </a>
        <?php endforeach; ?>
    </div>

    <!-- Search bar -->
    <div class="tanium-filter-bar">
        <form method="get" class="tanium-filter-form">
            <input type="hidden" name="tab" value="<?= htmlspecialchars($tab) ?>">
            <input type="text" name="search" class="tanium-input tanium-input-filter"
                   placeholder="<?= __('Search by name, IP, serial…', 'tanium') ?>"
                   value="<?= htmlspecialchars($search) ?>"/>
            <button type="submit" class="tanium-btn tanium-btn-primary"><?= __('Search', 'tanium') ?></button>
            <?php if ($search): ?>
            <a href="?tab=<?= htmlspecialchars($tab) ?>" class="tanium-btn tanium-btn-secondary"><?= __('Clear', 'tanium') ?></a>
            <?php endif; ?>
            <span class="tanium-muted tanium-small" style="margin-left:auto"><?= number_format($rowTotal) ?> <?= __('records', 'tanium') ?></span>
        </form>
    </div>

    <div class="tanium-card-body tanium-p0">
    <?php if (empty($rows)): ?>
        <p class="tanium-empty">
            <?php if ($tab === 'without_tanium'): ?>
            <span class="ti ti-circle-check" style="font-size:24px;color:#68d391;display:block;margin-bottom:8px"></span>
            <?= __('All GLPI computers have a Tanium agent. Full coverage achieved!', 'tanium') ?>
            <?php elseif ($tab === 'tanium_only'): ?>
            <?= __('All Tanium endpoints are matched to GLPI computers.', 'tanium') ?>
            <?php else: ?>
            <?= __('No results found.', 'tanium') ?>
            <?php endif; ?>
        </p>

    <?php elseif ($tab === 'without_tanium'): ?>
    <!-- GLPI computers without Tanium agent -->
    <table class="tanium-table">
        <thead>
            <tr>
                <th><?= __('Computer', 'tanium') ?></th>
                <th><?= __('Serial', 'tanium') ?></th>
                <th><?= __('User', 'tanium') ?></th>
                <th><?= __('Group', 'tanium') ?></th>
                <th><?= __('Location', 'tanium') ?></th>
                <th><?= __('Entity', 'tanium') ?></th>
                <th><?= __('State', 'tanium') ?></th>
                <th><?= __('Last modified', 'tanium') ?></th>
                <th style="width:36px">
                    <input type="checkbox" onchange="document.querySelectorAll('.cov-check').forEach(c => c.checked = this.checked); covUpdateBar()" style="cursor:pointer"/>
                </th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $r): ?>
        <tr>
            <td class="tanium-mono">
                <a href="/front/computer.form.php?id=<?= (int)$r['id'] ?>" class="tanium-link" target="_blank">
                    <?= htmlspecialchars($r['name']) ?>
                </a>
            </td>
            <td class="tanium-mono tanium-small"><?= htmlspecialchars($r['serial'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars($r['user_name'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars($r['group_name'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars($r['location_name'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars($r['entity_name'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars($r['state_name'] ?? '—') ?></td>
            <td class="tanium-small"><?= $r['date_mod'] ? Html::convDateTime($r['date_mod']) : '—' ?></td>
            <td>
                <input type="checkbox" class="cov-check" data-cid="<?= (int)$r['id'] ?>" onchange="covUpdateBar()" style="cursor:pointer"
                       title="<?= __('Select for agent-install ticket', 'tanium') ?>"/>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <div id="cov-bulk-bar" style="display:none;padding:10px 16px;border-top:1px solid rgba(122,141,168,.25)">
        <button class="tanium-btn tanium-btn-primary" onclick="covAgentTicket()">
            <span class="ti ti-ticket"></span>
            <?= __('Open agent-install ticket for selected', 'tanium') ?>
            (<span id="cov-count">0</span>)
        </button>
    </div>

    <?php elseif ($tab === 'with_tanium'): ?>
    <!-- GLPI computers WITH Tanium -->
    <table class="tanium-table">
        <thead>
            <tr>
                <th><?= __('GLPI Computer', 'tanium') ?></th>
                <th><?= __('Tanium Name', 'tanium') ?></th>
                <th><?= __('IP', 'tanium') ?></th>
                <th><?= __('OS', 'tanium') ?></th>
                <th><?= __('Risk Score', 'tanium') ?></th>
                <th><?= __('Compliance', 'tanium') ?></th>
                <th><?= __('Last seen', 'tanium') ?></th>
                <th><?= __('Entity', 'tanium') ?></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $r):
            $rc       = $riskColor((float)($r['risk_score']??0));
            $cmpPct   = $r['patch_compliance'];
            $cmpClr   = $cmpPct === null ? '#718096' : ($cmpPct >= 90 ? '#68d391' : ($cmpPct >= 70 ? '#ecc94b' : '#e53e3e'));
        ?>
        <tr>
            <td class="tanium-mono">
                <a href="/front/computer.form.php?id=<?= (int)$r['computers_id'] ?>" class="tanium-link" target="_blank">
                    <?= htmlspecialchars($r['glpi_name']) ?>
                </a>
            </td>
            <td class="tanium-mono">
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($r['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($r['tanium_name'] ?? $r['tanium_eid']) ?>
                </a>
            </td>
            <td class="tanium-mono tanium-small"><?= htmlspecialchars($r['ip_address'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars(mb_substr($r['os_name']??'—',0,30)) ?></td>
            <td>
                <span style="font-weight:700;color:<?= $rc ?>"><?= number_format((float)($r['risk_score']??0),1) ?></span>
                <span class="tanium-muted tanium-small">/100</span>
            </td>
            <td>
                <?php if ($cmpPct !== null): ?>
                <div style="display:flex;align-items:center;gap:8px">
                    <div style="background:#2d3748;border-radius:3px;height:8px;width:60px;overflow:hidden">
                        <div style="height:100%;width:<?= $cmpPct ?>%;background:<?= $cmpClr ?>"></div>
                    </div>
                    <span style="font-size:12px;color:<?= $cmpClr ?>"><?= $cmpPct ?>%</span>
                </div>
                <?php else: ?>
                <span class="tanium-muted tanium-small">—</span>
                <?php endif; ?>
            </td>
            <td class="tanium-small"><?= $r['last_seen'] ? Html::convDateTime($r['last_seen']) : '—' ?></td>
            <td class="tanium-small"><?= htmlspecialchars($r['entity_name'] ?? '—') ?></td>
            <td>
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($r['tanium_eid']) ?>" class="tanium-btn-xs tanium-btn-secondary" title="Tanium details">
                    <span class="ti ti-shield"></span>
                </a>
                <a href="<?= $webDir ?>/front/patches.php?eid=<?= urlencode($r['tanium_eid']) ?>" class="tanium-btn-xs tanium-btn-primary" title="Patch remediation">
                    <span class="ti ti-rocket"></span>
                </a>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <?php elseif ($tab === 'tanium_only'): ?>
    <!-- Tanium endpoints NOT in GLPI -->
    <table class="tanium-table">
        <thead>
            <tr>
                <th><?= __('Tanium Name', 'tanium') ?></th>
                <th>EID</th>
                <th><?= __('IP', 'tanium') ?></th>
                <th><?= __('OS', 'tanium') ?></th>
                <th><?= __('Risk Score', 'tanium') ?></th>
                <th><?= __('Last seen', 'tanium') ?></th>
                <th><?= __('Missing patches', 'tanium') ?></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $r):
            $rc = $riskColor((float)($r['risk_score']??0));
        ?>
        <tr>
            <td class="tanium-mono">
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($r['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($r['tanium_name'] ?? $r['tanium_eid']) ?>
                </a>
            </td>
            <td class="tanium-mono tanium-small" style="font-size:10px;max-width:120px;overflow:hidden;text-overflow:ellipsis"><?= htmlspecialchars($r['tanium_eid']) ?></td>
            <td class="tanium-mono tanium-small"><?= htmlspecialchars($r['ip_address'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars(mb_substr($r['os_name']??'—',0,30)) ?></td>
            <td><span style="font-weight:700;color:<?= $rc ?>"><?= number_format((float)($r['risk_score']??0),1) ?></span><span class="tanium-muted tanium-small">/100</span></td>
            <td class="tanium-small"><?= $r['last_seen'] ? Html::convDateTime($r['last_seen']) : '—' ?></td>
            <td class="tanium-center">
                <?php
                $mpRes = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_patches WHERE tanium_eid='" . $DB->escape($r['tanium_eid']) . "' AND status='missing'");
                $mp = (int)($mpRes ? $mpRes->fetch_assoc()['cnt'] : 0);
                ?>
                <?php if ($mp > 0): ?>
                <span class="tanium-badge tanium-badge-error"><?= $mp ?></span>
                <?php else: ?>
                <span class="tanium-badge tanium-badge-success">0</span>
                <?php endif; ?>
            </td>
            <td style="white-space:nowrap">
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($r['tanium_eid']) ?>" class="tanium-btn-xs tanium-btn-secondary" title="View in Tanium">
                    <span class="ti ti-shield"></span>
                </a>
                <button class="tanium-btn-xs tanium-btn-primary" title="<?= __('Create GLPI computer now', 'tanium') ?>"
                        onclick="covCreateComputer('<?= htmlspecialchars(addslashes($r['tanium_eid'])) ?>', this)">
                    <span class="ti ti-device-desktop-plus"></span>
                </button>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <?php if ($pages > 1): ?>
    <div class="tanium-pagination">
        <?php for ($pg = 1; $pg <= min($pages, 20); $pg++): ?>
        <a href="?tab=<?= htmlspecialchars($tab) ?>&page=<?= $pg ?>&search=<?= urlencode($search) ?>"
           class="tanium-page-btn <?= $pg === $page ? 'active' : '' ?>"><?= $pg ?></a>
        <?php endfor; ?>
    </div>
    <?php endif; ?>

    </div><!-- card-body -->
</div><!-- card -->

</div><!-- .tanium-page-wrap -->

<script>
const covCsrf   = <?= json_encode(Session::getNewCSRFToken()) ?>;
const covAjax   = <?= json_encode($webDir . '/ajax/coverage_action.php') ?>;

function covUpdateBar() {
    const n   = document.querySelectorAll('.cov-check:checked').length;
    const bar = document.getElementById('cov-bulk-bar');
    if (bar) {
        bar.style.display = n > 0 ? 'block' : 'none';
        document.getElementById('cov-count').textContent = n;
    }
}

async function covAgentTicket() {
    const ids = Array.from(document.querySelectorAll('.cov-check:checked')).map(c => parseInt(c.dataset.cid, 10));
    if (!ids.length) { return; }
    const r = await fetch(covAjax, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': covCsrf},
        body: JSON.stringify({action: 'agent_ticket', computers_ids: ids})
    });
    const d = await r.json();
    if (d.success) {
        window.open('/front/ticket.form.php?id=' + d.ticket_id, '_blank');
    } else {
        alert(d.error || 'Error');
    }
}

async function covCreateComputer(eid, btn) {
    btn.disabled = true;
    const r = await fetch(covAjax, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': covCsrf},
        body: JSON.stringify({action: 'create_computer', tanium_eid: eid})
    });
    const d = await r.json();
    if (d.success) {
        location.reload();
    } else {
        alert(d.error || 'Error');
        btn.disabled = false;
    }
}
</script>
<?php Html::footer();
