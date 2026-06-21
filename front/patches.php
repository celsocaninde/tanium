<?php

use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');
Session::checkRight('config', READ);

global $DB;

$webDir = \Plugin::getWebDir('tanium');
$eid    = $_GET['eid'] ?? '';  // if set → per-endpoint view

// ── Per-endpoint view ─────────────────────────────────────────────────────────
if ($eid) {
    $endpoint = null;
    $res = $DB->doQuery(
        "SELECT a.*, a.tanium_name, a.ip_address, a.os_name, a.last_seen, a.risk_score,
                c.id AS computers_id_link
         FROM glpi_plugin_tanium_assets a
         LEFT JOIN glpi_computers c ON a.computers_id = c.id
         WHERE a.tanium_eid = '" . $DB->escape($eid) . "' LIMIT 1"
    );
    if ($res) $endpoint = $res->fetch_assoc();
    if (!$endpoint) {
        Html::header(__('Tanium — Patch Remediation', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
        echo '<div class="tanium-page-wrap"><p class="tanium-empty">' . __('Endpoint not found.', 'tanium') . '</p></div>';
        Html::footer(); exit;
    }

    // Pending patches for this endpoint
    $patches = [];
    foreach ($DB->doQuery(
        "SELECT * FROM glpi_plugin_tanium_patches
         WHERE tanium_eid = '" . $DB->escape($eid) . "' AND status = 'missing'
         ORDER BY FIELD(severity,'critical','important','high','moderate','medium','low','unknown'), release_date ASC"
    ) as $r) {
        $patches[] = $r;
    }

    // Active CVEs for this endpoint
    $cves = [];
    foreach ($DB->doQuery(
        "SELECT ec.cve_id, v.title, v.severity, v.cvss_score
         FROM glpi_plugin_tanium_endpoint_cves ec
         LEFT JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
         WHERE ec.tanium_eid = '" . $DB->escape($eid) . "' AND ec.status != 'resolved'
         ORDER BY v.cvss_score DESC LIMIT 100"
    ) as $r) {
        $cves[] = $r;
    }

    // Existing deployments for this endpoint
    $deployments = [];
    foreach ($DB->doQuery(
        "SELECT d.*, t.name AS ticket_name,
                ub.name AS approved_by_name, ur.name AS requested_by_name
         FROM glpi_plugin_tanium_patch_deployments d
         LEFT JOIN glpi_tickets t ON d.ticket_id = t.id
         LEFT JOIN glpi_users ub ON d.approved_by = ub.id
         LEFT JOIN glpi_users ur ON d.requested_by = ur.id
         WHERE d.tanium_eid = '" . $DB->escape($eid) . "'
         ORDER BY d.created_at DESC LIMIT 20"
    ) as $r) {
        $deployments[] = $r;
    }

    $sevClass = fn(string $s) => match(strtolower($s)) {
        'critical'           => 'tanium-badge-critical',
        'important', 'high'  => 'tanium-badge-high',
        'moderate', 'medium' => 'tanium-badge-warning',
        'low'                => 'tanium-badge-success',
        default              => 'tanium-badge-muted',
    };

    $depStatusClass = fn(string $s) => match($s) {
        'deployed'        => 'tanium-badge-success',
        'deploying'       => 'tanium-badge-warning',
        'pending_approval'=> 'tanium-badge-muted',
        'failed'          => 'tanium-badge-error',
        'rejected'        => 'tanium-badge-error',
        'cancelled'       => 'tanium-badge-muted',
        default           => 'tanium-badge-muted',
    };

    $hasPending = !empty($patches);
    $hasDeploying = !empty(array_filter($deployments, fn($d) => $d['status'] === 'deploying'));

    Html::header(__('Tanium — Patch Remediation', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
    echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
    ?>
    <div class="tanium-page-wrap">

    <!-- Endpoint header card -->
    <div class="tanium-card" style="margin-bottom:20px">
        <div class="tanium-card-header" style="padding:20px 24px">
            <a href="<?= $webDir ?>/front/patches.php" class="tanium-btn tanium-btn-secondary tanium-btn-sm" style="margin-right:12px">
                <span class="ti ti-arrow-left"></span>
            </a>
            <div>
                <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:var(--tanium-muted);margin-bottom:2px">Patch Remediation</div>
                <div style="font-size:18px;font-weight:700"><?= htmlspecialchars($endpoint['tanium_name'] ?? $eid) ?></div>
            </div>
            <div style="margin-left:auto;display:flex;gap:12px;align-items:center">
                <?php if ($endpoint['computers_id_link']): ?>
                <a href="/front/computer.form.php?id=<?= (int)$endpoint['computers_id_link'] ?>" class="tanium-btn tanium-btn-secondary tanium-btn-sm">
                    <span class="ti ti-device-desktop"></span> GLPI
                </a>
                <?php endif; ?>
                <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($eid) ?>" class="tanium-btn tanium-btn-secondary tanium-btn-sm">
                    <span class="ti ti-shield"></span> CVEs
                </a>
                <?php if ($hasPending && !$hasDeploying): ?>
                <button id="btn-create-ticket" class="tanium-btn tanium-btn-primary" onclick="openDeployModal()">
                    <span class="ti ti-ticket"></span> <?= __('Create Remediation Ticket', 'tanium') ?>
                </button>
                <?php elseif ($hasDeploying): ?>
                <span class="tanium-badge tanium-badge-warning" style="font-size:13px;padding:6px 14px">
                    <span class="ti ti-loader-2"></span> <?= __('Deployment in progress…', 'tanium') ?>
                </span>
                <?php endif; ?>
            </div>
        </div>

        <div class="tanium-card-body" style="display:grid;grid-template-columns:repeat(5,1fr);gap:0;border-top:1px solid var(--tanium-border)">
            <?php
            $critical = count(array_filter($patches, fn($p) => strtolower($p['severity']??'') === 'critical'));
            $high     = count(array_filter($patches, fn($p) => in_array(strtolower($p['severity']??''), ['important','high'])));
            $kpis = [
                ['label' => 'IP Address',       'value' => $endpoint['ip_address'] ?? '—',          'clr' => '#63b3ed'],
                ['label' => 'OS',               'value' => mb_substr($endpoint['os_name']??'—',0,28), 'clr' => '#e2e8f0'],
                ['label' => 'Risk Score',       'value' => number_format((float)($endpoint['risk_score']??0),1).'/100', 'clr' => '#e53e3e'],
                ['label' => 'Missing Patches',  'value' => count($patches),                          'clr' => count($patches) > 0 ? '#ed8936' : '#68d391'],
                ['label' => 'Critical',         'value' => $critical,                                'clr' => $critical > 0 ? '#e53e3e' : '#68d391'],
            ];
            foreach ($kpis as $k): ?>
            <div style="padding:16px 20px;border-right:1px solid var(--tanium-border)">
                <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--tanium-muted);margin-bottom:6px"><?= $k['label'] ?></div>
                <div style="font-size:18px;font-weight:700;color:<?= $k['clr'] ?>"><?= htmlspecialchars((string)$k['value']) ?></div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- Pending patches table -->
    <div class="tanium-card" style="margin-bottom:20px">
        <div class="tanium-card-header">
            <span class="ti ti-shield-exclamation"></span> <?= __('Missing Patches', 'tanium') ?>
            <span class="tanium-muted" style="font-size:.8rem;margin-left:8px">(<?= count($patches) ?>)</span>
            <?php if ($hasPending): ?>
            <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
                <button class="tanium-btn tanium-btn-xs tanium-btn-secondary" onclick="toggleSelectAll()">
                    <span class="ti ti-checkbox"></span> <?= __('Select all', 'tanium') ?>
                </button>
                <button class="tanium-btn tanium-btn-xs tanium-btn-primary" id="btn-deploy-selected" style="display:none" onclick="openDeployModal(true)">
                    <span class="ti ti-rocket"></span> <?= __('Deploy selected', 'tanium') ?>
                </button>
            </div>
            <?php endif; ?>
        </div>

        <?php if (empty($patches)): ?>
        <div class="tanium-card-body">
            <p class="tanium-empty" style="color:#68d391">
                <span class="ti ti-circle-check" style="font-size:24px;display:block;margin-bottom:8px"></span>
                <?= __('No missing patches — this endpoint is up to date.', 'tanium') ?>
            </p>
        </div>
        <?php else: ?>
        <div class="tanium-card-body tanium-p0">
        <table class="tanium-table">
            <thead>
                <tr>
                    <th style="width:36px"><input type="checkbox" id="chk-all" onchange="selectAllPatches(this.checked)" style="cursor:pointer"></th>
                    <th>Patch ID</th>
                    <th><?= __('Title', 'tanium') ?></th>
                    <th><?= __('Severity', 'tanium') ?></th>
                    <th>KB</th>
                    <th><?= __('Released', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($patches as $p):
                $sc = $sevClass($p['severity']);
            ?>
            <tr class="patch-row <?= strtolower($p['severity']) === 'critical' ? 'tanium-row-overdue' : '' ?>">
                <td><input type="checkbox" class="patch-chk" value="<?= htmlspecialchars($p['patch_id']) ?>" onchange="onPatchCheck()"></td>
                <td class="tanium-mono tanium-small"><?= htmlspecialchars($p['patch_id']) ?></td>
                <td class="tanium-small"><?= htmlspecialchars(mb_substr($p['patch_title'] ?: $p['patch_id'], 0, 85)) ?><?= mb_strlen($p['patch_title']??'') > 85 ? '…' : '' ?></td>
                <td><span class="tanium-badge <?= $sc ?>"><?= ucfirst($p['severity']) ?></span></td>
                <td class="tanium-mono tanium-small">
                    <?php if ($p['kb_id']): ?>
                    <a href="https://support.microsoft.com/kb/<?= htmlspecialchars($p['kb_id']) ?>" target="_blank" class="tanium-link"><?= htmlspecialchars($p['kb_id']) ?></a>
                    <?php else: ?>—<?php endif; ?>
                </td>
                <td class="tanium-small"><?= $p['release_date'] ?? '—' ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- Deployment history -->
    <?php if (!empty($deployments)): ?>
    <div class="tanium-card" style="margin-bottom:20px">
        <div class="tanium-card-header">
            <span class="ti ti-history"></span> <?= __('Deployment History', 'tanium') ?>
        </div>
        <div class="tanium-card-body tanium-p0">
        <table class="tanium-table">
            <thead>
                <tr>
                    <th><?= __('Date', 'tanium') ?></th>
                    <th><?= __('Status', 'tanium') ?></th>
                    <th>GLPI Ticket</th>
                    <th>Tanium ID</th>
                    <th><?= __('Patches', 'tanium') ?></th>
                    <th><?= __('Approved by', 'tanium') ?></th>
                    <th><?= __('Deployed at', 'tanium') ?></th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($deployments as $dep):
                $pids = json_decode($dep['patch_ids'], true) ?: [];
            ?>
            <tr>
                <td class="tanium-small"><?= Html::convDateTime($dep['created_at']) ?></td>
                <td><span class="tanium-badge <?= $depStatusClass($dep['status']) ?>"><?= htmlspecialchars($dep['status']) ?></span></td>
                <td>
                    <?php if ($dep['ticket_id']): ?>
                    <a href="/front/ticket.form.php?id=<?= (int)$dep['ticket_id'] ?>" class="tanium-link tanium-small" target="_blank">
                        #<?= (int)$dep['ticket_id'] ?> <?= htmlspecialchars(mb_substr($dep['ticket_name']??'',0,40)) ?>
                    </a>
                    <?php else: ?>—<?php endif; ?>
                </td>
                <td class="tanium-mono tanium-small"><?= $dep['tanium_deployment_id'] ? htmlspecialchars(mb_substr($dep['tanium_deployment_id'],0,20)).'…' : '—' ?></td>
                <td class="tanium-center tanium-small"><?= count($pids) ?></td>
                <td class="tanium-small"><?= htmlspecialchars($dep['approved_by_name'] ?? '—') ?></td>
                <td class="tanium-small"><?= $dep['deployed_at'] ? Html::convDateTime($dep['deployed_at']) : '—' ?></td>
                <td>
                    <?php if ($dep['status'] === 'failed'): ?>
                    <button class="tanium-btn-xs tanium-btn-primary" onclick="retryDeploy(<?= (int)$dep['id'] ?>)" title="Retry deployment">
                        <span class="ti ti-refresh"></span>
                    </button>
                    <?php elseif ($dep['status'] === 'deploying'): ?>
                    <button class="tanium-btn-xs tanium-btn-secondary" onclick="checkStatus(<?= (int)$dep['id'] ?>)" title="Check status">
                        <span class="ti ti-refresh"></span>
                    </button>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php endif; ?>

    </div><!-- .tanium-page-wrap -->

    <!-- Deploy modal -->
    <div id="deploy-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center">
        <div style="background:var(--tanium-card-bg,#1a1e2e);border:1px solid var(--tanium-border);border-radius:12px;padding:28px;max-width:520px;width:90%;box-shadow:0 25px 60px rgba(0,0,0,.5)">
            <div style="font-size:16px;font-weight:700;margin-bottom:6px">
                <span class="ti ti-rocket"></span> Criar chamado de remediação de patches
            </div>
            <div class="tanium-muted tanium-small" style="margin-bottom:20px">
                Um chamado GLPI será criado. Após aprovação, o deploy é acionado automaticamente no Tanium.
            </div>
            <div style="margin-bottom:16px">
                <label class="tanium-small" style="display:block;margin-bottom:6px;font-weight:600">Patches selecionados</label>
                <div id="modal-patch-count" class="tanium-small tanium-muted"></div>
            </div>
            <?php
            $modalGroups = \GlpiPlugin\Tanium\ComputerGroup::getAll();
            if (!empty($modalGroups)):
            ?>
            <div style="margin-bottom:16px">
                <label class="tanium-small" style="display:block;margin-bottom:6px;font-weight:600">
                    Grupo de deploy (Tanium) <span style="color:#e53e3e">*</span>
                </label>
                <select id="modal-group" class="tanium-input" style="width:100%" required>
                    <option value="0">— Selecione o grupo —</option>
                    <?php foreach ($modalGroups as $g):
                        $gid      = (int)$g['tanium_group_id'];
                        $dispName = htmlspecialchars(\GlpiPlugin\Tanium\ComputerGroup::displayName($g));
                    ?>
                    <option value="<?= $gid ?>"><?= $dispName ?></option>
                    <?php endforeach; ?>
                </select>
                <div class="tanium-small tanium-muted" style="margin-top:4px">
                    Define o escopo de endpoints que o deploy pode atingir no Tanium.
                    <a href="<?= $webDir ?>/front/computergroups.php" target="_blank" class="tanium-link">Gerenciar grupos ↗</a>
                </div>
            </div>
            <?php else: ?>
            <div style="margin-bottom:16px;padding:12px;background:rgba(237,137,54,.1);border:1px solid rgba(237,137,54,.3);border-radius:8px">
                <div class="tanium-small" style="color:#ed8936">
                    <span class="ti ti-alert-triangle"></span>
                    Nenhum grupo de computadores importado.
                    <a href="<?= $webDir ?>/front/computergroups.php" target="_blank" class="tanium-link">Sincronizar grupos ↗</a>
                    antes de fazer o deploy.
                </div>
            </div>
            <input type="hidden" id="modal-group" value="0">
            <?php endif; ?>
            <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px">
                <button class="tanium-btn tanium-btn-secondary" onclick="closeDeployModal()">Cancelar</button>
                <button class="tanium-btn tanium-btn-primary" id="btn-confirm-deploy" onclick="confirmDeploy()">
                    <span class="ti ti-ticket"></span> Criar chamado
                </button>
            </div>
        </div>
    </div>

    <script>
    const _csrf   = <?= json_encode(Session::getNewCSRFToken()) ?>;
    const _webDir = <?= json_encode($webDir) ?>;
    const _eid    = <?= json_encode($eid) ?>;
    const _allPatchIds = <?= json_encode(array_column($patches, 'patch_id')) ?>;
    let _selectedForDeploy = [];

    function selectAllPatches(checked) {
        document.querySelectorAll('.patch-chk').forEach(c => c.checked = checked);
        onPatchCheck();
    }

    function toggleSelectAll() {
        const all = document.querySelectorAll('.patch-chk');
        const anyUnchecked = [...all].some(c => !c.checked);
        all.forEach(c => c.checked = anyUnchecked);
        document.getElementById('chk-all').checked = anyUnchecked;
        onPatchCheck();
    }

    function onPatchCheck() {
        const selected = [...document.querySelectorAll('.patch-chk:checked')].map(c => c.value);
        const btn = document.getElementById('btn-deploy-selected');
        if (btn) btn.style.display = selected.length > 0 ? 'inline-flex' : 'none';
    }

    function openDeployModal(selectedOnly = false) {
        const selected = selectedOnly
            ? [...document.querySelectorAll('.patch-chk:checked')].map(c => c.value)
            : _allPatchIds;
        _selectedForDeploy = selected;
        const countEl = document.getElementById('modal-patch-count');
        countEl.textContent = selected.length + ' patches selected';
        document.getElementById('deploy-modal').style.display = 'flex';
    }

    function closeDeployModal() {
        document.getElementById('deploy-modal').style.display = 'none';
    }

    function confirmDeploy() {
        if (!_selectedForDeploy.length) { alert('Nenhum patch selecionado.'); return; }
        const groupId = parseInt(document.getElementById('modal-group').value, 10);
        if (!groupId) { alert('Selecione o grupo de deploy do Tanium antes de continuar.'); return; }

        const btn = document.getElementById('btn-confirm-deploy');
        btn.disabled = true;
        btn.innerHTML = '<span class="ti ti-loader-2"></span> Criando…';

        fetch(_webDir + '/ajax/patch_ticket.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
            body: JSON.stringify({eid: _eid, patch_ids: _selectedForDeploy, limiting_group_id: groupId})
        })
        .then(r => r.json())
        .then(d => {
            if (d.success) {
                closeDeployModal();
                window.open(d.ticket_url, '_blank');
                location.reload();
            } else {
                alert('Erro: ' + (d.error || 'Erro desconhecido'));
                btn.disabled = false;
                btn.innerHTML = '<span class="ti ti-ticket"></span> Criar chamado';
            }
        })
        .catch(err => {
            alert('Erro de rede: ' + err);
            btn.disabled = false;
            btn.innerHTML = '<span class="ti ti-ticket"></span> Criar chamado';
        });
    }

    function retryDeploy(depId) {
        if (!confirm('Retry this deployment?')) return;
        fetch(_webDir + '/ajax/patch_deploy.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
            body: JSON.stringify({action: 'trigger', dep_id: depId})
        }).then(r => r.json()).then(d => {
            if (d.success) location.reload();
            else alert('Error: ' + (d.error || 'Unknown'));
        });
    }

    function checkStatus(depId) {
        fetch(_webDir + '/ajax/patch_deploy.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
            body: JSON.stringify({action: 'status', dep_id: depId})
        }).then(r => r.json()).then(d => {
            alert('Tanium status: ' + (d.tanium_status || d.error || 'Unknown'));
        });
    }
    </script>
    <?php
    Html::footer();
    exit;
}

// ── Main patches list (all endpoints) ─────────────────────────────────────────
$search   = $_GET['search']   ?? '';
$severity = $_GET['severity'] ?? '';
$status   = $_GET['status']   ?? 'missing';
$page     = max(1, (int)($_GET['page'] ?? 1));
$limit    = 50;
$offset   = ($page - 1) * $limit;

$whereConditions = ['1=1'];
if ($status)   $whereConditions[] = "p.status = '"   . $DB->escape($status)   . "'";
if ($severity) $whereConditions[] = "p.severity = '" . $DB->escape($severity) . "'";
if ($search)   $whereConditions[] = "(p.patch_title LIKE '%" . $DB->escape($search) . "%' OR p.patch_id LIKE '%" . $DB->escape($search) . "%' OR p.kb_id LIKE '%" . $DB->escape($search) . "%')";
$whereSQL = implode(' AND ', $whereConditions);

$rows = [];
foreach ($DB->doQuery("
    SELECT p.*, p.tanium_eid,
           a.tanium_name, a.ip_address, a.os_name, a.computers_id,
           (SELECT COUNT(*) FROM glpi_plugin_tanium_patch_deployments d
            WHERE d.tanium_eid = p.tanium_eid AND d.status IN ('pending_approval','deploying')) AS active_deployments
    FROM glpi_plugin_tanium_patches AS p
    LEFT JOIN glpi_plugin_tanium_assets AS a ON p.tanium_eid = a.tanium_eid
    WHERE {$whereSQL}
    ORDER BY FIELD(p.severity,'critical','important','high','moderate','medium','low','unknown'), p.release_date DESC
    LIMIT {$limit} OFFSET {$offset}
") as $r) {
    $rows[] = $r;
}

$countRes = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_patches AS p WHERE {$whereSQL}");
$total    = (int)($countRes ? $countRes->fetch_assoc()['cnt'] : 0);
$pages    = (int)ceil($total / $limit);

// Summary KPIs
$kpiRes = $DB->doQuery("
    SELECT
        COUNT(DISTINCT tanium_eid) AS endpoints_affected,
        SUM(severity = 'critical') AS cnt_critical,
        SUM(severity IN ('important','high')) AS cnt_high,
        COUNT(*) AS cnt_total
    FROM glpi_plugin_tanium_patches WHERE status = 'missing'
");
$kpi = $kpiRes ? $kpiRes->fetch_assoc() : [];

$depRes = $DB->doQuery("SELECT COUNT(*) AS cnt FROM glpi_plugin_tanium_patch_deployments WHERE status = 'deploying'");
$activeDeployments = (int)($depRes ? $depRes->fetch_assoc()['cnt'] : 0);

Html::header(__('Tanium — Patches', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<!-- Summary KPI bar -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px">
    <?php
    $kpis2 = [
        ['label' => __('Endpoints affected', 'tanium'), 'value' => number_format((int)($kpi['endpoints_affected']??0)), 'icon' => 'ti-device-desktop', 'clr' => '#ed8936'],
        ['label' => __('Critical patches',   'tanium'), 'value' => number_format((int)($kpi['cnt_critical']??0)),      'icon' => 'ti-alert-triangle','clr' => '#e53e3e'],
        ['label' => __('High patches',       'tanium'), 'value' => number_format((int)($kpi['cnt_high']??0)),          'icon' => 'ti-alert-circle',  'clr' => '#ed8936'],
        ['label' => __('Deployments active', 'tanium'), 'value' => $activeDeployments,                                  'icon' => 'ti-rocket',         'clr' => '#68d391'],
    ];
    foreach ($kpis2 as $k): ?>
    <div class="tanium-card" style="padding:18px 22px;display:flex;align-items:center;gap:16px">
        <span class="ti <?= $k['icon'] ?>" style="font-size:28px;color:<?= $k['clr'] ?>"></span>
        <div>
            <div style="font-size:22px;font-weight:700;color:<?= $k['clr'] ?>"><?= $k['value'] ?></div>
            <div class="tanium-small tanium-muted"><?= $k['label'] ?></div>
        </div>
    </div>
    <?php endforeach; ?>
</div>

<!-- Filter + list -->
<div class="tanium-card">
    <div class="tanium-card-header">
        <span class="ti ti-shield-exclamation"></span> <?= __('Patch Inventory', 'tanium') ?>
        <span class="tanium-muted" style="font-size:.8rem;margin-left:8px"><?= number_format($total) ?> <?= __('records', 'tanium') ?></span>
    </div>

    <div class="tanium-filter-bar">
        <form method="get" class="tanium-filter-form">
            <input type="text" name="search" class="tanium-input tanium-input-filter"
                   placeholder="<?= __('Search patch, title or KB…', 'tanium') ?>"
                   value="<?= htmlspecialchars($search) ?>"/>
            <select name="severity" class="tanium-input tanium-select">
                <option value=""><?= __('All severities', 'tanium') ?></option>
                <?php foreach (['critical','important','moderate','low'] as $s): ?>
                <option value="<?= $s ?>" <?= $severity === $s ? 'selected' : '' ?>><?= ucfirst($s) ?></option>
                <?php endforeach; ?>
            </select>
            <select name="status" class="tanium-input tanium-select">
                <option value=""><?= __('All statuses', 'tanium') ?></option>
                <option value="missing"    <?= $status === 'missing'    ? 'selected' : '' ?>><?= __('Missing',    'tanium') ?></option>
                <option value="installed"  <?= $status === 'installed'  ? 'selected' : '' ?>><?= __('Installed',  'tanium') ?></option>
                <option value="remediated" <?= $status === 'remediated' ? 'selected' : '' ?>><?= __('Remediated', 'tanium') ?></option>
                <option value="pending"    <?= $status === 'pending'    ? 'selected' : '' ?>><?= __('Pending',    'tanium') ?></option>
            </select>
            <button type="submit" class="tanium-btn tanium-btn-primary"><?= __('Filter', 'tanium') ?></button>
            <?php if ($search || $severity || $status): ?>
            <a href="<?= $webDir ?>/front/patches.php" class="tanium-btn tanium-btn-secondary"><?= __('Clear', 'tanium') ?></a>
            <?php endif; ?>
        </form>
    </div>

    <div class="tanium-card-body tanium-p0">
    <?php if (empty($rows)): ?>
        <p class="tanium-empty"><?= __('No patch data found. Enable "Missing patches" sync (requires Tanium Patch module) and run a sync.', 'tanium') ?></p>
    <?php else: ?>
    <table class="tanium-table">
        <thead>
            <tr>
                <th><?= __('Endpoint', 'tanium') ?></th>
                <th><?= __('IP', 'tanium') ?></th>
                <th><?= __('Patch / Title', 'tanium') ?></th>
                <th>KB</th>
                <th><?= __('Severity', 'tanium') ?></th>
                <th><?= __('Status', 'tanium') ?></th>
                <th><?= __('Released', 'tanium') ?></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($rows as $p):
            $sc    = Vulnerability::sevClass($p['severity']);
            $stCls = $p['status'] === 'missing'    ? 'tanium-badge-error'   :
                    ($p['status'] === 'installed'   ? 'tanium-badge-success' :
                    ($p['status'] === 'remediated'  ? 'tanium-badge-success' : 'tanium-badge-warning'));
        ?>
        <tr class="<?= strtolower($p['severity'] ?? '') === 'critical' && $p['status'] === 'missing' ? 'tanium-row-overdue' : '' ?>">
            <td class="tanium-mono">
                <a href="<?= $webDir ?>/front/patches.php?eid=<?= urlencode($p['tanium_eid']) ?>" class="tanium-link">
                    <?= htmlspecialchars($p['tanium_name'] ?? $p['tanium_eid']) ?>
                </a>
                <?php if ((int)($p['active_deployments']??0) > 0): ?>
                <span class="tanium-badge tanium-badge-warning tanium-small" style="margin-left:4px">deploying</span>
                <?php endif; ?>
            </td>
            <td class="tanium-mono tanium-small"><?= htmlspecialchars($p['ip_address'] ?? '—') ?></td>
            <td class="tanium-small"><?= htmlspecialchars(mb_substr($p['patch_title'] ?: $p['patch_id'], 0, 75)) ?><?= mb_strlen($p['patch_title']??'') > 75 ? '…' : '' ?></td>
            <td class="tanium-mono tanium-small">
                <?php if ($p['kb_id']): ?>
                <a href="https://support.microsoft.com/kb/<?= htmlspecialchars($p['kb_id']) ?>" target="_blank" class="tanium-link"><?= htmlspecialchars($p['kb_id']) ?></a>
                <?php else: ?>—<?php endif; ?>
            </td>
            <td><span class="tanium-badge <?= $sc ?>"><?= ucfirst($p['severity']) ?></span></td>
            <td><span class="tanium-badge <?= $stCls ?>"><?= htmlspecialchars($p['status']) ?></span></td>
            <td class="tanium-small"><?= $p['release_date'] ?? '—' ?></td>
            <td>
                <a href="<?= $webDir ?>/front/patches.php?eid=<?= urlencode($p['tanium_eid']) ?>" class="tanium-btn-xs tanium-btn-primary" title="<?= __('Deploy / manage patches for this endpoint', 'tanium') ?>">
                    <span class="ti ti-rocket"></span>
                </a>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <?php if ($pages > 1): ?>
    <div class="tanium-pagination">
        <?php for ($pg = 1; $pg <= min($pages, 20); $pg++): ?>
        <a href="?page=<?= $pg ?>&search=<?= urlencode($search) ?>&severity=<?= urlencode($severity) ?>&status=<?= urlencode($status) ?>"
           class="tanium-page-btn <?= $pg === $page ? 'active' : '' ?>"><?= $pg ?></a>
        <?php endfor; ?>
    </div>
    <?php endif; ?>
    <?php endif; ?>
    </div>
</div>

</div><!-- .tanium-page-wrap -->
<?php Html::footer();
