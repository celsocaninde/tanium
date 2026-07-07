<?php

use GlpiPlugin\Tanium\Sync;
use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

global $DB;

$eid = $_GET['eid'] ?? '';
if ($eid === '') {
    Html::redirect(Plugin::getWebDir('tanium') . '/front/endpoints.php');
}

$asset = $DB->request([
    'FROM'  => 'glpi_plugin_tanium_assets',
    'WHERE' => ['tanium_eid' => $eid],
    'LIMIT' => 1,
])->current();

if (!$asset) {
    Html::displayErrorAndDie(__('Endpoint not found.', 'tanium'));
}

// CVEs for this endpoint
$cves = [];
foreach ($DB->request([
    'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
    'WHERE' => ['tanium_eid' => $eid],
    'ORDER' => 'cvss_score DESC',
]) as $r) {
    $cves[] = $r;
}

// Missing patches for this endpoint
$patches = [];
foreach ($DB->request([
    'FROM'  => 'glpi_plugin_tanium_patches',
    'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'],
    'ORDER' => ['severity ASC', 'release_date DESC'],
    'LIMIT' => 50,
]) as $r) {
    $patches[] = $r;
}

// Recent syncs (from log table filtered by date range, approximate)
$recentSyncs = [];
foreach ($DB->request([
    'FROM'  => 'glpi_plugin_tanium_sync_logs',
    'ORDER' => 'started_at DESC',
    'LIMIT' => 5,
]) as $r) {
    $recentSyncs[] = $r;
}

// CVE severity breakdown
$sevCount = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'unknown' => 0];
foreach ($cves as $cve) {
    $sev = strtolower($cve['severity'] ?? 'unknown');
    $sevCount[$sev] = ($sevCount[$sev] ?? 0) + 1;
}

// Plain-text CVE list injected into the generic ticket description ($cves is
// already ordered by CVSS DESC, so the cut keeps the worst ones).
$cveListText = '';
if (!empty($cves)) {
    $lines = [];
    foreach (array_slice($cves, 0, 30) as $c) {
        $lines[] = '- ' . $c['cve_id']
            . ' (' . ucfirst(strtolower((string)($c['severity'] ?? 'unknown')))
            . ($c['cvss_score'] !== null ? ', CVSS ' . number_format((float)$c['cvss_score'], 1) : '')
            . ', ' . ($c['status'] ?? 'open') . ')';
    }
    if (count($cves) > 30) {
        $lines[] = sprintf('... e mais %d CVE(s) — lista completa na aba de CVEs do endpoint no GLPI.', count($cves) - 30);
    }
    $cveListText = "\n\nCVEs detectados neste endpoint ("
        . count($cves) . ' no total: '
        . "{$sevCount['critical']} críticos, {$sevCount['high']} altos, {$sevCount['medium']} médios, {$sevCount['low']} baixos):\n"
        . implode("\n", $lines);
}

// Load exceptions for this endpoint (keyed by cve_id). An exception past its
// expires_at no longer suppresses SLA — it is kept here only to render the
// "expired" badge so the analyst sees the risk acceptance has lapsed.
$exceptions = [];
foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_cve_exceptions', 'WHERE' => ['tanium_eid' => $eid]]) as $ex) {
    $ex['is_active'] = !$ex['expires_at'] || strtotime($ex['expires_at']) > time();
    $exceptions[$ex['cve_id']] = $ex;
}

// Load assignments for this endpoint (keyed by cve_id)
$assignments = [];
foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_cve_assignments', 'WHERE' => ['tanium_eid' => $eid]]) as $as) {
    $assignments[$as['cve_id']] = $as;
}

// SLA config
$slaConfig = \GlpiPlugin\Tanium\Config::getConfig();
$slaDays   = ['critical' => (int)($slaConfig['sla_critical_days'] ?? 7), 'high' => (int)($slaConfig['sla_high_days'] ?? 30), 'medium' => (int)($slaConfig['sla_medium_days'] ?? 90)];

// CVE history for this endpoint (last 20 changes)
$cveHistory = [];
foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_cve_history', 'WHERE' => ['tanium_eid' => $eid], 'ORDER' => 'changed_at DESC', 'LIMIT' => 20]) as $h) {
    $cveHistory[] = $h;
}

// Risk history timeline (global — last 12 syncs)
$riskHistory = [];
foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_risk_history', 'ORDER' => 'recorded_at DESC', 'LIMIT' => 12]) as $h) {
    $riskHistory[] = $h;
}
$riskHistory = array_reverse($riskHistory);

// Fetch GLPI users for assignment modal
$glpiUsers = [];
foreach ($DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_users', 'WHERE' => ['is_deleted' => 0, 'is_active' => 1], 'ORDER' => 'name ASC', 'LIMIT' => 500]) as $u) {
    $glpiUsers[] = $u;
}

$webDir    = \Plugin::getWebDir('tanium');
$riskScore = (int) ($asset['risk_score'] ?? 0);
$riskLabel = match (true) {
    $riskScore >= 70 => ['Crítico', 'tanium-risk-critical'],
    $riskScore >= 40 => ['Alto',    'tanium-risk-high'],
    $riskScore >= 15 => ['Médio',   'tanium-risk-medium'],
    default          => ['Baixo',   'tanium-risk-low'],
};

$lastSeen    = $asset['last_seen'] ? strtotime($asset['last_seen']) : 0;
$isOnline    = $lastSeen && (time() - $lastSeen) < 3600;
$isRecent    = $lastSeen && (time() - $lastSeen) < 86400;

$sevClass = function(string $s): string {
    return match (strtolower($s)) {
        'critical'  => 'tanium-badge-critical',
        'high'      => 'tanium-badge-high',
        'medium'    => 'tanium-badge-warning',
        'low'       => 'tanium-badge-success',
        default     => 'tanium-badge-muted',
    };
};

Html::header(
    __('Tanium — Endpoint Detail', 'tanium'),
    $_SERVER['PHP_SELF'],
    'tools',
    'plugins'
);
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<!-- ── Breadcrumb ───────────────────────────────────────────── -->
<nav class="tanium-breadcrumb">
    <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-link">Dashboard</a>
    <span class="tanium-bc-sep">›</span>
    <a href="<?= $webDir ?>/front/endpoints.php" class="tanium-link">Endpoints</a>
    <span class="tanium-bc-sep">›</span>
    <span><?= htmlspecialchars($asset['tanium_name']) ?></span>
</nav>

<!-- ── Hero header ──────────────────────────────────────────── -->
<div class="tanium-ep-hero">
    <div class="tanium-ep-hero-left">
        <div class="tanium-ep-icon"><span class="ti ti-device-laptop"></span></div>
        <div>
            <h1 class="tanium-ep-name"><?= htmlspecialchars($asset['tanium_name']) ?></h1>
            <div class="tanium-ep-meta">
                <span class="tanium-badge <?= $isOnline ? 'tanium-badge-success' : ($isRecent ? 'tanium-badge-warning' : 'tanium-badge-muted') ?>">
                    <?= $isOnline ? 'Online' : ($isRecent ? 'Recente' : 'Offline') ?>
                </span>
                <span class="tanium-muted"><?= __('EID:', 'tanium') ?> <code><?= htmlspecialchars($eid) ?></code></span>
                <?php if ($asset['is_virtual']): ?>
                <span class="tanium-badge tanium-badge-muted">Virtual</span>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <div class="tanium-ep-hero-right">
        <!-- Risk gauge -->
        <div class="tanium-risk-gauge <?= $riskLabel[1] ?>">
            <div class="tanium-risk-score"><?= $riskScore ?></div>
            <div class="tanium-risk-label"><?= $riskLabel[0] ?></div>
            <div class="tanium-risk-sub">Risk Score</div>
        </div>
        <!-- Quick actions -->
        <div class="tanium-ep-actions">
            <?php if ($asset['computers_id']): ?>
            <a href="/front/computer.form.php?id=<?= (int)$asset['computers_id'] ?>" class="tanium-btn tanium-btn-secondary">
                <span class="ti ti-link"></span> GLPI Computer
            </a>
            <?php endif; ?>
            <a href="<?= $webDir ?>/front/report.php?eid=<?= urlencode($eid) ?>" target="_blank" class="tanium-btn tanium-btn-secondary">
                <span class="ti ti-printer"></span> <?= __('Report', 'tanium') ?>
            </a>
            <?php if (\GlpiPlugin\Tanium\Profile::hasSyncRight()): ?>
            <button onclick="openTicketModal()" class="tanium-btn tanium-btn-primary">
                <span class="ti ti-ticket"></span> <?= __('Open ticket', 'tanium') ?>
            </button>
            <button onclick="requestRemoteAction('restart_client')" class="tanium-btn tanium-btn-secondary"
                    title="<?= __('Opens an approval ticket — the action only runs on Tanium after approval', 'tanium') ?>">
                <span class="ti ti-refresh"></span> <?= __('Restart client', 'tanium') ?>
            </button>
            <button onclick="requestRemoteAction('quarantine')" class="tanium-btn tanium-btn-secondary" style="color:#e8212a"
                    title="<?= __('Opens an approval ticket — the endpoint is only isolated after approval', 'tanium') ?>">
                <span class="ti ti-shield-lock"></span> <?= __('Quarantine', 'tanium') ?>
            </button>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- ── Info grid ─────────────────────────────────────────────── -->
<div class="tanium-ep-grid">

    <div class="tanium-card">
        <div class="tanium-card-header"><span class="ti ti-network"></span> <?= __('Network', 'tanium') ?></div>
        <div class="tanium-card-body">
            <dl class="tanium-dl">
                <dt><?= __('IP Address', 'tanium') ?></dt>
                <dd><code><?= htmlspecialchars($asset['ip_address'] ?? '—') ?></code></dd>
                <dt><?= __('MAC Address', 'tanium') ?></dt>
                <dd><code><?= htmlspecialchars($asset['mac_address'] ?? '—') ?></code></dd>
            </dl>
        </div>
    </div>

    <div class="tanium-card">
        <div class="tanium-card-header"><span class="ti ti-brand-windows"></span> <?= __('Operating System', 'tanium') ?></div>
        <div class="tanium-card-body">
            <dl class="tanium-dl">
                <dt><?= __('Name', 'tanium') ?></dt>
                <dd><?= htmlspecialchars($asset['os_name'] ?? '—') ?></dd>
                <dt><?= __('Version', 'tanium') ?></dt>
                <dd><code><?= htmlspecialchars($asset['os_version'] ?? '—') ?></code></dd>
                <dt><?= __('Build', 'tanium') ?></dt>
                <dd><code><?= htmlspecialchars($asset['os_build'] ?? '—') ?></code></dd>
                <dt><?= __('Platform', 'tanium') ?></dt>
                <dd><?= htmlspecialchars($asset['os_platform'] ?? '—') ?></dd>
            </dl>
        </div>
    </div>

    <div class="tanium-card">
        <div class="tanium-card-header"><span class="ti ti-activity"></span> <?= __('Status', 'tanium') ?></div>
        <div class="tanium-card-body">
            <dl class="tanium-dl">
                <dt><?= __('Last seen', 'tanium') ?></dt>
                <dd><?= $asset['last_seen'] ? Html::convDateTime($asset['last_seen']) : '—' ?></dd>
                <dt><?= __('Sync status', 'tanium') ?></dt>
                <dd>
                    <span class="tanium-badge tanium-badge-<?= $asset['sync_status'] === 'ok' ? 'success' : 'error' ?>">
                        <?= htmlspecialchars($asset['sync_status']) ?>
                    </span>
                </dd>
                <dt><?= __('Virtual machine', 'tanium') ?></dt>
                <dd><?= (int)($asset['is_virtual'] ?? 0) ? __('Yes', 'tanium') : __('No', 'tanium') ?></dd>
            </dl>
        </div>
    </div>

    <?php
    // ── Security hygiene (only when the tenant provides the data) ──────
    $hasHygiene = $asset['is_encrypted'] !== null || !empty($asset['defender_healthy'])
        || !empty($asset['sccm_health']) || !empty($asset['open_ports']) || $asset['event_crashes'] !== null;
    $openPorts  = json_decode((string)($asset['open_ports'] ?? ''), true) ?: [];
    $riskyPorts = [21, 22, 23, 135, 139, 445, 3389, 5900];
    $defBad     = static function (?string $v): bool {
        $v = strtolower(trim((string)$v));
        return $v !== '' && !in_array($v, ['true', 'yes', 'healthy', '1'], true);
    };
    if ($hasHygiene): ?>
    <div class="tanium-card">
        <div class="tanium-card-header"><span class="ti ti-shield-check"></span> <?= __('Security hygiene', 'tanium') ?></div>
        <div class="tanium-card-body">
            <dl class="tanium-dl">
                <?php if ($asset['is_encrypted'] !== null): ?>
                <dt><?= __('Disk encryption', 'tanium') ?></dt>
                <dd>
                    <span class="tanium-badge tanium-badge-<?= (int)$asset['is_encrypted'] ? 'success' : 'critical' ?>">
                        <?= (int)$asset['is_encrypted'] ? __('Encrypted', 'tanium') : __('NOT encrypted', 'tanium') ?>
                    </span>
                </dd>
                <?php endif; ?>
                <?php if (!empty($asset['defender_healthy'])): ?>
                <dt>Windows Defender</dt>
                <dd>
                    <span class="tanium-badge tanium-badge-<?= $defBad($asset['defender_healthy']) ? 'critical' : 'success' ?>">
                        <?= $defBad($asset['defender_healthy']) ? __('Unhealthy', 'tanium') : __('Healthy', 'tanium') ?>
                    </span>
                    <?php if (!empty($asset['defender_sig_age'])): ?>
                        <span class="tanium-small tanium-muted"><?= __('Signatures', 'tanium') ?>: <?= htmlspecialchars($asset['defender_sig_age']) ?></span>
                    <?php endif; ?>
                </dd>
                <?php endif; ?>
                <?php if (!empty($asset['sccm_health'])): ?>
                <dt>SCCM</dt>
                <dd><?= htmlspecialchars($asset['sccm_health']) ?></dd>
                <?php endif; ?>
                <?php if ($asset['event_crashes'] !== null): ?>
                <dt><?= __('App crashes', 'tanium') ?></dt>
                <dd>
                    <span class="tanium-badge tanium-badge-<?= (int)$asset['event_crashes'] > 10 ? 'critical' : ((int)$asset['event_crashes'] > 0 ? 'warning' : 'success') ?>">
                        <?= (int)$asset['event_crashes'] ?>
                    </span>
                </dd>
                <?php endif; ?>
                <?php if ($openPorts): ?>
                <dt><?= __('Open ports', 'tanium') ?></dt>
                <dd>
                    <?php foreach (array_slice($openPorts, 0, 15) as $port): ?>
                        <span class="tanium-badge tanium-badge-<?= in_array((int)$port, $riskyPorts, true) ? 'critical' : 'muted' ?>"
                              style="font-size:.68rem;margin:1px"><?= (int)$port ?></span>
                    <?php endforeach; ?>
                    <?php if (count($openPorts) > 15): ?>
                        <span class="tanium-small tanium-muted">+<?= count($openPorts) - 15 ?></span>
                    <?php endif; ?>
                </dd>
                <?php endif; ?>
                <?php if (!empty($asset['nat_ip'])): ?>
                <dt>NAT IP</dt>
                <dd><code><?= htmlspecialchars($asset['nat_ip']) ?></code></dd>
                <?php endif; ?>
            </dl>
        </div>
    </div>
    <?php endif; ?>

    <?php $sensorData = json_decode((string)($asset['sensor_data'] ?? ''), true) ?: []; ?>
    <?php if ($sensorData): ?>
    <div class="tanium-card">
        <div class="tanium-card-header"><span class="ti ti-cpu"></span> <?= __('Custom sensors', 'tanium') ?></div>
        <div class="tanium-card-body">
            <dl class="tanium-dl">
                <?php foreach ($sensorData as $sName => $sValue): ?>
                <dt><?= htmlspecialchars($sName) ?></dt>
                <dd><?= htmlspecialchars($sValue !== '' ? $sValue : '—') ?></dd>
                <?php endforeach; ?>
            </dl>
        </div>
    </div>
    <?php endif; ?>

    <!-- CVE severity boxes -->
    <div class="tanium-card">
        <div class="tanium-card-header"><span class="ti ti-shield-exclamation"></span> <?= __('CVE Summary', 'tanium') ?></div>
        <div class="tanium-card-body">
            <div class="tanium-tab-cve-grid">
                <div class="tanium-tab-cve-box tanium-sev-critical">
                    <div class="tanium-cve-count"><?= $sevCount['critical'] ?></div>
                    <div class="tanium-cve-sev"><?= __('Critical', 'tanium') ?></div>
                </div>
                <div class="tanium-tab-cve-box tanium-sev-high">
                    <div class="tanium-cve-count"><?= $sevCount['high'] ?></div>
                    <div class="tanium-cve-sev"><?= __('High', 'tanium') ?></div>
                </div>
                <div class="tanium-tab-cve-box tanium-sev-medium">
                    <div class="tanium-cve-count"><?= $sevCount['medium'] ?></div>
                    <div class="tanium-cve-sev"><?= __('Medium', 'tanium') ?></div>
                </div>
                <div class="tanium-tab-cve-box tanium-sev-low">
                    <div class="tanium-cve-count"><?= $sevCount['low'] ?></div>
                    <div class="tanium-cve-sev"><?= __('Low', 'tanium') ?></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ── CVE table ──────────────────────────────────────────────── -->
<div class="tanium-card" style="margin-top:16px">
    <div class="tanium-card-header">
        <span class="ti ti-shield-exclamation"></span> <?= __('CVEs', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:auto;font-size:.8rem"><?= count($cves) ?> registros</span>
    </div>
    <div class="tanium-card-body tanium-p0">
        <?php if (empty($cves)): ?>
            <p class="tanium-empty"><?= __('No CVEs found for this endpoint.', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th><?= __('CVE ID', 'tanium') ?></th>
                    <th><?= __('Severity', 'tanium') ?></th>
                    <th><?= __('CVSS', 'tanium') ?></th>
                    <th><?= __('Status', 'tanium') ?></th>
                    <th><?= __('Detected', 'tanium') ?></th>
                    <th><?= __('SLA', 'tanium') ?></th>
                    <th><?= __('Actions', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($cves as $cve):
                $exRow          = $exceptions[$cve['cve_id']] ?? null;
                $hasException   = $exRow && $exRow['is_active'];
                $hasExpiredEx   = $exRow && !$exRow['is_active'];
                $hasAssignment  = isset($assignments[$cve['cve_id']]);
                $sev = strtolower($cve['severity'] ?? 'low');
                $slaDayLimit = $slaDays[$sev] ?? null;
                $detectedTs  = $cve['detected_at'] ? strtotime($cve['detected_at']) : 0;
                $slaBreached = $slaDayLimit && $detectedTs && $cve['status'] !== 'remediated' && !$hasException
                    && (time() - $detectedTs) > ($slaDayLimit * 86400);
            ?>
                <tr class="<?= $hasException ? 'tanium-row-exception' : ($slaBreached ? 'tanium-row-overdue' : '') ?>">
                    <td class="tanium-mono">
                        <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($cve['cve_id']) ?>" target="_blank" class="tanium-link">
                            <?= htmlspecialchars($cve['cve_id']) ?>
                        </a>
                        <?php if ($hasException): ?>
                        <span class="tanium-badge tanium-badge-muted" style="font-size:.65rem;margin-left:4px" title="<?= htmlspecialchars($exRow['reason']) ?>">
                            <span class="ti ti-shield-off"></span> <?= __('Exception', 'tanium') ?>
                        </span>
                        <?php elseif ($hasExpiredEx): ?>
                        <span class="tanium-badge tanium-badge-warning" style="font-size:.65rem;margin-left:4px" title="<?= htmlspecialchars($exRow['reason']) ?>">
                            <span class="ti ti-alert-triangle"></span> <?= __('Exception expired', 'tanium') ?>
                        </span>
                        <?php endif; ?>
                    </td>
                    <td><span class="tanium-badge <?= $sevClass($cve['severity']) ?>"><?= ucfirst($cve['severity']) ?></span></td>
                    <td class="tanium-center tanium-mono">
                        <?php if ($cve['cvss_score'] !== null): ?>
                        <span class="tanium-cvss tanium-cvss-<?= Vulnerability::cvssClass((float)$cve['cvss_score']) ?>">
                            <?= number_format((float)$cve['cvss_score'], 1) ?>
                        </span>
                        <?php else: ?>—<?php endif; ?>
                    </td>
                    <td>
                        <span class="tanium-badge tanium-badge-<?= $cve['status'] === 'remediated' ? 'success' : 'muted' ?>">
                            <?= htmlspecialchars($cve['status'] ?? 'open') ?>
                        </span>
                        <?php if ($hasAssignment): ?>
                        <span class="tanium-badge tanium-badge-warning" style="font-size:.65rem;margin-left:2px">
                            <span class="ti ti-user-check"></span> <?= htmlspecialchars($assignments[$cve['cve_id']]['status']) ?>
                        </span>
                        <?php endif; ?>
                    </td>
                    <td class="tanium-small"><?= $cve['detected_at'] ? Html::convDateTime($cve['detected_at']) : '—' ?></td>
                    <td>
                        <?php if ($slaBreached): ?>
                        <span class="tanium-badge tanium-badge-error" title="SLA de <?= $slaDayLimit ?> dias ultrapassado">
                            <span class="ti ti-alarm"></span> +<?= $slaDayLimit ?>d
                        </span>
                        <?php elseif ($slaDayLimit && $detectedTs && $cve['status'] !== 'remediated' && !$hasException): ?>
                        <?php $daysLeft = $slaDayLimit - round((time() - $detectedTs) / 86400); ?>
                        <span class="tanium-small tanium-muted"><?= max(0, $daysLeft) ?>d left</span>
                        <?php else: ?>
                        <span class="tanium-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td style="white-space:nowrap">
                        <button onclick="openTicketModal('<?= htmlspecialchars(addslashes($cve['cve_id'])) ?>','cve')"
                                class="tanium-btn-xs tanium-btn-primary" title="<?= __('Open ticket', 'tanium') ?>">
                            <span class="ti ti-ticket"></span>
                        </button>
                        <?php if (!$hasException): ?>
                        <button onclick="openExceptionModal('<?= htmlspecialchars(addslashes($cve['cve_id'])) ?>')"
                                class="tanium-btn-xs tanium-btn-secondary" title="<?= __('Accept risk / create exception', 'tanium') ?>">
                            <span class="ti ti-shield-off"></span>
                        </button>
                        <?php else: ?>
                        <button onclick="revokeException('<?= htmlspecialchars(addslashes($cve['cve_id'])) ?>', <?= (int)$exRow['id'] ?>)"
                                class="tanium-btn-xs tanium-btn-danger" title="<?= __('Revoke exception', 'tanium') ?>">
                            <span class="ti ti-shield-check"></span>
                        </button>
                        <?php endif; ?>
                        <button onclick="openAssignModal('<?= htmlspecialchars(addslashes($cve['cve_id'])) ?>')"
                                class="tanium-btn-xs tanium-btn-secondary" title="<?= __('Assign to user', 'tanium') ?>">
                            <span class="ti ti-user-plus"></span>
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<!-- ── Missing patches table ──────────────────────────────────── -->
<div class="tanium-card" style="margin-top:16px">
    <div class="tanium-card-header">
        <span class="ti ti-shield-check"></span> <?= __('Missing Patches', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:auto;font-size:.8rem"><?= count($patches) ?> registros</span>
    </div>
    <div class="tanium-card-body tanium-p0">
        <?php if (empty($patches)): ?>
            <p class="tanium-empty"><?= __('No missing patches recorded. Excellent!', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th><?= __('Patch / Title', 'tanium') ?></th>
                    <th><?= __('KB', 'tanium') ?></th>
                    <th><?= __('Severity', 'tanium') ?></th>
                    <th><?= __('Release', 'tanium') ?></th>
                    <th><?= __('Actions', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($patches as $patch): ?>
                <tr>
                    <td class="tanium-small"><?= htmlspecialchars(substr($patch['patch_title'] ?: $patch['patch_id'], 0, 80)) ?></td>
                    <td class="tanium-mono tanium-small"><?= htmlspecialchars($patch['kb_id'] ?? '—') ?></td>
                    <td><span class="tanium-badge <?= $sevClass($patch['severity']) ?>"><?= ucfirst($patch['severity']) ?></span></td>
                    <td class="tanium-small"><?= $patch['release_date'] ?? '—' ?></td>
                    <td>
                        <button onclick="openTicketModal('<?= htmlspecialchars(addslashes($patch['patch_id'])) ?>','patch')"
                                class="tanium-btn-xs tanium-btn-primary" title="<?= __('Open ticket', 'tanium') ?>">
                            <span class="ti ti-ticket"></span>
                        </button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<?php
// ── Compliance (Tanium Comply benchmarks) — shown only when data exists ──
$complyScore = \GlpiPlugin\Tanium\Compliance::scoreForEndpoint($eid);
if ($complyScore !== null):
    $complyFailed = \GlpiPlugin\Tanium\Compliance::failedRules($eid, 15);
    $complyColor  = $complyScore >= 90 ? '#1eb464' : ($complyScore >= 70 ? '#e8c42a' : '#e8212a');
?>
<!-- ── Compliance benchmarks ──────────────────────────────────── -->
<div class="tanium-card" style="margin-top:16px">
    <div class="tanium-card-header">
        <span class="ti ti-checklist"></span> <?= __('Compliance benchmarks (Tanium Comply)', 'tanium') ?>
        <span style="margin-left:auto;font-weight:800;color:<?= $complyColor ?>"><?= $complyScore ?>%</span>
    </div>
    <div class="tanium-card-body tanium-p0">
        <?php if (empty($complyFailed)): ?>
            <p class="tanium-empty"><?= __('All benchmark checks pass on this endpoint.', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th><?= __('Benchmark', 'tanium') ?></th>
                    <th><?= __('Failed rule', 'tanium') ?></th>
                    <th><?= __('Severity', 'tanium') ?></th>
                    <th><?= __('Checked', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($complyFailed as $cr): ?>
                <tr>
                    <td class="tanium-small"><?= htmlspecialchars($cr['benchmark'] ?: '—') ?></td>
                    <td class="tanium-small"><?= htmlspecialchars(substr($cr['rule_title'], 0, 100)) ?></td>
                    <td><span class="tanium-badge <?= $sevClass($cr['severity']) ?>"><?= ucfirst($cr['severity']) ?></span></td>
                    <td class="tanium-small"><?= $cr['checked_at'] ? Html::convDateTime($cr['checked_at']) : '—' ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>
<?php endif; ?>

<!-- ── Ticket modal ───────────────────────────────────────────── -->
<div id="tanium-ticket-modal" class="tanium-modal-overlay" style="display:none">
    <div class="tanium-modal">
        <div class="tanium-modal-header">
            <span class="ti ti-ticket"></span> <?= __('Open GLPI Ticket', 'tanium') ?>
            <button onclick="closeTicketModal()" class="tanium-modal-close">✕</button>
        </div>
        <form method="post" action="<?= $webDir ?>/ajax/ticket.php">
            <input type="hidden" name="_glpi_csrf_token" value="<?= Session::getNewCSRFToken() ?>">
            <input type="hidden" name="tanium_eid"    value="<?= htmlspecialchars($eid) ?>">
            <input type="hidden" name="computers_id"  value="<?= (int)($asset['computers_id'] ?? 0) ?>">
            <input type="hidden" id="ticket-ref-id"   name="ref_id"   value="">
            <input type="hidden" id="ticket-ref-type" name="ref_type" value="">

            <div class="tanium-modal-body">
                <label class="tanium-form-label"><?= __('Title', 'tanium') ?></label>
                <input type="text" name="title" id="ticket-title" class="tanium-input" style="width:100%" required>

                <label class="tanium-form-label" style="margin-top:12px"><?= __('Category', 'tanium') ?></label>
                <select name="itilcategories_id" class="tanium-input tanium-select" style="width:100%">
                    <option value="0"><?= __('(no category)', 'tanium') ?></option>
                    <?php
                    // Same list the native ticket form offers: ITIL categories
                    // enabled for incidents, visible in the active entities,
                    // hierarchical (parent > child) via completename.
                    foreach ($DB->request([
                        'SELECT' => ['id', 'completename'],
                        'FROM'   => 'glpi_itilcategories',
                        'WHERE'  => ['is_incident' => 1]
                            + getEntitiesRestrictCriteria('glpi_itilcategories', '', '', true),
                        'ORDER'  => 'completename ASC',
                    ]) as $cat): ?>
                    <option value="<?= (int)$cat['id'] ?>"><?= htmlspecialchars($cat['completename']) ?></option>
                    <?php endforeach; ?>
                </select>

                <label class="tanium-form-label" style="margin-top:12px"><?= __('Priority', 'tanium') ?></label>
                <select name="priority" class="tanium-input tanium-select" style="width:100%">
                    <option value="5">5 — <?= __('Very High', 'tanium') ?></option>
                    <option value="4">4 — <?= __('High', 'tanium') ?></option>
                    <option value="3" selected>3 — <?= __('Medium', 'tanium') ?></option>
                    <option value="2">2 — <?= __('Low', 'tanium') ?></option>
                    <option value="1">1 — <?= __('Very Low', 'tanium') ?></option>
                </select>

                <label class="tanium-form-label" style="margin-top:12px"><?= __('Description', 'tanium') ?></label>
                <textarea name="content" id="ticket-content" class="tanium-input" rows="6" style="width:100%"></textarea>
            </div>

            <div class="tanium-modal-footer">
                <button type="button" onclick="closeTicketModal()" class="tanium-btn tanium-btn-secondary"><?= __('Cancel', 'tanium') ?></button>
                <button type="submit" class="tanium-btn tanium-btn-primary">
                    <span class="ti ti-send"></span> <?= __('Create ticket', 'tanium') ?>
                </button>
            </div>
        </form>
    </div>
</div>

<!-- ── CVE History ─────────────────────────────────────────────── -->
<?php if (!empty($cveHistory)): ?>
<div class="tanium-card" style="margin-top:16px">
    <div class="tanium-card-header">
        <span class="ti ti-history"></span> <?= __('CVE Status History', 'tanium') ?>
        <span class="tanium-muted" style="margin-left:auto;font-size:.8rem"><?= __('Last 20 changes', 'tanium') ?></span>
    </div>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead><tr><th>CVE ID</th><th><?= __('From', 'tanium') ?></th><th><?= __('To', 'tanium') ?></th><th><?= __('When', 'tanium') ?></th></tr></thead>
        <tbody>
        <?php foreach ($cveHistory as $h): ?>
        <tr>
            <td class="tanium-mono"><a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($h['cve_id']) ?>" target="_blank" class="tanium-link"><?= htmlspecialchars($h['cve_id']) ?></a></td>
            <td><span class="tanium-badge tanium-badge-muted"><?= htmlspecialchars($h['old_status'] ?? 'new') ?></span></td>
            <td><span class="tanium-badge tanium-badge-<?= $h['new_status'] === 'remediated' ? 'success' : 'warning' ?>"><?= htmlspecialchars($h['new_status']) ?></span></td>
            <td class="tanium-small"><?= Html::convDateTime($h['changed_at']) ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
</div>
<?php endif; ?>

<!-- ── Exception modal ─────────────────────────────────────────── -->
<div id="tanium-exception-modal" class="tanium-modal-overlay" style="display:none">
    <div class="tanium-modal">
        <div class="tanium-modal-header">
            <span class="ti ti-shield-off"></span> <?= __('Accept Risk — CVE Exception', 'tanium') ?>
            <button onclick="document.getElementById('tanium-exception-modal').style.display='none'" class="tanium-modal-close">✕</button>
        </div>
        <div class="tanium-modal-body">
            <input type="hidden" id="exc-cve-id" value="">
            <label class="tanium-form-label"><?= __('CVE ID', 'tanium') ?></label>
            <input type="text" id="exc-cve-display" class="tanium-input" style="width:100%" readonly>

            <label class="tanium-form-label" style="margin-top:12px"><?= __('Reason / Justification', 'tanium') ?> <span style="color:#e8212a">*</span></label>
            <textarea id="exc-reason" class="tanium-input" rows="4" style="width:100%" placeholder="<?= __('Describe why this CVE is accepted as risk (e.g. mitigating controls in place, not exploitable in this environment)', 'tanium') ?>"></textarea>

            <label class="tanium-form-label" style="margin-top:12px"><?= __('Expiry date (optional)', 'tanium') ?></label>
            <input type="date" id="exc-expires" class="tanium-input" style="width:200px" min="<?= date('Y-m-d') ?>">
        </div>
        <div class="tanium-modal-footer">
            <button onclick="document.getElementById('tanium-exception-modal').style.display='none'" class="tanium-btn tanium-btn-secondary"><?= __('Cancel', 'tanium') ?></button>
            <button onclick="submitException()" class="tanium-btn tanium-btn-primary">
                <span class="ti ti-shield-off"></span> <?= __('Accept Risk', 'tanium') ?>
            </button>
        </div>
    </div>
</div>

<!-- ── Assignment modal ────────────────────────────────────────── -->
<div id="tanium-assign-modal" class="tanium-modal-overlay" style="display:none">
    <div class="tanium-modal">
        <div class="tanium-modal-header">
            <span class="ti ti-user-plus"></span> <?= __('Assign CVE for Remediation', 'tanium') ?>
            <button onclick="document.getElementById('tanium-assign-modal').style.display='none'" class="tanium-modal-close">✕</button>
        </div>
        <div class="tanium-modal-body">
            <input type="hidden" id="asgn-cve-id" value="">
            <label class="tanium-form-label"><?= __('CVE ID', 'tanium') ?></label>
            <input type="text" id="asgn-cve-display" class="tanium-input" style="width:100%" readonly>

            <label class="tanium-form-label" style="margin-top:12px"><?= __('Assign to', 'tanium') ?></label>
            <select id="asgn-user" class="tanium-input tanium-select" style="width:100%">
                <option value="0"><?= __('— select user —', 'tanium') ?></option>
                <?php foreach ($glpiUsers as $u): ?>
                <option value="<?= (int)$u['id'] ?>"><?= htmlspecialchars($u['name']) ?></option>
                <?php endforeach; ?>
            </select>

            <label class="tanium-form-label" style="margin-top:12px"><?= __('Due date', 'tanium') ?></label>
            <input type="date" id="asgn-due" class="tanium-input" style="width:200px" min="<?= date('Y-m-d') ?>">

            <label class="tanium-form-label" style="margin-top:12px"><?= __('Notes', 'tanium') ?></label>
            <textarea id="asgn-notes" class="tanium-input" rows="3" style="width:100%" placeholder="<?= __('Remediation notes or instructions', 'tanium') ?>"></textarea>
        </div>
        <div class="tanium-modal-footer">
            <button onclick="document.getElementById('tanium-assign-modal').style.display='none'" class="tanium-btn tanium-btn-secondary"><?= __('Cancel', 'tanium') ?></button>
            <button onclick="submitAssignment()" class="tanium-btn tanium-btn-primary">
                <span class="ti ti-user-check"></span> <?= __('Assign', 'tanium') ?>
            </button>
        </div>
    </div>
</div>

</div><!-- .tanium-page-wrap -->

<script>
const _webDir = <?= json_encode($webDir) ?>;
const _eid    = <?= json_encode($eid) ?>;
const _csrf   = <?= json_encode(Session::getNewCSRFToken()) ?>;

// Remote actions (approval-gated)
function requestRemoteAction(action) {
    const labels = {
        quarantine:     'QUARENTENA DE REDE (isolar o endpoint)',
        restart_client: 'reinício do Tanium Client'
    };
    if (!confirm('Abrir chamado de aprovação para ' + (labels[action] || action) +
                 '?\n\nA ação só é executada no Tanium depois que a aprovação for aceita.')) {
        return;
    }
    fetch(_webDir + '/ajax/remote_action.php', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({eid: _eid, action: action})
    }).then(r => r.json()).then(d => {
        if (d.success) {
            alert(d.message || ('Chamado #' + d.ticket_id + ' criado.'));
            window.open(d.ticket_url, '_blank');
        } else {
            alert(d.error || 'Error');
        }
    });
}

// Exception modal
function openExceptionModal(cveId) {
    document.getElementById('exc-cve-id').value      = cveId;
    document.getElementById('exc-cve-display').value = cveId;
    document.getElementById('exc-reason').value      = '';
    document.getElementById('exc-expires').value     = '';
    document.getElementById('tanium-exception-modal').style.display = 'flex';
}
function revokeException(cveId, exId) {
    if (!confirm('Revogar esta exceção? O CVE voltará a ser tratado como ativo.')) return;
    fetch(_webDir + '/ajax/exception.php', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({action: 'delete', id: exId})
    }).then(r => r.json()).then(d => { if (d.success) location.reload(); else alert(d.error||'Error'); });
}
function submitException() {
    const reason = document.getElementById('exc-reason').value.trim();
    if (!reason) { alert('Por favor informe a justificativa.'); return; }
    fetch(_webDir + '/ajax/exception.php', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({
            action: 'create',
            tanium_eid: _eid,
            cve_id: document.getElementById('exc-cve-id').value,
            reason: reason,
            expires_at: document.getElementById('exc-expires').value || ''
        })
    }).then(r => r.json()).then(d => { if (d.success) location.reload(); else alert(d.error||'Error'); });
}

// Assignment modal
function openAssignModal(cveId) {
    document.getElementById('asgn-cve-id').value      = cveId;
    document.getElementById('asgn-cve-display').value = cveId;
    document.getElementById('asgn-notes').value       = '';
    document.getElementById('asgn-due').value         = '';
    document.getElementById('asgn-user').value        = '0';
    document.getElementById('tanium-assign-modal').style.display = 'flex';
}
function submitAssignment() {
    fetch(_webDir + '/ajax/assign.php', {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify({
            action: 'create',
            tanium_eid: _eid,
            cve_id: document.getElementById('asgn-cve-id').value,
            assigned_to: parseInt(document.getElementById('asgn-user').value),
            due_date: document.getElementById('asgn-due').value || '',
            notes: document.getElementById('asgn-notes').value,
            ref_type: 'cve'
        })
    }).then(r => r.json()).then(d => { if (d.success) location.reload(); else alert(d.error||'Error'); });
}

function openTicketModal(refId, refType) {
    refId   = refId   || '';
    refType = refType || '';

    document.getElementById('ticket-ref-id').value   = refId;
    document.getElementById('ticket-ref-type').value = refType;

    const epName = <?= json_encode($asset['tanium_name']) ?>;

    let title   = '';
    let content = '';

    if (refType === 'cve') {
        title   = '[Tanium] CVE ' + refId + ' — ' + epName;
        content = 'A vulnerabilidade ' + refId + ' foi detectada pelo Tanium no endpoint ' + epName + '.\n\n'
                + 'Endpoint EID: <?= htmlspecialchars($eid) ?>\n'
                + 'IP: <?= htmlspecialchars($asset['ip_address'] ?? '') ?>\n'
                + 'OS: <?= htmlspecialchars($asset['os_name'] ?? '') ?>\n\n'
                + 'Referência NVD: https://nvd.nist.gov/vuln/detail/' + refId + '\n\n'
                + 'Por favor, aplique o patch/mitigação adequada.';
    } else if (refType === 'patch') {
        title   = '[Tanium] Patch ausente: ' + refId + ' — ' + epName;
        content = 'O patch ' + refId + ' está faltando no endpoint ' + epName + '.\n\n'
                + 'Endpoint EID: <?= htmlspecialchars($eid) ?>\n'
                + 'IP: <?= htmlspecialchars($asset['ip_address'] ?? '') ?>\n'
                + 'OS: <?= htmlspecialchars($asset['os_name'] ?? '') ?>\n\n'
                + 'Por favor, aplique o patch o mais breve possível.';
    } else {
        title   = '[Tanium] Problema de segurança — ' + epName;
        content = 'Endpoint detectado pelo Tanium com problema de segurança.\n\n'
                + 'Endpoint: ' + epName + '\n'
                + 'EID: <?= htmlspecialchars($eid) ?>\n'
                + 'IP: <?= htmlspecialchars($asset['ip_address'] ?? '') ?>\n'
                + 'Risk Score: <?= $riskScore ?>/100'
                + <?= json_encode($cveListText) ?>;
    }

    document.getElementById('ticket-title').value   = title;
    document.getElementById('ticket-content').value = content;
    document.getElementById('tanium-ticket-modal').style.display = 'flex';
}

function closeTicketModal() {
    document.getElementById('tanium-ticket-modal').style.display = 'none';
}

document.getElementById('tanium-ticket-modal').addEventListener('click', function(e) {
    if (e.target === this) closeTicketModal();
});
</script>
<?php
Html::footer();
