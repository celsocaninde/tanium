<?php

/**
 * Tanium — Branded Security Report (print-ready, SVG charts, no external deps).
 * ?eid=<eid>  → endpoint report
 * (no params) → global security report
 */

use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');

Session::checkRight('config', READ);

global $DB, $CFG_GLPI;

$eid    = $_GET['eid'] ?? '';
$mode   = $eid ? 'endpoint' : 'global';
$webDir = Plugin::getWebDir('tanium');
$logo   = $webDir . '/public/img/tanium-logo.svg';
$now    = date('d/m/Y H:i');

// ── SVG helpers ───────────────────────────────────────────────────────────────

function svgPie(array $slices, int $size = 140): string {
    $total = array_sum(array_column($slices, 'value'));
    if ($total <= 0) {
        return "<svg width='{$size}' height='{$size}'><circle cx='" . ($size/2) . "' cy='" . ($size/2) . "' r='" . ($size/2 - 4) . "' fill='#e5e7eb'/><text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#9ca3af' font-size='11'>N/A</text></svg>";
    }

    $cx = $size / 2; $cy = $size / 2; $r = $size / 2 - 6;
    $paths   = '';
    $angle   = -90.0;

    foreach ($slices as $slice) {
        $pct   = $slice['value'] / $total;
        $sweep = $pct * 360;
        if ($sweep < 0.5) continue;

        $startRad = deg2rad($angle);
        $endRad   = deg2rad($angle + $sweep);
        $x1 = round($cx + $r * cos($startRad), 3);
        $y1 = round($cy + $r * sin($startRad), 3);
        $x2 = round($cx + $r * cos($endRad),   3);
        $y2 = round($cy + $r * sin($endRad),   3);
        $large = $sweep > 180 ? 1 : 0;

        $paths .= "<path d='M{$cx},{$cy} L{$x1},{$y1} A{$r},{$r} 0 {$large},1 {$x2},{$y2} Z' fill='{$slice['color']}' stroke='#fff' stroke-width='1.5'/>";
        $angle += $sweep;
    }

    return "<svg width='{$size}' height='{$size}' viewBox='0 0 {$size} {$size}'>{$paths}</svg>";
}

function svgBar(array $bars, int $w = 380, int $h = 120): string {
    if (empty($bars)) return '';
    $max    = max(array_column($bars, 'value')) ?: 1;
    $count  = count($bars);
    $bw     = max(8, (int)(($w - 20) / $count) - 4);
    $gap    = (int)(($w - 20 - $bw * $count) / max(1, $count));
    $svg    = "<svg width='{$w}' height='{$h}' viewBox='0 0 {$w} {$h}' style='overflow:visible'>";
    $x      = 10;

    foreach ($bars as $bar) {
        $bh    = (int)(($bar['value'] / $max) * ($h - 28));
        $bh    = max(2, $bh);
        $by    = $h - 20 - $bh;
        $label = htmlspecialchars(mb_strimwidth($bar['label'], 0, 8, '…'));

        $svg .= "<rect x='{$x}' y='{$by}' width='{$bw}' height='{$bh}' rx='3' fill='{$bar['color']}'/>";
        $svg .= "<text x='" . ($x + $bw/2) . "' y='" . ($h - 6) . "' text-anchor='middle' font-size='9' fill='#9ca3af'>{$label}</text>";
        if ($bar['value'] > 0) {
            $svg .= "<text x='" . ($x + $bw/2) . "' y='" . ($by - 3) . "' text-anchor='middle' font-size='9' fill='#374151' font-weight='bold'>{$bar['value']}</text>";
        }
        $x += $bw + $gap + 2;
    }
    $svg .= "</svg>";
    return $svg;
}

function riskColor(int $s): string {
    if ($s >= 70) return '#e8212a';
    if ($s >= 40) return '#f97316';
    if ($s >= 15) return '#f59e0b';
    return '#22c55e';
}

function sevBg(string $s): string {
    return match (strtolower($s)) { 'critical' => '#e8212a', 'high' => '#f97316', 'medium' => '#f59e0b', 'low' => '#22c55e', default => '#9ca3af' };
}

// ── Data ──────────────────────────────────────────────────────────────────────

if ($mode === 'endpoint') {
    $asset = $DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();
    if (!$asset) { Html::displayErrorAndDie('Endpoint not found.'); }

    $cves = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_endpoint_cves', 'WHERE' => ['tanium_eid' => $eid], 'ORDER' => 'cvss_score DESC']) as $r) { $cves[] = $r; }

    $patches = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'], 'ORDER' => ['severity ASC', 'release_date DESC']]) as $r) { $patches[] = $r; }

    $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($cves as $c) { $s = strtolower($c['severity']); if (isset($sev[$s])) $sev[$s]++; }

    $rs       = (int)($asset['risk_score'] ?? 0);
    $reportTitle = 'Relatório de Segurança — ' . $asset['tanium_name'];

} else {
    $config       = $DB->request(['FROM' => 'glpi_plugin_tanium_configs', 'LIMIT' => 1])->current() ?? [];
    $totalEp      = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_assets',          'COUNT' => 'id'])->current()['cpt'] ?? 0);
    $totalCve     = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_vulnerabilities',  'COUNT' => 'id'])->current()['cpt'] ?? 0);
    $totalMissing = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['status' => 'missing'], 'COUNT' => 'id'])->current()['cpt'] ?? 0);
    $totalPatches = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_patches',          'COUNT' => 'id'])->current()['cpt'] ?? 0);
    $compliance   = $totalPatches > 0 ? round(($totalPatches - $totalMissing) / $totalPatches * 100) : null;

    $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_vulnerabilities']) as $r) { $s = strtolower($r['severity']); if (isset($sev[$s])) $sev[$s]++; }

    // Risk distribution
    $riskDist = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    $riskSum  = 0; $riskN = 0;
    foreach ($DB->request(['SELECT' => ['risk_score'], 'FROM' => 'glpi_plugin_tanium_assets']) as $r) {
        $rs = (int)$r['risk_score']; $riskSum += $rs; $riskN++;
        if ($rs >= 70)     $riskDist['critical']++;
        elseif ($rs >= 40) $riskDist['high']++;
        elseif ($rs >= 15) $riskDist['medium']++;
        else               $riskDist['low']++;
    }
    $avgRisk = $riskN > 0 ? round($riskSum / $riskN) : 0;

    // OS distribution
    $osDist = [];
    foreach ($DB->request(['SELECT' => ['os_name', 'COUNT' => 'id AS cnt'], 'FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['NOT' => ['os_name' => null]], 'GROUPBY' => 'os_name', 'ORDER' => 'cnt DESC', 'LIMIT' => 8]) as $r) {
        $osDist[$r['os_name']] = (int)$r['cnt'];
    }

    // Top 20 CVEs
    $topCves = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_vulnerabilities', 'ORDER' => ['cvss_score DESC', 'affected_count DESC'], 'LIMIT' => 20]) as $r) { $topCves[] = $r; }

    // Top 15 risky endpoints
    $topEndpoints = [];
    foreach ($DB->doQuery("SELECT tanium_eid,tanium_name,ip_address,os_name,risk_score,last_seen FROM glpi_plugin_tanium_assets ORDER BY risk_score DESC LIMIT 15") as $r) { $topEndpoints[] = $r; }

    // Top 10 most-missing patches
    $topPatches = [];
    $sql = "SELECT patch_id, patch_title, severity, COUNT(*) AS missing_count
            FROM glpi_plugin_tanium_patches WHERE status='missing'
            GROUP BY patch_id, patch_title, severity
            ORDER BY missing_count DESC LIMIT 10";
    foreach ($DB->doQuery($sql) as $r) { $topPatches[] = $r; }

    // Compliance by OS
    $osCmp = [];
    $sql2  = "SELECT os_name,
                     SUM(CASE WHEN p.status='missing' THEN 1 ELSE 0 END) AS missing,
                     COUNT(*) AS total
              FROM glpi_plugin_tanium_patches p
              JOIN glpi_plugin_tanium_assets a ON p.tanium_eid = a.tanium_eid
              WHERE a.os_name IS NOT NULL
              GROUP BY a.os_name ORDER BY missing DESC LIMIT 10";
    foreach ($DB->doQuery($sql2) as $r) { $osCmp[] = $r; }

    $reportTitle = 'Relatório Global de Segurança — Tanium';
}

header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title><?= htmlspecialchars($reportTitle) ?></title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;font-size:13px;color:#111827;background:#fff}
a{color:#e8212a;text-decoration:none}
code{font-family:'Courier New',monospace;font-size:11px;background:#f3f4f6;padding:1px 5px;border-radius:3px}
.page{max-width:1120px;margin:0 auto;padding:32px 28px}
@media print{
  body{font-size:11px}.page{padding:0;max-width:100%}.no-print{display:none!important}
  .page-break{page-break-before:always}.avoid-break{page-break-inside:avoid}
}
/* Header */
.rh{display:flex;align-items:flex-start;justify-content:space-between;padding-bottom:18px;margin-bottom:24px;border-bottom:4px solid #e8212a}
.rh-logo{height:40px}
.rh-right{text-align:right}
.rh-right h1{font-size:17px;font-weight:800;color:#111827}
.rh-right p{font-size:11px;color:#6b7280;margin-top:4px}
/* Section title */
.sec{font-size:12px;font-weight:700;color:#e8212a;text-transform:uppercase;letter-spacing:.07em;
     border-left:3px solid #e8212a;padding-left:8px;margin:24px 0 10px}
/* KPI row */
.krow{display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap}
.kcard{flex:1;min-width:110px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;text-align:center}
.kcard.red   {border-top:3px solid #e8212a}.kcard.orange{border-top:3px solid #f97316}
.kcard.amber {border-top:3px solid #f59e0b}.kcard.green {border-top:3px solid #22c55e}
.kcard.blue  {border-top:3px solid #3b82f6}.kcard.navy  {border-top:3px solid #1a1a2e}
.kval{font-size:28px;font-weight:800;line-height:1}.klbl{font-size:10px;color:#6b7280;margin-top:3px}
/* Risk gauge */
.gauge-row{display:flex;align-items:center;gap:12px;margin:8px 0}
.gauge-bar{flex:1;background:#e5e7eb;border-radius:99px;height:10px;overflow:hidden}
.gauge-fill{height:100%;border-radius:99px}
/* Charts row */
.chart-row{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:18px}
.chart-box{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;flex:1;min-width:200px}
.chart-box h3{font-size:11px;font-weight:700;color:#e8212a;text-transform:uppercase;margin-bottom:10px}
.legend{font-size:11px;color:#374151;margin-top:8px}
.ld{display:inline-flex;align-items:center;gap:4px;margin-right:10px;margin-bottom:3px}
.ldot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
/* Tables */
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}
thead th{background:#1a1a2e;color:#fff;padding:6px 10px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.04em}
tbody tr:nth-child(even){background:#f9fafb}
tbody td{padding:5px 10px;border-bottom:1px solid #e5e7eb;vertical-align:middle}
.mono{font-family:'Courier New',monospace;font-size:11px}
/* Severity badge */
.sev{display:inline-block;padding:2px 7px;border-radius:99px;font-size:10px;font-weight:700;color:#fff;text-transform:uppercase}
/* Info grid */
.igrid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
.ibox{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px}
.ibox h3{font-size:10px;font-weight:700;color:#e8212a;text-transform:uppercase;margin-bottom:8px}
.irow{display:flex;gap:8px;margin-bottom:4px;font-size:12px}
.ilbl{color:#6b7280;min-width:100px;flex-shrink:0}
/* Risk stacked */
.stacked{display:flex;height:18px;border-radius:5px;overflow:hidden;gap:2px;margin:8px 0}
.seg{display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#fff;min-width:16px}
/* Footer */
.rfooter{margin-top:36px;padding-top:14px;border-top:1px solid #e5e7eb;display:flex;justify-content:space-between;color:#9ca3af;font-size:10px}
/* Print button */
.pbtn{position:fixed;top:18px;right:18px;background:#e8212a;color:#fff;border:none;padding:9px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:700;box-shadow:0 2px 8px rgba(232,33,42,.3);z-index:1000}
.pbtn:hover{background:#c41a22}
</style>
</head>
<body>
<button class="pbtn no-print" onclick="window.print()">🖨 Imprimir / PDF</button>
<div class="page">

<!-- ── Header ── -->
<div class="rh">
  <img src="<?= htmlspecialchars($logo) ?>" alt="Tanium" class="rh-logo">
  <div class="rh-right">
    <h1><?= htmlspecialchars($reportTitle) ?></h1>
    <p>Gerado em <?= $now ?> &nbsp;|&nbsp; GLPI + Tanium Security Integration</p>
  </div>
</div>

<?php if ($mode === 'endpoint'): ?>
<!-- ════════════ ENDPOINT REPORT ════════════ -->

<div class="sec">Informações do Endpoint</div>
<div class="igrid">
  <div class="ibox">
    <h3>Identificação</h3>
    <div class="irow"><span class="ilbl">Nome:</span><strong><?= htmlspecialchars($asset['tanium_name']) ?></strong></div>
    <div class="irow"><span class="ilbl">EID:</span><code><?= htmlspecialchars($eid) ?></code></div>
    <div class="irow"><span class="ilbl">Virtual:</span><?= (int)($asset['is_virtual'] ?? 0) ? 'Sim' : 'Não' ?></div>
    <div class="irow"><span class="ilbl">Último acesso:</span><?= $asset['last_seen'] ? date('d/m/Y H:i', strtotime($asset['last_seen'])) : '—' ?></div>
  </div>
  <div class="ibox">
    <h3>Rede</h3>
    <div class="irow"><span class="ilbl">IP:</span><code><?= htmlspecialchars($asset['ip_address'] ?? '—') ?></code></div>
    <div class="irow"><span class="ilbl">MAC:</span><code><?= htmlspecialchars($asset['mac_address'] ?? '—') ?></code></div>
  </div>
  <div class="ibox">
    <h3>Sistema Operacional</h3>
    <div class="irow"><span class="ilbl">Nome:</span><?= htmlspecialchars($asset['os_name'] ?? '—') ?></div>
    <div class="irow"><span class="ilbl">Versão:</span><code><?= htmlspecialchars($asset['os_version'] ?? '—') ?></code></div>
    <div class="irow"><span class="ilbl">Build:</span><code><?= htmlspecialchars($asset['os_build'] ?? '—') ?></code></div>
  </div>
  <div class="ibox">
    <h3>Risco</h3>
    <div class="irow"><span class="ilbl">Risk Score:</span>
      <strong style="color:<?= riskColor($rs) ?>;font-size:22px"><?= $rs ?>/100</strong>
    </div>
    <div class="gauge-row">
      <div class="gauge-bar"><div class="gauge-fill" style="width:<?= $rs ?>%;background:<?= riskColor($rs) ?>"></div></div>
    </div>
    <div class="irow"><span class="ilbl">CVEs críticos:</span><strong style="color:#e8212a"><?= $sev['critical'] ?></strong></div>
    <div class="irow"><span class="ilbl">Patches ausentes:</span><strong style="color:#f97316"><?= count($patches) ?></strong></div>
  </div>
</div>

<div class="sec">Distribuição de CVEs</div>
<div class="chart-row avoid-break">
  <div class="chart-box" style="max-width:180px;text-align:center">
    <?= svgPie([
        ['value' => $sev['critical'], 'color' => '#e8212a'],
        ['value' => $sev['high'],     'color' => '#f97316'],
        ['value' => $sev['medium'],   'color' => '#f59e0b'],
        ['value' => $sev['low'],      'color' => '#22c55e'],
    ]) ?>
    <div class="legend">
      <span class="ld"><span class="ldot" style="background:#e8212a"></span>Crítico (<?= $sev['critical'] ?>)</span>
      <span class="ld"><span class="ldot" style="background:#f97316"></span>Alto (<?= $sev['high'] ?>)</span>
      <span class="ld"><span class="ldot" style="background:#f59e0b"></span>Médio (<?= $sev['medium'] ?>)</span>
      <span class="ld"><span class="ldot" style="background:#22c55e"></span>Baixo (<?= $sev['low'] ?>)</span>
    </div>
  </div>
  <div class="chart-box">
    <h3>Resumo</h3>
    <div class="krow">
      <div class="kcard red">  <div class="kval" style="color:#e8212a"><?= $sev['critical'] ?></div><div class="klbl">Crítico</div></div>
      <div class="kcard orange"><div class="kval" style="color:#f97316"><?= $sev['high'] ?></div><div class="klbl">Alto</div></div>
      <div class="kcard amber"><div class="kval" style="color:#f59e0b"><?= $sev['medium'] ?></div><div class="klbl">Médio</div></div>
      <div class="kcard green"><div class="kval" style="color:#22c55e"><?= $sev['low'] ?></div><div class="klbl">Baixo</div></div>
      <div class="kcard blue"><div class="kval" style="color:#3b82f6"><?= count($cves) ?></div><div class="klbl">Total</div></div>
    </div>
  </div>
</div>

<?php if (!empty($cves)): ?>
<div class="sec">Lista de CVEs</div>
<table class="avoid-break">
  <thead><tr><th>CVE ID</th><th>Severidade</th><th>CVSS</th><th>Status</th><th>Detectado</th></tr></thead>
  <tbody>
  <?php foreach ($cves as $c): $s = strtolower($c['severity']); ?>
  <tr>
    <td class="mono"><?= htmlspecialchars($c['cve_id']) ?></td>
    <td><span class="sev" style="background:<?= sevBg($c['severity']) ?>"><?= ucfirst($s) ?></span></td>
    <td class="mono"><?= $c['cvss_score'] !== null ? number_format((float)$c['cvss_score'],1) : '—' ?></td>
    <td><?= htmlspecialchars($c['status'] ?? 'open') ?></td>
    <td><?= $c['detected_at'] ? date('d/m/Y', strtotime($c['detected_at'])) : '—' ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($patches)): ?>
<div class="sec page-break">Patches Ausentes</div>
<table class="avoid-break">
  <thead><tr><th>Patch / Título</th><th>KB</th><th>Severidade</th><th>Lançamento</th></tr></thead>
  <tbody>
  <?php foreach ($patches as $p): ?>
  <tr>
    <td><?= htmlspecialchars(substr($p['patch_title'] ?: $p['patch_id'], 0, 80)) ?></td>
    <td class="mono"><?= htmlspecialchars($p['kb_id'] ?? '—') ?></td>
    <td><span class="sev" style="background:<?= sevBg($p['severity']) ?>"><?= ucfirst($p['severity']) ?></span></td>
    <td><?= $p['release_date'] ?? '—' ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php else: ?>
<!-- ════════════ GLOBAL REPORT ════════════ -->

<div class="sec">Visão Geral da Organização</div>
<div class="krow">
  <div class="kcard blue"> <div class="kval" style="color:#3b82f6"><?= number_format($totalEp) ?></div>     <div class="klbl">Endpoints</div></div>
  <div class="kcard blue"> <div class="kval" style="color:#3b82f6"><?= number_format($totalCve) ?></div>    <div class="klbl">CVEs únicos</div></div>
  <div class="kcard red">  <div class="kval" style="color:#e8212a"><?= number_format($sev['critical']) ?></div><div class="klbl">CVEs críticos</div></div>
  <div class="kcard orange"><div class="kval" style="color:#f97316"><?= number_format($totalMissing) ?></div><div class="klbl">Patches ausentes</div></div>
  <?php
  $compDisplay = $compliance !== null ? $compliance . '%' : 'N/A';
  $compClass   = $compliance === null ? 'blue' : ($compliance >= 90 ? 'green' : ($compliance >= 70 ? 'amber' : 'red'));
  $cc          = $compliance !== null ? riskColor(100 - $compliance) : '#7a8da8';
  ?>
  <div class="kcard <?= $compClass ?>">
    <div class="kval" style="color:<?= $cc ?>"><?= $compDisplay ?></div><div class="klbl">Compliance</div>
  </div>
  <?php $ac = riskColor($avgRisk); ?>
  <div class="kcard navy"><div class="kval" style="color:<?= $ac ?>"><?= $avgRisk ?></div><div class="klbl">Risk Score médio</div></div>
</div>

<!-- Risk overview bar -->
<?php if ($totalEp > 0):
    $pct = fn($n) => max(0, round($n/$totalEp*100));
?>
<div style="margin-bottom:18px">
  <div style="font-size:11px;color:#6b7280;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.04em">Distribuição de Risco dos Endpoints</div>
  <div class="stacked">
    <?php if ($riskDist['critical']): ?><div class="seg" style="width:<?= $pct($riskDist['critical']) ?>%;background:#e8212a" title="Crítico"><?= $riskDist['critical'] ?></div><?php endif; ?>
    <?php if ($riskDist['high']):     ?><div class="seg" style="width:<?= $pct($riskDist['high']) ?>%;background:#f97316"     title="Alto"><?= $riskDist['high'] ?></div><?php endif; ?>
    <?php if ($riskDist['medium']):   ?><div class="seg" style="width:<?= $pct($riskDist['medium']) ?>%;background:#f59e0b"   title="Médio"><?= $riskDist['medium'] ?></div><?php endif; ?>
    <?php if ($riskDist['low']):      ?><div class="seg" style="width:<?= max(1,$pct($riskDist['low'])) ?>%;background:#22c55e" title="Baixo"><?= $riskDist['low'] ?></div><?php endif; ?>
  </div>
  <div class="legend">
    <span class="ld"><span class="ldot" style="background:#e8212a"></span>Crítico (<?= $riskDist['critical'] ?>)</span>
    <span class="ld"><span class="ldot" style="background:#f97316"></span>Alto (<?= $riskDist['high'] ?>)</span>
    <span class="ld"><span class="ldot" style="background:#f59e0b"></span>Médio (<?= $riskDist['medium'] ?>)</span>
    <span class="ld"><span class="ldot" style="background:#22c55e"></span>Baixo (<?= $riskDist['low'] ?>)</span>
  </div>
</div>
<?php endif; ?>

<!-- Charts -->
<div class="chart-row avoid-break">
  <div class="chart-box" style="text-align:center">
    <h3>CVEs por Severidade</h3>
    <?= svgPie([
        ['value' => $sev['critical'], 'color' => '#e8212a'],
        ['value' => $sev['high'],     'color' => '#f97316'],
        ['value' => $sev['medium'],   'color' => '#f59e0b'],
        ['value' => $sev['low'],      'color' => '#22c55e'],
    ]) ?>
    <div class="legend">
      <span class="ld"><span class="ldot" style="background:#e8212a"></span>Crítico (<?= $sev['critical'] ?>)</span>
      <span class="ld"><span class="ldot" style="background:#f97316"></span>Alto (<?= $sev['high'] ?>)</span>
      <span class="ld"><span class="ldot" style="background:#f59e0b"></span>Médio (<?= $sev['medium'] ?>)</span>
      <span class="ld"><span class="ldot" style="background:#22c55e"></span>Baixo (<?= $sev['low'] ?>)</span>
    </div>
  </div>
  <?php if (!empty($osDist)): ?>
  <div class="chart-box" style="text-align:center">
    <h3>Distribuição de SO</h3>
    <?php $osColors = ['#e8212a','#f97316','#3b82f6','#22c55e','#9b59b6','#f59e0b','#00bcd4','#7a8da8'];
    $osPie = []; $ci = 0; foreach ($osDist as $n => $v) { $osPie[] = ['value' => $v, 'color' => $osColors[$ci++ % count($osColors)]]; } ?>
    <?= svgPie($osPie) ?>
    <div class="legend">
      <?php $ci = 0; foreach ($osDist as $n => $v): ?>
      <span class="ld"><span class="ldot" style="background:<?= $osColors[$ci++ % count($osColors)] ?>"></span><?= htmlspecialchars(mb_strimwidth($n,0,20,'…')) ?> (<?= $v ?>)</span>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>
  <div class="chart-box">
    <h3>CVEs por Severidade (barra)</h3>
    <?= svgBar([
        ['label' => 'Crítico', 'value' => $sev['critical'], 'color' => '#e8212a'],
        ['label' => 'Alto',    'value' => $sev['high'],     'color' => '#f97316'],
        ['label' => 'Médio',   'value' => $sev['medium'],   'color' => '#f59e0b'],
        ['label' => 'Baixo',   'value' => $sev['low'],      'color' => '#22c55e'],
    ]) ?>
  </div>
</div>

<?php if (!empty($topEndpoints)): ?>
<div class="sec">Top 15 Endpoints por Risco</div>
<table class="avoid-break">
  <thead><tr><th>#</th><th>Endpoint</th><th>IP</th><th>OS</th><th>Risk Score</th><th>Último acesso</th></tr></thead>
  <tbody>
  <?php foreach ($topEndpoints as $i => $ep): $rs2 = (int)$ep['risk_score']; ?>
  <tr>
    <td style="color:#6b7280"><?= $i+1 ?></td>
    <td class="mono"><?= htmlspecialchars($ep['tanium_name']) ?></td>
    <td class="mono"><?= htmlspecialchars($ep['ip_address'] ?? '—') ?></td>
    <td><?= htmlspecialchars($ep['os_name'] ?? '—') ?></td>
    <td>
      <div class="gauge-row">
        <div class="gauge-bar"><div class="gauge-fill" style="width:<?= $rs2 ?>%;background:<?= riskColor($rs2) ?>"></div></div>
        <strong style="color:<?= riskColor($rs2) ?>;width:28px;text-align:right;font-size:12px"><?= $rs2 ?></strong>
      </div>
    </td>
    <td><?= $ep['last_seen'] ? date('d/m/Y', strtotime($ep['last_seen'])) : '—' ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($topCves)): ?>
<div class="sec page-break">Top 20 CVEs (maior CVSS)</div>
<table class="avoid-break">
  <thead><tr><th>CVE ID</th><th>Sev.</th><th>CVSS</th><th>Título</th><th>Endpoints afetados</th></tr></thead>
  <tbody>
  <?php foreach ($topCves as $c): ?>
  <tr>
    <td class="mono"><?= htmlspecialchars($c['cve_id']) ?></td>
    <td><span class="sev" style="background:<?= sevBg($c['severity']) ?>"><?= ucfirst(strtolower($c['severity'])) ?></span></td>
    <td class="mono"><?= $c['cvss_score'] !== null ? number_format((float)$c['cvss_score'],1) : '—' ?></td>
    <td><?= htmlspecialchars(substr($c['title'],0,70)) ?></td>
    <td style="text-align:center"><?= (int)$c['affected_count'] ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($topPatches)): ?>
<div class="sec">Top 10 Patches mais ausentes</div>
<table class="avoid-break">
  <thead><tr><th>Patch ID</th><th>Título</th><th>Severidade</th><th>Endpoints faltando</th></tr></thead>
  <tbody>
  <?php foreach ($topPatches as $p): ?>
  <tr>
    <td class="mono"><?= htmlspecialchars($p['patch_id']) ?></td>
    <td><?= htmlspecialchars(substr($p['patch_title'],0,60)) ?></td>
    <td><span class="sev" style="background:<?= sevBg($p['severity']) ?>"><?= ucfirst($p['severity']) ?></span></td>
    <td style="text-align:center;font-weight:bold;color:#e8212a"><?= (int)$p['missing_count'] ?></td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php if (!empty($osCmp)): ?>
<div class="sec">Compliance por SO</div>
<table class="avoid-break">
  <thead><tr><th>Sistema Operacional</th><th>Patches ausentes</th><th>Total patches</th><th>Compliance %</th></tr></thead>
  <tbody>
  <?php foreach ($osCmp as $row):
    $cmpPct  = $row['total'] > 0 ? round(($row['total'] - $row['missing']) / $row['total'] * 100) : null;
    $cc2     = $cmpPct !== null ? riskColor(100 - $cmpPct) : '#7a8da8';
    $cmpDisp = $cmpPct !== null ? $cmpPct . '%' : 'N/A';
  ?>
  <tr>
    <td><?= htmlspecialchars($row['os_name']) ?></td>
    <td style="text-align:center;color:#e8212a;font-weight:bold"><?= (int)$row['missing'] ?></td>
    <td style="text-align:center"><?= (int)$row['total'] ?></td>
    <td>
      <div class="gauge-row">
        <div class="gauge-bar"><div class="gauge-fill" style="width:<?= $cmpPct ?? 0 ?>%;background:<?= $cc2 ?>"></div></div>
        <strong style="color:<?= $cc2 ?>;width:36px;text-align:right;font-size:12px"><?= $cmpDisp ?></strong>
      </div>
    </td>
  </tr>
  <?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>

<?php endif; ?>

<div class="rfooter">
  <span>Tanium Plugin para GLPI &nbsp;|&nbsp; <?= htmlspecialchars($CFG_GLPI['url_base'] ?? '') ?></span>
  <span>Relatório gerado em <?= $now ?></span>
</div>

</div><!-- .page -->
</body>
</html>
<?php exit;
