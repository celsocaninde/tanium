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

function svgBar(array $bars, int $w = 380, int $h = 200): string {
    if (empty($bars)) return '';
    $max     = max(array_column($bars, 'value')) ?: 1;
    $count   = count($bars);
    $padT    = 22;  // room for value labels above bars
    $padB    = 22;  // room for category labels below
    $plotH   = $h - $padT - $padB;
    $slot    = ($w - 20) / $count;
    $bw      = max(10, (int)($slot * 0.6));
    $svg     = "<svg width='100%' viewBox='0 0 {$w} {$h}' preserveAspectRatio='xMidYMid meet' style='display:block'>";

    // baseline
    $baseY = $padT + $plotH;
    $svg  .= "<line x1='10' y1='{$baseY}' x2='" . ($w - 10) . "' y2='{$baseY}' stroke='#e5e7eb' stroke-width='1'/>";

    foreach ($bars as $i => $bar) {
        $bh    = (int) round(($bar['value'] / $max) * $plotH);
        $bh    = max(2, $bh);
        $by    = $baseY - $bh;
        $cx    = 10 + $slot * $i + $slot / 2;
        $x     = $cx - $bw / 2;
        $label = htmlspecialchars(mb_strimwidth($bar['label'], 0, 10, '…'));

        $svg .= "<rect x='" . round($x, 1) . "' y='" . round($by, 1) . "' width='{$bw}' height='{$bh}' rx='4' fill='{$bar['color']}'/>";
        $svg .= "<text x='" . round($cx, 1) . "' y='" . ($h - 6) . "' text-anchor='middle' font-size='11' fill='#6b7280'>{$label}</text>";
        if ($bar['value'] > 0) {
            $svg .= "<text x='" . round($cx, 1) . "' y='" . round($by - 6, 1) . "' text-anchor='middle' font-size='12' fill='#374151' font-weight='bold'>" . number_format($bar['value']) . "</text>";
        }
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

/** Donut chart with a centered total label. */
function svgDonut(array $slices, int $size = 150, string $centerVal = '', string $centerSub = ''): string {
    $total = array_sum(array_column($slices, 'value'));
    $cx = $size / 2; $cy = $size / 2; $r = $size / 2 - 6; $hole = $r * 0.62;

    if ($total <= 0) {
        return "<svg width='{$size}' height='{$size}' viewBox='0 0 {$size} {$size}'>
            <circle cx='{$cx}' cy='{$cy}' r='{$r}' fill='#eef0f3'/>
            <circle cx='{$cx}' cy='{$cy}' r='{$hole}' fill='#fff'/>
            <text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#9ca3af' font-size='11'>N/A</text></svg>";
    }

    $paths = ''; $angle = -90.0;
    foreach ($slices as $slice) {
        $val = (float)$slice['value']; if ($val <= 0) continue;
        $sweep = ($val / $total) * 360;
        $startRad = deg2rad($angle); $endRad = deg2rad($angle + $sweep);
        $x1 = round($cx + $r * cos($startRad), 3); $y1 = round($cy + $r * sin($startRad), 3);
        $x2 = round($cx + $r * cos($endRad), 3);   $y2 = round($cy + $r * sin($endRad), 3);
        $large = $sweep > 180 ? 1 : 0;
        $paths .= "<path d='M{$cx},{$cy} L{$x1},{$y1} A{$r},{$r} 0 {$large},1 {$x2},{$y2} Z' fill='{$slice['color']}'/>";
        $angle += $sweep;
    }

    $center = '';
    if ($centerVal !== '') {
        $center  = "<text x='{$cx}' y='" . ($cy - 2) . "' text-anchor='middle' font-size='24' font-weight='800' fill='#111827'>{$centerVal}</text>";
        if ($centerSub !== '') {
            $center .= "<text x='{$cx}' y='" . ($cy + 15) . "' text-anchor='middle' font-size='9' fill='#6b7280' letter-spacing='.05em'>" . strtoupper($centerSub) . "</text>";
        }
    }

    return "<svg width='{$size}' height='{$size}' viewBox='0 0 {$size} {$size}'>
        {$paths}
        <circle cx='{$cx}' cy='{$cy}' r='{$hole}' fill='#fff'/>
        {$center}</svg>";
}

/**
 * Area+line trend chart. $points = [['label'=>'01/06','area'=>30,'line'=>12], ...]
 * 'area' is plotted 0-100 (left), 'line' is auto-scaled (right).
 */
function svgTrend(array $points, int $w = 1060, int $h = 200, string $areaColor = '#e8212a', string $lineColor = '#f59e0b'): string {
    $n = count($points);
    if ($n < 2) return '';

    $padL = 36; $padR = 36; $padT = 18; $padB = 26;
    $plotW = $w - $padL - $padR; $plotH = $h - $padT - $padB;
    $lineMax = max(1, max(array_column($points, 'line')));

    $xAt = fn($i) => $padL + ($n === 1 ? $plotW / 2 : $i * $plotW / ($n - 1));
    $yArea = fn($v) => $padT + $plotH - (max(0, min(100, $v)) / 100) * $plotH;
    $yLine = fn($v) => $padT + $plotH - ($v / $lineMax) * $plotH;

    // gridlines + y labels (0,50,100 for area scale)
    $grid = '';
    foreach ([0, 25, 50, 75, 100] as $g) {
        $gy = round($yArea($g), 1);
        $grid .= "<line x1='{$padL}' y1='{$gy}' x2='" . ($w - $padR) . "' y2='{$gy}' stroke='#eef0f3' stroke-width='1'/>";
        $grid .= "<text x='" . ($padL - 6) . "' y='" . ($gy + 3) . "' text-anchor='end' font-size='9' fill='#9ca3af'>{$g}</text>";
    }

    // area path
    $areaPts = ''; $linePts = ''; $dots = ''; $xlabels = '';
    foreach ($points as $i => $p) {
        $x  = round($xAt($i), 1);
        $ya = round($yArea((float)$p['area']), 1);
        $yl = round($yLine((float)$p['line']), 1);
        $areaPts .= "{$x},{$ya} ";
        $linePts .= "{$x},{$yl} ";
        $dots .= "<circle cx='{$x}' cy='{$yl}' r='2.5' fill='{$lineColor}'/>";
        // label every ~ceil(n/8)
        $step = max(1, (int)ceil($n / 8));
        if ($i % $step === 0 || $i === $n - 1) {
            $xlabels .= "<text x='{$x}' y='" . ($h - 8) . "' text-anchor='middle' font-size='9' fill='#9ca3af'>" . htmlspecialchars($p['label']) . "</text>";
        }
    }
    $firstX = round($xAt(0), 1); $lastX = round($xAt($n - 1), 1); $baseY = round($yArea(0), 1);
    $areaFill = "M{$firstX},{$baseY} L" . trim($areaPts) . " L{$lastX},{$baseY} Z";

    return "<svg width='100%' viewBox='0 0 {$w} {$h}' preserveAspectRatio='xMidYMid meet' style='display:block'>
        <defs><linearGradient id='ar' x1='0' y1='0' x2='0' y2='1'>
            <stop offset='0%' stop-color='{$areaColor}' stop-opacity='.28'/>
            <stop offset='100%' stop-color='{$areaColor}' stop-opacity='.02'/>
        </linearGradient></defs>
        {$grid}
        <path d='{$areaFill}' fill='url(#ar)'/>
        <polyline points='" . trim($areaPts) . "' fill='none' stroke='{$areaColor}' stroke-width='2.5'/>
        <polyline points='" . trim($linePts) . "' fill='none' stroke='{$lineColor}' stroke-width='2' stroke-dasharray='4,3'/>
        {$dots}{$xlabels}</svg>";
}

/** Map a 0-100 posture score to a letter grade + verdict + color. */
function postureGrade(int $score): array {
    return match (true) {
        $score >= 90 => ['A', 'Excelente — postura de segurança sólida',           '#16a34a'],
        $score >= 80 => ['B', 'Boa — pontos de melhoria identificados',            '#65a30d'],
        $score >= 70 => ['C', 'Atenção — riscos relevantes a tratar',              '#f59e0b'],
        $score >= 55 => ['D', 'Frágil — ação corretiva recomendada',               '#f97316'],
        default      => ['F', 'Crítica — exposição elevada, ação imediata',        '#e8212a'],
    };
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
    $totalEp      = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_assets',          'COUNT' => 'cpt'])->current()['cpt'] ?? 0);
    $totalCve     = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_vulnerabilities',  'COUNT' => 'cpt'])->current()['cpt'] ?? 0);
    $totalMissing = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['status' => 'missing'], 'COUNT' => 'cpt'])->current()['cpt'] ?? 0);
    $totalPatches = (int)($DB->request(['FROM' => 'glpi_plugin_tanium_patches',          'COUNT' => 'cpt'])->current()['cpt'] ?? 0);
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

    // ── Posture score (0-100) and grade ──────────────────────────────────────
    $criticalPressure = $totalEp > 0 ? min(100, round($sev['critical'] / $totalEp * 10)) : 0;
    $complianceVal    = $compliance ?? 50;
    $postureScore     = (int) round(
        0.40 * $complianceVal
        + 0.35 * (100 - $avgRisk)
        + 0.25 * (100 - $criticalPressure)
    );
    $postureScore = max(0, min(100, $postureScore));
    [$grade, $verdict, $gradeColor] = postureGrade($postureScore);

    // ── Trend series from risk_history (one latest point per day) ─────────────
    $trend = [];
    $seenDays = [];
    foreach ($DB->doQuery(
        "SELECT DATE(recorded_at) AS d, avg_risk, critical_cves, patches_missing, recorded_at
         FROM glpi_plugin_tanium_risk_history
         WHERE avg_risk > 0
         ORDER BY recorded_at ASC"
    ) as $r) {
        $seenDays[(string)$r['d']] = [
            'label' => date('d/m', strtotime($r['d'])),
            'area'  => (float)$r['avg_risk'],
            'line'  => (int)$r['critical_cves'],
        ];
    }
    $trend = array_slice(array_values($seenDays), -14); // last 14 days

    // ── Remediation momentum (last 30 days) from cve_history ──────────────────
    $sinceSql  = "DATE_SUB(NOW(), INTERVAL 30 DAY)";
    $resolved30 = (int)($DB->doQuery(
        "SELECT COUNT(*) c FROM glpi_plugin_tanium_cve_history
         WHERE new_status IN ('resolved','remediated') AND changed_at >= {$sinceSql}"
    )->fetch_assoc()['c'] ?? 0);
    $new30 = (int)($DB->doQuery(
        "SELECT COUNT(*) c FROM glpi_plugin_tanium_cve_history
         WHERE new_status = 'open' AND changed_at >= {$sinceSql}"
    )->fetch_assoc()['c'] ?? 0);
    $momentumNet = $resolved30 - $new30; // >0 = backlog shrinking

    // ── SLA breaches (overdue open CVEs by severity) ──────────────────────────
    $critDays = (int)($config['sla_critical_days'] ?? 7);
    $highDays = (int)($config['sla_high_days']     ?? 30);
    $medDays  = (int)($config['sla_medium_days']   ?? 90);
    $slaRow = $DB->doQuery("
        SELECT
          SUM(CASE WHEN v.severity='critical' AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$critDays} DAY) THEN 1 ELSE 0 END) AS c,
          SUM(CASE WHEN v.severity='high'     AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$highDays} DAY) THEN 1 ELSE 0 END) AS h,
          SUM(CASE WHEN v.severity='medium'   AND ec.detected_at < DATE_SUB(NOW(), INTERVAL {$medDays}  DAY) THEN 1 ELSE 0 END) AS m
        FROM glpi_plugin_tanium_endpoint_cves ec
        JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
        WHERE ec.status NOT IN ('resolved','remediated')
    ")->fetch_assoc();
    $slaCrit = (int)($slaRow['c'] ?? 0);
    $slaHigh = (int)($slaRow['h'] ?? 0);
    $slaMed  = (int)($slaRow['m'] ?? 0);
    $slaTotal = $slaCrit + $slaHigh + $slaMed;

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
/* Hero — posture grade */
.hero{display:flex;gap:22px;align-items:stretch;background:linear-gradient(120deg,#15151f 0%,#26263a 100%);
      border-radius:14px;padding:22px 26px;margin-bottom:22px;color:#fff}
.hero-grade{flex-shrink:0;width:120px;border-radius:12px;display:flex;flex-direction:column;
            align-items:center;justify-content:center;color:#fff;text-align:center}
.hero-grade .g{font-size:56px;font-weight:900;line-height:.9}
.hero-grade .gs{font-size:11px;font-weight:700;opacity:.9;margin-top:2px}
.hero-body{flex:1;display:flex;flex-direction:column;justify-content:center}
.hero-body .ht{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:#8b8ba3}
.hero-body .hv{font-size:20px;font-weight:800;margin:4px 0 10px}
.hero-mini{display:flex;gap:22px;flex-wrap:wrap}
.hmi{display:flex;flex-direction:column}
.hmi .v{font-size:20px;font-weight:800;line-height:1}
.hmi .l{font-size:10px;color:#8b8ba3;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
/* Momentum cards */
.mom{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:6px}
.mcard{flex:1;min-width:150px;border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px;background:#f9fafb}
.mcard .mh{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280;display:flex;align-items:center;gap:6px}
.mcard .mv{font-size:26px;font-weight:800;margin-top:6px;line-height:1}
.mcard .ms{font-size:11px;color:#6b7280;margin-top:3px}
.trend-empty{background:#f9fafb;border:1px dashed #d1d5db;border-radius:10px;padding:26px;text-align:center;color:#9ca3af;font-size:12px}
.action-card{display:flex;align-items:center;gap:14px;background:#fff;border:1px solid #e5e7eb;border-left:4px solid #e8212a;
             border-radius:8px;padding:12px 16px;margin-bottom:8px}
.action-rank{flex-shrink:0;width:30px;height:30px;border-radius:50%;background:#1a1a2e;color:#fff;display:flex;
             align-items:center;justify-content:center;font-weight:800;font-size:13px}
.action-main{flex:1}
.action-fix{flex-shrink:0;text-align:right}
.action-fix .n{font-size:20px;font-weight:800;color:#e8212a;line-height:1}
.action-fix .l{font-size:10px;color:#6b7280;text-transform:uppercase}
@media print{.hero{background:#15151f!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
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

<!-- Hero: Security Posture Grade -->
<div class="hero avoid-break">
  <div class="hero-grade" style="background:<?= $gradeColor ?>">
    <div class="g"><?= $grade ?></div>
    <div class="gs"><?= $postureScore ?>/100</div>
  </div>
  <div class="hero-body">
    <div class="ht">Postura de Segurança</div>
    <div class="hv" style="color:<?= $gradeColor ?>"><?= htmlspecialchars($verdict) ?></div>
    <div class="hero-mini">
      <div class="hmi"><span class="v"><?= number_format($totalEp) ?></span><span class="l">Endpoints</span></div>
      <div class="hmi"><span class="v" style="color:#fc8181"><?= number_format($sev['critical']) ?></span><span class="l">CVEs críticos</span></div>
      <div class="hmi"><span class="v" style="color:#f6ad55"><?= number_format($totalMissing) ?></span><span class="l">Patches ausentes</span></div>
      <div class="hmi"><span class="v" style="color:<?= $compliance !== null && $compliance >= 70 ? '#68d391' : '#fc8181' ?>"><?= $compliance !== null ? $compliance . '%' : 'N/A' ?></span><span class="l">Compliance</span></div>
      <div class="hmi"><span class="v" style="color:<?= $slaTotal > 0 ? '#fc8181' : '#68d391' ?>"><?= number_format($slaTotal) ?></span><span class="l">SLA vencido</span></div>
    </div>
  </div>
</div>

<!-- Trend over time -->
<div class="sec">Tendência de Risco</div>
<div class="chart-box avoid-break" style="margin-bottom:18px">
  <?php if (count($trend) >= 2): ?>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <div class="legend" style="margin:0">
      <span class="ld"><span class="ldot" style="background:#e8212a"></span>Risco médio (0–100)</span>
      <span class="ld"><span class="ldot" style="background:#f59e0b"></span>CVEs críticos</span>
    </div>
    <span style="font-size:11px;color:#6b7280">Últimos <?= count($trend) ?> registros</span>
  </div>
  <?= svgTrend($trend) ?>
  <?php else: ?>
  <div class="trend-empty">
    📈 Coletando histórico — o gráfico de tendência aparece após algumas sincronizações.<br>
    <span style="font-size:11px">Cada sincronização registra um ponto de risco/CVEs ao longo do tempo.</span>
  </div>
  <?php endif; ?>
</div>

<!-- Remediation momentum + SLA -->
<div class="sec">Velocidade de Remediação &amp; SLA (últimos 30 dias)</div>
<div class="mom avoid-break" style="margin-bottom:18px">
  <div class="mcard" style="border-left:4px solid #22c55e">
    <div class="mh">✅ CVEs resolvidos</div>
    <div class="mv" style="color:#22c55e"><?= number_format($resolved30) ?></div>
    <div class="ms">remediados nos últimos 30 dias</div>
  </div>
  <div class="mcard" style="border-left:4px solid #f97316">
    <div class="mh">🆕 CVEs detectados</div>
    <div class="mv" style="color:#f97316"><?= number_format($new30) ?></div>
    <div class="ms">novos nos últimos 30 dias</div>
  </div>
  <?php
    $momColor = $momentumNet >= 0 ? '#22c55e' : '#e8212a';
    $momIcon  = $momentumNet >= 0 ? '📉' : '📈';
    $momText  = $momentumNet >= 0 ? 'backlog diminuindo' : 'backlog crescendo';
  ?>
  <div class="mcard" style="border-left:4px solid <?= $momColor ?>">
    <div class="mh"><?= $momIcon ?> Saldo</div>
    <div class="mv" style="color:<?= $momColor ?>"><?= ($momentumNet >= 0 ? '+' : '') . number_format($momentumNet) ?></div>
    <div class="ms"><?= $momText ?></div>
  </div>
  <div class="mcard" style="border-left:4px solid <?= $slaTotal > 0 ? '#e8212a' : '#22c55e' ?>">
    <div class="mh">⏰ SLA vencido</div>
    <div class="mv" style="color:<?= $slaTotal > 0 ? '#e8212a' : '#22c55e' ?>"><?= number_format($slaTotal) ?></div>
    <div class="ms"><?= $slaCrit ?> críticos · <?= $slaHigh ?> altos · <?= $slaMed ?> médios</div>
  </div>
</div>

<?php if (!empty($topPatches)): ?>
<!-- Recommended actions (highest ROI patches) -->
<div class="sec">⚡ Ações Recomendadas — Maior Impacto</div>
<p style="font-size:12px;color:#6b7280;margin-bottom:10px">Implantar estes patches resolve o maior número de endpoints expostos de uma só vez.</p>
<?php foreach (array_slice($topPatches, 0, 5) as $i => $p): ?>
<div class="action-card avoid-break">
  <div class="action-rank"><?= $i + 1 ?></div>
  <div class="action-main">
    <div style="font-weight:700;font-size:13px"><?= htmlspecialchars(substr($p['patch_title'] ?: $p['patch_id'], 0, 70)) ?></div>
    <div style="font-size:11px;color:#6b7280;margin-top:2px">
      <code><?= htmlspecialchars($p['patch_id']) ?></code>
      &nbsp;<span class="sev" style="background:<?= sevBg($p['severity']) ?>"><?= ucfirst($p['severity']) ?></span>
    </div>
  </div>
  <div class="action-fix">
    <div class="n"><?= (int)$p['missing_count'] ?></div>
    <div class="l">endpoints</div>
  </div>
</div>
<?php endforeach; ?>
<?php endif; ?>

<div class="sec page-break">Visão Geral da Organização</div>
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
    <?= svgDonut([
        ['value' => $sev['critical'], 'color' => '#e8212a'],
        ['value' => $sev['high'],     'color' => '#f97316'],
        ['value' => $sev['medium'],   'color' => '#f59e0b'],
        ['value' => $sev['low'],      'color' => '#22c55e'],
    ], 150, number_format($totalCve), 'CVEs') ?>
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
    $osPie = []; $ci = 0; $osTotal = array_sum($osDist); foreach ($osDist as $n => $v) { $osPie[] = ['value' => $v, 'color' => $osColors[$ci++ % count($osColors)]]; } ?>
    <?= svgDonut($osPie, 150, number_format($osTotal), 'Hosts') ?>
    <div class="legend">
      <?php $ci = 0; foreach ($osDist as $n => $v): ?>
      <span class="ld"><span class="ldot" style="background:<?= $osColors[$ci++ % count($osColors)] ?>"></span><?= htmlspecialchars(mb_strimwidth($n,0,20,'…')) ?> (<?= $v ?>)</span>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>
  <div class="chart-box" style="display:flex;flex-direction:column">
    <h3>CVEs por Severidade (barra)</h3>
    <div style="flex:1;display:flex;align-items:center">
      <?= svgBar([
          ['label' => 'Crítico', 'value' => $sev['critical'], 'color' => '#e8212a'],
          ['label' => 'Alto',    'value' => $sev['high'],     'color' => '#f97316'],
          ['label' => 'Médio',   'value' => $sev['medium'],   'color' => '#f59e0b'],
          ['label' => 'Baixo',   'value' => $sev['low'],      'color' => '#22c55e'],
      ]) ?>
    </div>
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
