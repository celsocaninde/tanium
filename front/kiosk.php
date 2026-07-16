<?php

/**
 * TV/Kiosk dashboard — full-screen carousel for NOC/SOC wall TVs.
 *
 * Rotates through 7 screens and reloads the page after a full cycle, so the
 * data refreshes continuously:
 *   1. Visão geral      4. SLA de remediação   7. Ameaças & agentes
 *   2. Riscos           5. Patches & deploys
 *   3. CVEs críticos    6. Postura & remediação
 *
 * Access is granted either by the kiosk token (?token=..., no GLPI login —
 * for TVs) or by a logged-in session holding the plugin read right. The
 * token path requires the kiosk to be enabled in the plugin configuration.
 *
 * Optional query params:
 *   interval=N  seconds per screen (5–120, default 15)
 *   slide=N     pin a single screen 1–7 (no rotation; still reloads for data)
 */

use GlpiPlugin\Tanium\Config as TaniumConfig;
use GlpiPlugin\Tanium\Kiosk as TaniumKiosk;

include('../../../inc/includes.php');

$config = TaniumConfig::getConfig();
$token  = (string)($_GET['token'] ?? '');

$byToken = $token !== ''
    && !empty($config['kiosk_enabled'])
    && !empty($config['kiosk_token'])
    && hash_equals((string)$config['kiosk_token'], $token);

$bySession = Session::getLoginUserID() && \GlpiPlugin\Tanium\Profile::hasReadRight();

if (!$byToken && !$bySession) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Acesso negado — kiosk desabilitado, token inválido ou sessão sem permissão.';
    exit;
}

$interval = max(5, min(120, (int)($_GET['interval'] ?? 15)));
$pinned   = max(0, min(7, (int)($_GET['slide'] ?? 0)));

$d    = TaniumKiosk::getData();
$sev  = $d['severity'];
$sla  = $d['sla'];
$mttr = $d['mttr'];

$slaValue = $sla['compliance'];
$slaLabel = $slaValue === null ? '—' : $slaValue . '%';
$slaColor = $slaValue === null ? '#7a8da8' : ($slaValue >= 90 ? '#1eb464' : ($slaValue >= 70 ? '#f0a030' : '#e8212a'));

$lastSync = !empty($d['last_sync']) ? date('d/m/Y H:i', strtotime($d['last_sync'])) : '—';

$sevTotal  = max(1, array_sum($sev));
$sevColors = ['critical' => '#e8212a', 'high' => '#f97316', 'medium' => '#e8c42a', 'low' => '#1eb464'];
$sevLabels = ['critical' => 'Críticos', 'high' => 'Altos', 'medium' => 'Médios', 'low' => 'Baixos'];

$fmtDays = static fn($v): string => $v === null ? '—' : number_format((float)$v, 1, ',', '.') . 'd';
$sevClass = static fn(string $s): string => in_array($s, ['critical', 'high', 'medium', 'low'], true) ? "sev-{$s}" : 'sev-low';

$riskColor = static fn(float $r): string => $r >= 70 ? '#e8212a' : ($r >= 40 ? '#f0a030' : '#1eb464');

$deployStatus = static function (string $s): array {
    return match ($s) {
        'deployed'         => ['Concluído', '#1eb464'],
        'failed'           => ['Falhou', '#e8212a'],
        'rejected'         => ['Recusado', '#7a8da8'],
        'pending_approval' => ['Aguardando aprovação', '#f0a030'],
        default            => ['Em andamento', '#4da3ff'],
    };
};

// ── Sparkline (risk trend) — pure inline SVG, no libraries ────────────────
$sparkW = 1000;
$sparkH = 110;
$trend  = $d['risk_trend'];
$sparkCrit = '';
$sparkRisk = '';
if (count($trend) >= 2) {
    $maxCrit = max(1, max(array_map(static fn($p) => (int)$p['critical_cves'], $trend)));
    $maxRisk = 100;
    $n       = count($trend) - 1;
    foreach ($trend as $i => $p) {
        $x = round($i * $sparkW / $n, 1);
        $sparkCrit .= $x . ',' . round($sparkH - ((int)$p['critical_cves'] * ($sparkH - 12) / $maxCrit) - 6, 1) . ' ';
        $sparkRisk .= $x . ',' . round($sparkH - ((float)$p['avg_risk'] * ($sparkH - 12) / $maxRisk) - 6, 1) . ' ';
    }
}

// ── Weekly remediation bars ───────────────────────────────────────────────
$weekMax = 1;
foreach ($d['weekly_remediation'] as $w) {
    $weekMax = max($weekMax, (int)$w['cpt']);
}

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Tanium — Kiosk</title>
<style>
:root{--bg:#0a1628;--panel:#0f1e33;--border:#1e2d44;--text:#e8edf5;--muted:#7a8da8;--red:#e8212a}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column}
.header{background:linear-gradient(120deg,#7a0d1f 0%,#e8212a 100%);padding:16px 32px;display:flex;align-items:center;gap:16px}
.roundel{width:42px;height:42px;border-radius:50%;background:rgba(255,255,255,.18);color:#fff;font-weight:900;font-size:22px;display:flex;align-items:center;justify-content:center}
.wordmark{font-size:24px;font-weight:800;letter-spacing:4px;color:#fff}
.subtitle{font-size:13px;color:#ffd6d9;margin-top:2px}
.slidetitle{margin-left:32px;font-size:20px;font-weight:700;color:#fff;opacity:.95}
.header .right{margin-left:auto;text-align:right}
.clock{font-size:30px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.syncinfo{font-size:12px;color:#ffd6d9}
.progress{height:4px;background:var(--border)}
.progress>div{height:100%;width:0;background:var(--red);transition:width .3s linear}
.stage{flex:1;position:relative;overflow:hidden}
.slide{position:absolute;inset:0;opacity:0;visibility:hidden;transition:opacity .6s ease;padding-bottom:16px;overflow:auto}
.slide.active{opacity:1;visibility:visible}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;padding:20px 32px 0}
.grid.g4{grid-template-columns:repeat(4,1fr)}
.grid.g5{grid-template-columns:repeat(5,1fr)}
@media(max-width:1100px){.grid,.grid.g4,.grid.g5{grid-template-columns:repeat(3,1fr)}}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 20px}
.tile .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.tile .value{font-size:46px;font-weight:800;line-height:1.15;font-variant-numeric:tabular-nums}
.tile .value.md{font-size:34px}
.tile .sub{font-size:12px;color:var(--muted);margin-top:2px}
.tile.mini{padding:12px 18px}
.tile.mini .value{font-size:30px}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:18px 32px 0;border:1px solid var(--border)}
.sevlegend{display:flex;gap:24px;padding:10px 32px 0;font-size:13px;color:var(--muted)}
.sevlegend b{color:var(--text)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:20px 32px 0}
.panels.single{grid-template-columns:1fr}
@media(max-width:1100px){.panels{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 20px}
.panel h2{font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:15px}
td,th{padding:7px 10px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
td.wrap{white-space:normal}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td.num{font-variant-numeric:tabular-nums}
.riskbar{display:inline-block;height:8px;border-radius:4px;background:var(--red);vertical-align:middle}
.cve{font-family:Consolas,monospace;color:#ff6b71;font-weight:700}
.empty{color:var(--muted);font-size:14px;padding:14px 0}
.footer{padding:10px 32px;font-size:12px;color:var(--muted);display:flex;align-items:center;gap:16px}
.dots{display:flex;gap:8px;margin-left:auto}
.dots span{width:10px;height:10px;border-radius:50%;background:var(--border);transition:background .3s}
.dots span.on{background:var(--red)}
.sev-critical{color:#e8212a;font-weight:700}
.sev-high{color:#f97316;font-weight:700}
.sev-medium{color:#e8c42a;font-weight:700}
.sev-low{color:#1eb464;font-weight:700}
.badge{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.5px;border-radius:4px;padding:2px 6px;margin-left:6px;vertical-align:middle}
.badge.kev{background:rgba(232,33,42,.18);color:#ff6b71;border:1px solid rgba(232,33,42,.5)}
.badge.rw{background:rgba(168,85,247,.15);color:#c48aff;border:1px solid rgba(168,85,247,.45)}
.wbar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}
.wbar .wl{width:60px;color:var(--muted);font-variant-numeric:tabular-nums}
.wbar .wt{flex:1;background:var(--border);border-radius:5px;height:20px;overflow:hidden}
.wbar .wf{height:100%;background:#1eb464;border-radius:5px;min-width:2px}
.wbar .wn{width:44px;text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.trendpanel{margin:18px 32px 0;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 20px}
.trendpanel h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.trendlegend{font-size:12px;color:var(--muted);display:flex;gap:18px;margin-top:4px}
</style>
</head>
<body>
<div class="header">
  <div class="roundel">T</div>
  <div>
    <div class="wordmark">TANIUM</div>
    <div class="subtitle">Painel de Segurança — GLPI</div>
  </div>
  <div class="slidetitle" id="slidetitle"></div>
  <div class="right">
    <div class="clock" id="clock">--:--:--</div>
    <div class="syncinfo">Última sincronização: <?php echo htmlspecialchars($lastSync); ?></div>
  </div>
</div>
<div class="progress"><div id="progressbar"></div></div>

<div class="stage">

<!-- ── Tela 1: Visão geral ─────────────────────────────────────────────── -->
<section class="slide" data-title="Visão geral">
  <div class="grid">
    <div class="tile"><div class="label">Endpoints</div><div class="value"><?php echo (int)$d['endpoints']; ?></div>
      <div class="sub">cobertura ativa: <?php echo $d['coverage_pct'] === null ? '—' : $d['coverage_pct'] . '%'; ?></div></div>
    <div class="tile"><div class="label">CVEs críticos</div><div class="value" style="color:#e8212a"><?php echo (int)$sev['critical']; ?></div>
      <div class="sub">altos: <?php echo (int)$sev['high']; ?></div></div>
    <div class="tile"><div class="label">KEV (explorados)</div><div class="value" style="color:#f97316"><?php echo (int)$d['kev']; ?></div>
      <div class="sub">ransomware: <?php echo (int)$d['ransomware']; ?></div></div>
    <div class="tile"><div class="label">SLA compliance</div><div class="value" style="color:<?php echo $slaColor; ?>"><?php echo htmlspecialchars($slaLabel); ?></div>
      <div class="sub">vencidos: <?php echo (int)$sla['breached']; ?></div></div>
    <div class="tile"><div class="label">Agentes silenciosos &gt;<?php echo (int)$d['stale_days']; ?>d</div><div class="value" style="color:<?php echo $d['stale'] > 0 ? '#f0a030' : '#1eb464'; ?>"><?php echo (int)$d['stale']; ?></div>
      <div class="sub">de <?php echo (int)$d['endpoints']; ?> endpoints</div></div>
    <div class="tile"><div class="label">Ameaças abertas</div><div class="value" style="color:<?php echo $d['threats'] > 0 ? '#e8212a' : '#1eb464'; ?>"><?php echo (int)$d['threats']; ?></div>
      <div class="sub">Threat Response</div></div>
  </div>

  <div class="grid g5">
    <div class="tile mini"><div class="label">Findings abertos</div><div class="value"><?php echo (int)array_sum($sev); ?></div></div>
    <div class="tile mini"><div class="label">Patches ausentes</div><div class="value" style="color:<?php echo $d['patches']['critical'] > 0 ? '#e8212a' : 'inherit'; ?>"><?php echo (int)$d['patches']['total']; ?></div>
      <div class="sub"><?php echo (int)$d['patches']['critical']; ?> críticos · <?php echo (int)$d['patches']['high']; ?> altos</div></div>
    <div class="tile mini"><div class="label">Remediados 7d</div><div class="value" style="color:#1eb464"><?php echo (int)$d['remediated_7d']; ?></div></div>
    <div class="tile mini"><div class="label">Deploys em andamento</div><div class="value" style="color:#4da3ff"><?php echo (int)$d['deploys_active']; ?></div></div>
    <div class="tile mini"><div class="label">MTTR 90d</div><div class="value"><?php echo htmlspecialchars($fmtDays($mttr['overall'])); ?></div></div>
  </div>

  <div class="sevbar">
  <?php foreach ($sev as $s => $n): if ($n > 0): ?>
    <div style="width:<?php echo round($n * 100 / $sevTotal, 2); ?>%;background:<?php echo $sevColors[$s]; ?>"></div>
  <?php endif; endforeach; ?>
  </div>
  <div class="sevlegend">
  <?php foreach ($sev as $s => $n): ?>
    <span><span class="dot" style="background:<?php echo $sevColors[$s]; ?>"></span><?php echo $sevLabels[$s]; ?>: <b><?php echo (int)$n; ?></b></span>
  <?php endforeach; ?>
  </div>

  <div class="trendpanel">
    <h2>📈 Tendência da frota — últimos 30 dias</h2>
    <?php if ($sparkCrit === ''): ?>
      <div class="empty">Histórico insuficiente — os pontos são gravados a cada sincronização.</div>
    <?php else: ?>
    <svg viewBox="0 0 <?php echo $sparkW; ?> <?php echo $sparkH; ?>" preserveAspectRatio="none" style="width:100%;height:<?php echo $sparkH; ?>px;display:block">
      <polyline points="<?php echo trim($sparkRisk); ?>" fill="none" stroke="#4da3ff" stroke-width="2.5" stroke-linejoin="round"/>
      <polyline points="<?php echo trim($sparkCrit); ?>" fill="none" stroke="#e8212a" stroke-width="2.5" stroke-linejoin="round"/>
    </svg>
    <div class="trendlegend">
      <span><span class="dot" style="background:#e8212a"></span>CVEs críticos</span>
      <span><span class="dot" style="background:#4da3ff"></span>Risco médio da frota (0–100)</span>
    </div>
    <?php endif; ?>
  </div>
</section>

<!-- ── Tela 2: Riscos ──────────────────────────────────────────────────── -->
<section class="slide" data-title="Riscos &amp; exploração">
  <div class="panels">
    <div class="panel">
      <h2>🔥 Top 10 endpoints por risco</h2>
      <?php if ($d['top_risk'] === []): ?>
        <div class="empty">Nenhum endpoint com score de risco.</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Endpoint</th><th>Sistema</th><th>Risco</th></tr></thead>
        <tbody>
        <?php foreach ($d['top_risk'] as $r): $score = min(100, (int)$r['risk_score']); ?>
          <tr>
            <td><?php echo htmlspecialchars((string)$r['tanium_name']); ?></td>
            <td style="color:var(--muted)"><?php echo htmlspecialchars((string)($r['os_name'] ?? '')); ?></td>
            <td class="num"><span class="riskbar" style="width:<?php echo $score; ?>px;background:<?php echo $riskColor($score); ?>"></span> <?php echo $score; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>

    <div class="panel">
      <h2>🎯 CVEs mais exploráveis (EPSS)</h2>
      <?php if ($d['top_epss'] === []): ?>
        <div class="empty">Sem dados de EPSS — o cron diário de enriquecimento alimenta esta lista.</div>
      <?php else: ?>
      <table>
        <thead><tr><th>CVE</th><th>EPSS</th><th>Severidade</th><th>Afetados</th></tr></thead>
        <tbody>
        <?php foreach ($d['top_epss'] as $r): $s = strtolower((string)($r['severity'] ?? '')); ?>
          <tr>
            <td class="cve"><?php echo htmlspecialchars((string)$r['cve_id']); ?>
              <?php if ((int)$r['is_kev']): ?><span class="badge kev">KEV</span><?php endif; ?>
              <?php if ((int)$r['ransomware']): ?><span class="badge rw">RANSOMWARE</span><?php endif; ?>
            </td>
            <td class="num" style="color:#f97316;font-weight:700"><?php echo number_format((float)$r['epss'] * 100, 1, ',', '.'); ?>%</td>
            <td class="<?php echo $sevClass($s); ?>"><?php echo $s !== '' ? ucfirst($s) : '—'; ?></td>
            <td class="num"><?php echo (int)$r['affected']; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
  </div>
</section>

<!-- ── Tela 3: CVEs críticos ───────────────────────────────────────────── -->
<section class="slide" data-title="CVEs críticos">
  <div class="panels">
    <div class="panel">
      <h2>🚨 CVEs críticos abertos (mais recentes)</h2>
      <?php if ($d['recent_critical'] === []): ?>
        <div class="empty">Nenhum CVE crítico aberto. 🎉</div>
      <?php else: ?>
      <table>
        <thead><tr><th>CVE</th><th>Endpoint</th><th>CVSS</th><th>Detectado</th></tr></thead>
        <tbody>
        <?php foreach ($d['recent_critical'] as $r): ?>
          <tr>
            <td class="cve"><?php echo htmlspecialchars((string)$r['cve_id']); ?></td>
            <td><?php echo htmlspecialchars((string)($r['tanium_name'] ?? '—')); ?></td>
            <td class="num" style="color:#e8212a;font-weight:700"><?php echo htmlspecialchars((string)($r['cvss_score'] ?? '—')); ?></td>
            <td class="num" style="color:var(--muted)"><?php echo !empty($r['detected_at']) ? date('d/m H:i', strtotime($r['detected_at'])) : '—'; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>

    <div class="panel">
      <h2>📡 CVEs com maior alcance na frota</h2>
      <?php if ($d['widest_cves'] === []): ?>
        <div class="empty">Nenhum CVE crítico/alto aberto. 🎉</div>
      <?php else: ?>
      <table>
        <thead><tr><th>CVE</th><th>Título</th><th>Severidade</th><th>Endpoints</th></tr></thead>
        <tbody>
        <?php foreach ($d['widest_cves'] as $r): $s = strtolower((string)$r['severity']); ?>
          <tr>
            <td class="cve"><?php echo htmlspecialchars((string)$r['cve_id']); ?></td>
            <td class="wrap" style="color:var(--muted)"><?php echo htmlspecialchars(mb_substr((string)($r['title'] ?? ''), 0, 55)); ?></td>
            <td class="<?php echo $sevClass($s); ?>"><?php echo ucfirst($s); ?></td>
            <td class="num" style="font-weight:700"><?php echo (int)$r['affected']; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
  </div>
</section>

<!-- ── Tela 4: SLA de remediação ───────────────────────────────────────── -->
<section class="slide" data-title="SLA de remediação">
  <div class="grid g5">
    <div class="tile"><div class="label">SLA compliance</div><div class="value" style="color:<?php echo $slaColor; ?>"><?php echo htmlspecialchars($slaLabel); ?></div></div>
    <div class="tile"><div class="label">Vencidos</div><div class="value" style="color:<?php echo (int)$sla['breached'] > 0 ? '#e8212a' : '#1eb464'; ?>"><?php echo (int)$sla['breached']; ?></div></div>
    <div class="tile"><div class="label">Vencem em <?php echo (int)$sla['due_soon_days']; ?>d</div><div class="value" style="color:<?php echo (int)$sla['due_soon'] > 0 ? '#f0a030' : '#1eb464'; ?>"><?php echo (int)$sla['due_soon']; ?></div></div>
    <div class="tile"><div class="label">No prazo</div><div class="value" style="color:#1eb464"><?php echo (int)$sla['within']; ?></div></div>
    <div class="tile"><div class="label">MTTR 90d (geral)</div><div class="value md"><?php echo htmlspecialchars($fmtDays($mttr['overall'])); ?></div></div>
  </div>

  <div class="panels">
    <div class="panel">
      <h2>⏱️ MTTR por severidade (90 dias)</h2>
      <table>
        <thead><tr><th>Severidade</th><th>Tempo médio de correção</th></tr></thead>
        <tbody>
        <?php foreach (['critical', 'high', 'medium', 'low'] as $s): ?>
          <tr>
            <td class="sev-<?php echo $s; ?>"><?php echo $sevLabels[$s]; ?></td>
            <td class="num"><?php echo htmlspecialchars($fmtDays($mttr[$s])); ?></td>
          </tr>
        <?php endforeach; ?>
          <tr>
            <td style="color:var(--muted)">Correções na janela</td>
            <td class="num"><?php echo (int)$mttr['count']; ?></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="panel">
      <h2>🕰️ Findings mais atrasados (SLA vencido)</h2>
      <?php if ($d['most_overdue'] === []): ?>
        <div class="empty">Nenhum finding com SLA vencido. 🎉</div>
      <?php else: ?>
      <table>
        <thead><tr><th>CVE</th><th>Endpoint</th><th>Severidade</th><th>Atraso</th></tr></thead>
        <tbody>
        <?php foreach ($d['most_overdue'] as $r): $s = strtolower((string)$r['severity']); ?>
          <tr>
            <td class="cve"><?php echo htmlspecialchars((string)$r['cve_id']); ?></td>
            <td><?php echo htmlspecialchars((string)($r['tanium_name'] ?? '—')); ?></td>
            <td class="<?php echo $sevClass($s); ?>"><?php echo ucfirst($s); ?></td>
            <td class="num" style="color:#e8212a;font-weight:700"><?php echo (int)$r['days_overdue']; ?>d</td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
  </div>
</section>

<!-- ── Tela 5: Patches & deploys ───────────────────────────────────────── -->
<section class="slide" data-title="Patches &amp; deploys">
  <div class="grid g4">
    <div class="tile"><div class="label">Patches ausentes</div><div class="value"><?php echo (int)$d['patches']['total']; ?></div></div>
    <div class="tile"><div class="label">Críticos</div><div class="value" style="color:<?php echo $d['patches']['critical'] > 0 ? '#e8212a' : '#1eb464'; ?>"><?php echo (int)$d['patches']['critical']; ?></div></div>
    <div class="tile"><div class="label">Altos</div><div class="value" style="color:<?php echo $d['patches']['high'] > 0 ? '#f97316' : '#1eb464'; ?>"><?php echo (int)$d['patches']['high']; ?></div></div>
    <div class="tile"><div class="label">Deploys em andamento</div><div class="value" style="color:#4da3ff"><?php echo (int)$d['deploys_active']; ?></div>
      <?php if ($d['recent_deploys'] !== []): $last = $d['recent_deploys'][0]; [$dsLabel, $dsColor] = $deployStatus((string)$last['status']); ?>
      <div class="sub">último: <span style="color:<?php echo $dsColor; ?>"><?php echo $dsLabel; ?></span> · <?php echo htmlspecialchars((string)($last['tanium_name'] ?? '—')); ?></div>
      <?php endif; ?>
    </div>
  </div>

  <div class="panels">
    <div class="panel">
      <h2>🖥️ Endpoints com mais patches críticos/altos ausentes</h2>
      <?php if ($d['patch_top_endpoints'] === []): ?>
        <div class="empty">Nenhum patch crítico/alto ausente. 🎉</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Endpoint</th><th>Sistema</th><th>Críticos</th><th>Total</th></tr></thead>
        <tbody>
        <?php foreach ($d['patch_top_endpoints'] as $r): ?>
          <tr>
            <td><?php echo htmlspecialchars((string)$r['tanium_name']); ?></td>
            <td style="color:var(--muted)"><?php echo htmlspecialchars((string)($r['os_name'] ?? '')); ?></td>
            <td class="num" style="color:#e8212a;font-weight:700"><?php echo (int)$r['crit']; ?></td>
            <td class="num"><?php echo (int)$r['missing']; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>

    <div class="panel">
      <h2>🩹 Patches ausentes mais comuns</h2>
      <?php if ($d['patch_top_titles'] === []): ?>
        <div class="empty">Nenhum patch ausente registrado.</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Patch</th><th>Severidade</th><th>Endpoints</th></tr></thead>
        <tbody>
        <?php foreach ($d['patch_top_titles'] as $r): $s = strtolower((string)$r['severity']); ?>
          <tr>
            <td class="wrap"><?php echo htmlspecialchars(mb_substr((string)$r['patch_title'], 0, 65)); ?></td>
            <td class="<?php echo $sevClass($s); ?>"><?php echo ucfirst($s); ?></td>
            <td class="num" style="font-weight:700"><?php echo (int)$r['affected']; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
  </div>
</section>

<!-- ── Tela 6: Postura & remediação ────────────────────────────────────── -->
<section class="slide" data-title="Postura &amp; remediação">
  <div class="panels">
    <div class="panel">
      <h2>🧭 Postura por plataforma (pior primeiro)</h2>
      <?php if ($d['platform'] === []): ?>
        <div class="empty">Sem dados de plataforma — habilite a sincronização de detalhes de SO.</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Plataforma</th><th>Endpoints</th><th>Risco médio</th><th>Críticos abertos</th></tr></thead>
        <tbody>
        <?php foreach (array_slice($d['platform'], 0, 8) as $r): $avg = (float)$r['avg_risk']; ?>
          <tr>
            <td><?php echo htmlspecialchars((string)$r['os_platform']); ?></td>
            <td class="num"><?php echo (int)$r['endpoints']; ?></td>
            <td class="num" style="color:<?php echo $riskColor($avg); ?>;font-weight:700"><?php echo number_format($avg, 1, ',', '.'); ?></td>
            <td class="num" style="color:<?php echo (int)$r['crit_open'] > 0 ? '#e8212a' : '#1eb464'; ?>;font-weight:700"><?php echo (int)$r['crit_open']; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>

    <div class="panel">
      <h2>✅ CVEs remediados por semana (8 semanas)</h2>
      <?php if ($d['weekly_remediation'] === []): ?>
        <div class="empty">Nenhuma remediação registrada no período.</div>
      <?php else: ?>
        <?php foreach ($d['weekly_remediation'] as $w): ?>
        <div class="wbar">
          <span class="wl"><?php echo date('d/m', strtotime((string)$w['week_start'])); ?></span>
          <span class="wt"><span class="wf" style="width:<?php echo round((int)$w['cpt'] * 100 / $weekMax); ?>%"></span></span>
          <span class="wn"><?php echo (int)$w['cpt']; ?></span>
        </div>
        <?php endforeach; ?>
        <div class="trendlegend" style="margin-top:10px">
          <span>Remediados nos últimos 7 dias: <b style="color:#1eb464"><?php echo (int)$d['remediated_7d']; ?></b></span>
        </div>
      <?php endif; ?>
    </div>
  </div>
</section>

<!-- ── Tela 7: Ameaças & agentes ───────────────────────────────────────── -->
<section class="slide" data-title="Ameaças &amp; agentes">
  <div class="panels">
    <div class="panel">
      <h2>🛡️ Alertas de ameaça abertos (Threat Response)</h2>
      <?php if ($d['recent_threats'] === []): ?>
        <div class="empty">Nenhum alerta de ameaça aberto. 🎉</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Alerta</th><th>Endpoint</th><th>Severidade</th><th>Detectado</th></tr></thead>
        <tbody>
        <?php foreach ($d['recent_threats'] as $r): $s = strtolower((string)$r['severity']); ?>
          <tr>
            <td class="wrap"><?php echo htmlspecialchars(mb_substr((string)$r['title'], 0, 70)); ?></td>
            <td><?php echo htmlspecialchars((string)($r['tanium_name'] ?? '—')); ?></td>
            <td class="<?php echo $sevClass($s); ?>"><?php echo ucfirst($s); ?></td>
            <td class="num" style="color:var(--muted)"><?php echo !empty($r['detected_at']) ? date('d/m H:i', strtotime($r['detected_at'])) : '—'; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>

    <div class="panel">
      <h2>📡 Agentes silenciosos (&gt;<?php echo (int)$d['stale_days']; ?> dias)</h2>
      <?php if ($d['stale_list'] === []): ?>
        <div class="empty">Todos os agentes estão comunicando. 🎉</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Endpoint</th><th>IP</th><th>Sistema</th><th>Silêncio</th></tr></thead>
        <tbody>
        <?php foreach ($d['stale_list'] as $r): ?>
          <tr>
            <td><?php echo htmlspecialchars((string)$r['tanium_name']); ?></td>
            <td style="color:var(--muted)"><?php echo htmlspecialchars((string)($r['ip_address'] ?: '—')); ?></td>
            <td style="color:var(--muted)"><?php echo htmlspecialchars((string)($r['os_name'] ?: '—')); ?></td>
            <td class="num" style="color:#f0a030;font-weight:700"><?php echo (int)$r['days_silent']; ?>d</td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>
  </div>
</section>

</div>

<div class="footer">
  <span>Troca de tela a cada <?php echo $interval; ?>s · dados atualizados a cada ciclo · Gerado em <?php echo date('d/m/Y H:i:s'); ?> · Plugin Tanium para GLPI</span>
  <div class="dots" id="dots"></div>
</div>

<script>
(function () {
  var slides   = document.querySelectorAll('.slide');
  var dotsBox  = document.getElementById('dots');
  var titleBox = document.getElementById('slidetitle');
  var progress = document.getElementById('progressbar');
  var INTERVAL = <?php echo $interval * 1000; ?>;
  var PINNED   = <?php echo $pinned; ?>; // 0 = rotate through all
  var current  = PINNED > 0 ? PINNED - 1 : 0;
  var shown    = 0;
  var sliceStart = Date.now();

  slides.forEach(function (s, i) {
    var dot = document.createElement('span');
    dot.dataset.idx = i;
    dotsBox.appendChild(dot);
  });

  function show(i) {
    slides.forEach(function (s, j) { s.classList.toggle('active', j === i); });
    dotsBox.querySelectorAll('span').forEach(function (d, j) { d.classList.toggle('on', j === i); });
    titleBox.textContent = slides[i].dataset.title;
    sliceStart = Date.now();
  }

  show(current);

  setInterval(function () {
    var pct = Math.min(100, (Date.now() - sliceStart) * 100 / INTERVAL);
    progress.style.width = pct + '%';
  }, 250);

  setInterval(function () {
    shown++;
    // full cycle complete (or pinned screen timed out) → reload for fresh data
    if (shown >= (PINNED > 0 ? Math.max(2, Math.round(60000 / INTERVAL)) : slides.length)) {
      location.reload();
      return;
    }
    if (PINNED === 0) {
      current = (current + 1) % slides.length;
      show(current);
    }
  }, INTERVAL);

  function tick() {
    var d = new Date();
    document.getElementById('clock').textContent =
      String(d.getHours()).padStart(2, '0') + ':' +
      String(d.getMinutes()).padStart(2, '0') + ':' +
      String(d.getSeconds()).padStart(2, '0');
  }
  tick();
  setInterval(tick, 1000);
})();
</script>
</body>
</html>
