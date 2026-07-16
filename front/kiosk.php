<?php

/**
 * TV/Kiosk dashboard — full-screen, auto-refresh, made for NOC/SOC wall TVs.
 *
 * Access is granted either by the kiosk token (?token=..., no GLPI login —
 * for TVs) or by a logged-in session holding the plugin read right. The
 * token path requires the kiosk to be enabled in the plugin configuration.
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

$d   = TaniumKiosk::getData();
$sev = $d['severity'];
$sla = $d['sla'];

$slaValue = $sla['compliance'];
$slaLabel = $slaValue === null ? '—' : $slaValue . '%';
$slaColor = $slaValue === null ? '#7a8da8' : ($slaValue >= 90 ? '#1eb464' : ($slaValue >= 70 ? '#f0a030' : '#e8212a'));

$lastSync = !empty($d['last_sync']) ? date('d/m/Y H:i', strtotime($d['last_sync'])) : '—';

$sevTotal = max(1, array_sum($sev));
$sevColors = ['critical' => '#e8212a', 'high' => '#f97316', 'medium' => '#e8c42a', 'low' => '#1eb464'];
$sevLabels = ['critical' => 'Críticos', 'high' => 'Altos', 'medium' => 'Médios', 'low' => 'Baixos'];

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
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;padding:0 0 24px}
.header{background:linear-gradient(120deg,#7a0d1f 0%,#e8212a 100%);padding:18px 32px;display:flex;align-items:center;gap:16px}
.roundel{width:42px;height:42px;border-radius:50%;background:rgba(255,255,255,.18);color:#fff;font-weight:900;font-size:22px;display:flex;align-items:center;justify-content:center}
.wordmark{font-size:24px;font-weight:800;letter-spacing:4px;color:#fff}
.subtitle{font-size:14px;color:#ffd6d9;margin-top:2px}
.header .right{margin-left:auto;text-align:right}
.clock{font-size:32px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.syncinfo{font-size:12px;color:#ffd6d9}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:16px;padding:24px 32px 0}
@media(max-width:1100px){.grid{grid-template-columns:repeat(3,1fr)}}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px 22px}
.tile .label{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.tile .value{font-size:52px;font-weight:800;line-height:1.15;font-variant-numeric:tabular-nums}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:20px 32px 0;border:1px solid var(--border)}
.sevlegend{display:flex;gap:24px;padding:10px 32px 0;font-size:13px;color:var(--muted)}
.sevlegend b{color:var(--text)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:24px 32px 0}
@media(max-width:1100px){.panels{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 22px}
.panel h2{font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:15px}
td,th{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td.num{font-variant-numeric:tabular-nums}
.riskbar{display:inline-block;height:8px;border-radius:4px;background:var(--red);vertical-align:middle}
.cve{font-family:Consolas,monospace;color:#ff6b71;font-weight:700}
.empty{color:var(--muted);font-size:14px;padding:16px 0}
.footer{padding:18px 32px 0;font-size:12px;color:var(--muted)}
</style>
</head>
<body>
<div class="header">
  <div class="roundel">T</div>
  <div>
    <div class="wordmark">TANIUM</div>
    <div class="subtitle">Painel de Segurança — GLPI</div>
  </div>
  <div class="right">
    <div class="clock" id="clock">--:--:--</div>
    <div class="syncinfo">Última sincronização: <?php echo htmlspecialchars($lastSync); ?></div>
  </div>
</div>

<div class="grid">
  <div class="tile"><div class="label">Endpoints</div><div class="value"><?php echo (int)$d['endpoints']; ?></div></div>
  <div class="tile"><div class="label">CVEs críticos</div><div class="value" style="color:#e8212a"><?php echo (int)$sev['critical']; ?></div></div>
  <div class="tile"><div class="label">KEV (explorados)</div><div class="value" style="color:#f97316"><?php echo (int)$d['kev']; ?></div></div>
  <div class="tile"><div class="label">SLA compliance</div><div class="value" style="color:<?php echo $slaColor; ?>"><?php echo htmlspecialchars($slaLabel); ?></div></div>
  <div class="tile"><div class="label">Agentes silenciosos &gt;<?php echo (int)$d['stale_days']; ?>d</div><div class="value" style="color:<?php echo $d['stale'] > 0 ? '#f0a030' : '#1eb464'; ?>"><?php echo (int)$d['stale']; ?></div></div>
  <div class="tile"><div class="label">Ameaças abertas</div><div class="value" style="color:<?php echo $d['threats'] > 0 ? '#e8212a' : '#1eb464'; ?>"><?php echo (int)$d['threats']; ?></div></div>
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
  <span style="margin-left:auto">Findings abertos: <b><?php echo (int)array_sum($sev); ?></b></span>
</div>

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
          <td class="num"><span class="riskbar" style="width:<?php echo $score; ?>px"></span> <?php echo $score; ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <?php endif; ?>
  </div>

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
</div>

<div class="footer">Atualização automática a cada 60 segundos · Gerado em <?php echo date('d/m/Y H:i:s'); ?> · Plugin Tanium para GLPI</div>

<script>
function tick() {
  var d = new Date();
  document.getElementById('clock').textContent =
    String(d.getHours()).padStart(2, '0') + ':' +
    String(d.getMinutes()).padStart(2, '0') + ':' +
    String(d.getSeconds()).padStart(2, '0');
}
tick();
setInterval(tick, 1000);
setTimeout(function () { location.reload(); }, 60000);
</script>
</body>
</html>
