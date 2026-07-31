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

// A wall panel that always shows the same seven screens stops being read.
// When something happened that was not true yesterday, an extra screen is
// prepended and the rotation starts there — so the display earns attention
// back exactly when it has something to say. Empty on a quiet day, which is
// the point: an alert state that fires most days is ignored like any other.
$alerts = !empty($config['kiosk_alerts']) ? TaniumKiosk::alerts() : [];

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

/**
 * Compact headline strip for a slide.
 *
 * Every slide used to open straight into two tables, so the room had to derive
 * the conclusion from rows it cannot read at that distance. The first attempt
 * at fixing that over-corrected: one enormous number and a full sentence ate
 * the top of the screen and said less than the tables did.
 *
 * This is the middle: a moderate lead figure, a short label, and the rest of
 * the context as inline facts — more numbers on screen, less prose to read.
 *
 * @param array<string,string> $facts label => value, rendered inline
 */
$slideHead = static function (string|int $n, string $color, string $label, array $facts = []): void {
    echo '<div class="slidehead">';
    printf(
        '<div class="lead"><span class="n" style="color:%s">%s</span><span class="l">%s</span></div>',
        htmlspecialchars($color),
        htmlspecialchars(is_int($n) ? number_format($n, 0, ',', '.') : $n),
        htmlspecialchars($label)
    );
    if ($facts !== []) {
        echo '<div class="facts">';
        foreach ($facts as $k => $v) {
            printf(
                '<span class="fact"><b>%s</b><i>%s</i></span>',
                htmlspecialchars((string)$v),
                htmlspecialchars((string)$k)
            );
        }
        echo '</div>';
    }
    echo '</div>';
};

$deployStatus = static function (string $s): array {
    return match ($s) {
        'deployed'         => ['Concluído', '#1eb464'],
        'failed'           => ['Falhou', '#e8212a'],
        'rejected'         => ['Recusado', '#7a8da8'],
        'cancelled'        => ['Cancelado', '#7a8da8'],
        'pending_approval' => ['Aguardando aprovação', '#f0a030'],
        default            => ['Em andamento', '#4da3ff'],
    };
};

// ── Trend sparklines — pure inline SVG, no libraries ──────────────────────
//
// Two separate charts, deliberately. These were one plot with two polylines:
// critical CVEs scaled to their own max, fleet risk scaled to 100, drawn on top
// of each other in the same 110px box. Two y-scales on one plot make the
// alignment of the two lines arbitrary, so the picture invents a correlation
// that is not in the data — the crossings and the gaps meant nothing. Small
// multiples keep each series honest against its own axis, and each chart is a
// single series, so its title is its legend.
$sparkW = 1000;
$sparkH = 84;
$trend  = $d['risk_trend'];

/**
 * Builds the polyline points plus the end-marker for one series.
 *
 * @return array{points:string,max:float,last:float,cx:float,cy:float}|null
 */
$sparkline = static function (array $rows, string $field, ?float $fixedMax) use ($sparkW, $sparkH): ?array {
    if (count($rows) < 2) {
        return null;
    }
    $vals = array_map(static fn($p) => (float)$p[$field], $rows);
    $max  = $fixedMax ?? max(1.0, max($vals));
    $n    = count($rows) - 1;
    $pts  = '';
    $cx   = 0.0;
    $cy   = 0.0;
    foreach ($vals as $i => $v) {
        $x = round($i * $sparkW / $n, 1);
        $y = round($sparkH - ($v * ($sparkH - 14) / $max) - 7, 1);
        $pts .= $x . ',' . $y . ' ';
        $cx = $x;
        $cy = $y;
    }
    return ['points' => trim($pts), 'max' => $max, 'last' => end($vals), 'cx' => $cx, 'cy' => $cy];
};

$sparkCrit = $sparkline($trend, 'critical_cves', null);
$sparkRisk = $sparkline($trend, 'avg_risk', 100.0);

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
:root{
  --bg:#0a1628;--panel:#0f1e33;--border:#1e2d44;--text:#e8edf5;--muted:#7a8da8;--red:#e8212a;
  /* Fluid type. Every size below scales with the viewport instead of sitting at
   * a fixed px built for a monitor at arm's length. The same page has to read
   * on a 24" desk screen and on a 65" TV across a room, and the old fixed 11-15px
   * table text was unreadable at the second one. vw units do the work; the clamp
   * floors keep the desk case from shrinking. */
  --fs-micro: clamp(11px, .70vw, 20px);
  --fs-small: clamp(12px, .85vw, 24px);
  --fs-body:  clamp(15px, 1.05vw, 30px);
  --fs-h2:    clamp(14px, 1.00vw, 28px);
  --fs-tile:  clamp(40px, 3.60vw, 104px);
  --fs-tilemd:clamp(30px, 2.60vw, 76px);
  --fs-mini:  clamp(28px, 2.40vw, 68px);
  --fs-alert: clamp(38px, 3.20vw, 92px);
  --fs-alertd:clamp(20px, 1.60vw, 46px);
  --fs-clock: clamp(26px, 2.20vw, 62px);
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column}
.header{background:linear-gradient(120deg,#7a0d1f 0%,#e8212a 100%);padding:16px 32px;display:flex;align-items:center;gap:16px}
.roundel{width:42px;height:42px;border-radius:50%;background:rgba(255,255,255,.18);color:#fff;font-weight:900;font-size:22px;display:flex;align-items:center;justify-content:center}
.wordmark{font-size:clamp(22px,1.7vw,48px);font-weight:800;letter-spacing:4px;color:#fff}
.subtitle{font-size:var(--fs-small);color:#ffd6d9;margin-top:2px}
.slidetitle{margin-left:32px;font-size:clamp(18px,1.5vw,42px);font-weight:700;color:#fff;opacity:.95}
.header .right{margin-left:auto;text-align:right}
.clock{font-size:var(--fs-clock);font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.syncinfo{font-size:var(--fs-small);color:#ffd6d9}
.progress{height:4px;background:var(--border)}
.progress>div{height:100%;width:0;background:var(--red);transition:width .3s linear}
.stage{flex:1;position:relative;overflow:hidden}
.slide{position:absolute;inset:0;opacity:0;visibility:hidden;transition:opacity .6s ease;padding-bottom:16px;overflow:auto}
.slide.active{opacity:1;visibility:visible}
.alertwrap{display:flex;flex-direction:column;justify-content:center;gap:24px;height:100%;padding:0 48px}
.alertbox{border-left:10px solid;border-radius:12px;padding:28px 36px;animation:alertpulse 2.4s ease-in-out infinite}
.alertbox.lvl-critical{border-color:#e8212a;background:rgba(232,33,42,.14)}
.alertbox.lvl-warning{border-color:#f0a030;background:rgba(240,160,48,.12)}
.alerttitle{font-size:var(--fs-alert);font-weight:800;color:#fff;line-height:1.15}
.alertdetail{margin-top:12px;font-size:var(--fs-alertd);color:#c7d3e3;line-height:1.4}
@keyframes alertpulse{0%,100%{opacity:1}50%{opacity:.82}}
@media (prefers-reduced-motion:reduce){.alertbox{animation:none}}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;padding:20px 32px 0}
.grid.g4{grid-template-columns:repeat(4,1fr)}
.grid.g5{grid-template-columns:repeat(5,1fr)}
@media(max-width:1100px){.grid,.grid.g4,.grid.g5{grid-template-columns:repeat(3,1fr)}}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 20px}
.tile .label{font-size:var(--fs-small);color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.tile .value{font-size:var(--fs-tile);font-weight:800;line-height:1.1}
.tile .value.md{font-size:var(--fs-tilemd)}
.tile .sub{font-size:var(--fs-small);color:var(--muted);margin-top:2px}
/* Hero row: one dominant figure, the rest stepped down to supporting size.
 * Proportional figures on the hero — tabular-nums gives every digit the width
 * of a zero, which makes a number like 121 look loose at display size. */
.herorow{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,2fr);gap:14px;padding:20px 32px 0;align-items:stretch}
@media(max-width:1100px){.herorow{grid-template-columns:1fr}}
.herorow .grid.herogrid{grid-template-columns:repeat(3,1fr);padding:0}
.tile.hero{display:flex;flex-direction:column;justify-content:center}
/* 7vw / 190px foi longe demais: o número dominava a tela e sobrava menos
 * informação do que antes. Grande o bastante para liderar, pequeno o bastante
 * para o resto do painel continuar existindo. */
.herovalue{font-size:clamp(52px,4.6vw,116px);font-weight:800;line-height:.95;letter-spacing:-.02em}
/* Screen headline: every slide states its point before showing its tables.
 * Without it each screen was two tables side by side and the room had to
 * derive the conclusion from rows it cannot read at that distance. */
.slidehead{display:flex;align-items:center;gap:clamp(16px,2vw,44px);padding:14px 32px 0;flex-wrap:wrap}
.slidehead .lead{display:flex;align-items:baseline;gap:10px;flex:0 0 auto}
.slidehead .n{font-size:clamp(30px,2.6vw,66px);font-weight:800;line-height:1;letter-spacing:-.02em}
.slidehead .l{font-size:clamp(13px,1vw,26px);color:var(--muted);font-weight:600}
.slidehead .facts{display:flex;gap:clamp(14px,1.6vw,36px);flex-wrap:wrap;margin-left:auto}
.slidehead .fact{display:flex;flex-direction:column;line-height:1.1}
.slidehead .fact b{font-size:clamp(17px,1.5vw,38px);font-weight:700;font-variant-numeric:tabular-nums}
.slidehead .fact i{font-size:clamp(11px,.8vw,20px);color:var(--muted);font-style:normal;margin-top:2px}
.tile.mini{padding:12px 18px}
.tile.mini .value{font-size:var(--fs-mini)}
/* The 2px surface gap is what separates touching segments — not a stroke around
 * them. It also carries a real measurement: critical (#e8212a) and high
 * (#f97316) sit ΔE 13.9 apart in normal vision, under the 15 floor, so side by
 * side on a wall TV they blur into one band. The gap plus the labelled legend
 * below is the separation; hue alone was never doing the job here. */
.sevbar{display:flex;height:clamp(14px,1.1vw,30px);border-radius:7px;margin:18px 32px 0;gap:2px;background:var(--panel)}
.sevbar>div:first-child{border-radius:7px 0 0 7px}
.sevbar>div:last-child{border-radius:0 7px 7px 0}
.sevlegend{display:flex;gap:24px;padding:10px 32px 0;font-size:var(--fs-body);color:var(--muted)}
.sevlegend b{color:var(--text)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:20px 32px 0}
.panels.single{grid-template-columns:1fr}
@media(max-width:1100px){.panels{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 20px}
.panel h2{font-size:var(--fs-h2);color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:var(--fs-body)}
td,th{padding:7px 10px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
td.wrap{white-space:normal}
th{color:var(--muted);font-size:var(--fs-micro);text-transform:uppercase;letter-spacing:.5px}
td.num{font-variant-numeric:tabular-nums}
.riskbar{display:inline-block;height:8px;border-radius:4px;background:var(--red);vertical-align:middle}
.cve{font-family:Consolas,monospace;color:#ff6b71;font-weight:700}
.empty{color:var(--muted);font-size:var(--fs-body);padding:14px 0}
.footer{padding:10px 32px;font-size:var(--fs-small);color:var(--muted);display:flex;align-items:center;gap:16px}
.dots{display:flex;gap:8px;margin-left:auto}
.dots span{width:10px;height:10px;border-radius:50%;background:var(--border);transition:background .3s}
.dots span.on{background:var(--red)}
.sev-critical{color:#e8212a;font-weight:700}
.sev-high{color:#f97316;font-weight:700}
.sev-medium{color:#e8c42a;font-weight:700}
.sev-low{color:#1eb464;font-weight:700}
.badge{display:inline-block;font-size:var(--fs-micro);font-weight:800;letter-spacing:.5px;border-radius:4px;padding:2px 6px;margin-left:6px;vertical-align:middle}
.badge.kev{background:rgba(232,33,42,.18);color:#ff6b71;border:1px solid rgba(232,33,42,.5)}
.badge.rw{background:rgba(168,85,247,.15);color:#c48aff;border:1px solid rgba(168,85,247,.45)}
.wbar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:var(--fs-body)}
.wbar .wl{width:60px;color:var(--muted);font-variant-numeric:tabular-nums}
.wbar .wt{flex:1;background:var(--border);border-radius:5px;height:20px;overflow:hidden}
.wbar .wf{height:100%;background:#1eb464;border-radius:5px;min-width:2px}
.wbar .wn{width:44px;text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.trendpanel{margin:18px 32px 0;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 20px}
.trendpanel h2{font-size:var(--fs-h2);color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.trendlegend{font-size:var(--fs-small);color:var(--muted);display:flex;gap:18px;margin-top:4px}
/* Small multiples: one series per chart, each against its own axis */
.sparkrow{display:grid;grid-template-columns:1fr 1fr;gap:24px}
@media(max-width:1100px){.sparkrow{grid-template-columns:1fr}}
.sparkcell svg{width:100%;height:clamp(64px,6vw,150px);display:block}
.sparkhead{display:flex;align-items:baseline;gap:12px;margin-bottom:2px}
.sparktitle{font-size:var(--fs-small);color:var(--muted)}
.sparknow{margin-left:auto;font-size:var(--fs-h2);font-weight:800}
.sparkscale{display:flex;justify-content:space-between;font-size:var(--fs-micro);color:var(--muted);font-variant-numeric:tabular-nums}
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

<?php if ($alerts !== []): ?>
<!-- ── Tela de alerta: só existe quando há o que interromper a rotação ── -->
<section class="slide alertslide" data-title="⚠ Atenção">
  <div class="alertwrap">
    <?php foreach ($alerts as $a): ?>
    <div class="alertbox <?php echo $a['level'] === 'critical' ? 'lvl-critical' : 'lvl-warning'; ?>">
      <div class="alerttitle"><?php echo htmlspecialchars($a['title']); ?></div>
      <div class="alertdetail"><?php echo htmlspecialchars($a['detail']); ?></div>
    </div>
    <?php endforeach; ?>
  </div>
</section>
<?php endif; ?>

<!-- ── Tela 1: Visão geral ─────────────────────────────────────────────── -->
<section class="slide" data-title="Visão geral">
  <!--
    Eleven equal-sized numbers used to sit here, so nothing led and the eye had
    nowhere to land — from across a room that reads as texture, not as a status.
    One hero carries the screen (exactly one per view) and the rest step down to
    supporting size. The hero is open critical CVEs because that is the number
    the room is supposed to act on; endpoints and coverage are context for it.
  -->
  <div class="herorow">
    <div class="tile hero">
      <div class="label">CVEs críticos abertos</div>
      <div class="herovalue" style="color:#e8212a"><?php echo number_format((int)$sev['critical'], 0, ',', '.'); ?></div>
      <div class="sub">altos: <?php echo number_format((int)$sev['high'], 0, ',', '.'); ?> · findings abertos: <?php echo number_format((int)array_sum($sev), 0, ',', '.'); ?></div>
    </div>
    <div class="grid herogrid">
      <div class="tile"><div class="label">Endpoints</div><div class="value"><?php echo (int)$d['endpoints']; ?></div>
        <div class="sub">cobertura ativa: <?php echo $d['coverage_pct'] === null ? '—' : $d['coverage_pct'] . '%'; ?></div></div>
      <div class="tile"><div class="label">KEV (explorados)</div><div class="value" style="color:#f97316"><?php echo (int)$d['kev']; ?></div>
        <div class="sub">ransomware: <?php echo (int)$d['ransomware']; ?></div></div>
      <div class="tile"><div class="label">SLA compliance</div><div class="value" style="color:<?php echo $slaColor; ?>"><?php echo htmlspecialchars($slaLabel); ?></div>
        <div class="sub">vencidos: <?php echo (int)$sla['breached']; ?></div></div>
      <div class="tile"><div class="label">Agentes silenciosos &gt;<?php echo (int)$d['stale_days']; ?>d</div><div class="value" style="color:<?php echo $d['stale'] > 0 ? '#f0a030' : '#1eb464'; ?>"><?php echo (int)$d['stale']; ?></div>
        <div class="sub">de <?php echo (int)$d['endpoints']; ?> endpoints</div></div>
      <div class="tile"><div class="label">Ameaças abertas</div><div class="value" style="color:<?php echo $d['threats'] > 0 ? '#e8212a' : '#1eb464'; ?>"><?php echo (int)$d['threats']; ?></div>
        <div class="sub">Threat Response</div></div>
      <div class="tile"><div class="label">Patches ausentes</div><div class="value" style="color:<?php echo $d['patches']['critical'] > 0 ? '#e8212a' : 'inherit'; ?>"><?php echo (int)$d['patches']['total']; ?></div>
        <div class="sub"><?php echo (int)$d['patches']['critical']; ?> críticos · <?php echo (int)$d['patches']['high']; ?> altos</div></div>
    </div>
  </div>

  <!-- Findings abertos e patches ausentes subiram para o bloco do hero; repeti-los
       aqui seria o mesmo número duas vezes na mesma tela. -->
  <div class="grid g4">
    <div class="tile mini"><div class="label">Remediados 7d</div><div class="value" style="color:#1eb464"><?php echo (int)$d['remediated_7d']; ?></div></div>
    <div class="tile mini"><div class="label">Deploys em andamento</div><div class="value" style="color:#4da3ff"><?php echo (int)$d['deploys_active']; ?></div></div>
    <div class="tile mini"><div class="label">MTTR 90d</div><div class="value"><?php echo htmlspecialchars($fmtDays($mttr['overall'])); ?></div></div>
    <div class="tile mini"><div class="label">SLA no prazo</div><div class="value" style="color:#1eb464"><?php echo (int)$sla['within']; ?></div></div>
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
    <?php if ($sparkCrit === null): ?>
      <div class="empty">Histórico insuficiente — os pontos são gravados a cada sincronização.</div>
    <?php else: ?>
    <div class="sparkrow">
      <?php
      // Each series gets its own chart and its own axis. Single series per
      // chart, so the caption is the legend — no swatch box needed.
      $sparks = [
          ['spark' => $sparkCrit, 'color' => '#e8212a', 'title' => 'CVEs críticos abertos',
           'fmt' => static fn($v) => number_format($v, 0, ',', '.')],
          ['spark' => $sparkRisk, 'color' => '#4da3ff', 'title' => 'Risco médio da frota (0–100)',
           'fmt' => static fn($v) => number_format($v, 1, ',', '.')],
      ];
      foreach ($sparks as $s): $sp = $s['spark']; if ($sp === null) { continue; } ?>
      <div class="sparkcell">
        <div class="sparkhead">
          <span class="sparktitle"><?php echo htmlspecialchars($s['title']); ?></span>
          <span class="sparknow" style="color:<?php echo $s['color']; ?>"><?php echo htmlspecialchars($s['fmt']($sp['last'])); ?></span>
        </div>
        <svg viewBox="0 0 <?php echo $sparkW; ?> <?php echo $sparkH; ?>" preserveAspectRatio="none"
             role="img" aria-label="<?php echo htmlspecialchars($s['title']); ?>">
          <line x1="0" y1="<?php echo $sparkH - 7; ?>" x2="<?php echo $sparkW; ?>" y2="<?php echo $sparkH - 7; ?>"
                stroke="#1e2d44" stroke-width="1"/>
          <polyline points="<?php echo $sp['points']; ?>" fill="none" stroke="<?php echo $s['color']; ?>"
                    stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
          <!-- 2px surface ring so the end marker stays legible over the line -->
          <circle cx="<?php echo $sp['cx']; ?>" cy="<?php echo $sp['cy']; ?>" r="7"
                  fill="<?php echo $s['color']; ?>" stroke="var(--panel)" stroke-width="2"/>
        </svg>
        <div class="sparkscale">
          <span>0</span><span>máx <?php echo htmlspecialchars($s['fmt']($sp['max'])); ?></span>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>
</section>

<!-- ── Tela 2: Riscos ──────────────────────────────────────────────────── -->
<section class="slide" data-title="Riscos &amp; exploração">
  <?php
  $rb = $d['risk_bands'];
  $slideHead(
      (int)$rb['critical'],
      $rb['critical'] > 0 ? '#e8212a' : '#1eb464',
      'em risco crítico (70+)',
      [
          'risco alto (40–69)' => number_format((int)$rb['high'], 0, ',', '.'),
          'abaixo de 40'       => number_format((int)$rb['ok'], 0, ',', '.'),
          'KEV explorados'     => number_format((int)$d['kev'], 0, ',', '.'),
          'com ransomware'     => number_format((int)$d['ransomware'], 0, ',', '.'),
      ]
  );
  ?>
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
  <?php $slideHead(
      (int)$sev['critical'],
      $sev['critical'] > 0 ? '#e8212a' : '#1eb464',
      'CVEs críticos abertos',
      [
          'altos'            => number_format((int)$sev['high'], 0, ',', '.'),
          'médios'           => number_format((int)$sev['medium'], 0, ',', '.'),
          'no catálogo KEV'  => number_format((int)$d['kev'], 0, ',', '.'),
          'total de achados' => number_format((int)array_sum($sev), 0, ',', '.'),
      ]
  ); ?>
  <div class="panels">
    <div class="panel">
      <h2>🚨 CVEs críticos abertos (mais recentes)</h2>
      <?php if ($d['recent_critical'] === []): ?>
        <div class="empty">Nenhum CVE crítico aberto. 🎉</div>
      <?php else: ?>
      <table>
        <?php // Sem coluna de CVSS: nesta tabela todo achado é crítico, então
              // a nota é sempre 9.x e a coluna repetia o mesmo número seis
              // vezes, roubando largura do nome do endpoint — que é a parte
              // acionável. ?>
        <thead><tr><th>CVE</th><th>Endpoint</th><th>Detectado</th></tr></thead>
        <tbody>
        <?php foreach ($d['recent_critical'] as $r): ?>
          <tr>
            <td class="cve"><?php echo htmlspecialchars((string)$r['cve_id']); ?></td>
            <td><?php echo htmlspecialchars((string)($r['tanium_name'] ?? '—')); ?></td>
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
  <?php $slideHead(
      $slaLabel,
      $slaColor,
      'dentro do prazo',
      [
          'vencidos'                                  => number_format((int)$sla['breached'], 0, ',', '.'),
          sprintf('vencem em %dd', (int)$sla['due_soon_days']) => number_format((int)$sla['due_soon'], 0, ',', '.'),
          'no prazo'                                  => number_format((int)$sla['within'], 0, ',', '.'),
          'MTTR 90d'                                  => $fmtDays($mttr['overall']),
      ]
  ); ?>
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
  <?php $slideHead(
      (int)$d['patches']['critical'],
      $d['patches']['critical'] > 0 ? '#e8212a' : '#1eb464',
      'patches críticos ausentes',
      [
          'altos'            => number_format((int)$d['patches']['high'], 0, ',', '.'),
          'ausentes no total'=> number_format((int)$d['patches']['total'], 0, ',', '.'),
          'deploys ativos'   => number_format((int)$d['deploys_active'], 0, ',', '.'),
          'endpoints'        => number_format((int)$d['endpoints'], 0, ',', '.'),
      ]
  ); ?>
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
  <?php $slideHead(
      (int)$d['remediated_7d'],
      $d['remediated_7d'] > 0 ? '#1eb464' : '#7a8da8',
      'remediados em 7 dias',
      array_filter([
          'MTTR 90d'    => $fmtDays($mttr['overall']),
          'correções 90d' => number_format((int)$mttr['count'], 0, ',', '.'),
          'plataformas' => $d['platform'] !== [] ? (string)count($d['platform']) : null,
          'pior agora'  => $d['platform'] !== [] ? (string)$d['platform'][0]['os_platform'] : null,
      ], static fn($v) => $v !== null)
  ); ?>
  <div class="panels">
    <div class="panel">
      <h2>🧭 Postura por plataforma (pior primeiro)</h2>
      <?php if ($d['platform'] === []): ?>
        <div class="empty">Sem dados de plataforma — habilite a sincronização de detalhes de SO.</div>
      <?php else: ?>
      <table>
        <thead><tr><th>Plataforma</th><th>Endpoints</th><th>Risco médio</th><th>Críticos abertos</th></tr></thead>
        <tbody>
        <?php foreach (array_slice($d['platform'], 0, 6) as $r): $avg = (float)$r['avg_risk']; ?>
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
  <?php $slideHead(
      (int)$d['threats'],
      $d['threats'] > 0 ? '#e8212a' : '#1eb464',
      'ameaças abertas',
      [
          sprintf('mudos >%dd', (int)$d['stale_days']) => number_format((int)$d['stale'], 0, ',', '.'),
          'cobertura'  => $d['coverage_pct'] === null ? '—' : $d['coverage_pct'] . '%',
          'endpoints'  => number_format((int)$d['endpoints'], 0, ',', '.'),
      ]
  ); ?>
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
  // The alert screen, when present, is prepended — so ?slide=N must be shifted
  // by it or every pinned screen would silently point one to the left.
  var OFFSET   = <?php echo $alerts !== [] ? 1 : 0; ?>;
  var PINNED   = <?php echo $pinned; ?>; // 0 = rotate through all
  var current  = PINNED > 0 ? Math.min(slides.length - 1, PINNED - 1 + OFFSET) : 0;
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
