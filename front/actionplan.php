<?php

/**
 * Action plan — what to do next, ranked by the fleet risk each action removes.
 *
 * The counterpart to the vulnerability list: that one answers "how bad is it",
 * this one answers "what do I do first".
 */

use GlpiPlugin\Tanium\ActionPlan;
use GlpiPlugin\Tanium\Lifecycle;

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$limit = min(100, max(5, (int) ($_GET['limit'] ?? 25)));
$type  = trim($_GET['type'] ?? '');

$plan    = ActionPlan::build(200);
$actions = $plan['actions'];

if ($type !== '') {
    $actions = array_values(array_filter($actions, static fn(array $a): bool => $a['type'] === $type));
}
$actions = array_slice($actions, 0, $limit);

// Headline: how much of the fleet's risk the shown plan would remove.
$planRemoves = 0;
foreach ($actions as $a) {
    $planRemoves += (int) $a['risk_removed'];
}
$fleetRisk = max(1, (int) $plan['fleet']['risk_total']);

$webDir  = Plugin::getWebDir('tanium');
$logoUrl = $webDir . '/public/img/tanium-logo.svg';

$typeLabels = [
    'patch'   => __('Patch', 'tanium'),
    'cve'     => __('CVE', 'tanium'),
    'migrate' => __('Migration', 'tanium'),
];
$typeIcons = [
    'patch'   => 'ti ti-rocket',
    'cve'     => 'ti ti-shield-exclamation',
    'migrate' => 'ti ti-refresh-alert',
];

Html::header(__('Tanium — Action Plan', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<!-- Hero -->
<div class="tanium-dashboard-hero">
    <div class="tanium-hero-brand">
        <img src="<?= $logoUrl ?>" alt="Tanium" class="tanium-hero-logo"/>
        <div>
            <div class="tanium-hero-title"><?= __('Action Plan', 'tanium') ?></div>
            <div class="tanium-hero-sub">
                <?= __('Ranked by how much fleet risk each action actually removes — not by severity alone', 'tanium') ?>
                &nbsp;·&nbsp; <?= date('d/m/Y H:i') ?>
            </div>
        </div>
    </div>
    <div class="tanium-hero-actions">
        <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary">
            <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
        </a>
        <button onclick="window.print()" class="tanium-btn tanium-btn-secondary">
            <span class="ti ti-printer"></span> <?= __('Print', 'tanium') ?>
        </button>
    </div>
</div>

<!-- Summary -->
<div class="tanium-kpi-grid">
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value"><?= number_format((int) $plan['fleet']['endpoints']) ?></div>
        <div class="tanium-kpi-label"><?= __('Endpoints', 'tanium') ?></div>
    </div>
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value"><?= number_format((float) $plan['fleet']['avg'], 1) ?></div>
        <div class="tanium-kpi-label"><?= __('Average risk', 'tanium') ?></div>
    </div>
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value" style="color:#1eb464"><?= number_format($planRemoves) ?></div>
        <div class="tanium-kpi-label"><?= __('Risk points this plan removes', 'tanium') ?></div>
    </div>
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value" style="color:#1eb464"><?= round($planRemoves / $fleetRisk * 100) ?>%</div>
        <div class="tanium-kpi-label"><?= __('of the fleet total', 'tanium') ?></div>
    </div>
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value"><?= count($actions) ?></div>
        <div class="tanium-kpi-label"><?= __('Actions listed', 'tanium') ?></div>
    </div>
</div>

<!-- Filters -->
<div class="tanium-card" style="margin-bottom:14px">
    <div class="tanium-card-body">
        <form method="get" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
            <select name="type" class="tanium-input tanium-select" style="max-width:200px">
                <option value=""><?= __('All action types', 'tanium') ?></option>
                <?php foreach ($typeLabels as $key => $label): ?>
                <option value="<?= $key ?>" <?= $type === $key ? 'selected' : '' ?>><?= htmlspecialchars($label) ?></option>
                <?php endforeach; ?>
            </select>
            <select name="limit" class="tanium-input tanium-select" style="max-width:140px">
                <?php foreach ([10, 25, 50, 100] as $n): ?>
                <option value="<?= $n ?>" <?= $limit === $n ? 'selected' : '' ?>><?= sprintf(__('top %d', 'tanium'), $n) ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="tanium-btn tanium-btn-primary">
                <span class="ti ti-filter"></span> <?= __('Filter', 'tanium') ?>
            </button>
        </form>
    </div>
</div>

<!-- Plan -->
<div class="tanium-card">
    <div class="tanium-card-body tanium-p0">
        <?php if (!$actions): ?>
        <p class="tanium-empty"><?= __('Nothing to do — no open findings. Run a sync first if that seems wrong.', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th class="tanium-center">#</th>
                    <th><?= __('Action', 'tanium') ?></th>
                    <th class="tanium-center"><?= __('Type', 'tanium') ?></th>
                    <th class="tanium-center"><?= __('Endpoints', 'tanium') ?></th>
                    <th class="tanium-center"><?= __('Findings closed', 'tanium') ?></th>
                    <th class="tanium-center" title="<?= __('Total risk points removed across the fleet', 'tanium') ?>">
                        <?= __('Risk removed', 'tanium') ?>
                    </th>
                    <th class="tanium-center"><?= __('Fleet average', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($actions as $i => $a): ?>
                <tr>
                    <td class="tanium-center tanium-mono tanium-muted"><?= $i + 1 ?></td>
                    <td>
                        <?php if ($a['type'] === 'cve'): ?>
                            <a href="<?= $webDir ?>/front/vulnerabilities.php?search=<?= urlencode((string) $a['key']) ?>" class="tanium-link">
                                <?= htmlspecialchars((string) $a['title']) ?>
                            </a>
                            <?php if (!empty($a['kev'])): ?>
                                <span class="tanium-badge tanium-badge-critical" style="font-size:.62rem">&#128293; KEV</span>
                            <?php endif; ?>
                        <?php elseif ($a['type'] === 'migrate'): ?>
                            <strong><?= htmlspecialchars((string) $a['title']) ?></strong>
                            <div class="tanium-small tanium-trend-bad">
                                <?= sprintf(
                                    __('unsupported since %1$s — %2$d days without security fixes', 'tanium'),
                                    Html::convDate((string) $a['eol_date']),
                                    (int) $a['days_overdue']
                                ) ?>
                            </div>
                        <?php else: ?>
                            <?= htmlspecialchars((string) $a['title']) ?>
                            <div class="tanium-small tanium-muted tanium-mono"><?= htmlspecialchars((string) $a['key']) ?></div>
                        <?php endif; ?>
                    </td>
                    <td class="tanium-center">
                        <span class="tanium-badge <?= $a['type'] === 'migrate' ? 'tanium-badge-critical' : 'tanium-badge-muted' ?>">
                            <span class="<?= $typeIcons[$a['type']] ?? '' ?>"></span>
                            <?= htmlspecialchars($typeLabels[$a['type']] ?? $a['type']) ?>
                        </span>
                    </td>
                    <td class="tanium-center tanium-mono"><?= number_format((int) $a['endpoints']) ?></td>
                    <td class="tanium-center tanium-mono"><?= number_format((int) $a['findings']) ?></td>
                    <td class="tanium-center tanium-mono tanium-trend-good" style="font-weight:700">
                        −<?= number_format((int) $a['risk_removed']) ?>
                    </td>
                    <td class="tanium-center tanium-mono tanium-small">
                        −<?= number_format((float) $a['avg_impact'], 2) ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>
</div>

<div class="tanium-card" style="margin-top:14px">
    <div class="tanium-card-body tanium-small tanium-muted">
        <p style="margin-top:0">
            <strong><?= __('How the ranking works:', 'tanium') ?></strong>
            <?= __('every candidate action is simulated against the real risk model — the score of each affected endpoint is recomputed as if the action had been completed, and the points freed are summed across the fleet. That is why one cumulative update missing on 99 machines can outrank a single critical CVE, and why a tool like the Malicious Software Removal Tool ranks low despite being missing almost everywhere: closing it barely moves any score.', 'tanium') ?>
        </p>
        <p style="margin-bottom:0">
            <strong><?= __('Migration actions', 'tanium') ?></strong>
            <?= sprintf(
                __('carry the whole current risk of the affected endpoints, because on an end-of-support system the patch and CVE actions above simply do not exist — no fix is coming. End-of-support dates reviewed on %s.', 'tanium'),
                Html::convDate(Lifecycle::REVIEWED_ON)
            ) ?>
        </p>
    </div>
</div>

</div><!-- .tanium-page-wrap -->

<style>
@media print {
    #header, #footer, .tanium-hero-actions, form, nav, .sidebar, header { display: none !important; }
    .tanium-page-wrap { padding: 0 !important; }
}
</style>

<?php Html::footer();
