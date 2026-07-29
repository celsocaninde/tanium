<?php

/**
 * Tanium — burn-down: is the queue shrinking, and does the work stay done?
 *
 * The dashboard shows the stock of findings. This shows the flow, which is the
 * only thing that says whether the effort is winning.
 */

use GlpiPlugin\Tanium\Analytics;

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$weeks  = max(4, min(52, (int)($_GET['weeks'] ?? 12)));
$days   = max(7, min(365, (int)($_GET['days'] ?? 90)));
$bd     = Analytics::burndown($weeks);
$reinc  = Analytics::reincidence($days);
$webDir = Plugin::getWebDir('tanium');

/** Forecast wording: "never" is a real answer and must not read like a date. */
$forecast = static function (array $b): array {
    if ($b['backlog'] === 0) {
        return ['—', __('Nothing open.', 'tanium'), '#1eb464'];
    }
    if ($b['weeks_to_zero'] === null) {
        return [
            __('never at this rate', 'tanium'),
            __('More is opening than closing — the backlog is growing.', 'tanium'),
            '#e8212a',
        ];
    }
    $w = (int) $b['weeks_to_zero'];
    return [
        sprintf(_n('%d week', '%d weeks', $w, 'tanium'), $w),
        sprintf(__('At the current net rate of %s per week.', 'tanium'), number_format((float) $b['net_weekly'], 1)),
        $w <= 26 ? '#1eb464' : '#f0a030',
    ];
};

// Sparkline points for opened vs closed, scaled to the tallest bar.
$flow = $bd['flow'];
$maxY = 1;
foreach ($flow as $f) {
    $maxY = max($maxY, $f['cve_opened'] + $f['patch_opened'], $f['cve_closed'] + $f['patch_closed']);
}

Html::header(__('Tanium — Burn-down', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

    <div class="tanium-card">
        <div class="tanium-card-header">
            <img src="<?= $webDir ?>/public/img/tanium-logo.svg" alt="Tanium" class="tanium-header-logo"/>
            <span><?= __('Are we winning?', 'tanium') ?></span>
            <form method="get" style="margin-left:auto;display:flex;gap:8px;align-items:center">
                <label class="tanium-small"><?= __('Weeks', 'tanium') ?></label>
                <input type="number" name="weeks" min="4" max="52" value="<?= $weeks ?>" class="tanium-input tanium-input-sm" style="width:80px"/>
                <button type="submit" class="tanium-btn tanium-btn-secondary tanium-btn-sm"><?= __('Apply', 'tanium') ?></button>
            </form>
        </div>
        <div class="tanium-card-body">

            <div class="tanium-overview-grid">
            <?php foreach ([['cve', __('CVEs', 'tanium')], ['patch', __('Patches', 'tanium')]] as [$key, $title]): ?>
                <?php [$fcText, $fcHint, $fcColor] = $forecast($bd[$key]); ?>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= $title ?> — <?= __('open now', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-stat-big"><?= number_format($bd[$key]['backlog']) ?></div>
                    <div class="tanium-small" style="margin-top:8px">
                        <?= sprintf(__('opening %s/week · closing %s/week', 'tanium'),
                            number_format((float) $bd[$key]['opened_weekly'], 1),
                            number_format((float) $bd[$key]['closed_weekly'], 1)) ?>
                    </div>
                    <div style="margin-top:10px;font-weight:700;color:<?= $fcColor ?>"><?= htmlspecialchars($fcText) ?></div>
                    <div class="tanium-small"><?= htmlspecialchars($fcHint) ?></div>
                </div>
            <?php endforeach; ?>
            </div>

            <p class="tanium-small">
                <?= __('The current, still-running week is excluded from the averages — counting a partial week always makes the forecast look worse than it is.', 'tanium') ?>
            </p>

            <table class="tanium-table" style="margin-top:16px">
                <thead>
                    <tr>
                        <th><?= __('Week', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('CVEs opened', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('CVEs closed', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Patches appeared', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Patches installed', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Net', 'tanium') ?></th>
                        <th style="width:30%"></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach (array_reverse($flow) as $f): ?>
                    <?php
                    $opened = $f['cve_opened'] + $f['patch_opened'];
                    $closed = $f['cve_closed'] + $f['patch_closed'];
                    $net    = $closed - $opened;
                    $wOpen  = (int) round($opened * 100 / $maxY);
                    $wClose = (int) round($closed * 100 / $maxY);
                    ?>
                    <tr>
                        <td class="tanium-mono"><?= htmlspecialchars($f['week']) ?></td>
                        <td class="tanium-center tanium-mono"><?= number_format($f['cve_opened']) ?></td>
                        <td class="tanium-center tanium-mono" style="color:#1eb464"><?= number_format($f['cve_closed']) ?></td>
                        <td class="tanium-center tanium-mono"><?= number_format($f['patch_opened']) ?></td>
                        <td class="tanium-center tanium-mono" style="color:#1eb464"><?= number_format($f['patch_closed']) ?></td>
                        <td class="tanium-center tanium-mono" style="font-weight:700;color:<?= $net >= 0 ? '#1eb464' : '#e8212a' ?>">
                            <?= $net > 0 ? '+' : '' ?><?= number_format($net) ?>
                        </td>
                        <td>
                            <div style="display:flex;flex-direction:column;gap:2px">
                                <div style="height:6px;width:<?= $wOpen ?>%;background:#e8212a;border-radius:3px" title="<?= __('opened', 'tanium') ?>"></div>
                                <div style="height:6px;width:<?= $wClose ?>%;background:#1eb464;border-radius:3px" title="<?= __('closed', 'tanium') ?>"></div>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Does the work stay done?', 'tanium') ?></span>
            <form method="get" style="margin-left:auto;display:flex;gap:8px;align-items:center">
                <input type="hidden" name="weeks" value="<?= $weeks ?>"/>
                <label class="tanium-small"><?= __('Days', 'tanium') ?></label>
                <input type="number" name="days" min="7" max="365" value="<?= $days ?>" class="tanium-input tanium-input-sm" style="width:80px"/>
                <button type="submit" class="tanium-btn tanium-btn-secondary tanium-btn-sm"><?= __('Apply', 'tanium') ?></button>
            </form>
        </div>
        <div class="tanium-card-body">
            <div class="tanium-overview-grid">
            <?php foreach ([['patch', __('Patches reinstalled', 'tanium')], ['cve', __('CVEs reopened', 'tanium')]] as [$key, $title]): ?>
                <?php $pct = (int) round($reinc[$key]['rate'] * 100); ?>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= $title ?></div>
                    <div class="tanium-stat-value tanium-stat-big" style="color:<?= $pct >= 20 ? '#e8212a' : ($pct >= 5 ? '#f0a030' : '#1eb464') ?>">
                        <?= $pct ?>%
                    </div>
                    <div class="tanium-small" style="margin-top:8px">
                        <?= sprintf(__('%1$s came back out of %2$s closed in %3$d days', 'tanium'),
                            number_format($reinc[$key]['reopened']),
                            number_format($reinc[$key]['closed']),
                            $reinc['days']) ?>
                    </div>
                </div>
            <?php endforeach; ?>
            </div>

            <p class="tanium-small">
                <?= __('A high rate is rarely the team repeating itself: it usually means a base image still shipping the old package, a policy putting it back, or a repository serving an outdated version. One root cause instead of hundreds of repeated fixes.', 'tanium') ?>
            </p>

            <?php if ($reinc['offenders'] !== []): ?>
            <table class="tanium-table" style="margin-top:12px">
                <thead>
                    <tr>
                        <th><?= __('Endpoint', 'tanium') ?></th>
                        <th><?= __('Operating system', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Times reverted', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Distinct patches', 'tanium') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($reinc['offenders'] as $o): ?>
                    <tr>
                        <td class="tanium-mono"><?= htmlspecialchars((string) ($o['tanium_name'] ?? $o['tanium_eid'])) ?></td>
                        <td class="tanium-small"><?= htmlspecialchars((string) ($o['os_name'] ?? '—')) ?></td>
                        <td class="tanium-center tanium-mono" style="font-weight:700"><?= (int) $o['reopened'] ?></td>
                        <td class="tanium-center tanium-mono"><?= (int) $o['distinct_patches'] ?></td>
                        <td>
                            <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode((string) $o['tanium_eid']) ?>" class="tanium-link tanium-small">
                                <?= __('open', 'tanium') ?>
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php else: ?>
            <p class="tanium-empty"><?= __('Nothing has come back in this window — the fixes are holding.', 'tanium') ?></p>
            <?php endif; ?>
        </div>
    </div>

</div>
<?php
Html::footer();
