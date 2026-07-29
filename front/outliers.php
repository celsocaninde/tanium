<?php

/**
 * Tanium — endpoints that stand out from their own peers.
 *
 * Not "which machine has the most findings" (that is the risk list), but
 * "which machine is worse than the machines just like it" — a different
 * question with a different fix: configuration drift, not a missing patch.
 */

use GlpiPlugin\Tanium\Analytics;

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$limit  = max(10, min(200, (int)($_GET['limit'] ?? 40)));
$result = Analytics::outliers($limit);
$webDir = Plugin::getWebDir('tanium');

Html::header(__('Tanium — Outliers', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

    <div class="tanium-card">
        <div class="tanium-card-header">
            <img src="<?= $webDir ?>/public/img/tanium-logo.svg" alt="Tanium" class="tanium-header-logo"/>
            <span><?= __('Endpoints out of step with their peers', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body">
            <p class="tanium-small" style="margin-top:0">
                <?= sprintf(
                    __('Each endpoint is compared against machines with the same operating system family and the same virtual/physical nature. Only groups of %1$d or more are judged, and only endpoints carrying at least %2$sx their group median are listed. The median is used, not the average, so one very bad machine cannot redefine "normal" for everyone else.', 'tanium'),
                    Analytics::MIN_PEERS,
                    number_format(Analytics::OUTLIER_THRESHOLD, 1)
                ) ?>
            </p>

            <div class="tanium-overview-grid">
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Peer groups compared', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-stat-big"><?= (int) $result['groups'] ?></div>
                </div>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Endpoints standing out', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-stat-big" style="color:<?= $result['outliers'] === [] ? '#1eb464' : '#f0a030' ?>">
                        <?= count($result['outliers']) ?>
                    </div>
                </div>
            </div>

            <?php if ($result['outliers'] === []): ?>
                <p class="tanium-empty">
                    <?= __('No endpoint deviates meaningfully from its peers — the fleet is consistent. Findings here are fleet-wide gaps, not one-off drift.', 'tanium') ?>
                </p>
            <?php else: ?>
            <table class="tanium-table" style="margin-top:12px">
                <thead>
                    <tr>
                        <th><?= __('Endpoint', 'tanium') ?></th>
                        <th><?= __('Peer group', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Findings', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Peer median', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('How far off', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Risk', 'tanium') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($result['outliers'] as $o): ?>
                    <tr>
                        <td class="tanium-mono"><?= htmlspecialchars((string) ($o['tanium_name'] ?: $o['tanium_eid'])) ?></td>
                        <td class="tanium-small">
                            <?= htmlspecialchars((string) $o['peer_key']) ?>
                            <span style="color:#7a8da8">(<?= (int) $o['peer_count'] ?>)</span>
                        </td>
                        <td class="tanium-center tanium-mono">
                            <?= (int) $o['findings'] ?>
                            <span class="tanium-small" style="color:#7a8da8">
                                (<?= (int) $o['open_cves'] ?> CVE / <?= (int) $o['missing_patches'] ?> patch)
                            </span>
                        </td>
                        <td class="tanium-center tanium-mono"><?= number_format((float) $o['peer_median'], 1) ?></td>
                        <td class="tanium-center tanium-mono" style="font-weight:700;color:<?= $o['ratio'] >= 4 ? '#e8212a' : '#f0a030' ?>">
                            <?= number_format((float) $o['ratio'], 1) ?>×
                        </td>
                        <td class="tanium-center tanium-mono"><?= (int) $o['risk_score'] ?></td>
                        <td>
                            <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode((string) $o['tanium_eid']) ?>" class="tanium-link tanium-small">
                                <?= __('open', 'tanium') ?>
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

</div>
<?php
Html::footer();
