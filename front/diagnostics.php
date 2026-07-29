<?php

/**
 * Tanium — plugin self-diagnostics.
 *
 * Answers "is this plugin actually working?" without reading the database or
 * the log file by hand. Everything shown is derived live.
 */

use GlpiPlugin\Tanium\Diagnostics;

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$checks   = Diagnostics::checks();
$overall  = Diagnostics::worst($checks);
$crons    = Diagnostics::cronTasks();
$tables   = Diagnostics::tableSizes();
$runs     = Diagnostics::recentRuns(8);
$logLines = Diagnostics::logTail(25);
$webDir   = Plugin::getWebDir('tanium');

$badge = static fn(string $s): string => match ($s) {
    Diagnostics::ERROR => 'tanium-badge-critical',
    Diagnostics::WARN  => 'tanium-badge-warning',
    default            => 'tanium-badge-success',
};
$icon = static fn(string $s): string => match ($s) {
    Diagnostics::ERROR => 'ti ti-alert-octagon',
    Diagnostics::WARN  => 'ti ti-alert-triangle',
    default            => 'ti ti-circle-check',
};
$label = static fn(string $s): string => match ($s) {
    Diagnostics::ERROR => __('Problem', 'tanium'),
    Diagnostics::WARN  => __('Attention', 'tanium'),
    default            => __('OK', 'tanium'),
};

Html::header(__('Tanium — Diagnostics', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

    <div class="tanium-card">
        <div class="tanium-card-header">
            <img src="<?= $webDir ?>/public/img/tanium-logo.svg" alt="Tanium" class="tanium-header-logo"/>
            <span><?= __('Plugin diagnostics', 'tanium') ?></span>
            <span class="tanium-badge <?= $badge($overall) ?>" style="margin-left:auto">
                <span class="<?= $icon($overall) ?>"></span> <?= $label($overall) ?>
            </span>
        </div>
        <div class="tanium-card-body">
            <p class="tanium-small" style="margin-top:0">
                <?= __('Everything on this page is read live from the database and the cron table — it cannot go stale.', 'tanium') ?>
            </p>

            <table class="tanium-table">
                <thead>
                    <tr>
                        <th style="width:34%"><?= __('Check', 'tanium') ?></th>
                        <th style="width:12%"><?= __('Status', 'tanium') ?></th>
                        <th style="width:18%"><?= __('Value', 'tanium') ?></th>
                        <th><?= __('What it means', 'tanium') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($checks as $c): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($c['label']) ?></strong></td>
                        <td><span class="tanium-badge <?= $badge($c['status']) ?>"><?= $label($c['status']) ?></span></td>
                        <td class="tanium-mono"><?= htmlspecialchars($c['value']) ?></td>
                        <td class="tanium-small"><?= htmlspecialchars($c['detail']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Scheduled tasks', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body tanium-p0">
            <table class="tanium-table">
                <thead>
                    <tr>
                        <th><?= __('Task', 'tanium') ?></th>
                        <th><?= __('State', 'tanium') ?></th>
                        <th><?= __('Last run', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Every', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Status', 'tanium') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($crons as $t): ?>
                    <tr>
                        <td class="tanium-mono"><?= htmlspecialchars($t['name']) ?></td>
                        <td><?= htmlspecialchars($t['state']) ?></td>
                        <td>
                            <?= $t['lastrun'] ? Html::convDateTime($t['lastrun']) : '—' ?>
                            <?php if ($t['late_hours'] !== null && $t['late_hours'] >= 24): ?>
                                <span class="tanium-small" style="color:#f97316">
                                    (<?= sprintf(__('%d day(s) ago', 'tanium'), intdiv($t['late_hours'], 24)) ?>)
                                </span>
                            <?php endif; ?>
                        </td>
                        <td class="tanium-center tanium-mono">
                            <?= $t['frequency'] >= 3600
                                ? sprintf(__('%dh', 'tanium'), intdiv($t['frequency'], 3600))
                                : sprintf(__('%dmin', 'tanium'), intdiv($t['frequency'], 60)) ?>
                        </td>
                        <td class="tanium-center">
                            <span class="tanium-badge <?= $badge($t['status']) ?>"><?= $label($t['status']) ?></span>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <p class="tanium-small" style="padding:10px 16px;margin:0">
                <?= __('A task left in "running" after its process was killed is never scheduled again by GLPI. The daily purge task releases it automatically; the Synchronize screen releases it on demand.', 'tanium') ?>
            </p>
        </div>
    </div>

    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Recent synchronizations', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body tanium-p0">
            <table class="tanium-table">
                <thead>
                    <tr>
                        <th><?= __('Started', 'tanium') ?></th>
                        <th><?= __('Duration', 'tanium') ?></th>
                        <th><?= __('Status', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Total', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Errors', 'tanium') ?></th>
                        <th><?= __('Message', 'tanium') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($runs as $r): ?>
                    <?php
                    $dur = ($r['finished_at'] && $r['started_at'])
                        ? max(0, strtotime($r['finished_at']) - strtotime($r['started_at']))
                        : null;
                    ?>
                    <tr>
                        <td><?= Html::convDateTime($r['started_at']) ?></td>
                        <td class="tanium-mono">
                            <?= $dur === null ? '—' : sprintf('%dm%02ds', intdiv($dur, 60), $dur % 60) ?>
                        </td>
                        <td>
                            <span class="tanium-badge <?= $r['status'] === 'success' ? 'tanium-badge-success' : ($r['status'] === 'error' ? 'tanium-badge-critical' : 'tanium-badge-warning') ?>">
                                <?= htmlspecialchars($r['status']) ?>
                            </span>
                        </td>
                        <td class="tanium-center tanium-mono"><?= (int) $r['total'] ?></td>
                        <td class="tanium-center tanium-mono"><?= (int) $r['errors'] ?></td>
                        <td class="tanium-small tanium-mono"><?= htmlspecialchars((string) ($r['message'] ?? '')) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Stored data', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body">
            <div class="tanium-overview-grid">
            <?php foreach ($tables as $t): ?>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label tanium-mono"><?= htmlspecialchars($t['table']) ?></div>
                    <div class="tanium-stat-value tanium-stat-big"><?= number_format($t['rows']) ?></div>
                </div>
            <?php endforeach; ?>
            </div>
            <p class="tanium-small">
                <?= __('An empty table usually means a capability nobody enabled yet, not a failure.', 'tanium') ?>
            </p>
        </div>
    </div>

    <?php if ($logLines !== []): ?>
    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Recent log entries', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body">
            <pre class="tanium-mono tanium-small" style="white-space:pre-wrap;word-break:break-word;margin:0;max-height:340px;overflow:auto"><?php
                echo htmlspecialchars(implode("\n", $logLines));
            ?></pre>
        </div>
    </div>
    <?php endif; ?>

</div>
<?php
Html::footer();
