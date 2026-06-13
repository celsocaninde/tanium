<?php

use GlpiPlugin\Tanium\Config as TaniumConfig;
use GlpiPlugin\Tanium\Sync as TaniumSync;

include('../../../inc/includes.php');

Session::checkRight('config', UPDATE);

if (isset($_POST['run_sync'])) {
    $result = TaniumSync::run();

    $level = $result['errors'] > 0 && $result['total'] === 0 ? ERROR : INFO;
    $msg   = sprintf(
        __('Tanium sync complete — %d endpoints processed: %d created, %d updated, %d errors.', 'tanium'),
        $result['total'],
        $result['created'],
        $result['updated'],
        $result['errors']
    );
    Session::addMessageAfterRedirect($msg, true, $level);
    Html::redirect('sync.form.php');
}

$config = TaniumConfig::getConfig();
$logs   = TaniumSync::getRecentLogs(15);

Html::header(__('Tanium — Synchronization', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

    <div class="tanium-card">
        <div class="tanium-card-header">
            <img src="<?= Plugin::getWebDir('tanium') . '/public/img/tanium-logo.svg' ?>" alt="Tanium" class="tanium-header-logo"/>
            <span><?= __('Endpoint Synchronization', 'tanium') ?></span>
        </div>

        <div class="tanium-card-body">

            <div class="tanium-overview-grid">
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('API URL', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-mono">
                        <?= htmlspecialchars($config['api_url'] ?: __('Not configured', 'tanium')) ?>
                    </div>
                </div>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Last sync', 'tanium') ?></div>
                    <div class="tanium-stat-value">
                        <?= $config['last_sync'] ? Html::convDateTime($config['last_sync']) : '—' ?>
                    </div>
                </div>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Endpoints processed', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-stat-big"><?= intval($config['last_sync_count']) ?></div>
                </div>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Cron frequency', 'tanium') ?></div>
                    <div class="tanium-stat-value"><?= intval($config['cron_frequency']) ?>h</div>
                </div>
            </div>

            <form method="post" action="sync.form.php">
                <input type="hidden" name="_glpi_csrf_token" value="<?= Session::getNewCSRFToken() ?>">
                <div class="tanium-actions">
                    <button type="submit" name="run_sync" class="tanium-btn tanium-btn-primary tanium-btn-lg">
                        &#9654;&nbsp; <?= __('Run synchronization now', 'tanium') ?>
                    </button>
                    <a href="config.form.php" class="tanium-btn tanium-btn-secondary">
                        &#9881;&nbsp; <?= __('Configure', 'tanium') ?>
                    </a>
                </div>
            </form>

        </div>
    </div>

    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Sync History', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body tanium-p0">
            <?php if (empty($logs)): ?>
                <p class="tanium-empty"><?= __('No sync runs recorded yet.', 'tanium') ?></p>
            <?php else: ?>
            <table class="tanium-table">
                <thead>
                    <tr>
                        <th><?= __('Started', 'tanium') ?></th>
                        <th><?= __('Finished', 'tanium') ?></th>
                        <th><?= __('Status', 'tanium') ?></th>
                        <th><?= __('Total', 'tanium') ?></th>
                        <th><?= __('Created', 'tanium') ?></th>
                        <th><?= __('Updated', 'tanium') ?></th>
                        <th><?= __('Errors', 'tanium') ?></th>
                        <th><?= __('Message', 'tanium') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($logs as $log): ?>
                    <?php
                    $statusClass = match ($log['status']) {
                        'success' => 'tanium-badge-success',
                        'error'   => 'tanium-badge-error',
                        default   => 'tanium-badge-warning',
                    };
                    ?>
                    <tr>
                        <td><?= Html::convDateTime($log['started_at']) ?></td>
                        <td><?= $log['finished_at'] ? Html::convDateTime($log['finished_at']) : '…' ?></td>
                        <td><span class="tanium-badge <?= $statusClass ?>"><?= htmlspecialchars($log['status']) ?></span></td>
                        <td class="tanium-center"><?= intval($log['total']) ?></td>
                        <td class="tanium-center tanium-text-green"><?= intval($log['created']) ?></td>
                        <td class="tanium-center tanium-text-blue"><?= intval($log['updated']) ?></td>
                        <td class="tanium-center tanium-text-red"><?= intval($log['errors']) ?></td>
                        <td class="tanium-mono tanium-small"><?= htmlspecialchars($log['message'] ?? '') ?></td>
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
