<?php

/**
 * Tanium — remediation campaigns.
 *
 * The Action Plan says what to do first. This tracks what was decided, until
 * it is actually gone from the fleet.
 */

use GlpiPlugin\Tanium\Campaign;

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$canEdit    = \GlpiPlugin\Tanium\Profile::hasSyncRight();
$showClosed = !empty($_GET['closed']);
$detailId   = (int)($_GET['id'] ?? 0);
$webDir     = Plugin::getWebDir('tanium');

Html::header(__('Tanium — Campaigns', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<?php if ($detailId > 0 && ($c = Campaign::get($detailId)) !== null): ?>
    <?php $remaining = Campaign::remainingEndpoints((string)$c['target_type'], (string)$c['target_key']); ?>
    <div class="tanium-card">
        <div class="tanium-card-header">
            <span><?= htmlspecialchars((string)$c['name']) ?></span>
            <a href="campaigns.php" class="tanium-btn tanium-btn-secondary tanium-btn-sm" style="margin-left:auto">
                <?= __('Back to campaigns', 'tanium') ?>
            </a>
        </div>
        <div class="tanium-card-body">
            <div class="tanium-overview-grid">
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Progress', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-stat-big"><?= (int)$c['percent'] ?>%</div>
                    <div class="tanium-small"><?= sprintf(__('%1$d of %2$d endpoints cleared', 'tanium'), (int)$c['done'], (int)$c['baseline_count']) ?></div>
                </div>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Still affected', 'tanium') ?></div>
                    <div class="tanium-stat-value tanium-stat-big" style="color:<?= $c['remaining'] > 0 ? '#e8212a' : '#1eb464' ?>">
                        <?= (int)$c['remaining'] ?>
                    </div>
                </div>
                <div class="tanium-stat-box">
                    <div class="tanium-stat-label"><?= __('Due date', 'tanium') ?></div>
                    <div class="tanium-stat-value">
                        <?= $c['due_date'] ? Html::convDate($c['due_date']) : '—' ?>
                    </div>
                    <?php if ($c['days_left'] !== null): ?>
                    <div class="tanium-small" style="color:<?= $c['is_overdue'] ? '#e8212a' : '#7a8da8' ?>">
                        <?= $c['is_overdue']
                            ? sprintf(__('%d day(s) overdue', 'tanium'), abs((int)$c['days_left']))
                            : sprintf(__('%d day(s) left', 'tanium'), (int)$c['days_left']) ?>
                    </div>
                    <?php endif; ?>
                </div>
            </div>

            <div style="background:rgba(255,255,255,.06);border-radius:8px;height:14px;overflow:hidden;margin:8px 0 4px">
                <div style="height:100%;width:<?= (int)$c['percent'] ?>%;background:<?= $c['is_complete'] ? '#1eb464' : '#1a6dff' ?>"></div>
            </div>
            <p class="tanium-small">
                <?= sprintf(__('Target: %1$s (%2$s). Baseline taken when the campaign opened.', 'tanium'),
                    '<code>' . htmlspecialchars((string)$c['target_key']) . '</code>',
                    htmlspecialchars((string)$c['target_type'])) ?>
            </p>
            <?php if (!empty($c['notes'])): ?>
                <p class="tanium-small"><?= nl2br(htmlspecialchars((string)$c['notes'])) ?></p>
            <?php endif; ?>
        </div>
    </div>

    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Endpoints still affected', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body tanium-p0">
            <?php if ($remaining === []): ?>
                <p class="tanium-empty"><?= __('None left — this target is gone from the fleet.', 'tanium') ?></p>
            <?php else: ?>
            <table class="tanium-table">
                <thead>
                    <tr>
                        <th><?= __('Endpoint', 'tanium') ?></th>
                        <th><?= __('Operating system', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Risk', 'tanium') ?></th>
                        <th><?= __('Affected since', 'tanium') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($remaining as $r): ?>
                    <tr>
                        <td class="tanium-mono"><?= htmlspecialchars((string)($r['tanium_name'] ?: $r['tanium_eid'])) ?></td>
                        <td class="tanium-small"><?= htmlspecialchars((string)($r['os_name'] ?? '—')) ?></td>
                        <td class="tanium-center tanium-mono"><?= (int)$r['risk_score'] ?></td>
                        <td class="tanium-small"><?= $r['since'] ? Html::convDateTime($r['since']) : '—' ?></td>
                        <td>
                            <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode((string)$r['tanium_eid']) ?>" class="tanium-link tanium-small">
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

<?php else: ?>
    <?php $campaigns = Campaign::all($showClosed); ?>

    <div class="tanium-card">
        <div class="tanium-card-header">
            <img src="<?= $webDir ?>/public/img/tanium-logo.svg" alt="Tanium" class="tanium-header-logo"/>
            <span><?= __('Remediation campaigns', 'tanium') ?></span>
            <a href="campaigns.php?closed=<?= $showClosed ? 0 : 1 ?>" class="tanium-btn tanium-btn-secondary tanium-btn-sm" style="margin-left:auto">
                <?= $showClosed ? __('Active only', 'tanium') : __('Include closed', 'tanium') ?>
            </a>
        </div>
        <div class="tanium-card-body">
            <p class="tanium-small" style="margin-top:0">
                <?= __('The Action Plan re-ranks every time the data moves, which is right for triage and useless for follow through. A campaign records what was decided — target, owner, date — and measures the fleet against where it stood that day.', 'tanium') ?>
            </p>

            <?php if ($campaigns === []): ?>
                <p class="tanium-empty"><?= __('No campaigns yet. Pick a target below to start one.', 'tanium') ?></p>
            <?php else: ?>
            <table class="tanium-table">
                <thead>
                    <tr>
                        <th><?= __('Campaign', 'tanium') ?></th>
                        <th style="width:24%"><?= __('Progress', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Left', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Baseline', 'tanium') ?></th>
                        <th><?= __('Due', 'tanium') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($campaigns as $c): ?>
                    <tr>
                        <td>
                            <a href="campaigns.php?id=<?= (int)$c['id'] ?>" class="tanium-link">
                                <?= htmlspecialchars((string)$c['name']) ?>
                            </a>
                            <?php if ($c['status'] !== 'active'): ?>
                                <span class="tanium-badge tanium-badge-muted"><?= htmlspecialchars((string)$c['status']) ?></span>
                            <?php elseif ($c['is_complete']): ?>
                                <span class="tanium-badge tanium-badge-success"><?= __('eradicated', 'tanium') ?></span>
                            <?php elseif ($c['is_overdue']): ?>
                                <span class="tanium-badge tanium-badge-critical"><?= __('overdue', 'tanium') ?></span>
                            <?php endif; ?>
                            <div class="tanium-small tanium-mono" style="color:#7a8da8"><?= htmlspecialchars((string)$c['target_key']) ?></div>
                        </td>
                        <td>
                            <div style="background:rgba(255,255,255,.06);border-radius:6px;height:10px;overflow:hidden">
                                <div style="height:100%;width:<?= (int)$c['percent'] ?>%;background:<?= $c['is_complete'] ? '#1eb464' : ($c['is_overdue'] ? '#e8212a' : '#1a6dff') ?>"></div>
                            </div>
                            <div class="tanium-small"><?= (int)$c['percent'] ?>%</div>
                        </td>
                        <td class="tanium-center tanium-mono" style="font-weight:700"><?= (int)$c['remaining'] ?></td>
                        <td class="tanium-center tanium-mono"><?= (int)$c['baseline_count'] ?></td>
                        <td class="tanium-small"><?= $c['due_date'] ? Html::convDate($c['due_date']) : '—' ?></td>
                        <td>
                            <?php if ($canEdit && $c['status'] === 'active'): ?>
                            <button class="tanium-btn-xs tanium-btn-secondary" onclick="closeCampaign(<?= (int)$c['id'] ?>)">
                                <?= __('Close', 'tanium') ?>
                            </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>

    <?php if ($canEdit): ?>
    <?php $suggestions = Campaign::suggestions(15); ?>
    <div class="tanium-card" style="margin-top:24px">
        <div class="tanium-card-header tanium-card-header-dark">
            <span><?= __('Start a campaign', 'tanium') ?></span>
        </div>
        <div class="tanium-card-body tanium-p0">
            <?php if ($suggestions === []): ?>
                <p class="tanium-empty"><?= __('Nothing left worth a campaign — every widespread target already has one.', 'tanium') ?></p>
            <?php else: ?>
            <table class="tanium-table">
                <thead>
                    <tr>
                        <th><?= __('Target', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Severity', 'tanium') ?></th>
                        <th class="tanium-center"><?= __('Endpoints affected', 'tanium') ?></th>
                        <th style="width:170px"><?= __('Due date', 'tanium') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($suggestions as $i => $s): ?>
                    <tr>
                        <td>
                            <?= htmlspecialchars($s['label']) ?>
                            <div class="tanium-small tanium-mono" style="color:#7a8da8"><?= htmlspecialchars($s['key']) ?></div>
                        </td>
                        <td class="tanium-center tanium-small"><?= htmlspecialchars($s['severity']) ?></td>
                        <td class="tanium-center tanium-mono" style="font-weight:700"><?= (int)$s['endpoints'] ?></td>
                        <td><input type="date" id="due<?= $i ?>" class="tanium-input tanium-input-sm"/></td>
                        <td>
                            <button class="tanium-btn-xs tanium-btn-primary"
                                    onclick="startCampaign(<?= htmlspecialchars(json_encode($s['key']), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($s['label']), ENT_QUOTES) ?>, <?= $i ?>)">
                                <?= __('Start', 'tanium') ?>
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>
<?php endif; ?>

</div>

<?php if ($canEdit): ?>
<script>
const _webDir = <?= json_encode($webDir) ?>;
const _csrf   = <?= json_encode(Session::getNewCSRFToken()) ?>;

async function post(payload) {
    const r = await fetch(_webDir + '/ajax/campaign.php', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
        body: JSON.stringify(payload)
    });
    return r.json();
}

async function startCampaign(key, label, idx) {
    const due = document.getElementById('due' + idx).value;
    const res = await post({action: 'create', target_type: 'patch', target_key: key, name: label, due_date: due});
    if (res.success) { location.href = 'campaigns.php?id=' + res.id; }
    else { alert(res.error || 'Erro'); }
}

async function closeCampaign(id) {
    if (!confirm(<?= json_encode(__('Close this campaign? Progress stops being tracked.', 'tanium')) ?>)) return;
    const res = await post({action: 'close', id: id});
    if (res.success) { location.reload(); } else { alert(res.error || 'Erro'); }
}
</script>
<?php endif; ?>
<?php
Html::footer();
