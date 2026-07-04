<?php

/**
 * Fleet health report ("boletim de saúde") — one verdict + grade (0-10) per
 * endpoint. Printable; exportable to PDF.
 */

use GlpiPlugin\Tanium\HealthReport;

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$rows    = HealthReport::getFleet();
$summary = HealthReport::summary($rows);

// PDF export — before any HTML output
if (($_GET['export'] ?? '') === 'pdf') {
    $pdf = \GlpiPlugin\Tanium\PdfReport::health($rows, $summary);
    if ($pdf !== null) {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="tanium-boletim-' . date('Y-m-d') . '.pdf"');
        header('Content-Length: ' . strlen($pdf));
        echo $pdf;
        exit;
    }
    Session::addMessageAfterRedirect(__('PDF generation failed — check tanium.log.', 'tanium'), false, ERROR);
}

$verdict = trim($_GET['verdict'] ?? '');
$search  = trim($_GET['search'] ?? '');
$shown   = array_values(array_filter($rows, function (array $r) use ($verdict, $search): bool {
    if ($verdict !== '' && $r['verdict'] !== $verdict) {
        return false;
    }
    if ($search !== '' && stripos((string)$r['tanium_name'], $search) === false
        && stripos((string)($r['ip_address'] ?? ''), $search) === false) {
        return false;
    }
    return true;
}));

$webDir  = Plugin::getWebDir('tanium');
$logoUrl = $webDir . '/public/img/tanium-logo.svg';

Html::header(__('Tanium — Fleet Health Report', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
?>
<div class="tanium-page-wrap">

<!-- Hero -->
<div class="tanium-dashboard-hero">
    <div class="tanium-hero-brand">
        <img src="<?= $logoUrl ?>" alt="Tanium" class="tanium-hero-logo"/>
        <div>
            <div class="tanium-hero-title"><?= __('Fleet Health Report', 'tanium') ?></div>
            <div class="tanium-hero-sub">
                <?= __('One verdict and grade per endpoint — CVEs, patches, agent, encryption and Defender combined', 'tanium') ?>
                &nbsp;·&nbsp; <?= date('d/m/Y H:i') ?>
            </div>
        </div>
    </div>
    <div class="tanium-hero-actions">
        <a href="<?= $webDir ?>/front/dashboard.php" class="tanium-btn tanium-btn-secondary">
            <span class="ti ti-arrow-left"></span> <?= __('Back', 'tanium') ?>
        </a>
        <a href="?export=pdf" class="tanium-btn tanium-btn-secondary">
            <span class="ti ti-file-type-pdf"></span> <?= __('Export PDF', 'tanium') ?>
        </a>
        <button onclick="window.print()" class="tanium-btn tanium-btn-secondary">
            <span class="ti ti-printer"></span> <?= __('Print', 'tanium') ?>
        </button>
    </div>
</div>

<!-- Summary -->
<div class="tanium-kpi-grid">
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value"><?= number_format($summary['total']) ?></div>
        <div class="tanium-kpi-label"><?= __('Endpoints', 'tanium') ?></div>
    </div>
    <div class="tanium-kpi-card">
        <div class="tanium-kpi-value" style="color:<?= $summary['avg'] !== null && $summary['avg'] >= 7 ? '#1eb464' : ($summary['avg'] >= 5 ? '#e8c42a' : '#e8212a') ?>">
            <?= $summary['avg'] !== null ? number_format($summary['avg'], 1) : '—' ?>
        </div>
        <div class="tanium-kpi-label"><?= __('Fleet average grade', 'tanium') ?></div>
    </div>
    <?php foreach (HealthReport::BANDS as [, $label, $color]):
        $n = $summary['bands'][$label] ?? 0; ?>
    <div class="tanium-kpi-card" style="cursor:pointer" onclick="location.href='?verdict=<?= urlencode($label) ?>'">
        <div class="tanium-kpi-value" style="color:<?= $color ?>"><?= number_format($n) ?></div>
        <div class="tanium-kpi-label"><?= htmlspecialchars($label) ?></div>
    </div>
    <?php endforeach; ?>
</div>

<!-- Filters -->
<div class="tanium-card" style="margin-bottom:14px">
    <div class="tanium-card-body">
        <form method="get" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
            <input type="text" name="search" class="tanium-input" style="max-width:280px"
                   placeholder="<?= __('Search by name, IP or EID...', 'tanium') ?>" value="<?= htmlspecialchars($search) ?>"/>
            <select name="verdict" class="tanium-input tanium-select" style="max-width:180px">
                <option value=""><?= __('All verdicts', 'tanium') ?></option>
                <?php foreach (HealthReport::BANDS as [, $label]): ?>
                <option value="<?= htmlspecialchars($label) ?>" <?= $verdict === $label ? 'selected' : '' ?>><?= htmlspecialchars($label) ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="tanium-btn tanium-btn-primary"><span class="ti ti-filter"></span> <?= __('Filter', 'tanium') ?></button>
            <?php if ($verdict !== '' || $search !== ''): ?>
            <a href="healthreport.php" class="tanium-btn tanium-btn-secondary"><?= __('Clear', 'tanium') ?></a>
            <?php endif; ?>
            <span class="tanium-muted" style="margin-left:auto;font-size:.83rem">
                <?= sprintf(__('%d of %d endpoints', 'tanium'), count($shown), $summary['total']) ?>
            </span>
        </form>
    </div>
</div>

<!-- Report table -->
<div class="tanium-card">
    <div class="tanium-card-body tanium-p0">
        <?php if (!$shown): ?>
        <p class="tanium-empty"><?= __('No endpoints found. Run a sync first.', 'tanium') ?></p>
        <?php else: ?>
        <table class="tanium-table">
            <thead>
                <tr>
                    <th><?= __('Endpoint', 'tanium') ?></th>
                    <th class="tanium-center"><?= __('Grade', 'tanium') ?></th>
                    <th class="tanium-center"><?= __('Verdict', 'tanium') ?></th>
                    <th><?= __('Diagnosis', 'tanium') ?></th>
                    <th class="tanium-center" title="<?= __('Open CVEs: critical / high / medium', 'tanium') ?>">CVEs</th>
                    <th class="tanium-center"><?= __('Patches', 'tanium') ?></th>
                    <th><?= __('Last seen', 'tanium') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($shown as $r): ?>
                <tr>
                    <td>
                        <a href="<?= $webDir ?>/front/endpoint.php?eid=<?= urlencode($r['tanium_eid']) ?>" class="tanium-link">
                            <?= htmlspecialchars($r['tanium_name'] ?: $r['tanium_eid']) ?>
                        </a>
                        <div class="tanium-small tanium-muted">
                            <?= htmlspecialchars($r['ip_address'] ?? '') ?><?= $r['os_name'] ? ' · ' . htmlspecialchars($r['os_name']) : '' ?>
                        </div>
                    </td>
                    <td class="tanium-center">
                        <span style="display:inline-block;min-width:44px;padding:4px 8px;border-radius:8px;font-weight:800;font-size:.95rem;background:<?= $r['verdict_color'] ?>22;color:<?= $r['verdict_color'] ?>">
                            <?= number_format($r['score'], 1) ?>
                        </span>
                    </td>
                    <td class="tanium-center">
                        <span class="tanium-badge" style="background:<?= $r['verdict_color'] ?>22;color:<?= $r['verdict_color'] ?>;border:1px solid <?= $r['verdict_color'] ?>55">
                            <?= $r['issues'] === [] ? '✓ ' : '' ?><?= htmlspecialchars($r['verdict']) ?>
                        </span>
                    </td>
                    <td class="tanium-small" style="max-width:420px">
                        <?= htmlspecialchars($r['message']) ?>
                        <?php if ((int)$r['cves_kev'] > 0): ?>
                            <span class="tanium-badge tanium-badge-critical" style="font-size:.62rem;margin-left:4px">&#128293; KEV</span>
                        <?php endif; ?>
                    </td>
                    <td class="tanium-center tanium-mono tanium-small">
                        <span style="color:#e8212a;font-weight:700"><?= (int)$r['cves_critical'] ?></span> /
                        <span style="color:#f97316;font-weight:600"><?= (int)$r['cves_high'] ?></span> /
                        <span><?= (int)$r['cves_medium'] ?></span>
                    </td>
                    <td class="tanium-center">
                        <?php if ((int)$r['missing_patches'] > 0): ?>
                            <span class="tanium-badge tanium-badge-warning"><?= (int)$r['missing_patches'] ?></span>
                        <?php else: ?>
                            <span class="tanium-badge tanium-badge-success">0</span>
                        <?php endif; ?>
                    </td>
                    <td class="tanium-small"><?= $r['last_seen'] ? Html::convDateTime($r['last_seen']) : '—' ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
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
