<?php

namespace GlpiPlugin\Tanium;

use CommonGLPI;
use Html;
use Plugin;

/**
 * Adds a "Tanium" tab to the Computer page in GLPI.
 * Shows: EID, last seen, sync status, IP, OS, CVE summary, patches summary.
 */
class ComputerTab extends CommonGLPI {

    public static $rightname = 'computer';

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string {
        if ($item instanceof \Computer) {
            $asset = self::getAsset($item->getID());
            return $asset ? __('Tanium', 'tanium') : '';
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool {
        if (!($item instanceof \Computer)) {
            return false;
        }

        $computerId = $item->getID();
        $asset      = self::getAsset($computerId);

        if (!$asset) {
            echo '<p class="tanium-empty">' . __('This computer was not imported from Tanium.', 'tanium') . '</p>';
            return true;
        }

        $cves    = Vulnerability::getByComputer($computerId);
        $patches = self::getPatches($computerId);
        $webDir  = Plugin::getWebDir('tanium');

        $cveCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($cves as $c) {
            $s = strtolower($c['severity']);
            if (isset($cveCounts[$s])) $cveCounts[$s]++;
        }
        $missingPatches = count(array_filter($patches, fn($p) => $p['status'] === 'missing'));
        ?>
        <div class="tanium-page-wrap" style="padding:0;font-family:'Segoe UI',system-ui,sans-serif">

            <!-- Summary row -->
            <div class="tanium-tab-summary">
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('Tanium EID', 'tanium') ?></div>
                    <div class="tanium-tab-value tanium-mono"><?= htmlspecialchars($asset['tanium_eid']) ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('Last seen in Tanium', 'tanium') ?></div>
                    <div class="tanium-tab-value"><?= $asset['last_seen'] ? Html::convDateTime($asset['last_seen']) : '—' ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('IP Address', 'tanium') ?></div>
                    <div class="tanium-tab-value tanium-mono"><?= htmlspecialchars($asset['ip_address'] ?? '—') ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('MAC Address', 'tanium') ?></div>
                    <div class="tanium-tab-value tanium-mono"><?= htmlspecialchars($asset['mac_address'] ?? '—') ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('OS Version', 'tanium') ?></div>
                    <div class="tanium-tab-value"><?= htmlspecialchars(($asset['os_name'] ?? '') . ($asset['os_version'] ? ' ' . $asset['os_version'] : '')) ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('OS Build', 'tanium') ?></div>
                    <div class="tanium-tab-value tanium-mono"><?= htmlspecialchars($asset['os_build'] ?? '—') ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('Virtual', 'tanium') ?></div>
                    <div class="tanium-tab-value"><?= (int)($asset['is_virtual'] ?? 0) ? __('Yes', 'tanium') : __('No', 'tanium') ?></div>
                </div>
                <div class="tanium-tab-item">
                    <div class="tanium-tab-label"><?= __('Sync status', 'tanium') ?></div>
                    <div class="tanium-tab-value">
                        <span class="tanium-badge tanium-badge-<?= $asset['sync_status'] === 'ok' ? 'success' : 'error' ?>">
                            <?= htmlspecialchars($asset['sync_status']) ?>
                        </span>
                    </div>
                </div>
            </div>

            <!-- CVE mini summary -->
            <div class="tanium-tab-section">
                <div class="tanium-tab-section-title">
                    &#9762; <?= __('Vulnerabilities', 'tanium') ?>
                    <a href="<?= $webDir ?>/front/vulnerabilities.php" class="tanium-link tanium-small" style="margin-left:8px"><?= __('All CVEs', 'tanium') ?> →</a>
                </div>
                <?php if (empty($cves)): ?>
                    <p class="tanium-empty tanium-small"><?= __('No CVEs detected for this endpoint.', 'tanium') ?></p>
                <?php else: ?>
                <div class="tanium-tab-cve-grid">
                    <?php foreach ($cveCounts as $sev => $cnt): ?>
                    <div class="tanium-tab-cve-box tanium-sev-<?= $sev ?>">
                        <div class="tanium-tab-cve-count"><?= $cnt ?></div>
                        <div class="tanium-tab-cve-label"><?= ucfirst($sev) ?></div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <table class="tanium-table" style="margin-top:12px">
                    <thead>
                        <tr>
                            <th><?= __('CVE ID', 'tanium') ?></th>
                            <th><?= __('Severity', 'tanium') ?></th>
                            <th><?= __('CVSS', 'tanium') ?></th>
                            <th><?= __('Status', 'tanium') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach (array_slice($cves, 0, 10) as $cve): ?>
                        <tr>
                            <td class="tanium-mono">
                                <a href="https://nvd.nist.gov/vuln/detail/<?= htmlspecialchars($cve['cve_id']) ?>" target="_blank" class="tanium-link">
                                    <?= htmlspecialchars($cve['cve_id']) ?>
                                </a>
                            </td>
                            <td><span class="tanium-badge <?= Vulnerability::sevClass($cve['severity']) ?>"><?= ucfirst($cve['severity']) ?></span></td>
                            <td class="tanium-center tanium-mono"><?= $cve['cvss_score'] !== null ? number_format((float)$cve['cvss_score'], 1) : '—' ?></td>
                            <td><?= htmlspecialchars($cve['status'] ?? 'open') ?></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (count($cves) > 10): ?>
                        <tr><td colspan="4" class="tanium-center tanium-small tanium-muted">... <?= count($cves) - 10 ?> <?= __('more', 'tanium') ?></td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>

            <!-- Patches mini summary -->
            <?php if (!empty($patches)): ?>
            <div class="tanium-tab-section">
                <div class="tanium-tab-section-title">
                    &#128396; <?= __('Missing Patches', 'tanium') ?>
                    <a href="<?= $webDir ?>/front/patches.php" class="tanium-link tanium-small" style="margin-left:8px"><?= __('All patches', 'tanium') ?> →</a>
                </div>
                <table class="tanium-table">
                    <thead>
                        <tr>
                            <th><?= __('Patch / KB', 'tanium') ?></th>
                            <th><?= __('Severity', 'tanium') ?></th>
                            <th><?= __('Release date', 'tanium') ?></th>
                            <th><?= __('Status', 'tanium') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach (array_slice($patches, 0, 10) as $p): ?>
                        <tr>
                            <td>
                                <?= htmlspecialchars($p['patch_title'] ?: $p['patch_id']) ?>
                                <?php if ($p['kb_id']): ?>
                                    <span class="tanium-small tanium-mono tanium-muted">(<?= htmlspecialchars($p['kb_id']) ?>)</span>
                                <?php endif; ?>
                            </td>
                            <td><span class="tanium-badge <?= Vulnerability::sevClass($p['severity']) ?>"><?= ucfirst($p['severity']) ?></span></td>
                            <td class="tanium-small"><?= $p['release_date'] ?? '—' ?></td>
                            <td><span class="tanium-badge tanium-badge-<?= $p['status'] === 'missing' ? 'error' : 'success' ?>"><?= htmlspecialchars($p['status']) ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>

        </div>
        <?php
        return true;
    }

    private static function getAsset(int $computerId): ?array {
        global $DB;
        $row = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_assets',
            'WHERE' => ['computers_id' => $computerId],
            'LIMIT' => 1,
        ])->current();
        return $row ?: null;
    }

    private static function getPatches(int $computerId): array {
        global $DB;
        $rows = [];
        foreach ($DB->request([
            'FROM'   => 'glpi_plugin_tanium_patches',
            'WHERE'  => ['computers_id' => $computerId],
            'ORDER'  => 'severity ASC',
            'LIMIT'  => 50,
        ]) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }
}
