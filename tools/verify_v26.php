<?php
/**
 * v2.6.0 verification harness — remediation trend, auto-close, patch history,
 * digest email and weekly/monthly reports, against the live database.
 * Run inside the fpm container:
 *   docker exec glpi-nginx-glpi-fpm-1 php /var/www/glpi/plugins/tanium/tools/verify_v26.php
 *
 * Seeds fake rows (eid TEST-REMED-EID), exercises the real sync code paths via
 * reflection, sends the emails through the configured transport (mailpit in
 * dev) and cleans every fake row up at the end.
 */

use Glpi\Kernel\Kernel;
use GlpiPlugin\Tanium\MonthlyReport;
use GlpiPlugin\Tanium\Notification;
use GlpiPlugin\Tanium\PdfReport;
use GlpiPlugin\Tanium\Remediation;
use GlpiPlugin\Tanium\Sync;
use GlpiPlugin\Tanium\WeeklyReport;

require '/var/www/glpi/vendor/autoload.php';
$kernel = new Kernel();
$kernel->boot();

Plugin::load('tanium');
$_SESSION['glpiactiveprofile']['plugin_tanium_read'] = READ;

global $DB;

$pass = 0;
$fail = 0;
function check(string $name, bool $ok, string $extra = ''): void {
    global $pass, $fail;
    echo ($ok ? 'PASS' : 'FAIL') . " — {$name}" . ($extra !== '' ? " ({$extra})" : '') . "\n";
    $ok ? $pass++ : $fail++;
}

const EID = 'TEST-REMED-EID';
$cveKeep  = 'CVE-2099-0001'; // stays in the payload → must remain open
$cveGone  = 'CVE-2099-0002'; // vanishes from the payload → must auto-close
$patchId  = 'KBTEST-REMED-1';

function cleanup(): void {
    global $DB;
    $DB->doQuery("DELETE FROM glpi_plugin_tanium_endpoint_cves WHERE tanium_eid = '" . EID . "'");
    $DB->doQuery("DELETE FROM glpi_plugin_tanium_cve_history   WHERE tanium_eid = '" . EID . "'");
    $DB->doQuery("DELETE FROM glpi_plugin_tanium_patches       WHERE tanium_eid = '" . EID . "'");
    $DB->doQuery("DELETE FROM glpi_plugin_tanium_patch_history WHERE tanium_eid = '" . EID . "'");
    $DB->doQuery("DELETE FROM glpi_plugin_tanium_assets        WHERE tanium_eid = '" . EID . "'");
    $DB->doQuery("DELETE FROM glpi_plugin_tanium_vulnerabilities WHERE cve_id IN ('CVE-2099-0001','CVE-2099-0002')");
}
cleanup(); // in case a previous run died halfway

// ── Seed ──────────────────────────────────────────────────────────────────
$tenDaysAgo = date('Y-m-d H:i:s', time() - 10 * 86400);
$DB->insert('glpi_plugin_tanium_assets', [
    'tanium_eid' => EID, 'tanium_name' => 'TEST-REMED-PC', 'computers_id' => 0,
    'os_name' => 'Windows Test', 'risk_score' => 50, 'date_mod' => date('Y-m-d H:i:s'),
]);
foreach ([[$cveKeep, 'critical', 9.8], [$cveGone, 'high', 8.1]] as [$cve, $sev, $cvss]) {
    $DB->insert('glpi_plugin_tanium_endpoint_cves', [
        'tanium_eid' => EID, 'cve_id' => $cve, 'computers_id' => 0,
        'cvss_score' => $cvss, 'severity' => $sev, 'status' => 'open',
        'detected_at' => $tenDaysAgo, 'date_mod' => $tenDaysAgo,
    ]);
    $DB->insert('glpi_plugin_tanium_vulnerabilities', [
        'cve_id' => $cve, 'severity' => $sev, 'cvss_score' => $cvss,
        'title' => 'Test vuln ' . $cve, 'affected_count' => 1,
        'first_detected' => $tenDaysAgo, 'last_detected' => $tenDaysAgo,
        'date_mod' => $tenDaysAgo,
    ]);
}
$DB->insert('glpi_plugin_tanium_patches', [
    'tanium_eid' => EID, 'computers_id' => 0, 'patch_id' => $patchId,
    'patch_title' => 'Test Patch KBTEST', 'severity' => 'critical',
    'status' => 'missing', 'date_mod' => $tenDaysAgo,
]);

// ── Exercise the real sync code paths (reflection: methods are private) ──
$config = ['auto_close_cves' => 1, 'cve_min_severity' => 'all'];

$ref = new ReflectionClass(Sync::class);
foreach (['remediatedCves', 'installedPatches'] as $prop) {
    $p = $ref->getProperty($prop);
    $p->setAccessible(true);
    $p->setValue(null, []);
}

$mCves = $ref->getMethod('syncEndpointCVEs');
$mCves->setAccessible(true);
// Payload contains only cveKeep → cveGone must auto-close as remediated
$mCves->invoke(null, EID, 0, [[
    'cveId' => $cveKeep, 'cvssScore' => 9.8, 'severity' => 'critical',
    'status' => 'open', 'detectedAt' => $tenDaysAgo,
]], 'TEST-REMED-PC', true, $config);

$mPatches = $ref->getMethod('syncEndpointPatches');
$mPatches->setAccessible(true);
// Empty payload with dataPresent=true ("No Patches Required") → patch installed
$mPatches->invoke(null, EID, 0, [], true, 'TEST-REMED-PC', $config);

// ── Assert DB effects ─────────────────────────────────────────────────────
$row = $DB->request(['FROM' => 'glpi_plugin_tanium_endpoint_cves', 'WHERE' => ['tanium_eid' => EID, 'cve_id' => $cveGone]])->current();
check('vanished CVE auto-closed as remediated', ($row['status'] ?? '') === 'remediated', 'status=' . ($row['status'] ?? '?'));

$row = $DB->request(['FROM' => 'glpi_plugin_tanium_endpoint_cves', 'WHERE' => ['tanium_eid' => EID, 'cve_id' => $cveKeep]])->current();
check('present CVE stays open', ($row['status'] ?? '') === 'open', 'status=' . ($row['status'] ?? '?'));

$row = $DB->request(['FROM' => 'glpi_plugin_tanium_cve_history', 'WHERE' => ['tanium_eid' => EID, 'cve_id' => $cveGone, 'new_status' => 'remediated']])->current();
check('cve_history has the remediation transition', $row !== null, 'old=' . ($row['old_status'] ?? '?'));

$row = $DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['tanium_eid' => EID]])->current();
check('missing patch reconciled to installed', ($row['status'] ?? '') === 'installed', 'status=' . ($row['status'] ?? '?'));

$row = $DB->request(['FROM' => 'glpi_plugin_tanium_patch_history', 'WHERE' => ['tanium_eid' => EID, 'new_status' => 'installed']])->current();
check('patch_history has missing→installed', $row !== null && ($row['old_status'] ?? '') === 'missing');

// ── Accumulators + digest email with PDF ──────────────────────────────────
$remediated = $ref->getProperty('remediatedCves');
$remediated->setAccessible(true);
$remediated = $remediated->getValue();
$installed  = $ref->getProperty('installedPatches');
$installed->setAccessible(true);
$installed  = $installed->getValue();

check('remediation accumulator has 1 CVE', count($remediated) === 1, 'n=' . count($remediated));
check('accumulator computed days_open ≈ 10', ($remediated[0]['days_open'] ?? -1) === 10, 'days=' . var_export($remediated[0]['days_open'] ?? null, true));
check('patch accumulator has 1 entry', count($installed) === 1, 'n=' . count($installed));

$body = Notification::buildRemediationEmailBody($remediated, $installed, 'http://localhost');
check('digest email body mentions the CVE', str_contains($body, $cveGone));
check('digest email body mentions the patch', str_contains($body, 'Test Patch KBTEST'));

$pdf = PdfReport::remediation($remediated, $installed, 'http://localhost');
check('digest PDF generated', $pdf !== null && str_starts_with((string)$pdf, '%PDF'), strlen((string)$pdf) . ' bytes');

$sent = Notification::sendEmail('teste-remediacao@teste.local', '[Tanium] TESTE digest de remediação v2.6.0', $body, [
    ['filename' => 'digest-teste.pdf', 'content' => (string)$pdf, 'mime' => 'application/pdf'],
]);
check('digest email sent through GLPI mailer', $sent);

// ── Remediation data layer ────────────────────────────────────────────────
$stats = Remediation::getStats(30);
check('getStats counts the remediated CVE', $stats['cves_remediated'] >= 1, 'cves=' . $stats['cves_remediated']);
check('getStats counts the installed patch', $stats['patches_installed'] >= 1, 'patches=' . $stats['patches_installed']);
check('getStats MTTR present (≈10d)', $stats['mttr'] !== null && $stats['mttr'] >= 9 && $stats['mttr'] <= 11, 'mttr=' . var_export($stats['mttr'], true));

$byEp = Remediation::getByEndpoint(30, 100);
$mine = array_values(array_filter($byEp, static fn(array $r): bool => $r['tanium_eid'] === EID));
check('getByEndpoint lists the endpoint', $mine !== [], 'rows=' . count($byEp));
check('getByEndpoint counts 1 CVE + 1 patch', ($mine[0]['cves_fixed'] ?? 0) === 1 && ($mine[0]['patches_fixed'] ?? 0) === 1);
check('getByEndpoint avg_days ≈ 10', ($mine[0]['avg_days'] ?? -1) >= 9 && ($mine[0]['avg_days'] ?? -1) <= 11, 'avg=' . var_export($mine[0]['avg_days'] ?? null, true));
check('getByEndpoint still_open = 1', ($mine[0]['still_open'] ?? -1) === 1);

$recent = Remediation::getRecent(30, 50);
$types  = array_count_values(array_column(array_filter($recent, static fn($e) => str_contains((string)$e['endpoint'], 'TEST-REMED')), 'type'));
check('getRecent has the CVE event', ($types['cve'] ?? 0) === 1);
check('getRecent has the patch event', ($types['patch'] ?? 0) === 1);

$series = Remediation::getWeeklySeries(12);
$lastWeek = end($series);
check('weekly series: current week counts the fixes', $lastWeek !== false && $lastWeek['cves'] >= 1 && $lastWeek['patches'] >= 1, json_encode($lastWeek));

// ── Weekly + monthly reports through the real send() path ────────────────
$cfgRow = $DB->request(['FROM' => 'glpi_plugin_tanium_configs', 'LIMIT' => 1])->current();
$savedEmail   = (string)($cfgRow['notify_email'] ?? '');
$savedWeekly  = $cfgRow['last_weekly_report'] ?? null;
$savedMonthly = $cfgRow['last_monthly_report'] ?? null;
$DB->update('glpi_plugin_tanium_configs', ['notify_email' => 'teste-relatorio@teste.local'], ['id' => $cfgRow['id']]);

$sentW = WeeklyReport::send();
check('weekly report sent (1 recipient)', $sentW === 1, 'sent=' . $sentW);

$sentM = MonthlyReport::send();
check('monthly report sent (1 recipient)', $sentM === 1, 'sent=' . $sentM);

// restore config exactly as it was
$DB->update('glpi_plugin_tanium_configs', [
    'notify_email'        => $savedEmail,
    'last_weekly_report'  => $savedWeekly,
    'last_monthly_report' => $savedMonthly,
], ['id' => $cfgRow['id']]);

// ── Cleanup ───────────────────────────────────────────────────────────────
cleanup();
$left = $DB->request(['FROM' => 'glpi_plugin_tanium_cve_history', 'WHERE' => ['tanium_eid' => EID], 'COUNT' => 'cpt'])->current();
check('fake rows cleaned up', (int)($left['cpt'] ?? -1) === 0);

echo "\n{$pass} passed, {$fail} failed\n";
exit($fail > 0 ? 1 : 0);
