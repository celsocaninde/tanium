<?php
/**
 * v2.0.0 verification harness — exercises the new-feature code paths against
 * the live database. Run inside the fpm container:
 *   docker exec glpi-nginx-glpi-fpm-1 php /var/www/glpi/plugins/tanium/tools/verify_v2.php
 */

use Glpi\Kernel\Kernel;

require '/var/www/glpi/vendor/autoload.php';
$kernel = new Kernel();
$kernel->boot();

Plugin::load('tanium');

$pass = 0;
$fail = 0;
function check(string $name, bool $ok, string $extra = ''): void {
    global $pass, $fail;
    echo ($ok ? 'PASS' : 'FAIL') . " — {$name}" . ($extra !== '' ? " ({$extra})" : '') . "\n";
    $ok ? $pass++ : $fail++;
}

// 1) Dashboard cards
$cards = GlpiPlugin\Tanium\DashboardCards::register([]);
check('dashboard_cards hook returns 7 cards', count($cards) === 7, (string)count($cards));
foreach (['cardEndpoints', 'cardCriticalFindings', 'cardKevFindings', 'cardSlaCompliance', 'cardStaleAgents', 'cardOpenThreats'] as $m) {
    try {
        $r = GlpiPlugin\Tanium\DashboardCards::$m();
        check("provider {$m}", isset($r['number']) && is_numeric($r['number']), 'number=' . $r['number']);
    } catch (Throwable $e) {
        check("provider {$m}", false, $e->getMessage());
    }
}
try {
    $sev = GlpiPlugin\Tanium\DashboardCards::cardFindingsBySeverity();
    check('provider cardFindingsBySeverity', count($sev['data']) === 4);
} catch (Throwable $e) {
    check('provider cardFindingsBySeverity', false, $e->getMessage());
}

// 2) Cross-plugin correlation
$sources = GlpiPlugin\Tanium\CrossPlugin::sources();
check('CrossPlugin::sources runs', is_array($sources), json_encode($sources));
global $DB;
$someCves = [];
foreach ($DB->request(['SELECT' => ['cve_id'], 'FROM' => 'glpi_plugin_tanium_vulnerabilities', 'LIMIT' => 20]) as $r) {
    $someCves[] = $r['cve_id'];
}
try {
    $map = GlpiPlugin\Tanium\CrossPlugin::forCves($someCves);
    check('CrossPlugin::forCves runs', is_array($map), 'matches=' . count($map));
} catch (Throwable $e) {
    check('CrossPlugin::forCves runs', false, $e->getMessage());
}

// 3) SLA payload builders
$stats = GlpiPlugin\Tanium\Sla::getStats();
$p = GlpiPlugin\Tanium\Notification::buildSlaBreachPayload($stats, GlpiPlugin\Tanium\Sla::getTopBreachedEndpoints(5));
check('buildSlaBreachPayload shape', isset($p['attachments'][0]['fields']) && isset($p['text']));
$p2 = GlpiPlugin\Tanium\Notification::buildDeployPayload('deployed', 'HOST-1', 3, 42, 'abc123');
check('buildDeployPayload shape', str_contains($p2['text'], 'HOST-1') && str_contains($p2['title'], 'concluído'));

// 4) RemoteAction table + package resolution
GlpiPlugin\Tanium\RemoteAction::ensureTable();
check('remote_actions table exists', $DB->tableExists('glpi_plugin_tanium_remote_actions'));
$cfg = GlpiPlugin\Tanium\Config::getConfig();
check('quarantine package default', GlpiPlugin\Tanium\RemoteAction::packageFor('quarantine', $cfg) !== '');
check('restart package default', GlpiPlugin\Tanium\RemoteAction::packageFor('restart_client', $cfg) !== '');

// 5) Enrichment table + reads
GlpiPlugin\Tanium\Enrichment::ensureTable();
check('cve_enrichment table exists', $DB->tableExists('glpi_plugin_tanium_cve_enrichment'));
check('Enrichment::forCves runs', is_array(GlpiPlugin\Tanium\Enrichment::forCves($someCves)));
check('Enrichment::kevSet runs', is_array(GlpiPlugin\Tanium\Enrichment::kevSet()));

// 6) Compare PDF
$loadEp = function (string $eid) use ($DB): ?array {
    $a = $DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();
    if (!$a) return null;
    $cves = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_endpoint_cves', 'WHERE' => ['tanium_eid' => $eid], 'ORDER' => 'cvss_score DESC', 'LIMIT' => 50]) as $r) { $cves[] = $r; }
    $patches = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'], 'LIMIT' => 50]) as $r) { $patches[] = $r; }
    $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($cves as $c) { $s = strtolower($c['severity']); if (isset($sev[$s])) $sev[$s]++; }
    return ['asset' => $a, 'cves' => $cves, 'patches' => $patches, 'sev' => $sev, 'cve_ids' => array_column($cves, 'cve_id')];
};
$eids = [];
foreach ($DB->request(['SELECT' => ['tanium_eid'], 'FROM' => 'glpi_plugin_tanium_assets', 'LIMIT' => 2]) as $r) {
    $eids[] = $r['tanium_eid'];
}
if (count($eids) === 2) {
    $pdf = GlpiPlugin\Tanium\PdfReport::compare($loadEp($eids[0]), $loadEp($eids[1]));
    check('PdfReport::compare produces PDF', $pdf !== null && str_starts_with($pdf, '%PDF'), strlen((string)$pdf) . ' bytes');
} else {
    check('PdfReport::compare (skipped — <2 endpoints)', true);
}

// 7) Sla MTTR + config new keys
check('Sla::getMttr runs', is_array(GlpiPlugin\Tanium\Sla::getMttr(90)));
foreach (['webhook_sla', 'webhook_deploy', 'auto_ticket_critical', 'quarantine_package', 'restart_package'] as $k) {
    check("config key {$k} present", array_key_exists($k, $cfg));
}

echo "\nRESULT: {$pass} passed, {$fail} failed\n";
exit($fail > 0 ? 1 : 0);
