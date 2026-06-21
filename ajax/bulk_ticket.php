<?php

include('../../../inc/includes.php');
Session::checkRight('config', UPDATE);

header('Content-Type: application/json');
global $DB;

$body    = json_decode(file_get_contents('php://input'), true) ?? [];
$eids    = array_map('strval', (array)($body['eids'] ?? []));
$title   = trim($body['title']    ?? '');
$content = trim($body['content']  ?? '');
$priority = (int)($body['priority'] ?? 3);

if (empty($eids)) {
    echo json_encode(['success' => false, 'error' => 'No endpoints selected']);
    exit;
}

if (!$title) {
    $title = sprintf('[Tanium] Security findings for %d endpoint(s)', count($eids));
}

// Build ticket content with endpoint details
$lines = ["== Tanium Security Findings ==\n"];
$lines[] = sprintf("Endpoints affected: %d\n", count($eids));
$lines[] = "Generated: " . date('Y-m-d H:i:s') . "\n\n";

$totalCritical = 0;
$totalHigh     = 0;
$endpointNames = [];

foreach ($eids as $eid) {
    $asset = $DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();
    if (!$asset) continue;

    $endpointNames[] = $asset['tanium_name'];
    $rs = (int)($asset['risk_score'] ?? 0);

    $lines[] = "--- {$asset['tanium_name']} (IP: {$asset['ip_address']}, Risk: {$rs}) ---";

    $cves = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_endpoint_cves', 'WHERE' => ['tanium_eid' => $eid, 'status' => ['!=', 'remediated']], 'ORDER' => ['severity ASC', 'cvss_score DESC'], 'LIMIT' => 20]) as $c) {
        $cves[] = "  [{$c['severity']}] {$c['cve_id']} CVSS:{$c['cvss_score']}";
        if (strtolower($c['severity']) === 'critical') $totalCritical++;
        elseif (strtolower($c['severity']) === 'high')  $totalHigh++;
    }
    if ($cves) {
        $lines[] = "CVEs (" . count($cves) . "):";
        $lines = array_merge($lines, $cves);
    }

    $patches = [];
    foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_patches', 'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'], 'LIMIT' => 10]) as $p) {
        $patches[] = "  [{$p['severity']}] {$p['patch_title']}";
    }
    if ($patches) {
        $lines[] = "Missing patches (" . count($patches) . "):";
        $lines = array_merge($lines, $patches);
    }
    $lines[] = '';
}

if ($content) {
    $lines[] = "\n== Additional notes ==\n" . $content;
}

$ticketContent = implode("\n", $lines);

$config   = \GlpiPlugin\Tanium\Config::getConfig();
$entityId = (int)($config['ticket_entity_id'] ?? 0) > 0
    ? (int)$config['ticket_entity_id']
    : ($_SESSION['glpiactive_entity'] ?? 0);

// Create the ticket
$ticket = new \Ticket();
$ticketId = $ticket->add([
    'name'            => $title,
    'content'         => $ticketContent,
    'entities_id'     => $entityId,
    'type'            => \Ticket::INCIDENT_TYPE,
    'priority'        => $priority,
    'urgency'         => $totalCritical > 0 ? 5 : ($totalHigh > 0 ? 4 : 3),
    'impact'          => $totalCritical > 0 ? 5 : ($totalHigh > 0 ? 4 : 3),
    '_users_id_assign'=> [],
]);

if (!$ticketId) {
    echo json_encode(['success' => false, 'error' => 'Failed to create GLPI ticket']);
    exit;
}

// Link computers
foreach ($eids as $eid) {
    $asset = $DB->request(['SELECT' => ['computers_id'], 'FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();
    if ($asset && $asset['computers_id']) {
        $iitem = new \Item_Ticket();
        $iitem->add([
            'tickets_id' => $ticketId,
            'itemtype'   => 'Computer',
            'items_id'   => (int)$asset['computers_id'],
        ]);
    }
}

$ticketUrl = \Plugin::getWebDir('') . '/front/ticket.form.php?id=' . $ticketId;
echo json_encode(['success' => true, 'ticket_id' => $ticketId, 'ticket_url' => $ticketUrl]);
