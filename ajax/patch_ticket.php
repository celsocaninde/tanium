<?php

/**
 * Creates a GLPI ticket with professional HTML content for patch remediation.
 * Also creates a glpi_plugin_tanium_patch_deployments record in pending_approval state.
 * When the ticket is set to "Processing (Assigned)", the hook auto-triggers Tanium deploy.
 */

include('../../../inc/includes.php');
Session::checkRight('config', READ);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

global $DB;

// Wrap the whole handler so any error (bad query, schema mismatch, etc.) returns
// JSON instead of an HTML error page — an HTML response makes the browser throw
// "Unexpected token '<'" when it tries to parse the reply as JSON.
try {

$body     = json_decode(file_get_contents('php://input'), true) ?? [];
$eid      = trim($body['eid'] ?? '');
$patchIds = array_values(array_filter((array)($body['patch_ids'] ?? []), fn($p) => trim($p) !== ''));

if (!$eid || empty($patchIds)) {
    echo json_encode(['success' => false, 'error' => 'eid and patch_ids are required']); exit;
}

// ── Load endpoint ──────────────────────────────────────────────────────────────
$res = $DB->doQuery(
    "SELECT * FROM glpi_plugin_tanium_assets WHERE tanium_eid = '" . $DB->escape($eid) . "' LIMIT 1"
);
if (!$res || !($endpoint = $res->fetch_assoc())) {
    echo json_encode(['success' => false, 'error' => 'Endpoint not found']); exit;
}

// ── Load requested patches ────────────────────────────────────────────────────
$patches = [];
foreach ($patchIds as $pid) {
    $pr = $DB->doQuery(
        "SELECT * FROM glpi_plugin_tanium_patches
         WHERE tanium_eid = '" . $DB->escape($eid) . "'
           AND patch_id   = '" . $DB->escape($pid) . "'
         LIMIT 1"
    );
    if ($pr && ($row = $pr->fetch_assoc())) {
        $patches[] = $row;
    }
}

if (empty($patches)) {
    echo json_encode(['success' => false, 'error' => 'None of the requested patches found for this endpoint']); exit;
}

// ── Load active CVEs for this endpoint ───────────────────────────────────────
$cves = [];
foreach ($DB->doQuery(
    "SELECT ec.cve_id, v.title, v.severity, v.cvss_score
     FROM glpi_plugin_tanium_endpoint_cves ec
     LEFT JOIN glpi_plugin_tanium_vulnerabilities v ON ec.cve_id = v.cve_id
     WHERE ec.tanium_eid = '" . $DB->escape($eid) . "' AND ec.status != 'resolved'
     ORDER BY v.cvss_score DESC LIMIT 100"
) as $r) {
    $cves[] = $r;
}

$config = \GlpiPlugin\Tanium\Config::getConfig();

// ── Build ticket content ──────────────────────────────────────────────────────
$html = \GlpiPlugin\Tanium\PatchDeploy::buildTicketHtml($endpoint, $patches, $cves, $config);

// Calculate urgency/impact from severity
$hasCritical  = !empty(array_filter($patches, fn($p) => strtolower($p['severity']??'') === 'critical'));
$hasHigh      = !empty(array_filter($patches, fn($p) => in_array(strtolower($p['severity']??''), ['important','high'])));
$urgency      = $hasCritical ? 5 : ($hasHigh ? 4 : 3);
$impact       = $urgency;
$priority     = $urgency; // GLPI calculates this but we set it directly

$endpointName = $endpoint['tanium_name'] ?? $eid;
$patchCount   = count($patches);
$title        = sprintf('[Tanium] Patch Remediation — %s (%d patch%s)', $endpointName, $patchCount, $patchCount > 1 ? 'es' : '');

// ── Create GLPI ticket ────────────────────────────────────────────────────────
    $ticket = new Ticket();
    $ticketData = [
        'name'             => $title,
        'content'          => $html,
        'status'           => CommonITILObject::INCOMING, // 1 = New — awaiting approval
        'urgency'          => $urgency,
        'impact'           => $impact,
        'priority'         => $priority,
        'type'             => Ticket::INCIDENT_TYPE,
        'requesttypes_id'  => 1, // Direct
        '_users_id_requester' => Session::getLoginUserID(),
    ];

    $ticketId = $ticket->add($ticketData);
    if (!$ticketId) {
        throw new \RuntimeException('Ticket::add() returned false');
    }

    // Link GLPI computer to ticket if available
    if (!empty($endpoint['computers_id'])) {
        $itemTicket = new Item_Ticket();
        $itemTicket->add([
            'itemtype'   => 'Computer',
            'items_id'   => (int)$endpoint['computers_id'],
            'tickets_id' => $ticketId,
        ]);
    }

    // ── Create deployment record ──────────────────────────────────────────────
    $DB->insert('glpi_plugin_tanium_patch_deployments', [
        'ticket_id'    => $ticketId,
        'tanium_eid'   => $eid,
        'computers_id' => $endpoint['computers_id'] ?: null,
        'patch_ids'    => json_encode($patchIds),
        'status'       => 'pending_approval',
        'requested_by' => Session::getLoginUserID(),
        'created_at'   => date('Y-m-d H:i:s'),
    ]);

    $ticketUrl = \Plugin::getWebDir('tanium', false, true);
    $ticketUrl = '/front/ticket.form.php?id=' . $ticketId;

    echo json_encode([
        'success'    => true,
        'ticket_id'  => $ticketId,
        'ticket_url' => $ticketUrl,
        'message'    => sprintf('Ticket #%d created successfully. Set it to "Processing (Assigned)" to trigger Tanium deployment.', $ticketId),
    ]);

} catch (\Throwable $e) {
    if (!headers_sent()) {
        header('Content-Type: application/json');
    }
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
