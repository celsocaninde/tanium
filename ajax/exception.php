<?php

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }

header('Content-Type: application/json');
global $DB;

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    case 'create':
        $eid     = trim($body['tanium_eid'] ?? '');
        $cveId   = trim($body['cve_id']     ?? '');
        $reason  = trim($body['reason']     ?? '');
        $expires = trim($body['expires_at'] ?? '');

        if (!$eid || !$cveId || !$reason) {
            echo json_encode(['success' => false, 'error' => 'Missing required fields']);
            exit;
        }

        // Look up computers_id
        $asset = $DB->request(['SELECT' => ['computers_id'], 'FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();

        $data = [
            'tanium_eid'   => $eid,
            'cve_id'       => $cveId,
            'computers_id' => $asset['computers_id'] ?? null,
            'reason'       => substr($reason, 0, 1000),
            'accepted_by'  => Session::getLoginUserID(),
            'expires_at'   => $expires ? date('Y-m-d H:i:s', strtotime($expires)) : null,
            'created_at'   => date('Y-m-d H:i:s'),
        ];

        // Upsert: delete old if exists, then insert
        $DB->delete('glpi_plugin_tanium_cve_exceptions', ['tanium_eid' => $eid, 'cve_id' => $cveId]);
        $DB->insert('glpi_plugin_tanium_cve_exceptions', $data);

        echo json_encode(['success' => true, 'id' => (int)$DB->insertId()]);
        break;

    case 'delete':
        $id = (int)($body['id'] ?? 0);
        if (!$id) { echo json_encode(['success' => false, 'error' => 'Invalid id']); exit; }
        $DB->delete('glpi_plugin_tanium_cve_exceptions', ['id' => $id]);
        echo json_encode(['success' => true]);
        break;

    case 'check':
        // Check if a CVE has an active exception
        $eid   = trim($body['tanium_eid'] ?? '');
        $cveId = trim($body['cve_id']     ?? '');
        $row   = $DB->request(['FROM' => 'glpi_plugin_tanium_cve_exceptions', 'WHERE' => ['tanium_eid' => $eid, 'cve_id' => $cveId], 'LIMIT' => 1])->current();
        echo json_encode(['has_exception' => (bool)$row, 'exception' => $row ?: null]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
}
