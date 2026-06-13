<?php

include('../../../inc/includes.php');
Session::checkRight('config', UPDATE);

header('Content-Type: application/json');
global $DB;

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? '';

switch ($action) {
    case 'create':
        $eid        = trim($body['tanium_eid']  ?? '');
        $cveId      = trim($body['cve_id']      ?? '');
        $refType    = in_array($body['ref_type'] ?? 'cve', ['cve', 'patch']) ? $body['ref_type'] : 'cve';
        $assignedTo = (int)($body['assigned_to'] ?? 0);
        $dueDate    = trim($body['due_date']     ?? '');
        $notes      = trim($body['notes']        ?? '');

        if (!$eid || !$cveId) {
            echo json_encode(['success' => false, 'error' => 'Missing required fields']);
            exit;
        }

        $asset = $DB->request(['SELECT' => ['computers_id'], 'FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eid], 'LIMIT' => 1])->current();

        $data = [
            'tanium_eid'   => $eid,
            'cve_id'       => $cveId,
            'ref_type'     => $refType,
            'computers_id' => $asset['computers_id'] ?? null,
            'assigned_to'  => $assignedTo ?: null,
            'assigned_by'  => Session::getLoginUserID(),
            'due_date'     => $dueDate ? date('Y-m-d H:i:s', strtotime($dueDate)) : null,
            'status'       => 'open',
            'notes'        => substr($notes, 0, 2000),
            'created_at'   => date('Y-m-d H:i:s'),
            'date_mod'     => date('Y-m-d H:i:s'),
        ];

        // Upsert
        $existing = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_cve_assignments',
            'WHERE' => ['tanium_eid' => $eid, 'cve_id' => $cveId, 'ref_type' => $refType],
            'LIMIT' => 1,
        ])->current();

        if ($existing) {
            $DB->update('glpi_plugin_tanium_cve_assignments', array_merge($data, ['date_mod' => date('Y-m-d H:i:s')]), ['id' => $existing['id']]);
            echo json_encode(['success' => true, 'id' => (int)$existing['id']]);
        } else {
            $DB->insert('glpi_plugin_tanium_cve_assignments', $data);
            echo json_encode(['success' => true, 'id' => (int)$DB->insertId()]);
        }
        break;

    case 'update_status':
        $id     = (int)($body['id'] ?? 0);
        $status = $body['status'] ?? '';
        if (!$id || !in_array($status, ['open', 'in_progress', 'resolved'])) {
            echo json_encode(['success' => false, 'error' => 'Invalid params']); exit;
        }
        $DB->update('glpi_plugin_tanium_cve_assignments', ['status' => $status, 'date_mod' => date('Y-m-d H:i:s')], ['id' => $id]);
        echo json_encode(['success' => true]);
        break;

    case 'delete':
        $id = (int)($body['id'] ?? 0);
        if (!$id) { echo json_encode(['success' => false, 'error' => 'Invalid id']); exit; }
        $DB->delete('glpi_plugin_tanium_cve_assignments', ['id' => $id]);
        echo json_encode(['success' => true]);
        break;

    case 'get_users':
        $users = [];
        foreach ($DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_users', 'WHERE' => ['is_deleted' => 0, 'is_active' => 1], 'ORDER' => 'name ASC', 'LIMIT' => 500]) as $u) {
            $users[] = $u;
        }
        echo json_encode(['success' => true, 'users' => $users]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
}
