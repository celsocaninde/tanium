<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);

header('Content-Type: application/json');
global $DB;

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_POST['action'] ?? '';
$userId = (int)Session::getLoginUserID();

switch ($action) {
    case 'save':
        $name = trim($body['name'] ?? '');
        $type = in_array($body['filter_type'] ?? '', ['cves', 'endpoints', 'patches']) ? $body['filter_type'] : 'cves';
        $data = is_array($body['filter_data'] ?? null) ? $body['filter_data'] : [];

        if ($name === '' || !$data) {
            echo json_encode(['success' => false, 'error' => 'Missing name or filter data']);
            exit;
        }

        // Upsert by (user, type, name): saving with an existing name overwrites it
        $DB->delete('glpi_plugin_tanium_saved_filters', [
            'users_id' => $userId, 'filter_type' => $type, 'name' => substr($name, 0, 100),
        ]);
        $DB->insert('glpi_plugin_tanium_saved_filters', [
            'users_id'    => $userId,
            'name'        => substr($name, 0, 100),
            'filter_type' => $type,
            'filter_data' => json_encode($data),
            'created_at'  => date('Y-m-d H:i:s'),
        ]);

        echo json_encode(['success' => true, 'id' => (int)$DB->insertId()]);
        break;

    case 'delete':
        $id = (int)($body['id'] ?? 0);
        if (!$id) {
            echo json_encode(['success' => false, 'error' => 'Invalid id']);
            exit;
        }
        // Users may only delete their own filters
        $DB->delete('glpi_plugin_tanium_saved_filters', ['id' => $id, 'users_id' => $userId]);
        echo json_encode(['success' => true]);
        break;

    case 'list':
        $type = in_array($body['filter_type'] ?? '', ['cves', 'endpoints', 'patches']) ? $body['filter_type'] : 'cves';
        $rows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_saved_filters',
            'WHERE' => ['users_id' => $userId, 'filter_type' => $type],
            'ORDER' => 'name ASC',
        ]) as $r) {
            $r['filter_data'] = json_decode($r['filter_data'], true) ?: [];
            $rows[] = $r;
        }
        echo json_encode(['success' => true, 'filters' => $rows]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
}
