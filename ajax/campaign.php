<?php

/**
 * Create / close a remediation campaign.
 */

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? '';

switch ($action) {

    case 'create':
        echo json_encode(\GlpiPlugin\Tanium\Campaign::create(
            (string)($body['target_type'] ?? 'patch'),
            (string)($body['target_key']  ?? ''),
            [
                'name'     => (string)($body['name']     ?? ''),
                'due_date' => (string)($body['due_date'] ?? ''),
                'owner_id' => (int)   ($body['owner_id'] ?? 0),
                'notes'    => (string)($body['notes']    ?? ''),
            ]
        ));
        break;

    case 'close':
        $id = (int)($body['id'] ?? 0);
        if ($id <= 0) {
            echo json_encode(['success' => false, 'error' => 'id required']);
            break;
        }
        $ok = \GlpiPlugin\Tanium\Campaign::close($id, (string)($body['status'] ?? 'closed'));
        echo json_encode(['success' => $ok, 'error' => $ok ? null : 'Campaign not found or already closed']);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Unknown action: ' . htmlspecialchars($action)]);
}
