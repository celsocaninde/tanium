<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

$body          = json_decode(file_get_contents('php://input'), true) ?? [];
$taniumGroupId = (int)($body['tanium_group_id'] ?? 0);

if ($taniumGroupId <= 0) {
    echo json_encode(['success' => false, 'error' => 'tanium_group_id required']); exit;
}

// Entity mapping update (select onchange) and label update (text input) come
// through the same endpoint; the payload decides which field is being saved.
if (array_key_exists('entities_id', $body)) {
    \GlpiPlugin\Tanium\ComputerGroup::saveEntity($taniumGroupId, (int)$body['entities_id']);
} else {
    \GlpiPlugin\Tanium\ComputerGroup::saveLabel($taniumGroupId, trim((string)($body['label'] ?? '')));
}
echo json_encode(['success' => true]);
