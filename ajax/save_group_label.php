<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

$body          = json_decode(file_get_contents('php://input'), true) ?? [];
$taniumGroupId = (int)($body['tanium_group_id'] ?? 0);
$label         = trim((string)($body['label'] ?? ''));

if ($taniumGroupId <= 0) {
    echo json_encode(['success' => false, 'error' => 'tanium_group_id required']); exit;
}

\GlpiPlugin\Tanium\ComputerGroup::saveLabel($taniumGroupId, $label);
echo json_encode(['success' => true]);
