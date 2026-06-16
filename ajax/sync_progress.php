<?php

include('../../../inc/includes.php');

Session::checkRight('config', READ);

header('Content-Type: application/json');

global $DB;

$row = $DB->request([
    'FROM'  => 'glpi_plugin_tanium_sync_logs',
    'ORDER' => 'started_at DESC',
    'LIMIT' => 1,
])->current();

if (!$row) {
    echo json_encode(['status' => 'never', 'processed' => 0, 'total' => 0, 'percent' => 0, 'errors' => 0]);
    exit;
}

$status    = $row['status'];
$processed = (int) ($row['processed'] ?? 0);
$estimated = (int) ($row['total_estimated'] ?? 0);
$errors    = (int) ($row['errors'] ?? 0);

if ($status === 'running') {
    $percent = ($estimated > 0) ? min(99, (int) round($processed / $estimated * 100)) : 0;
    $total   = $estimated;
} else {
    $processed = (int) $row['total'];
    $total     = (int) $row['total'];
    $percent   = $total > 0 ? 100 : 0;
}

echo json_encode([
    'status'      => $status,
    'processed'   => $processed,
    'total'       => $total,
    'percent'     => $percent,
    'errors'      => $errors,
    'started_at'  => $row['started_at']  ? Html::convDateTime($row['started_at'])  : null,
    'finished_at' => $row['finished_at'] ? Html::convDateTime($row['finished_at']) : null,
]);
