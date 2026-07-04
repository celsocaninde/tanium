<?php

use GlpiPlugin\Tanium\Sync as TaniumSync;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }

header('Content-Type: application/json');

$result = TaniumSync::run();
echo json_encode($result);
