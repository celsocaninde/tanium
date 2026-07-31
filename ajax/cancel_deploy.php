<?php

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

// CSRF é validado pelo próprio GLPI: o plugin declara csrf_compliant em
// setup.php, então checar aqui de novo consumiria o token duas vezes.

$depId = (int)($_POST['deployment_id'] ?? 0);
if ($depId <= 0) {
    echo json_encode(['success' => false, 'error' => 'deployment_id ausente']); exit;
}

try {
    echo json_encode(
        \GlpiPlugin\Tanium\PatchDeploy::cancelDeploy($depId, (int)\Session::getLoginUserID())
    );
} catch (\Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
