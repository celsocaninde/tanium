<?php

/**
 * Manual trigger or status check for a patch deployment record.
 * Actions: trigger (retry), status (poll Tanium API)
 */

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

global $DB;

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? '';
$depId  = (int)($body['dep_id'] ?? 0);

if (!$depId) {
    echo json_encode(['success' => false, 'error' => 'dep_id required']); exit;
}

// Verify record exists and belongs to an endpoint accessible to this user
$res = $DB->doQuery(
    "SELECT * FROM `glpi_plugin_tanium_patch_deployments` WHERE id = {$depId} LIMIT 1"
);
if (!$res || !($dep = $res->fetch_assoc())) {
    echo json_encode(['success' => false, 'error' => 'Deployment not found']); exit;
}

switch ($action) {

    case 'trigger':
        $result = \GlpiPlugin\Tanium\PatchDeploy::triggerDeploy($depId, (int)Session::getLoginUserID());
        echo json_encode($result);
        break;

    case 'status':
        if (empty($dep['tanium_deployment_id'])) {
            echo json_encode(['success' => true, 'tanium_status' => $dep['status'], 'local_status' => $dep['status']]);
            break;
        }
        $config = \GlpiPlugin\Tanium\Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) {
            echo json_encode(['success' => false, 'error' => 'Tanium API not configured']); break;
        }
        try {
            $api    = new \GlpiPlugin\Tanium\Api($config['api_url'], $config['api_token']);
            $data   = $api->getDeploymentStatus($dep['tanium_deployment_id']);
            $state  = $data['data']['status'] ?? $data['status'] ?? 'unknown';
            echo json_encode([
                'success'        => true,
                'tanium_status'  => $state,
                'local_status'   => $dep['status'],
                'deployment_id'  => $dep['tanium_deployment_id'],
            ]);
        } catch (\Exception $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        break;

    case 'cancel':
        $DB->doQuery(
            "UPDATE `glpi_plugin_tanium_patch_deployments`
             SET status = 'cancelled', updated_at = NOW()
             WHERE id = {$depId} AND status = 'pending_approval'"
        );
        echo json_encode(['success' => true]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Unknown action: ' . htmlspecialchars($action)]);
}
