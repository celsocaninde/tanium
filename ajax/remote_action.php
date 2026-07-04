<?php

/**
 * Creates the approval ticket + pending record for a remote action
 * (quarantine / agent restart). The action only reaches Tanium after the
 * ticket's approval request is ACCEPTED — see RemoteAction::onValidationUpdate.
 */

include('../../../inc/includes.php');
Session::checkRight('config', UPDATE);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

try {
    $body   = json_decode(file_get_contents('php://input'), true) ?? [];
    $eid    = trim($body['eid'] ?? '');
    $action = trim($body['action'] ?? '');

    if ($eid === '' || $action === '') {
        echo json_encode(['success' => false, 'error' => 'eid and action are required']); exit;
    }

    $result = \GlpiPlugin\Tanium\RemoteAction::createRequest($eid, $action);
    if (!empty($result['ticket_id'])) {
        $result['ticket_url'] = '/front/ticket.form.php?id=' . $result['ticket_id'];
        $result['message']    = sprintf(
            'Chamado #%d criado. Envie a solicitação de aprovação — quando aprovada, a ação é disparada automaticamente no Tanium.',
            $result['ticket_id']
        );
    }
    echo json_encode($result);

} catch (\Throwable $e) {
    if (!headers_sent()) {
        header('Content-Type: application/json');
    }
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
