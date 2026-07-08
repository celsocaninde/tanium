<?php

/**
 * Tanium — Create GLPI ticket from CVE / patch finding.
 * POST: title, content, priority, itilcategories_id, tanium_eid, computers_id, ref_id, ref_type
 */

include('../../../inc/includes.php');

Session::checkLoginUser();
if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Html::redirect(Plugin::getWebDir('tanium') . '/front/endpoints.php');
}

global $DB;

$title             = trim($_POST['title']            ?? '');
$content           = trim($_POST['content']          ?? '');
$priority          = (int)($_POST['priority']         ?? 3);
$itilcategoriesId  = (int)($_POST['itilcategories_id'] ?? 0);
$taniumEid         = trim($_POST['tanium_eid']        ?? '');
$computersId       = (int)($_POST['computers_id']      ?? 0);
$refId             = trim($_POST['ref_id']            ?? '');
$refType           = trim($_POST['ref_type']          ?? '');

if ($title === '') {
    Html::displayErrorAndDie(__('Ticket title is required.', 'tanium'));
}

$config = \GlpiPlugin\Tanium\Config::getConfig();

$ticket = new Ticket();

$ticketData = [
    'name'                => $title,
    'content'             => nl2br(htmlspecialchars($content)),
    'priority'            => $priority,
    'status'              => Ticket::INCOMING,
    'type'                => Ticket::INCIDENT_TYPE,
    'entities_id'         => (int)($config['ticket_entity_id'] ?? 0) > 0
                                ? (int)$config['ticket_entity_id']
                                : ($_SESSION['glpiactive_entity'] ?? 0),
    '_users_id_requester' => \GlpiPlugin\Tanium\Config::ticketRequesterId(Session::getLoginUserID(), $config),
];

if ($itilcategoriesId > 0) {
    $ticketData['itilcategories_id'] = $itilcategoriesId;
}

// Link to GLPI computer if available
if ($computersId > 0) {
    $ticketData['items_id']   = $computersId;
    $ticketData['itemtype']   = 'Computer';
    $ticketData['_link']['Computer'][$computersId] = $computersId;
}

$ticketId = $ticket->add($ticketData);

if ($ticketId) {
    // Add a follow-up with Tanium context details
    if ($taniumEid || $refId) {
        $refRow = '';
        if ($refType === 'cve' && $refId) {
            $refRow = "<tr><td style='color:#718096;padding:4px 0;padding-right:20px;white-space:nowrap'>CVE ID</td>"
                    . "<td><a href='https://nvd.nist.gov/vuln/detail/" . htmlspecialchars($refId) . "' style='color:#63b3ed'>" . htmlspecialchars($refId) . "</a></td></tr>";
        } elseif ($refType === 'patch' && $refId) {
            $refRow = "<tr><td style='color:#718096;padding:4px 0;padding-right:20px;white-space:nowrap'>Patch ID</td>"
                    . "<td style='font-family:monospace;font-size:12px;color:#e2e8f0'>" . htmlspecialchars($refId) . "</td></tr>";
        }

        $note = "
<div style='font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:16px 20px;max-width:640px'>
  <div style='font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:14px'>🛡️ Contexto Tanium — Detecção Automática</div>
  <table style='border-collapse:collapse;font-size:13px'>
    <tr><td style='color:#718096;padding:4px 0;padding-right:20px;white-space:nowrap'>Tanium EID</td><td style='font-family:monospace;font-size:11px;color:#68d391'>" . htmlspecialchars($taniumEid) . "</td></tr>
    {$refRow}
  </table>
  <div style='margin-top:12px;font-size:.78rem;color:#4a5568'>Chamado gerado automaticamente pelo plugin Tanium para GLPI.</div>
</div>";

        $fup = new ITILFollowup();
        $fup->add([
            'items_id'   => $ticketId,
            'itemtype'   => 'Ticket',
            'content'    => $note,
            'is_private' => 0,
            'users_id'   => Session::getLoginUserID(),
        ]);
    }

    // Redirect to the new ticket
    Html::redirect('/front/ticket.form.php?id=' . $ticketId);
} else {
    Html::displayErrorAndDie(__('Falha ao criar chamado. Verifique as permissões no GLPI.', 'tanium'));
}
