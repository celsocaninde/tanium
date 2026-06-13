<?php

/**
 * Tanium — Create GLPI ticket from CVE / patch finding.
 * POST: title, content, priority, itilcategories_id, tanium_eid, computers_id, ref_id, ref_type
 */

include('../../../inc/includes.php');

Session::checkLoginUser();
Session::checkRight('config', READ);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Html::redirect(Plugin::getWebDir('tanium') . '/front/endpoints.php');
}

Session::checkCSRF($_POST);

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

$ticket = new Ticket();

$ticketData = [
    'name'                => $title,
    'content'             => nl2br(htmlspecialchars($content)),
    'priority'            => $priority,
    'status'              => Ticket::INCOMING,
    'type'                => Ticket::INCIDENT_TYPE,
    'entities_id'         => $_SESSION['glpiactive_entity'] ?? 0,
    '_users_id_requester' => Session::getLoginUserID(),
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
        $note  = "**Criado automaticamente pelo plugin Tanium para GLPI**\n\n";
        $note .= "EID: {$taniumEid}\n";
        if ($refType === 'cve')   $note .= "CVE ID: {$refId}\n";
        if ($refType === 'patch') $note .= "Patch ID: {$refId}\n";
        $note .= "\n_Este ticket foi gerado a partir de uma detecção do Tanium._";

        $fup = new ITILFollowup();
        $fup->add([
            'items_id'     => $ticketId,
            'itemtype'     => 'Ticket',
            'content'      => nl2br(htmlspecialchars($note)),
            'is_private'   => 0,
            'users_id'     => Session::getLoginUserID(),
        ]);
    }

    // Redirect to the new ticket
    Html::redirect('/front/ticket.form.php?id=' . $ticketId);
} else {
    Html::displayErrorAndDie(__('Failed to create ticket. Check your GLPI permissions.', 'tanium'));
}
