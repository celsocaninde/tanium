<?php

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasSyncRight()) { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['success' => false, 'error' => 'forbidden']); exit; }

header('Content-Type: application/json');
global $DB;

$body   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? '';

switch ($action) {
    // Create a GLPI Computer for an orphan Tanium endpoint right now, instead
    // of waiting for the next sync run.
    case 'create_computer':
        $eid   = trim((string)($body['tanium_eid'] ?? ''));
        $asset = $eid !== '' ? $DB->request([
            'FROM'  => 'glpi_plugin_tanium_assets',
            'WHERE' => ['tanium_eid' => $eid],
            'LIMIT' => 1,
        ])->current() : null;

        if (!$asset) {
            echo json_encode(['success' => false, 'error' => 'Endpoint not found']);
            exit;
        }

        $config   = \GlpiPlugin\Tanium\Config::getConfig();
        $computer = new Computer();
        $cid      = (int)$computer->add([
            'name'        => $asset['tanium_name'] ?: ('tanium-' . $eid),
            'entities_id' => (int)($config['default_entity_id'] ?? 0),
            'is_dynamic'  => 1,
        ]);
        if (!$cid) {
            echo json_encode(['success' => false, 'error' => 'Failed to create computer']);
            exit;
        }

        Log::history($cid, 'Computer', [0, '', sprintf(
            __('Created from Tanium coverage page (EID %s)', 'tanium'),
            $eid
        )], 0, Log::HISTORY_LOG_SIMPLE_MESSAGE);

        $DB->update('glpi_plugin_tanium_assets', ['computers_id' => $cid], ['tanium_eid' => $eid]);

        echo json_encode(['success' => true, 'computers_id' => $cid]);
        break;

    // One consolidated "install the Tanium agent" ticket for the selected
    // computers (never one ticket per machine).
    case 'agent_ticket':
        $ids = array_values(array_filter(array_map('intval', (array)($body['computers_ids'] ?? []))));
        if (!$ids) {
            echo json_encode(['success' => false, 'error' => 'No computers selected']);
            exit;
        }

        $names = [];
        foreach ($DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_computers', 'WHERE' => ['id' => $ids]]) as $c) {
            $names[(int)$c['id']] = $c['name'];
        }

        $lines   = [];
        $lines[] = sprintf('Instalar o agente Tanium em %d computador(es) sem cobertura:', count($names));
        $lines[] = '';
        foreach ($names as $n) {
            $lines[] = '- ' . $n;
        }

        $config   = \GlpiPlugin\Tanium\Config::getConfig();
        $ticket   = new Ticket();
        $ticketId = (int)$ticket->add([
            'name'        => sprintf('[Tanium] Instalar agente em %d computador(es)', count($names)),
            'content'     => implode("\n", $lines),
            'entities_id' => (int)($config['ticket_entity_id'] ?? 0),
            'type'        => Ticket::DEMAND_TYPE,
            'priority'    => 3,
        ]);
        if (!$ticketId) {
            echo json_encode(['success' => false, 'error' => 'Failed to create ticket']);
            exit;
        }

        foreach (array_keys($names) as $cid) {
            (new Item_Ticket())->add([
                'tickets_id' => $ticketId,
                'itemtype'   => 'Computer',
                'items_id'   => $cid,
            ]);
        }

        echo json_encode(['success' => true, 'ticket_id' => $ticketId]);
        break;

    default:
        echo json_encode(['success' => false, 'error' => 'Unknown action']);
}
