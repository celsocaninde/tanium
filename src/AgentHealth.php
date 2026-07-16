<?php

namespace GlpiPlugin\Tanium;

use ITILSolution;
use Item_Ticket;
use Ticket;

/**
 * Agent health: an endpoint whose last_seen is older than the configured
 * threshold has a Tanium agent that stopped reporting (stopped service,
 * uninstall, network isolation…). Installed coverage ≠ working coverage.
 */
class AgentHealth {

    public const TICKET_TITLE = '[Tanium] Agentes sem comunicação';

    /** Endpoints not seen for at least $days days, oldest first. */
    public static function getStale(int $days): array {
        global $DB;

        $days = max(1, $days);
        $rows = [];
        foreach ($DB->doQuery("
            SELECT tanium_eid, tanium_name, ip_address, os_name, computers_id, last_seen,
                   DATEDIFF(NOW(), last_seen) AS days_silent
            FROM glpi_plugin_tanium_assets
            WHERE last_seen IS NOT NULL
              AND last_seen < DATE_SUB(NOW(), INTERVAL {$days} DAY)
            ORDER BY last_seen ASC
        ") as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    public static function countStale(int $days): int {
        global $DB;

        $days = max(1, $days);
        $row = $DB->doQuery("
            SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_assets
            WHERE last_seen IS NOT NULL
              AND last_seen < DATE_SUB(NOW(), INTERVAL {$days} DAY)
        ")->fetch_assoc();
        return (int)($row['cpt'] ?? 0);
    }

    /**
     * Open ONE consolidated ticket listing the stale agents (never one ticket
     * per endpoint — a fleet-wide outage would flood the helpdesk). Skips when
     * a previous agent-health ticket is still open. Returns the ticket id, 0
     * when skipped/none stale.
     */
    public static function openTicketIfNeeded(): int {
        global $DB;

        $config = Config::getConfig();
        if (empty($config['agent_health_ticket'])) {
            return 0;
        }

        $days  = (int)($config['agent_stale_days'] ?? 7);
        $stale = self::getStale($days);
        if (!$stale) {
            return 0;
        }

        // Dedup: an open ticket with our marker title means the team is on it.
        $open = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_tickets',
            'WHERE'  => [
                'name'       => self::TICKET_TITLE,
                'is_deleted' => 0,
                'NOT'        => ['status' => [Ticket::SOLVED, Ticket::CLOSED]],
            ],
            'LIMIT'  => 1,
        ])->current();
        if ($open) {
            return 0;
        }

        $entityId = (int)($config['ticket_entity_id'] ?? 0);

        $ticketData = [
            'name'        => self::TICKET_TITLE,
            'content'     => Notification::buildAgentHealthTicketHtml($stale, $days),
            'entities_id' => $entityId,
            'type'        => Ticket::INCIDENT_TYPE,
            'priority'    => 4,
            'urgency'     => 4,
            'impact'      => 4,
        ];
        $requester = Config::ticketRequesterId(0, $config);
        if ($requester > 0) {
            $ticketData['_users_id_requester'] = $requester;
        }

        $ticket   = new Ticket();
        $ticketId = (int)$ticket->add($ticketData);
        if (!$ticketId) {
            return 0;
        }

        foreach (array_slice($stale, 0, 50) as $a) {
            if (!empty($a['computers_id'])) {
                (new Item_Ticket())->add([
                    'tickets_id' => $ticketId,
                    'itemtype'   => 'Computer',
                    'items_id'   => (int)$a['computers_id'],
                ]);
            }
        }

        return $ticketId;
    }

    /**
     * Counterpart of openTicketIfNeeded(): once no endpoint remains silent
     * beyond the threshold, solve the open consolidated ticket automatically.
     * Returns the solved ticket id, 0 when there is nothing to do.
     */
    public static function resolveTicketIfHealthy(int $days): int {
        global $DB;

        if (self::countStale($days) > 0) {
            return 0;
        }

        $open = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_tickets',
            'WHERE'  => [
                'name'       => self::TICKET_TITLE,
                'is_deleted' => 0,
                'NOT'        => ['status' => [Ticket::SOLVED, Ticket::CLOSED]],
            ],
            'LIMIT'  => 1,
        ])->current();
        if (!$open) {
            return 0;
        }

        (new ITILSolution())->add([
            'itemtype'         => 'Ticket',
            'items_id'         => (int)$open['id'],
            'content'          => Notification::autoSolutionHtml(
                '✅ Todos os agentes voltaram a comunicar',
                sprintf(
                    'Nenhum endpoint permanece sem comunicação com o Tanium além do limite configurado (%d dia(s)). Este chamado foi <strong>encerrado automaticamente</strong>.',
                    $days
                )
            ),
            'solutiontypes_id' => 0,
        ]);

        return (int)$open['id'];
    }
}
