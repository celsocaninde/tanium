<?php

namespace GlpiPlugin\Tanium;

use ITILSolution;
use Item_Ticket;
use Ticket;
use Toolbox;

/**
 * Tanium Threat Response — imports threat alerts and (optionally) opens one
 * GLPI ticket per new alert at or above the configured severity, linked to the
 * matching Computer. Mirrors the ZDX alerts→tickets pattern used in the
 * Zscaler plugin.
 */
class ThreatResponse {

    public static $table = 'glpi_plugin_tanium_threat_alerts';

    private const SEV_RANK = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

    public static function ensureTable(): void {
        global $DB;

        if ($DB->tableExists(self::$table)) {
            return;
        }

        $DB->doQuery(
            "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
                `id`           int unsigned NOT NULL AUTO_INCREMENT,
                `alert_id`     varchar(100) NOT NULL DEFAULT '',
                `tanium_eid`   varchar(100) NOT NULL DEFAULT '',
                `computers_id` int unsigned DEFAULT NULL,
                `title`        varchar(500) NOT NULL DEFAULT '',
                `severity`     varchar(20)  NOT NULL DEFAULT 'unknown',
                `status`       varchar(30)  NOT NULL DEFAULT 'open',
                `detected_at`  timestamp NULL DEFAULT NULL,
                `tickets_id`   int unsigned DEFAULT NULL,
                `date_mod`     timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `alert_id` (`alert_id`),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `status` (`status`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    /** Fetch alerts from the API and process them. Returns [imported, tickets]. */
    public static function syncFromApi(Api $api): array {
        try {
            $alerts = $api->getThreatAlerts();
        } catch (\Throwable $e) {
            Toolbox::logInFile('tanium', '[Tanium] Threat Response sync failed: ' . $e->getMessage() . "\n");
            return [0, 0];
        }
        return self::processAlerts($alerts);
    }

    /**
     * Upsert alerts and open tickets for NEW ones at/above the threshold.
     * Public and API-free so the pipeline is testable without a live Tanium.
     *
     * @return array{0:int,1:int} [alerts imported, tickets opened]
     */
    public static function processAlerts(array $alerts): array {
        global $DB;
        self::ensureTable();

        $config     = Config::getConfig();
        $openTicket = !empty($config['threat_ticket']);
        $minSev     = strtolower((string)($config['threat_min_severity'] ?? 'high'));
        $minRank    = self::SEV_RANK[$minSev] ?? 3;

        $imported = 0;
        $tickets  = 0;
        $now      = date('Y-m-d H:i:s');

        foreach ($alerts as $a) {
            $alertId = (string)($a['id'] ?? $a['alertId'] ?? $a['guid'] ?? '');
            if ($alertId === '') {
                continue;
            }

            $eid      = (string)($a['eid'] ?? $a['endpointId'] ?? $a['computerId'] ?? '');
            $severity = strtolower((string)($a['severity'] ?? $a['priority'] ?? 'unknown'));
            $title    = trim((string)($a['name'] ?? $a['title'] ?? $a['type'] ?? 'Threat alert'));
            $status   = strtolower((string)($a['state'] ?? $a['status'] ?? 'open'));

            $asset = $eid !== '' ? $DB->request([
                'SELECT' => ['computers_id', 'tanium_name'],
                'FROM'   => 'glpi_plugin_tanium_assets',
                'WHERE'  => ['tanium_eid' => $eid],
                'LIMIT'  => 1,
            ])->current() : null;

            $row = [
                'tanium_eid'   => $eid,
                'computers_id' => $asset['computers_id'] ?? null,
                'title'        => substr($title, 0, 500),
                'severity'     => $severity,
                'status'       => $status,
                'detected_at'  => !empty($a['alertedAt']) || !empty($a['createdAt'])
                    ? date('Y-m-d H:i:s', strtotime($a['alertedAt'] ?? $a['createdAt']))
                    : $now,
                'date_mod'     => $now,
            ];

            $existing = $DB->request([
                'SELECT' => ['id', 'tickets_id'],
                'FROM'   => self::$table,
                'WHERE'  => ['alert_id' => $alertId],
                'LIMIT'  => 1,
            ])->current();

            if ($existing) {
                $DB->update(self::$table, $row, ['id' => $existing['id']]);
                if (!empty($existing['tickets_id'])
                    && in_array($status, ['resolved', 'closed', 'suppressed'], true)) {
                    self::resolveTicket((int)$existing['tickets_id'], $title, $status);
                }
                continue;
            }

            $DB->insert(self::$table, $row + ['alert_id' => $alertId]);
            $localId = (int)$DB->insertId();
            $imported++;

            $rank = self::SEV_RANK[$severity] ?? 0;
            if ($openTicket && $rank >= $minRank) {
                $ticketId = self::openTicket($alertId, $row, $asset);
                if ($ticketId > 0) {
                    $DB->update(self::$table, ['tickets_id' => $ticketId], ['id' => $localId]);
                    $tickets++;
                }
            }
        }

        return [$imported, $tickets];
    }

    private static function openTicket(string $alertId, array $row, ?array $asset): int {
        $config   = Config::getConfig();
        $entityId = (int)($config['ticket_entity_id'] ?? 0);

        $endpointLabel = $asset['tanium_name'] ?? ($row['tanium_eid'] ?: 'desconhecido');

        $urgency = $row['severity'] === 'critical' ? 5 : 4;

        $ticketData = [
            'name'        => sprintf('[Tanium TR] %s — %s', ucfirst($row['severity']), substr($row['title'], 0, 120)),
            'content'     => Notification::buildThreatTicketHtml($alertId, $row, $endpointLabel),
            'entities_id' => $entityId,
            'type'        => Ticket::INCIDENT_TYPE,
            'priority'    => $urgency,
            'urgency'     => $urgency,
            'impact'      => $urgency,
        ];
        $ticketData = Config::applyTicketDefaults($ticketData, 'threat', $config);

        $ticket   = new Ticket();
        $ticketId = (int)$ticket->add($ticketData);

        if ($ticketId > 0 && !empty($row['computers_id'])) {
            (new Item_Ticket())->add([
                'tickets_id' => $ticketId,
                'itemtype'   => 'Computer',
                'items_id'   => (int)$row['computers_id'],
            ]);
        }

        return $ticketId;
    }

    /**
     * The other direction: a GLPI ticket reaching Solved/Closed resolves the
     * Tanium alert it came from.
     *
     * Import was one-way. An analyst who worked an alert to completion in GLPI
     * left it open in Tanium, so the two consoles disagreed about the backlog
     * and the Tanium queue only ever grew.
     *
     * Deliberately quiet: a Tanium that is unreachable, or a token without the
     * permission, must never block someone from closing a ticket. The failure
     * goes to the plugin log and the ticket closes regardless.
     */
    public static function onTicketUpdate($ticket): void {
        global $DB;

        if (!is_object($ticket) || empty($ticket->fields['id'])) {
            return;
        }
        // Only act on the transition into a resolved state.
        if (!in_array((int)($ticket->fields['status'] ?? 0), [Ticket::SOLVED, Ticket::CLOSED], true)) {
            return;
        }
        if (!array_key_exists('status', (array)($ticket->updates ?? []))
            && !in_array('status', (array)($ticket->updates ?? []), true)) {
            return; // status untouched by this update
        }

        self::ensureTable();
        $row = $DB->request([
            'SELECT' => ['id', 'alert_id', 'status'],
            'FROM'   => self::$table,
            'WHERE'  => ['tickets_id' => (int)$ticket->fields['id']],
            'LIMIT'  => 1,
        ])->current();

        if ($row === null
            || empty($row['alert_id'])
            || in_array((string)$row['status'], ['resolved', 'closed', 'suppressed'], true)) {
            return;
        }

        $config = Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) {
            return;
        }

        try {
            $res = (new Api($config['api_url'], $config['api_token']))
                ->resolveThreatAlert((string)$row['alert_id']);

            if ($res['ok']) {
                $DB->update(self::$table, [
                    'status'   => 'resolved',
                    'date_mod' => date('Y-m-d H:i:s'),
                ], ['id' => (int)$row['id']]);
            } else {
                \Toolbox::logInFile('tanium', sprintf(
                    "[Tanium] Alerta %s nao pode ser resolvido no Tanium: %s\n",
                    $row['alert_id'],
                    $res['message']
                ));
            }
        } catch (\Throwable $e) {
            \Toolbox::logInFile('tanium', '[Tanium] Falha ao resolver alerta no Tanium: ' . $e->getMessage() . "\n");
        }
    }

    /**
     * Solve the GLPI ticket linked to an alert once the alert itself is
     * resolved/closed/suppressed on the Tanium side. Idempotent: tickets
     * already solved/closed (or deleted) are left untouched.
     */
    private static function resolveTicket(int $ticketId, string $alertTitle, string $status): void {
        $ticket = new Ticket();
        if (!$ticket->getFromDB($ticketId)
            || $ticket->fields['is_deleted']
            || in_array((int)$ticket->fields['status'], [Ticket::SOLVED, Ticket::CLOSED], true)) {
            return;
        }

        (new ITILSolution())->add([
            'itemtype'         => 'Ticket',
            'items_id'         => $ticketId,
            'content'          => Notification::autoSolutionHtml(
                '✅ Alerta resolvido no Tanium Threat Response',
                sprintf(
                    'O alerta <strong>%s</strong> mudou para o status <strong>%s</strong> no Tanium. Este chamado foi <strong>encerrado automaticamente</strong>.',
                    htmlspecialchars($alertTitle),
                    htmlspecialchars($status)
                )
            ),
            'solutiontypes_id' => 0,
            'users_id'         => Config::automationUserId(),
        ]);
    }

    /** Open (non-resolved) alert count for the dashboard KPI. */
    public static function countOpen(): int {
        global $DB;
        self::ensureTable();

        $row = $DB->doQuery(
            "SELECT COUNT(*) AS cpt FROM `" . self::$table . "`
             WHERE status NOT IN ('resolved', 'closed', 'suppressed')"
        )->fetch_assoc();
        return (int)($row['cpt'] ?? 0);
    }
}
