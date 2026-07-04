<?php

namespace GlpiPlugin\Tanium;

use CommonITILValidation;
use ITILFollowup;
use Item_Ticket;
use Session;
use Ticket;
use TicketValidation;
use Toolbox;

/**
 * Approval-gated remote actions on an endpoint (quarantine, agent restart),
 * mirroring the patch-deployment workflow:
 *
 *   request (endpoint page) → GLPI ticket + pending_approval record
 *   → TicketValidation ACCEPTED → GraphQL `actionCreate` runs the package
 *   → REFUSED → record marked rejected, nothing reaches the endpoint.
 *
 * The package that each action runs is configurable (Tanium content names
 * vary per tenant); targeting reuses the patch limiting group.
 */
class RemoteAction {

    public static $table = 'glpi_plugin_tanium_remote_actions';

    /** Built-in actions: key → [label, config key holding the package name, default package]. */
    public const ACTIONS = [
        'quarantine' => [
            'label'       => 'Quarentena de rede (isolar endpoint)',
            'package_key' => 'quarantine_package',
            'default'     => 'Apply Windows IPsec Quarantine',
        ],
        'restart_client' => [
            'label'       => 'Reiniciar o Tanium Client',
            'package_key' => 'restart_package',
            'default'     => 'Restart Tanium Client',
        ],
    ];

    public static function ensureTable(): void {
        global $DB;

        if ($DB->tableExists(self::$table)) {
            return;
        }

        $DB->doQuery(
            "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
                `id`               int unsigned NOT NULL AUTO_INCREMENT,
                `ticket_id`        int unsigned NOT NULL DEFAULT 0,
                `tanium_eid`       varchar(255) NOT NULL DEFAULT '',
                `computers_id`     int unsigned DEFAULT NULL,
                `action_key`       varchar(50) NOT NULL DEFAULT '',
                `package_name`     varchar(255) NOT NULL DEFAULT '',
                `status`           varchar(30) NOT NULL DEFAULT 'pending_approval',
                `tanium_action_id` varchar(64) DEFAULT NULL,
                `error_message`    text DEFAULT NULL,
                `requested_by`     int unsigned NOT NULL DEFAULT 0,
                `approved_by`      int unsigned NOT NULL DEFAULT 0,
                `created_at`       timestamp NULL DEFAULT NULL,
                `approved_at`      timestamp NULL DEFAULT NULL,
                `updated_at`       timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `ticket_id` (`ticket_id`),
                KEY `status` (`status`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    /** Package name an action key runs, honouring the config override. */
    public static function packageFor(string $actionKey, array $config): string {
        $meta = self::ACTIONS[$actionKey] ?? null;
        if ($meta === null) {
            return '';
        }
        $override = trim((string)($config[$meta['package_key']] ?? ''));
        return $override !== '' ? $override : $meta['default'];
    }

    /**
     * Create the approval ticket + pending record for an action request.
     *
     * @return array{success:bool,ticket_id?:int,error?:string}
     */
    public static function createRequest(string $eid, string $actionKey): array {
        global $DB;

        $meta = self::ACTIONS[$actionKey] ?? null;
        if ($meta === null) {
            return ['success' => false, 'error' => 'Unknown action'];
        }

        $res = $DB->doQuery(
            "SELECT * FROM glpi_plugin_tanium_assets WHERE tanium_eid = '" . $DB->escape($eid) . "' LIMIT 1"
        );
        if (!$res || !($asset = $res->fetch_assoc())) {
            return ['success' => false, 'error' => 'Endpoint not found'];
        }

        self::ensureTable();

        $config  = Config::getConfig();
        $package = self::packageFor($actionKey, $config);
        $name    = $asset['tanium_name'] ?: $eid;

        $isQuarantine = $actionKey === 'quarantine';
        $warn         = $isQuarantine
            ? '⚠️ A quarentena <strong>isola o endpoint da rede</strong> (mantendo apenas a comunicação com o Tanium). Use para conter comprometimentos ativos.'
            : 'O serviço do agente Tanium será reiniciado no endpoint. Operação de baixo impacto.';

        $html = "
<div style='border-left:4px solid #e8212a;background:#fff5f5;padding:16px 20px;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,sans-serif'>
  <div style='font-weight:700;color:#c53030;font-size:1rem;margin-bottom:10px'>🛡️ Ação remota Tanium — aguardando aprovação</div>
  <div style='color:#4a5568;font-size:.9rem;line-height:1.7'>
    <strong>Ação:</strong> " . htmlspecialchars($meta['label']) . "<br>
    <strong>Endpoint:</strong> " . htmlspecialchars($name) . " (IP " . htmlspecialchars($asset['ip_address'] ?: '?') . ", " . htmlspecialchars($asset['os_name'] ?: '?') . ")<br>
    <strong>Pacote Tanium:</strong> <code style='background:#e2e8f0;padding:2px 6px;border-radius:4px'>" . htmlspecialchars($package) . "</code><br><br>
    {$warn}<br><br>
    Envie uma <strong>solicitação de aprovação</strong> neste chamado. Quando <strong>aprovada</strong>, a ação é disparada
    automaticamente no Tanium; se <strong>recusada</strong>, nada é executado.
  </div>
</div>";

        $entityId = (int)($config['ticket_entity_id'] ?? 0) > 0
            ? (int)$config['ticket_entity_id']
            : (int)($_SESSION['glpiactive_entity'] ?? 0);

        $ticket   = new Ticket();
        $ticketId = (int)$ticket->add([
            'name'                => sprintf('[Tanium] Ação remota — %s — %s', $meta['label'], $name),
            'content'             => $html,
            'status'              => Ticket::INCOMING,
            'type'                => Ticket::INCIDENT_TYPE,
            'urgency'             => $isQuarantine ? 5 : 3,
            'impact'              => $isQuarantine ? 5 : 3,
            'priority'            => $isQuarantine ? 5 : 3,
            'entities_id'         => $entityId,
            'requesttypes_id'     => 1,
            '_users_id_requester' => Session::getLoginUserID(),
        ]);
        if (!$ticketId) {
            return ['success' => false, 'error' => 'Ticket creation failed'];
        }

        if (!empty($asset['computers_id'])) {
            (new Item_Ticket())->add([
                'itemtype'   => 'Computer',
                'items_id'   => (int)$asset['computers_id'],
                'tickets_id' => $ticketId,
            ]);
        }

        $DB->insert(self::$table, [
            'ticket_id'    => $ticketId,
            'tanium_eid'   => $eid,
            'computers_id' => $asset['computers_id'] ?: null,
            'action_key'   => $actionKey,
            'package_name' => $package,
            'status'       => 'pending_approval',
            'requested_by' => (int)Session::getLoginUserID(),
            'created_at'   => date('Y-m-d H:i:s'),
        ]);

        return ['success' => true, 'ticket_id' => $ticketId];
    }

    /** Companion to PatchDeploy::onValidationUpdate for remote actions. */
    public static function onValidationUpdate($validation): void {
        global $DB;

        if (!($validation instanceof TicketValidation)) {
            return;
        }

        $ticketId = (int)($validation->fields['tickets_id'] ?? 0);
        $status   = (int)($validation->fields['status'] ?? 0);
        if (!$ticketId || !in_array($status, [CommonITILValidation::ACCEPTED, CommonITILValidation::REFUSED], true)) {
            return;
        }

        self::ensureTable();
        $res = $DB->doQuery(
            "SELECT * FROM `" . self::$table . "`
             WHERE ticket_id = {$ticketId} AND status = 'pending_approval'
             LIMIT 1"
        );
        if (!$res || !($action = $res->fetch_assoc())) {
            return;
        }

        if ($status === CommonITILValidation::ACCEPTED) {
            $approver = (int)($validation->fields['users_id_validate'] ?? 0);
            if ($approver <= 0) {
                $approver = (int)Session::getLoginUserID();
            }
            self::trigger((int)$action['id'], $approver);
        } else {
            $DB->doQuery(
                "UPDATE `" . self::$table . "`
                 SET status = 'rejected', updated_at = NOW()
                 WHERE id = " . (int)$action['id'] . " AND status = 'pending_approval'"
            );
            self::followup((int)$action['ticket_id'], 'danger', '❌ Aprovação RECUSADA — ação cancelada',
                'A solicitação foi <strong>recusada</strong>. Nenhuma ação foi enviada ao Tanium.');
        }
    }

    /** Fire the approved action on Tanium. Idempotent on 'pending_approval'. */
    public static function trigger(int $id, int $approvedBy): array {
        global $DB;

        self::ensureTable();
        $res = $DB->doQuery("SELECT * FROM `" . self::$table . "` WHERE id = {$id} LIMIT 1");
        if (!$res || !($action = $res->fetch_assoc())) {
            return ['success' => false, 'error' => 'Action record not found'];
        }
        if (!in_array($action['status'], ['pending_approval', 'failed'], true)) {
            return ['success' => false, 'error' => 'Action already processed'];
        }

        $config = Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) {
            return ['success' => false, 'error' => 'Tanium API not configured'];
        }

        $ar = $DB->doQuery(
            "SELECT tanium_name FROM glpi_plugin_tanium_assets
             WHERE tanium_eid = '" . $DB->escape($action['tanium_eid']) . "' LIMIT 1"
        );
        $computerName = ($ar && ($a = $ar->fetch_assoc())) ? (string)$a['tanium_name'] : '';

        try {
            $api    = new Api($config['api_url'], $config['api_token']);
            $result = $api->createAction(
                $computerName,
                (string)$action['package_name'],
                'GLPI-Ticket-' . $action['ticket_id'] . ' ' . $action['action_key'],
                (int)($config['patch_limiting_group_id'] ?? 0)
            );

            $DB->doQuery(sprintf(
                "UPDATE `" . self::$table . "`
                 SET status = 'sent', approved_by = %d, approved_at = NOW(),
                     tanium_action_id = '%s', error_message = NULL, updated_at = NOW()
                 WHERE id = %d",
                $approvedBy,
                $DB->escape((string)$result['id']),
                $id
            ));

            self::followup((int)$action['ticket_id'], 'success', '✅ Ação aprovada e enviada ao Tanium',
                'A ação <strong>' . htmlspecialchars((string)$action['action_key']) . '</strong> foi disparada com sucesso no endpoint.<br>'
                . '🔖 ID da ação Tanium: <code style="background:#e2e8f0;padding:2px 6px;border-radius:4px">'
                . htmlspecialchars((string)$result['id']) . '</code>');

            return ['success' => true, 'tanium_action_id' => $result['id']];

        } catch (\Throwable $e) {
            $DB->doQuery(sprintf(
                "UPDATE `" . self::$table . "`
                 SET status = 'failed', error_message = '%s', updated_at = NOW()
                 WHERE id = %d",
                $DB->escape($e->getMessage()),
                $id
            ));
            self::followup((int)$action['ticket_id'], 'danger', '❌ Falha ao disparar a ação no Tanium',
                htmlspecialchars($e->getMessage()) . '<br>Verifique o nome do pacote na configuração do plugin e acione manualmente se necessário.');
            Toolbox::logInFile('tanium', '[Tanium] Remote action failed: ' . $e->getMessage() . "\n");

            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    private static function followup(int $ticketId, string $type, string $title, string $body): void {
        if ($ticketId <= 0) {
            return;
        }

        $styles = [
            'success' => ['border' => '#38a169', 'bg' => '#f0fff4', 'title' => '#276749'],
            'danger'  => ['border' => '#e53e3e', 'bg' => '#fff5f5', 'title' => '#c53030'],
        ];
        $s = $styles[$type] ?? $styles['success'];

        (new ITILFollowup())->add([
            'itemtype'   => 'Ticket',
            'items_id'   => $ticketId,
            'content'    => "
<div style='border-left:4px solid {$s['border']};background:{$s['bg']};padding:16px 20px;border-radius:8px;margin:4px 0'>
  <div style='font-weight:700;color:{$s['title']};font-size:.95rem;margin-bottom:10px'>{$title}</div>
  <div style='color:#4a5568;font-size:.88rem;line-height:1.6'>{$body}</div>
  <div style='margin-top:12px;font-size:.75rem;color:#a0aec0'>🤖 Resposta automática do plugin Tanium &nbsp;·&nbsp; " . date('d/m/Y H:i') . "</div>
</div>",
            'is_private' => 0,
        ]);
    }
}
