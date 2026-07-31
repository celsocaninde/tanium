<?php

namespace GlpiPlugin\Tanium;

use CommonGLPI;
use CommonITILValidation;
use CronTask;
use Html;
use ITILFollowup;
use ITILSolution;
use Item_Ticket;
use Session;
use Ticket;
use TicketValidation;

class PatchDeploy extends CommonGLPI {

    public static function getTypeName($nb = 0): string {
        return __('Tanium Patch Deployment', 'tanium');
    }

    /**
     * GLPI reads this to describe the task in Setup > Automatic actions.
     * Without it the row shows up bare, with no hint of why a Tanium task
     * runs every five minutes.
     */
    public static function cronInfo(string $name): array {
        return match ($name) {
            'checkdeployments' => [
                'description' => __('Tanium — poll active patch deployments and auto-close the ticket when the deployment finishes.', 'tanium'),
            ],
            default => [],
        };
    }

    // ── GLPI approval (TicketValidation) hook ────────────────────────────────

    /**
     * Called by plugin_tanium_validation_update hook when a Ticket approval
     * request (TicketValidation) is created or updated.
     *
     * Flow: the patch deployment waits in 'pending_approval' until the GLPI
     * approver responds to the validation request.
     *   • ACCEPTED → send the deployment to Tanium (triggerDeploy)
     *   • REFUSED  → mark the deployment 'rejected' and notify on the ticket
     *
     * Reading $validation->fields['status'] is correct here: on item_update the
     * record already holds the new (post-decision) status.
     */
    public static function onValidationUpdate($validation): void {
        global $DB;

        if (!($validation instanceof TicketValidation)) return;

        $ticketId = (int)($validation->fields['tickets_id'] ?? 0);
        $status   = (int)($validation->fields['status'] ?? 0);
        if (!$ticketId) return;

        // Act only on a final decision (accepted/refused), not on "waiting".
        if (!in_array($status, [CommonITILValidation::ACCEPTED, CommonITILValidation::REFUSED], true)) {
            return;
        }

        // Find a deployment still awaiting approval for this ticket.
        // triggerDeploy/markRejected are idempotent (they only act on
        // 'pending_approval'), so multiple validators cannot double-deploy.
        $res = $DB->doQuery(
            "SELECT * FROM `glpi_plugin_tanium_patch_deployments`
             WHERE ticket_id = {$ticketId} AND status = 'pending_approval'
             LIMIT 1"
        );
        if (!$res || !($dep = $res->fetch_assoc())) return;

        if ($status === CommonITILValidation::ACCEPTED) {
            $approver = (int)($validation->fields['users_id_validate'] ?? 0);
            if ($approver <= 0) {
                $approver = (int)Session::getLoginUserID();
            }
            self::triggerDeploy((int)$dep['id'], $approver);
        } else { // REFUSED
            self::markRejected((int)$dep['id'], $dep, $validation);
        }
    }

    // ── HTML helper for styled follow-up messages ────────────────────────────

    private static function followupHtml(string $type, string $title, string $body, string $extra = ''): string {
        $styles = [
            'success' => ['border' => '#38a169', 'bg' => '#f0fff4', 'title' => '#276749'],
            'danger'  => ['border' => '#e53e3e', 'bg' => '#fff5f5', 'title' => '#c53030'],
            'warning' => ['border' => '#d69e2e', 'bg' => '#fffff0', 'title' => '#975a16'],
            'info'    => ['border' => '#3182ce', 'bg' => '#ebf8ff', 'title' => '#2b6cb0'],
        ];
        $s   = $styles[$type] ?? $styles['info'];
        $now = date('d/m/Y H:i');
        return "
<div style='border-left:4px solid {$s['border']};background:{$s['bg']};padding:16px 20px;border-radius:8px;margin:4px 0;font-family:-apple-system,BlinkMacSystemFont,sans-serif'>
  <div style='font-weight:700;color:{$s['title']};font-size:.95rem;margin-bottom:10px'>{$title}</div>
  <div style='color:#4a5568;font-size:.88rem;line-height:1.6'>{$body}</div>
  " . ($extra !== '' ? "<div style='margin-top:12px;padding:10px 14px;background:rgba(0,0,0,.04);border-radius:6px;font-size:.83rem;color:#4a5568'>{$extra}</div>" : '') . "
  <div style='margin-top:12px;font-size:.75rem;color:#a0aec0'>🤖 Resposta automática do plugin Tanium &nbsp;·&nbsp; {$now}</div>
</div>";
    }

    // ── Approval refused — cancel the deployment ─────────────────────────────

    private static function markRejected(int $depId, array $dep, TicketValidation $validation): void {
        global $DB;

        $DB->doQuery(
            "UPDATE `glpi_plugin_tanium_patch_deployments`
             SET status = 'rejected', updated_at = NOW()
             WHERE id = {$depId} AND status = 'pending_approval'"
        );

        if (!empty($dep['ticket_id'])) {
            $comment = trim((string)($validation->fields['comment_validation'] ?? ''));
            $extra   = $comment !== ''
                ? '<strong>Motivo informado pelo aprovador:</strong><br><em>"' . htmlspecialchars($comment) . '"</em>'
                : '';

            $fu = new ITILFollowup();
            $fu->add([
                'itemtype'   => 'Ticket',
                'items_id'   => (int)$dep['ticket_id'],
                'content'    => self::followupHtml(
                    'danger',
                    '❌ Aprovação RECUSADA — Deploy cancelado',
                    'A solicitação de aprovação foi <strong>recusada</strong>. Nenhum patch foi enviado ao Tanium e o deploy não será executado.',
                    $extra
                ),
                'is_private' => 0,
                'users_id'   => Config::automationUserId(),
            ]);
        }
    }

    // ── Trigger Tanium deployment ───────────────────────────────────────────

    /**
     * Stops a deployment that is already running in Tanium.
     *
     * Everything this plugin could start, it could not stop: a deployment
     * aimed at the wrong group had to be chased down in the Tanium console,
     * which is the worst moment to be hunting for another browser tab.
     *
     * A deployment that never reached Tanium (no `tanium_deployment_id`) is
     * cancelled locally — there is nothing on the other side to stop.
     *
     * @return array{success:bool,error?:string,message?:string}
     */
    public static function cancelDeploy(int $depId, int $cancelledBy): array {
        global $DB;

        $res = $DB->doQuery(
            "SELECT * FROM `glpi_plugin_tanium_patch_deployments` WHERE id = {$depId} LIMIT 1"
        );
        if (!$res || !($dep = $res->fetch_assoc())) {
            return ['success' => false, 'error' => 'Deployment record not found'];
        }

        if (in_array($dep['status'], ['deployed', 'failed', 'rejected', 'cancelled'], true)) {
            return ['success' => false, 'error' => 'Este deployment já terminou — não há o que cancelar.'];
        }

        $taniumId = trim((string)($dep['tanium_deployment_id'] ?? ''));

        if ($taniumId === '') {
            $DB->update('glpi_plugin_tanium_patch_deployments', [
                'status'        => 'cancelled',
                'error_message' => 'Cancelado no GLPI antes de ser enviado ao Tanium.',
            ], ['id' => $depId]);
            return ['success' => true, 'message' => 'Deployment cancelado (ainda não havia sido enviado ao Tanium).'];
        }

        $config = Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) {
            return ['success' => false, 'error' => 'Tanium API not configured'];
        }

        $out = (new Api($config['api_url'], $config['api_token']))->stopPatchDeployment($taniumId);
        if (!$out['ok']) {
            return ['success' => false, 'error' => $out['message']];
        }

        $DB->update('glpi_plugin_tanium_patch_deployments', [
            'status'        => 'cancelled',
            'error_message' => sprintf('Cancelado no GLPI por users_id=%d.', $cancelledBy),
        ], ['id' => $depId]);

        return ['success' => true, 'message' => $out['message']];
    }

    public static function triggerDeploy(int $depId, int $approvedBy): array {
        global $DB;

        $res = $DB->doQuery(
            "SELECT * FROM `glpi_plugin_tanium_patch_deployments` WHERE id = {$depId} LIMIT 1"
        );
        if (!$res || !($dep = $res->fetch_assoc())) {
            return ['success' => false, 'error' => 'Deployment record not found'];
        }

        if (!in_array($dep['status'], ['pending_approval', 'failed'])) {
            return ['success' => false, 'error' => 'Deployment already in progress or completed'];
        }

        $config = Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) {
            return ['success' => false, 'error' => 'Tanium API not configured'];
        }

        $patches = json_decode($dep['patch_ids'], true) ?: [];
        if (empty($patches)) {
            return ['success' => false, 'error' => 'No patches selected for this deployment'];
        }

        // Tanium targets by computer name + osType, so load them from the asset.
        $asset = null;
        $ar = $DB->doQuery(
            "SELECT tanium_name, os_name, os_platform FROM `glpi_plugin_tanium_assets`
             WHERE tanium_eid = '" . $DB->escape($dep['tanium_eid']) . "' LIMIT 1"
        );
        if ($ar) {
            $asset = $ar->fetch_assoc();
        }

        // Build patch descriptors — the title carries the exact version Tanium
        // needs (a single KB can map to many versioned patches).
        $titleByKb = [];
        $inList = "'" . implode("','", array_map([$DB, 'escape'], $patches)) . "'";
        $prr = $DB->doQuery(
            "SELECT patch_id, patch_title FROM `glpi_plugin_tanium_patches`
             WHERE tanium_eid = '" . $DB->escape($dep['tanium_eid']) . "'
               AND patch_id IN ({$inList})"
        );
        if ($prr) {
            while ($row = $prr->fetch_assoc()) {
                $titleByKb[$row['patch_id']] = $row['patch_title'];
            }
        }
        $patchDescriptors = [];
        foreach ($patches as $kb) {
            $patchDescriptors[] = ['kb' => $kb, 'title' => $titleByKb[$kb] ?? ''];
        }

        $api = new Api($config['api_url'], $config['api_token']);

        try {
            $result      = $api->deployPatches($dep['tanium_eid'], $patchDescriptors, 'GLPI-Ticket-' . $dep['ticket_id'], [
                'osType'          => self::mapOsType(($asset['os_platform'] ?? '') . ' ' . ($asset['os_name'] ?? '')),
                'computerName'    => $asset['tanium_name'] ?? '',
                'limitingGroupId' => (int)($dep['limiting_group_id'] ?? 0) > 0
                    ? (int)$dep['limiting_group_id']
                    : (int)($config['patch_limiting_group_id'] ?? 0),
                'restart'         => true,
            ]);
            $taniumDepId = $result['data']['id'] ?? $result['id'] ?? null;
            $newStatus   = $taniumDepId ? 'deploying' : 'failed';
            $errMsg      = $taniumDepId ? null : 'No deployment ID returned from Tanium API';

            $DB->doQuery(sprintf(
                "UPDATE `glpi_plugin_tanium_patch_deployments`
                 SET status = '%s', approved_by = %d, approved_at = NOW(),
                     tanium_deployment_id = %s, error_message = %s, updated_at = NOW()
                 WHERE id = %d",
                $newStatus,
                $approvedBy,
                $taniumDepId ? ("'" . $DB->escape((string)$taniumDepId) . "'") : 'NULL',
                $errMsg     ? ("'" . $DB->escape($errMsg) . "'")             : 'NULL',
                $depId
            ));

            if ($dep['ticket_id']) {
                $fu = new ITILFollowup();
                $fu->add([
                    'itemtype'        => 'Ticket',
                    'items_id'        => (int)$dep['ticket_id'],
                    'content'         => $taniumDepId
                        ? self::followupHtml(
                            'success',
                            '✅ Deploy aprovado e iniciado no Tanium',
                            'A aprovação foi aceita e o comando de deploy foi enviado ao agente Tanium com sucesso.<br><br>'
                            . 'O chamado será <strong>encerrado automaticamente</strong> quando o Tanium confirmar a instalação de todos os patches.',
                            '🔖 ID de implantação Tanium: <code style="background:#e2e8f0;padding:2px 6px;border-radius:4px">' . htmlspecialchars((string)$taniumDepId) . '</code>'
                          )
                        : self::followupHtml(
                            'warning',
                            '⚠️ Aprovação registrada — sem confirmação do Tanium',
                            'A aprovação foi aceita, mas a API do Tanium não retornou um ID de implantação.<br>'
                            . 'Verifique o console do Tanium e acione o deploy manualmente se necessário.'
                          ),
                    'is_private'      => 0,
                    'requesttypes_id' => 0,
                    'users_id'        => Config::automationUserId($config),
                ]);
            }

            if ($taniumDepId) {
                self::notifyDeployWebhook('started', $dep, count($patches), (string)$taniumDepId);
            }

            return ['success' => (bool)$taniumDepId, 'tanium_deployment_id' => $taniumDepId];

        } catch (\Exception $e) {
            $DB->doQuery(sprintf(
                "UPDATE `glpi_plugin_tanium_patch_deployments`
                 SET status = 'failed', error_message = '%s', updated_at = NOW()
                 WHERE id = %d",
                $DB->escape($e->getMessage()), $depId
            ));
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Webhook on deploy lifecycle events (started/deployed/failed), gated by
     * the "webhook_deploy" plugin setting. Never throws — a webhook failure
     * must not break the deployment flow.
     */
    private static function notifyDeployWebhook(string $event, array $dep, int $patchCount, string $taniumDepId = '', string $error = ''): void {
        global $DB;

        try {
            $config = Config::getConfig();
            if (empty($config['webhook_deploy']) || empty($config['webhook_url'])) {
                return;
            }

            $endpointName = (string)$dep['tanium_eid'];
            $ar = $DB->doQuery(
                "SELECT tanium_name FROM `glpi_plugin_tanium_assets`
                 WHERE tanium_eid = '" . $DB->escape($dep['tanium_eid']) . "' LIMIT 1"
            );
            if ($ar && ($a = $ar->fetch_assoc()) && !empty($a['tanium_name'])) {
                $endpointName = $a['tanium_name'];
            }

            Notification::sendWebhook(
                $config['webhook_url'],
                Notification::buildDeployPayload($event, $endpointName, $patchCount, (int)$dep['ticket_id'], $taniumDepId, $error)
            );
        } catch (\Throwable $e) {
            \Toolbox::logInFile('tanium', '[Tanium] Deploy webhook error: ' . $e->getMessage() . "\n");
        }
    }

    /**
     * Split a patch's advisory field into renderable parts. Tanium concatenates
     * every advisory ID of a patch into one string — "KB5034441, KB5034123" for
     * a Windows cumulative update, "USN-6013-1 USN-6013-2" on Ubuntu — which is
     * why the column is TEXT. Linking that raw value to support.microsoft.com
     * produced a dead URL for multi-KB rows and pointed Linux advisories at
     * Microsoft, so only a genuine KB number gets a link; anything else renders
     * as plain text.
     *
     * @return array<int,array{label:string,url:?string}>
     */
    public static function kbParts(?string $kbId): array {
        // Hyphens are NOT separators: USN/DSA/RHSA ids embed them.
        $tokens = preg_split('/[\s,;|]+/', trim((string)$kbId), -1, PREG_SPLIT_NO_EMPTY) ?: [];

        $out = [];
        foreach ($tokens as $token) {
            $label = trim($token, ".,;:()[]'\"");
            if ($label === '') {
                continue;
            }
            $out[] = [
                'label' => $label,
                'url'   => preg_match('/^KB\d+$/i', $label)
                    // The canonical article URL takes the bare number — /kb/KB123 404s.
                    ? 'https://support.microsoft.com/help/' . preg_replace('/^KB/i', '', $label)
                    : null,
            ];
        }
        return $out;
    }

    /**
     * Whether the endpoint is waiting for a reboot to finish applying patches.
     *
     * Tanium exposes this through a sensor ("Reboot Required", "Pending
     * Reboot", … — the name varies per tenant), collected only when the admin
     * lists it under the plugin's custom sensors. Until the machine reboots,
     * Windows keeps reporting the KB as still applicable, so the patch shows as
     * MISSING even though it is installed — this flag is what lets the UI say
     * so instead of looking like a failed remediation.
     *
     * @param  ?string $sensorDataJson the asset's `sensor_data` column
     * @param  ?string $sensorName     the configured sensor; falls back to a
     *                                 name match when empty
     * @return ?bool   null when no reboot sensor is collected (unknown)
     */
    public static function rebootPending(?string $sensorDataJson, ?string $sensorName = null): ?bool {
        $sensors = json_decode((string)$sensorDataJson, true);
        if (!is_array($sensors)) {
            return null;
        }

        // An explicitly configured sensor wins: the guess below would also
        // match an unrelated sensor that merely has "restart" in its name.
        $configured = trim((string)$sensorName);
        if ($configured !== '' && array_key_exists($configured, $sensors)) {
            return self::rebootValue((string)$sensors[$configured]);
        }

        foreach ($sensors as $name => $value) {
            if (!preg_match('/reboot|restart|reinicial/i', (string)$name)) {
                continue;
            }
            $parsed = self::rebootValue((string)$value);
            if ($parsed !== null) {
                return $parsed;
            }
        }
        return null;
    }

    /** Truthiness of a reboot sensor reading; null when it said nothing. */
    private static function rebootValue(string $value): ?bool {
        $v = strtolower(trim($value));
        if ($v === '' || $v === '[no results]') {
            return null;
        }
        return (bool)preg_match('/^(1|true|yes|sim|required|pending|reboot)/i', $v);
    }

    /**
     * Map a GLPI/Tanium OS string to the Tanium Patch `osType` value.
     *
     * The fallback is 'windows', so every distro that does NOT spell out
     * "Linux" has to be listed explicitly — "RHEL 9" and "Fedora 40" carry no
     * 'lin' substring and used to be deployed as Windows, which also picks the
     * wrong patch UIDs in resolvePatchUids(). Names that do contain "Linux"
     * (Rocky Linux, AlmaLinux, Oracle Linux, Amazon Linux) match on 'lin'.
     */
    private static function mapOsType(string $os): string {
        $o = strtolower($os);
        // macOS is tested FIRST because "darwin" contains "win": checking
        // Windows first classified every Darwin-reported Mac as Windows.
        if (str_contains($o, 'mac') || str_contains($o, 'darwin'))  return 'mac';
        if (str_contains($o, 'win'))                               return 'windows';

        foreach ([
            'lin', 'ubuntu', 'debian', 'red hat', 'redhat', 'rhel', 'centos',
            'suse', 'sles', 'fedora', 'rocky', 'alma', 'oracle', 'amzn',
        ] as $marker) {
            if (str_contains($o, $marker)) {
                return 'linux';
            }
        }
        return 'windows';
    }

    // ── Cron: poll deploying records ────────────────────────────────────────

    public static function cronCheckdeployments(CronTask $task): int {
        global $DB;

        $config = Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) return 0;

        $api = new Api($config['api_url'], $config['api_token']);

        // Deployments Tanium never resolves.
        //
        // The poll below only reacts to terminal states. A deployment left in
        // PENDING or WAITING — agent offline, maintenance window never opened,
        // the record lost on the Tanium side — was re-polled every five
        // minutes forever and its ticket never closed, so a request that will
        // never complete looked identical to one still in progress.
        self::failStalledDeployments();

        $res = $DB->doQuery(
            "SELECT * FROM `glpi_plugin_tanium_patch_deployments`
             WHERE status = 'deploying' AND tanium_deployment_id IS NOT NULL
             ORDER BY created_at ASC LIMIT 50"
        );

        $processed = 0;
        while ($dep = $res->fetch_assoc()) {
            try {
                $statusData   = $api->getDeploymentStatus((string)$dep['tanium_deployment_id']);
                $taniumState  = strtoupper($statusData['data']['status'] ?? $statusData['status'] ?? '');

                if (in_array($taniumState, ['SUCCEEDED', 'COMPLETED', 'SUCCESS', 'COMPLETE', 'FINISHED'])) {
                    self::markDeployed((int)$dep['id'], $dep);
                    $processed++;
                } elseif (in_array($taniumState, ['FAILED', 'ERROR', 'CANCELLED', 'ABORTED'])) {
                    $DB->doQuery(sprintf(
                        "UPDATE `glpi_plugin_tanium_patch_deployments`
                         SET status = 'failed', error_message = 'Tanium status: %s', updated_at = NOW()
                         WHERE id = %d",
                        $DB->escape($taniumState), (int)$dep['id']
                    ));
                    if ($dep['ticket_id']) {
                        $fu = new ITILFollowup();
                        $fu->add([
                            'itemtype'   => 'Ticket',
                            'items_id'   => (int)$dep['ticket_id'],
                            'content'    => self::followupHtml(
                                'danger',
                                '❌ Falha na implantação de patches',
                                'O Tanium reportou uma falha durante a execução do deploy. <strong>Intervenção manual necessária.</strong><br>'
                                . 'Acesse o console do Tanium para verificar os logs e o estado do agente no endpoint.',
                                '📋 Status reportado pelo Tanium: <code style="background:#fed7d7;padding:2px 6px;border-radius:4px">'
                                . htmlspecialchars($taniumState) . '</code>'
                            ),
                            'is_private' => 0,
                            'users_id'   => Config::automationUserId($config),
                        ]);
                    }
                    self::notifyDeployWebhook(
                        'failed',
                        $dep,
                        count(json_decode($dep['patch_ids'], true) ?: []),
                        (string)$dep['tanium_deployment_id'],
                        'Tanium status: ' . $taniumState
                    );
                    $processed++;
                }
            } catch (\Exception $e) {
                // Skip on API error — will retry on next cron run
            }
        }

        // Remote actions share the same polling cadence.
        $processed += RemoteAction::pollSent($api);

        $task->addVolume($processed);
        return $processed > 0 ? 1 : 0;
    }

    /**
     * Hours a deployment may stay in flight before it is called a failure.
     *
     * The deployment window itself defaults to 24h (Api::deployPatches), so
     * anything still open well past that is not slow, it is stuck.
     */
    private const DEPLOY_MAX_HOURS = 72;

    /** Close out deployments that have been in flight too long to be real. */
    private static function failStalledDeployments(): void {
        global $DB;

        $cutoff = date('Y-m-d H:i:s', strtotime('-' . self::DEPLOY_MAX_HOURS . ' hours'));
        $config = Config::getConfig();

        $res = $DB->doQuery(sprintf(
            "SELECT * FROM `glpi_plugin_tanium_patch_deployments`
              WHERE status = 'deploying'
                AND COALESCE(approved_at, created_at) < '%s'",
            $DB->escape($cutoff)
        ));

        while ($res && ($dep = $res->fetch_assoc())) {
            $DB->doQuery(sprintf(
                "UPDATE `glpi_plugin_tanium_patch_deployments`
                    SET status = 'failed', error_message = '%s', updated_at = NOW()
                  WHERE id = %d AND status = 'deploying'",
                $DB->escape(sprintf('Timed out: no terminal status from Tanium within %dh', self::DEPLOY_MAX_HOURS)),
                (int)$dep['id']
            ));

            if (!empty($dep['ticket_id'])) {
                $fu = new ITILFollowup();
                $fu->add([
                    'itemtype'   => 'Ticket',
                    'items_id'   => (int)$dep['ticket_id'],
                    'content'    => self::followupHtml(
                        'warning',
                        '⏱️ Implantação sem resposta — encerrada por tempo',
                        sprintf(
                            'O Tanium não reportou conclusão nem falha em <strong>%dh</strong>. '
                            . 'O deploy foi marcado como falho para não ficar em aberto indefinidamente.<br><br>'
                            . 'Verifique no console do Tanium se a implantação chegou a rodar — o agente pode estar '
                            . 'offline ou a janela de manutenção pode não ter aberto.',
                            self::DEPLOY_MAX_HOURS
                        )
                    ),
                    'is_private' => 0,
                    'users_id'   => Config::automationUserId($config),
                ]);
            }

            self::notifyDeployWebhook(
                'failed',
                $dep,
                count(json_decode((string)$dep['patch_ids'], true) ?: []),
                (string)($dep['tanium_deployment_id'] ?? ''),
                'timeout'
            );
        }
    }

    // ── Mark deployment as successfully completed ───────────────────────────

    private static function markDeployed(int $depId, array $dep): void {
        global $DB;

        $DB->doQuery(
            "UPDATE `glpi_plugin_tanium_patch_deployments`
             SET status = 'deployed', deployed_at = NOW(), updated_at = NOW()
             WHERE id = {$depId}"
        );

        $patches = json_decode($dep['patch_ids'], true) ?: [];

        // Mark every deployed patch as remediated, recording the transition in
        // patch_history so the remediation trend/reports count deploys too.
        foreach ($patches as $patchId) {
            $row = $DB->request([
                'FROM'  => 'glpi_plugin_tanium_patches',
                'WHERE' => ['tanium_eid' => $dep['tanium_eid'], 'patch_id' => $patchId],
                'LIMIT' => 1,
            ])->current();
            if (!$row || $row['status'] === 'remediated') {
                continue;
            }

            $DB->update('glpi_plugin_tanium_patches', [
                'status'   => 'remediated',
                'date_mod' => date('Y-m-d H:i:s'),
            ], ['id' => $row['id']]);
            $DB->insert('glpi_plugin_tanium_patch_history', [
                'tanium_eid'   => $dep['tanium_eid'],
                'patch_id'     => $row['patch_id'],
                'patch_title'  => (string)$row['patch_title'],
                'severity'     => strtolower((string)($row['severity'] ?? 'unknown')),
                'computers_id' => $row['computers_id'] ?? null,
                'old_status'   => $row['status'],
                'new_status'   => 'remediated',
                'changed_at'   => date('Y-m-d H:i:s'),
            ]);
        }

        // Resolve only the assignments backed by evidence.
        //
        // Tanium exposes no patch→CVE mapping, so a finished deploy proves
        // nothing about any particular CVE: it only proves the patches it
        // carried are installed. Patch assignments therefore close here, while
        // CVE assignments wait for a sync to confirm Tanium stopped reporting
        // the finding. Blanket-resolving every assignment of the endpoint (the
        // behaviour up to v2.15.0) closed findings nobody had fixed.
        $eidEsc = $DB->escape($dep['tanium_eid']);

        $DB->doQuery(
            "UPDATE `glpi_plugin_tanium_cve_assignments` asgn
             JOIN `glpi_plugin_tanium_patches` p
                  ON p.tanium_eid = asgn.tanium_eid AND p.patch_id = asgn.cve_id
             SET asgn.status = 'resolved', asgn.date_mod = NOW()
             WHERE asgn.tanium_eid = '{$eidEsc}'
               AND asgn.ref_type = 'patch'
               AND asgn.status != 'resolved'
               AND p.status = 'remediated'"
        );

        $DB->doQuery(
            "UPDATE `glpi_plugin_tanium_cve_assignments` asgn
             JOIN `glpi_plugin_tanium_endpoint_cves` ec
                  ON ec.tanium_eid = asgn.tanium_eid AND ec.cve_id = asgn.cve_id
             SET asgn.status = 'resolved', asgn.date_mod = NOW()
             WHERE asgn.tanium_eid = '{$eidEsc}'
               AND asgn.ref_type = 'cve'
               AND asgn.status != 'resolved'
               AND ec.status = 'remediated'"
        );

        // Recalculate endpoint risk score
        Sync::updateRiskScore($dep['tanium_eid']);

        self::notifyDeployWebhook('deployed', $dep, count($patches), (string)($dep['tanium_deployment_id'] ?? ''));

        // Auto-close the GLPI ticket with a solution comment
        if ($dep['ticket_id']) {
            $ticket = new Ticket();
            if ($ticket->getFromDB((int)$dep['ticket_id'])) {
                $patchCount = count($patches);
                $solution = new ITILSolution();
                $solution->add([
                    'itemtype'         => 'Ticket',
                    'items_id'         => (int)$dep['ticket_id'],
                    'content'          => self::followupHtml(
                        'success',
                        '✅ Implantação concluída — Todos os patches foram aplicados',
                        sprintf(
                            '<strong>%d patch%s</strong> implantado%s com sucesso pelo agente Tanium em <strong>%s</strong>.<br><br>'
                            . '✔ Os patches acima foram marcados como <strong>corrigidos</strong>.<br>'
                            . '✔ Score de risco do endpoint foi <strong>recalculado</strong>.<br>'
                            . '✔ Este chamado foi <strong>encerrado automaticamente</strong>.<br><br>'
                            . '⏳ As <strong>CVEs</strong> deste endpoint permanecem abertas até que uma sincronização '
                            . 'confirme que o Tanium deixou de reportá-las — o Tanium não informa qual patch corrige '
                            . 'qual CVE, então a instalação por si só não comprova a correção de nenhuma CVE específica.',
                            $patchCount,
                            $patchCount > 1 ? 's' : '',
                            $patchCount > 1 ? 's' : '',
                            date('d/m/Y \à\s H:i')
                        )
                    ),
                    'solutiontypes_id' => 0,
                ]);
            }
        }
    }

    // ── KEV auto-remediation ─────────────────────────────────────────────────

    /**
     * Days an endpoint stays out of the KEV automation after any deployment
     * attempt. Without it a refused approval re-qualified on the very next
     * cron run — the automation reopened, every run, exactly the tickets a
     * human had just declined.
     */
    private const KEV_COOLDOWN_DAYS = 30;

    /**
     * Opt-in automation: endpoints exposed to KEV (actively exploited) CVEs
     * that have missing high-severity patches get a patch-remediation ticket
     * opened automatically, in pending_approval state — the deploy itself
     * still goes through the human approval flow. Skips endpoints with a
     * deployment already pending/in-flight or attempted within the cooldown;
     * capped per run to avoid floods.
     */
    public static function autoDeployKev(array $config, int $maxPerRun = 5): int {
        global $DB;

        if (empty($config['auto_deploy_kev'])) {
            return 0;
        }

        $res = $DB->doQuery("
            SELECT DISTINCT a.tanium_eid
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_cve_enrichment e
                 ON e.cve_id = ec.cve_id AND e.is_kev = 1
            JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = ec.tanium_eid
            " . Sla::activeExceptionJoin() . "
            WHERE ec.status != 'remediated'
              AND ex.id IS NULL
              AND EXISTS (
                  SELECT 1 FROM glpi_plugin_tanium_patches p
                  WHERE p.tanium_eid = ec.tanium_eid AND p.status = 'missing'
                    AND LOWER(p.severity) IN ('critical', 'important', 'high')
              )
              AND NOT EXISTS (
                  SELECT 1 FROM glpi_plugin_tanium_patch_deployments d
                  WHERE d.tanium_eid = ec.tanium_eid
                    AND (
                         d.status IN ('pending_approval', 'deploying')
                      OR COALESCE(d.updated_at, d.created_at)
                         > DATE_SUB(NOW(), INTERVAL " . self::KEV_COOLDOWN_DAYS . " DAY)
                    )
              )
            LIMIT " . max(1, $maxPerRun)
        );

        $opened = 0;
        while ($res && ($row = $res->fetch_assoc())) {
            try {
                if (self::openKevRemediation((string)$row['tanium_eid'], $config)) {
                    $opened++;
                }
            } catch (\Throwable $e) {
                \Toolbox::logInFile('tanium', '[Tanium] KEV auto-deploy failed for ' . $row['tanium_eid'] . ': ' . $e->getMessage() . "\n");
            }
        }
        return $opened;
    }

    private static function openKevRemediation(string $eid, array $config): bool {
        global $DB;

        $er = $DB->doQuery("SELECT * FROM glpi_plugin_tanium_assets WHERE tanium_eid = '" . $DB->escape($eid) . "' LIMIT 1");
        if (!$er || !($endpoint = $er->fetch_assoc())) {
            return false;
        }

        $patches = [];
        foreach ($DB->doQuery("
            SELECT * FROM glpi_plugin_tanium_patches
            WHERE tanium_eid = '" . $DB->escape($eid) . "' AND status = 'missing'
              AND LOWER(severity) IN ('critical', 'important', 'high')
            ORDER BY FIELD(LOWER(severity), 'critical', 'important', 'high'), release_date DESC
            LIMIT 20
        ") as $p) {
            $patches[] = $p;
        }
        if (!$patches) {
            return false;
        }

        $kevCves = [];
        foreach ($DB->doQuery("
            SELECT ec.cve_id, v.title, v.severity, v.cvss_score
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_cve_enrichment e ON e.cve_id = ec.cve_id AND e.is_kev = 1
            LEFT JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
            WHERE ec.tanium_eid = '" . $DB->escape($eid) . "' AND ec.status != 'remediated'
            ORDER BY v.cvss_score DESC LIMIT 50
        ") as $c) {
            $kevCves[] = $c;
        }

        $name = $endpoint['tanium_name'] ?: $eid;
        $html = "<div style='border-left:4px solid #e8212a;background:#fff5f5;padding:12px 16px;border-radius:8px;margin-bottom:10px'>"
              . "<strong style='color:#c53030'>🔥 Aberto automaticamente:</strong> este endpoint tem "
              . count($kevCves) . " CVE(s) do catálogo <strong>CISA KEV</strong> (exploração ativa confirmada), "
              . "o que o coloca na fila de correção prioritária."
              . "<br><br><span style='font-size:.85rem;color:#742a2a'>⚠️ Os <strong>" . count($patches) . " patch(es)</strong> listados abaixo são "
              . "<strong>todos os pendentes de severidade crítica/alta</strong> deste endpoint — o Tanium não informa qual patch "
              . "corrige qual CVE, portanto esta lista não é uma correspondência às CVEs KEV acima. As CVEs só serão dadas como "
              . "corrigidas quando o Tanium deixar de reportá-las.</span>"
              . "</div>"
              . self::buildTicketHtml($endpoint, $patches, $kevCves, $config);

        $ticketData = [
            'name'        => sprintf('[Tanium] Auto: remediação KEV — %s (%d patches)', $name, count($patches)),
            'content'     => $html,
            'status'      => Ticket::INCOMING,
            'type'        => Ticket::INCIDENT_TYPE,
            'urgency'     => 5,
            'impact'      => 5,
            'priority'    => 5,
            'entities_id' => (int)($config['ticket_entity_id'] ?? 0),
        ];
        $requester = Config::ticketRequesterId(0, $config);
        if ($requester > 0) {
            $ticketData['_users_id_requester'] = $requester;
            $ticketData['_users_id_assign']    = $requester;
        }

        $ticket   = new Ticket();
        $ticketId = (int)$ticket->add($ticketData);
        if (!$ticketId) {
            return false;
        }

        if (!empty($endpoint['computers_id'])) {
            (new \Item_Ticket())->add([
                'itemtype'   => 'Computer',
                'items_id'   => (int)$endpoint['computers_id'],
                'tickets_id' => $ticketId,
            ]);
        }

        $DB->insert('glpi_plugin_tanium_patch_deployments', [
            'ticket_id'    => $ticketId,
            'tanium_eid'   => $eid,
            'computers_id' => $endpoint['computers_id'] ?: null,
            'patch_ids'    => json_encode(array_column($patches, 'patch_id')),
            'status'       => 'pending_approval',
            'requested_by' => 0,
            'created_at'   => date('Y-m-d H:i:s'),
        ]);

        return true;
    }

    // ── Build professional ticket HTML ──────────────────────────────────────

    public static function buildTicketHtml(
        array $endpoint,
        array $patches,
        array $cves,
        array $config
    ): string {
        $total    = count($patches);
        $critical = array_values(array_filter($patches, fn($p) => strtolower($p['severity'] ?? '') === 'critical'));
        $high     = array_values(array_filter($patches, fn($p) => in_array(strtolower($p['severity'] ?? ''), ['important', 'high'])));
        $riskKey  = count($critical) > 0 ? 'CRITICAL' : (count($high) > 0 ? 'HIGH' : 'MEDIUM');
        $riskClr  = match($riskKey) { 'CRITICAL' => '#e53e3e', 'HIGH' => '#ed8936', default => '#ecc94b' };
        $riskLbl  = match($riskKey) { 'CRITICAL' => 'RISCO CRÍTICO', 'HIGH' => 'RISCO ALTO', default => 'RISCO MÉDIO' };

        $taniumConsoleUrl = htmlspecialchars(str_replace('/api', '', rtrim($config['api_url'] ?? '', '/')));

        // ── Patch rows ────────────────────────────────────────────────────
        $patchRows = '';
        foreach ($patches as $p) {
            $sev      = strtolower($p['severity'] ?? 'unknown');
            $sevClr   = match($sev) {
                'critical'            => '#e53e3e',
                'important', 'high'   => '#ed8936',
                'moderate', 'medium'  => '#ecc94b',
                default               => '#68d391',
            };
            $sevLabel = match($sev) {
                'critical'            => 'CRÍTICO',
                'important', 'high'   => 'ALTO',
                'moderate', 'medium'  => 'MÉDIO',
                default               => 'BAIXO',
            };
            $kbBits = [];
            foreach (self::kbParts($p['kb_id'] ?? null) as $part) {
                $label    = htmlspecialchars($part['label']);
                $kbBits[] = $part['url'] !== null
                    ? '<a href="' . htmlspecialchars($part['url']) . '" style="color:#63b3ed;text-decoration:none">' . $label . '</a>'
                    : $label;
            }
            $kb  = $kbBits !== [] ? implode(' ', $kbBits) : '—';
            $rel = $p['release_date'] ? date('d/m/Y', strtotime($p['release_date'])) : '—';
            $patchRows .= '
            <tr>
                <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#e2e8f0;border-bottom:1px solid #2d3748">' . htmlspecialchars($p['patch_id']) . '</td>
                <td style="padding:8px 12px;font-size:12px;color:#cbd5e0;border-bottom:1px solid #2d3748">' . htmlspecialchars(mb_substr($p['patch_title'] ?? $p['patch_id'], 0, 90)) . '</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;text-align:center"><span style="background:' . $sevClr . ';color:#fff;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px">' . $sevLabel . '</span></td>
                <td style="padding:8px 12px;text-align:center;border-bottom:1px solid #2d3748">' . $kb . '</td>
                <td style="padding:8px 12px;font-size:12px;color:#a0aec0;border-bottom:1px solid #2d3748;text-align:center">' . $rel . '</td>
            </tr>';
        }

        // ── CVE rows (top 15) ──────────────────────────────────────────────
        $cveRows = '';
        foreach (array_slice($cves, 0, 15) as $c) {
            $sev      = strtolower($c['severity'] ?? 'unknown');
            $sevClr   = match($sev) { 'critical' => '#e53e3e', 'high' => '#ed8936', 'medium' => '#ecc94b', default => '#68d391' };
            $sevLabel = match($sev) { 'critical' => 'CRÍTICO', 'high' => 'ALTO', 'medium' => 'MÉDIO', default => 'BAIXO' };
            $cvss     = $c['cvss_score'] !== null ? number_format((float)$c['cvss_score'], 1) : '—';
            $cveRows .= '
            <tr>
                <td style="padding:7px 12px;font-family:monospace;font-size:12px;border-bottom:1px solid #2d3748">
                    <a href="https://nvd.nist.gov/vuln/detail/' . htmlspecialchars($c['cve_id']) . '" style="color:#63b3ed;text-decoration:none">' . htmlspecialchars($c['cve_id']) . '</a>
                </td>
                <td style="padding:7px 12px;font-size:12px;color:#cbd5e0;border-bottom:1px solid #2d3748">' . htmlspecialchars(mb_substr($c['title'] ?? '', 0, 80)) . '</td>
                <td style="padding:7px 12px;border-bottom:1px solid #2d3748;text-align:center"><span style="background:' . $sevClr . ';color:#fff;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700">' . $sevLabel . '</span></td>
                <td style="padding:7px 12px;font-family:monospace;font-size:13px;color:#f6ad55;border-bottom:1px solid #2d3748;text-align:center">' . $cvss . '</td>
            </tr>';
        }
        if (count($cves) > 15) {
            $cveRows .= '<tr><td colspan="4" style="padding:8px 12px;color:#718096;font-style:italic;border-bottom:1px solid #2d3748">+ ' . (count($cves) - 15) . ' outras CVEs</td></tr>';
        }

        $patchListStr = htmlspecialchars(implode(', ', array_column($patches, 'patch_id')));
        $riskScore    = number_format((float)($endpoint['risk_score'] ?? 0), 1);
        $lastSeen     = !empty($endpoint['last_seen']) ? date('d/m/Y H:i', strtotime($endpoint['last_seen'])) : '—';
        $endpointName = htmlspecialchars($endpoint['tanium_name'] ?? $endpoint['tanium_eid']);
        $ipAddr       = htmlspecialchars($endpoint['ip_address'] ?? '—');
        $osName       = htmlspecialchars($endpoint['os_name'] ?? '—');
        $taniumEid    = htmlspecialchars($endpoint['tanium_eid']);
        $openedAt     = date('d/m/Y H:i');

        $cveSection = '';
        if (!empty($cveRows)) {
            $cveSection = '
    <div style="padding:24px 32px;background:#0f1117;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:16px">🔍 CVEs RESOLVIDAS POR ESTES PATCHES (' . count($cves) . ')</div>
        <table style="width:100%;border-collapse:collapse;background:#1a202c;border-radius:8px;overflow:hidden">
            <thead><tr style="background:#2d3748">
                <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">CVE ID</th>
                <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Descrição</th>
                <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Severidade</th>
                <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">CVSS</th>
            </tr></thead>
            <tbody>' . $cveRows . '</tbody>
        </table>
    </div>';
        }

        return '
<div style="font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;background:#0f1117;color:#e2e8f0;border-radius:12px;overflow:hidden;border:1px solid #2d3748;max-width:960px;margin:0 auto">

    <!-- ╔═ HEADER ═══════════════════════════════════════════════════════╗ -->
    <div style="background:linear-gradient(135deg,#1a202c 0%,#2d3748 100%);padding:28px 32px;border-bottom:3px solid ' . $riskClr . '">
        <div style="display:flex;align-items:flex-start;gap:20px">
            <div style="flex:1">
                <div style="font-size:10px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#fc8181;margin-bottom:8px">
                    🛡️&nbsp; TANIUM &nbsp;·&nbsp; SOLICITAÇÃO DE REMEDIAÇÃO DE PATCHES
                </div>
                <div style="font-size:22px;font-weight:700;color:#fff;margin-bottom:4px">' . $endpointName . '</div>
                <div style="font-size:13px;color:#a0aec0">' . $ipAddr . ' &nbsp;·&nbsp; ' . $osName . '</div>
            </div>
            <div style="text-align:right;flex-shrink:0">
                <div style="background:' . $riskClr . ';color:#fff;padding:6px 20px;border-radius:6px;font-size:12px;font-weight:700;letter-spacing:1px;margin-bottom:8px;display:inline-block">' . $riskLbl . '</div>
                <div style="font-size:11px;color:#718096">Aberto em ' . $openedAt . '</div>
            </div>
        </div>
    </div>

    <!-- ╔═ ENDPOINT IDENTITY ════════════════════════════════════════════╗ -->
    <div style="padding:24px 32px;background:#161b22;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:16px">💻 IDENTIFICAÇÃO DO ENDPOINT</div>
        <table style="width:100%;border-collapse:separate;border-spacing:8px 0">
            <tr>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Tanium EID</div>
                    <div style="font-family:monospace;font-size:11px;color:#68d391;word-break:break-all">' . $taniumEid . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Endereço IP</div>
                    <div style="font-family:monospace;font-size:14px;color:#63b3ed">' . $ipAddr . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Sistema Operacional</div>
                    <div style="font-size:12px;color:#e2e8f0">' . $osName . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Última Visão</div>
                    <div style="font-size:12px;color:#e2e8f0">' . $lastSeen . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid ' . $riskClr . '44;border-radius:8px;padding:14px;vertical-align:top;text-align:center">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Score de Risco</div>
                    <div style="font-size:22px;font-weight:700;color:' . $riskClr . ';line-height:1">' . $riskScore . '<span style="font-size:11px;color:#718096;font-weight:400">/100</span></div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top;text-align:center">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Console</div>
                    <div><a href="' . $taniumConsoleUrl . '" style="color:#63b3ed;text-decoration:none;font-size:13px">Tanium&nbsp;↗</a></div>
                </td>
            </tr>
        </table>
    </div>

    <!-- ╔═ RISK SUMMARY ═════════════════════════════════════════════════╗ -->
    <div style="padding:20px 32px;background:#1a1f2e;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:14px">📊 RESUMO DE RISCO</div>
        <table style="width:100%;border-collapse:separate;border-spacing:12px 0">
            <tr>
                <td style="background:#1a202c;border:1px solid #e53e3e33;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#e53e3e;line-height:1">' . count($critical) . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">Críticos</div>
                </td>
                <td style="background:#1a202c;border:1px solid #ed893633;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#ed8936;line-height:1">' . count($high) . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">Altos</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#e2e8f0;line-height:1">' . $total . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">Total de Patches</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#fc8181;line-height:1">' . count($cves) . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">CVEs Resolvidas</div>
                </td>
            </tr>
        </table>
    </div>

    <!-- ╔═ PATCHES TABLE ════════════════════════════════════════════════╗ -->
    <div style="padding:24px 32px;background:#161b22;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:16px">📦 PATCHES PENDENTES PARA IMPLANTAÇÃO (' . $total . ')</div>
        <table style="width:100%;border-collapse:collapse;background:#1a202c;border-radius:8px;overflow:hidden">
            <thead>
                <tr style="background:#2d3748">
                    <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Patch ID</th>
                    <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Título</th>
                    <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Severidade</th>
                    <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Artigo KB</th>
                    <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Lançado em</th>
                </tr>
            </thead>
            <tbody>' . $patchRows . '</tbody>
        </table>
    </div>

    ' . $cveSection . '

    <!-- ╔═ APPROVAL WORKFLOW ════════════════════════════════════════════╗ -->
    <div style="padding:24px 32px;background:#161b22;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#f6ad55;margin-bottom:16px">⚡ APROVAÇÃO E IMPLANTAÇÃO AUTOMATIZADA</div>
        <div style="background:#1a202c;border:1px solid #ed893644;border-radius:8px;padding:20px">
            <div style="font-size:13px;color:#fbd38d;font-weight:600;margin-bottom:18px">Como este chamado funciona:</div>
            <table style="width:100%;border-collapse:separate;border-spacing:0 0">
                <tr>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#2d3748;border:2px solid #4a5568;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:8px">1</div>
                        <div style="font-size:11px;color:#a0aec0;line-height:1.6">Revise os patches<br>e solicite aprovação</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#276749;border:2px solid #48bb78;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;margin-bottom:8px">2</div>
                        <div style="font-size:11px;color:#68d391;font-weight:600;line-height:1.6">Aprovador <strong>aceita</strong><br>a aprovação no GLPI</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#2d3748;border:2px solid #4a5568;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:8px">3</div>
                        <div style="font-size:11px;color:#a0aec0;line-height:1.6">Agente Tanium recebe<br>o comando de deploy</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#1a365d;border:2px solid #4299e1;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;margin-bottom:8px">4</div>
                        <div style="font-size:11px;color:#90cdf4;line-height:1.6">Patches são instalados<br>no endpoint</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#276749;border:2px solid #48bb78;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#fff;margin-bottom:8px">✓</div>
                        <div style="font-size:11px;color:#68d391;font-weight:600;line-height:1.6">Chamado encerrado<br>automaticamente</div>
                    </td>
                </tr>
            </table>
            <div style="margin-top:16px;padding:10px 14px;background:#0f1117;border-radius:6px">
                <div style="font-size:9px;color:#4a5568;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Patches na fila para implantação</div>
                <div style="font-family:monospace;font-size:10px;color:#718096;word-break:break-all">' . $patchListStr . '</div>
            </div>
        </div>
    </div>

    <!-- ╔═ FOOTER ═══════════════════════════════════════════════════════╗ -->
    <div style="padding:14px 32px;background:#0f1117;display:flex;justify-content:space-between;align-items:center">
        <div style="font-size:10px;color:#4a5568">Plugin de Integração Tanium &nbsp;·&nbsp; GLPI ' . GLPI_VERSION . ' &nbsp;·&nbsp; Remediação Automatizada de Patches</div>
        <div style="font-size:10px;color:#4a5568">Gerado em ' . $openedAt . '</div>
    </div>

</div>';
    }
}
