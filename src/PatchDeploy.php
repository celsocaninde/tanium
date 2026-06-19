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
            $fu = new ITILFollowup();
            $fu->add([
                'itemtype'   => 'Ticket',
                'items_id'   => (int)$dep['ticket_id'],
                'content'    => __('❌ The patch deployment approval was REFUSED. No deployment was sent to Tanium.', 'tanium')
                    . ($comment !== '' ? '<br><br><em>' . htmlspecialchars($comment) . '</em>' : ''),
                'is_private' => 0,
            ]);
        }
    }

    // ── Trigger Tanium deployment ───────────────────────────────────────────

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

        $api = new Api($config['api_url'], $config['api_token']);

        try {
            $result      = $api->deployPatches($dep['tanium_eid'], $patches, 'GLPI-Ticket-' . $dep['ticket_id']);
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
                        ? sprintf(
                            __('✅ Patch deployment approved and triggered on Tanium. Deployment ID: <code>%s</code>. The ticket will close automatically when all patches are confirmed applied.', 'tanium'),
                            htmlspecialchars((string)$taniumDepId)
                          )
                        : __('⚠️ Approval recorded, but Tanium API did not return a deployment ID. Check the Tanium console and use "Retry deploy" if needed.', 'tanium'),
                    'is_private'      => 0,
                    'requesttypes_id' => 0,
                ]);
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

    // ── Cron: poll deploying records ────────────────────────────────────────

    public static function cronCheckdeployments(CronTask $task): int {
        global $DB;

        $config = Config::getConfig();
        if (empty($config['api_url']) || empty($config['api_token'])) return 0;

        $api = new Api($config['api_url'], $config['api_token']);

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
                            'content'    => sprintf(
                                __('❌ Tanium patch deployment failed (status: %s). Manual intervention required. Check the Tanium console for details.', 'tanium'),
                                htmlspecialchars($taniumState)
                            ),
                            'is_private' => 0,
                        ]);
                    }
                    $processed++;
                }
            } catch (\Exception $e) {
                // Skip on API error — will retry on next cron run
            }
        }

        $task->addVolume($processed);
        return $processed > 0 ? 1 : 0;
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

        // Mark every deployed patch as remediated
        foreach ($patches as $patchId) {
            $DB->doQuery(sprintf(
                "UPDATE `glpi_plugin_tanium_patches`
                 SET status = 'remediated'
                 WHERE tanium_eid = '%s' AND patch_id = '%s'",
                $DB->escape($dep['tanium_eid']),
                $DB->escape($patchId)
            ));
        }

        // Auto-resolve open CVE assignments for this endpoint
        $DB->doQuery(sprintf(
            "UPDATE `glpi_plugin_tanium_cve_assignments`
             SET status = 'resolved'
             WHERE tanium_eid = '%s' AND status != 'resolved'",
            $DB->escape($dep['tanium_eid'])
        ));

        // Recalculate endpoint risk score
        Sync::updateRiskScore($dep['tanium_eid']);

        // Auto-close the GLPI ticket with a solution comment
        if ($dep['ticket_id']) {
            $ticket = new Ticket();
            if ($ticket->getFromDB((int)$dep['ticket_id'])) {
                $solution = new ITILSolution();
                $solution->add([
                    'itemtype'         => 'Ticket',
                    'items_id'         => (int)$dep['ticket_id'],
                    'content'          => sprintf(
                        __('✅ All %d patches were successfully deployed by Tanium on %s.<br><br>'
                         . 'CVE assignments for this endpoint have been automatically resolved and the risk score recalculated.', 'tanium'),
                        count($patches),
                        date('Y-m-d H:i:s')
                    ),
                    'solutiontypes_id' => 0,
                ]);
            }
        }
    }

    // ── Build professional ticket HTML ──────────────────────────────────────

    public static function buildTicketHtml(
        array $endpoint,
        array $patches,
        array $cves,
        array $config
    ): string {
        $total   = count($patches);
        $critical = array_values(array_filter($patches, fn($p) => strtolower($p['severity'] ?? '') === 'critical'));
        $high     = array_values(array_filter($patches, fn($p) => in_array(strtolower($p['severity'] ?? ''), ['important', 'high'])));
        $riskLvl  = count($critical) > 0 ? 'CRITICAL' : (count($high) > 0 ? 'HIGH' : 'MEDIUM');
        $riskClr  = match($riskLvl) { 'CRITICAL' => '#e53e3e', 'HIGH' => '#ed8936', default => '#ecc94b' };

        $taniumConsoleUrl = htmlspecialchars(str_replace('/api', '', rtrim($config['api_url'] ?? '', '/')));

        // ── Patch rows ────────────────────────────────────────────────────
        $patchRows = '';
        foreach ($patches as $p) {
            $sev    = strtolower($p['severity'] ?? 'unknown');
            $sevClr = match($sev) {
                'critical'            => '#e53e3e',
                'important', 'high'   => '#ed8936',
                'moderate', 'medium'  => '#ecc94b',
                default               => '#68d391',
            };
            $kb  = $p['kb_id']
                ? '<a href="https://support.microsoft.com/kb/' . htmlspecialchars($p['kb_id']) . '" style="color:#63b3ed;text-decoration:none">' . htmlspecialchars($p['kb_id']) . '</a>'
                : '—';
            $rel = $p['release_date'] ? htmlspecialchars($p['release_date']) : '—';
            $patchRows .= '
            <tr>
                <td style="padding:8px 12px;font-family:monospace;font-size:12px;color:#e2e8f0;border-bottom:1px solid #2d3748">' . htmlspecialchars($p['patch_id']) . '</td>
                <td style="padding:8px 12px;font-size:12px;color:#cbd5e0;border-bottom:1px solid #2d3748">' . htmlspecialchars(mb_substr($p['patch_title'] ?? $p['patch_id'], 0, 90)) . '</td>
                <td style="padding:8px 12px;border-bottom:1px solid #2d3748;text-align:center"><span style="background:' . $sevClr . ';color:#fff;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px">' . strtoupper($sev) . '</span></td>
                <td style="padding:8px 12px;text-align:center;border-bottom:1px solid #2d3748">' . $kb . '</td>
                <td style="padding:8px 12px;font-size:12px;color:#a0aec0;border-bottom:1px solid #2d3748;text-align:center">' . $rel . '</td>
            </tr>';
        }

        // ── CVE rows (top 15) ──────────────────────────────────────────────
        $cveRows = '';
        foreach (array_slice($cves, 0, 15) as $c) {
            $sev    = strtolower($c['severity'] ?? 'unknown');
            $sevClr = match($sev) { 'critical' => '#e53e3e', 'high' => '#ed8936', 'medium' => '#ecc94b', default => '#68d391' };
            $cvss   = $c['cvss_score'] !== null ? number_format((float)$c['cvss_score'], 1) : '—';
            $cveRows .= '
            <tr>
                <td style="padding:7px 12px;font-family:monospace;font-size:12px;border-bottom:1px solid #2d3748">
                    <a href="https://nvd.nist.gov/vuln/detail/' . htmlspecialchars($c['cve_id']) . '" style="color:#63b3ed;text-decoration:none">' . htmlspecialchars($c['cve_id']) . '</a>
                </td>
                <td style="padding:7px 12px;font-size:12px;color:#cbd5e0;border-bottom:1px solid #2d3748">' . htmlspecialchars(mb_substr($c['title'] ?? '', 0, 80)) . '</td>
                <td style="padding:7px 12px;border-bottom:1px solid #2d3748;text-align:center"><span style="background:' . $sevClr . ';color:#fff;padding:2px 10px;border-radius:4px;font-size:10px;font-weight:700">' . strtoupper($sev) . '</span></td>
                <td style="padding:7px 12px;font-family:monospace;font-size:13px;color:#f6ad55;border-bottom:1px solid #2d3748;text-align:center">' . $cvss . '</td>
            </tr>';
        }
        if (count($cves) > 15) {
            $cveRows .= '<tr><td colspan="4" style="padding:8px 12px;color:#718096;font-style:italic;border-bottom:1px solid #2d3748">+ ' . (count($cves) - 15) . ' more CVEs</td></tr>';
        }

        $patchListStr = htmlspecialchars(implode(', ', array_column($patches, 'patch_id')));
        $riskScore    = number_format((float)($endpoint['risk_score'] ?? 0), 1);
        $lastSeen     = !empty($endpoint['last_seen']) ? htmlspecialchars(Html::convDateTime($endpoint['last_seen'])) : '—';
        $endpointName = htmlspecialchars($endpoint['tanium_name'] ?? $endpoint['tanium_eid']);
        $ipAddr       = htmlspecialchars($endpoint['ip_address'] ?? '—');
        $osName       = htmlspecialchars($endpoint['os_name'] ?? '—');
        $taniumEid    = htmlspecialchars($endpoint['tanium_eid']);

        $cveSection = '';
        if (!empty($cveRows)) {
            $cveSection = '
    <div style="padding:24px 32px;background:#0f1117;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:16px">CVEs ADDRESSED BY THESE PATCHES (' . count($cves) . ')</div>
        <table style="width:100%;border-collapse:collapse;background:#1a202c;border-radius:8px;overflow:hidden">
            <thead><tr style="background:#2d3748">
                <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">CVE ID</th>
                <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Description</th>
                <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Severity</th>
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
                    🛡️&nbsp; TANIUM &nbsp;·&nbsp; PATCH REMEDIATION REQUEST
                </div>
                <div style="font-size:22px;font-weight:700;color:#fff;margin-bottom:4px">' . $endpointName . '</div>
                <div style="font-size:13px;color:#a0aec0">' . $ipAddr . ' &nbsp;·&nbsp; ' . $osName . '</div>
            </div>
            <div style="text-align:right;flex-shrink:0">
                <div style="background:' . $riskClr . ';color:#fff;padding:6px 20px;border-radius:6px;font-size:12px;font-weight:700;letter-spacing:1px;margin-bottom:8px;display:inline-block">' . $riskLvl . ' RISK</div>
                <div style="font-size:11px;color:#718096">' . date('Y-m-d H:i') . ' UTC</div>
            </div>
        </div>
    </div>

    <!-- ╔═ ENDPOINT IDENTITY ════════════════════════════════════════════╗ -->
    <div style="padding:24px 32px;background:#161b22;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:16px">ENDPOINT IDENTITY</div>
        <table style="width:100%;border-collapse:separate;border-spacing:8px 0">
            <tr>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Tanium EID</div>
                    <div style="font-family:monospace;font-size:11px;color:#68d391;word-break:break-all">' . $taniumEid . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">IP Address</div>
                    <div style="font-family:monospace;font-size:14px;color:#63b3ed">' . $ipAddr . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Operating System</div>
                    <div style="font-size:12px;color:#e2e8f0">' . $osName . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:14px;vertical-align:top">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Last Seen</div>
                    <div style="font-size:12px;color:#e2e8f0">' . $lastSeen . '</div>
                </td>
                <td style="background:#1a202c;border:1px solid ' . $riskClr . '44;border-radius:8px;padding:14px;vertical-align:top;text-align:center">
                    <div style="font-size:9px;text-transform:uppercase;color:#718096;letter-spacing:1px;margin-bottom:6px">Risk Score</div>
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
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:14px">RISK SUMMARY</div>
        <table style="width:100%;border-collapse:separate;border-spacing:12px 0">
            <tr>
                <td style="background:#1a202c;border:1px solid #e53e3e33;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#e53e3e;line-height:1">' . count($critical) . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">Critical</div>
                </td>
                <td style="background:#1a202c;border:1px solid #ed893633;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#ed8936;line-height:1">' . count($high) . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">High</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#e2e8f0;line-height:1">' . $total . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">Total Patches</div>
                </td>
                <td style="background:#1a202c;border:1px solid #2d3748;border-radius:8px;padding:18px;text-align:center">
                    <div style="font-size:32px;font-weight:700;color:#fc8181;line-height:1">' . count($cves) . '</div>
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-top:6px">CVEs Fixed</div>
                </td>
            </tr>
        </table>
    </div>

    <!-- ╔═ PATCHES TABLE ════════════════════════════════════════════════╗ -->
    <div style="padding:24px 32px;background:#161b22;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#63b3ed;margin-bottom:16px">PENDING PATCHES TO DEPLOY (' . $total . ')</div>
        <table style="width:100%;border-collapse:collapse;background:#1a202c;border-radius:8px;overflow:hidden">
            <thead>
                <tr style="background:#2d3748">
                    <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Patch ID</th>
                    <th style="padding:10px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Title</th>
                    <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Severity</th>
                    <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">KB Article</th>
                    <th style="padding:10px 12px;text-align:center;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#a0aec0;font-weight:600">Released</th>
                </tr>
            </thead>
            <tbody>' . $patchRows . '</tbody>
        </table>
    </div>

    ' . $cveSection . '

    <!-- ╔═ APPROVAL WORKFLOW ════════════════════════════════════════════╗ -->
    <div style="padding:24px 32px;background:#161b22;border-bottom:1px solid #2d3748">
        <div style="font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#f6ad55;margin-bottom:16px">⚡ APPROVAL &amp; AUTOMATED DEPLOYMENT</div>
        <div style="background:#1a202c;border:1px solid #ed893644;border-radius:8px;padding:20px">
            <div style="font-size:13px;color:#fbd38d;font-weight:600;margin-bottom:16px">How this ticket works:</div>
            <table style="width:100%;border-collapse:separate;border-spacing:0 0">
                <tr>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#2d3748;border:2px solid #4a5568;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:8px">1</div>
                        <div style="font-size:11px;color:#a0aec0;line-height:1.5">Review patches &amp;<br>request approval</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#276749;border:2px solid #48bb78;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;margin-bottom:8px">2</div>
                        <div style="font-size:11px;color:#68d391;font-weight:600;line-height:1.5">Approver <strong>accepts</strong><br>the GLPI approval</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#2d3748;border:2px solid #4a5568;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:8px">3</div>
                        <div style="font-size:11px;color:#a0aec0;line-height:1.5">Tanium agent receives<br>deployment command</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#1a365d;border:2px solid #4299e1;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;margin-bottom:8px">4</div>
                        <div style="font-size:11px;color:#90cdf4;line-height:1.5">Patches install<br>on endpoint</div>
                    </td>
                    <td style="color:#4a5568;font-size:20px;vertical-align:middle;padding-bottom:20px;text-align:center">→</td>
                    <td style="text-align:center;padding:0 8px;vertical-align:top">
                        <div style="width:38px;height:38px;background:#276749;border:2px solid #48bb78;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;color:#fff;margin-bottom:8px">✓</div>
                        <div style="font-size:11px;color:#68d391;font-weight:600;line-height:1.5">Ticket closes<br>automatically</div>
                    </td>
                </tr>
            </table>
            <div style="margin-top:16px;padding:10px 14px;background:#0f1117;border-radius:6px">
                <div style="font-size:9px;color:#4a5568;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Patches queued for deployment</div>
                <div style="font-family:monospace;font-size:10px;color:#718096;word-break:break-all">' . $patchListStr . '</div>
            </div>
        </div>
    </div>

    <!-- ╔═ FOOTER ═══════════════════════════════════════════════════════╗ -->
    <div style="padding:14px 32px;background:#0f1117;display:flex;justify-content:space-between;align-items:center">
        <div style="font-size:10px;color:#4a5568">Tanium Integration Plugin &nbsp;·&nbsp; GLPI ' . GLPI_VERSION . ' &nbsp;·&nbsp; Automated Patch Remediation</div>
        <div style="font-size:10px;color:#4a5568">' . date('Y-m-d\TH:i:s\Z') . '</div>
    </div>

</div>';
    }
}
