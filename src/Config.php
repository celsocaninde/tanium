<?php

namespace GlpiPlugin\Tanium;

use CommonDBTM;
use Html;
use Plugin;
use Session;
use Toolbox;

class Config extends CommonDBTM {

    public static $rightname = 'config';

    public static function getTypeName($nb = 0): string {
        return __('Tanium Configuration', 'tanium');
    }

    public static function getConfig(): array {
        global $DB;

        $row = $DB->request(['FROM' => 'glpi_plugin_tanium_configs', 'LIMIT' => 1])->current();

        if ($row !== null) {
            $row['api_token'] = self::decryptToken((string)($row['api_token'] ?? ''), (int)($row['token_encrypted'] ?? 0));
            return $row;
        }

        return [
            'id'                   => 0,
            'api_url'              => '',
            'api_token'            => '',
            'sync_computers'       => 1,
            'sync_software'        => 1,
            'sync_vulnerabilities' => 0,
            'sync_hardware'        => 1,
            'sync_network'         => 1,
            'sync_os_details'      => 1,
            'sync_patches'         => 0,
            'sync_incremental'     => 1,
            'cron_frequency'       => 24,
            'import_limit'         => 500,
            'last_sync'            => null,
            'last_sync_count'      => 0,
            'last_sync_cursor'     => null,
            'webhook_enabled'      => 0,
            'webhook_url'          => '',
            'notify_critical'      => 1,
            'notify_email'         => '',
            'notify_users'         => '',
            'sla_critical_days'    => 7,
            'sla_high_days'        => 30,
            'sla_medium_days'      => 90,
            'patch_limiting_group_id' => 0,
            'ticket_entity_id'        => 0,
            'default_entity_id'       => 0,
            'sync_group_membership'   => 0,
            'agent_stale_days'        => 7,
            'agent_health_ticket'     => 0,
            'sync_compliance'         => 0,
            'sync_threats'            => 0,
            'threat_ticket'           => 1,
            'threat_min_severity'     => 'high',
            'webhook_sla'             => 0,
            'webhook_deploy'          => 0,
            'auto_ticket_critical'    => 0,
            'quarantine_package'      => '',
            'restart_package'         => '',
            'token_encrypted'         => 0,
            'token_expires_at'        => null,
            'retention_days'          => 365,
            'custom_sensors'          => '',
            'auto_deploy_kev'         => 0,
            'report_day'              => 1,
            'report_hour'             => 8,
            'last_weekly_report'      => null,
        ];
    }

    public static function saveConfig(array $data): void {
        global $DB;

        $config = self::getConfig();

        if (empty($data['api_token']) && !empty($config['api_token'])) {
            unset($data['api_token']);
        }

        // At-rest encryption: a DB dump must not hand out a token that can
        // deploy patches or quarantine endpoints.
        if (!empty($data['api_token'])) {
            $data['api_token']       = self::encryptToken((string)$data['api_token']);
            $data['token_encrypted'] = 1;
        }

        $data['date_mod'] = date('Y-m-d H:i:s');

        if (($config['id'] ?? 0) > 0) {
            $DB->update('glpi_plugin_tanium_configs', $data, ['id' => $config['id']]);
        } else {
            $DB->insert('glpi_plugin_tanium_configs', $data);
        }
    }

    // ── API token at-rest encryption (GLPIKey / sodium) ───────────────────

    private static function encryptToken(string $plain): string {
        if ($plain === '') {
            return '';
        }
        try {
            return (new \GLPIKey())->encrypt($plain);
        } catch (\Throwable $e) {
            \Toolbox::logInFile('tanium', '[Tanium] Token encryption failed, storing as-is: ' . $e->getMessage() . "\n");
            return $plain;
        }
    }

    private static function decryptToken(string $stored, int $encrypted): string {
        if ($stored === '' || !$encrypted) {
            return $stored;
        }
        try {
            $plain = (new \GLPIKey())->decrypt($stored);
            return is_string($plain) && $plain !== '' ? $plain : $stored;
        } catch (\Throwable $e) {
            \Toolbox::logInFile('tanium', '[Tanium] Token decryption failed: ' . $e->getMessage() . "\n");
            return '';
        }
    }

    /**
     * One-time migration: encrypt a token stored in clear text by an older
     * version. Called from the install/upgrade hook.
     */
    public static function migrateTokenEncryption(): void {
        global $DB;

        $row = $DB->request(['FROM' => 'glpi_plugin_tanium_configs', 'LIMIT' => 1])->current();
        if (!$row || (int)($row['token_encrypted'] ?? 0) === 1 || (string)($row['api_token'] ?? '') === '') {
            return;
        }

        $cipher = self::encryptToken((string)$row['api_token']);
        if ($cipher !== (string)$row['api_token']) {
            $DB->update('glpi_plugin_tanium_configs', [
                'api_token'       => $cipher,
                'token_encrypted' => 1,
            ], ['id' => $row['id']]);
        }
    }

    /**
     * Merges GLPI users picked in the "Notification recipients" dropdown
     * (resolved to their account email) with any manually typed addresses,
     * deduplicated and validated.
     *
     * @return string[]
     */
    public static function resolveNotifyRecipients(array $config): array {
        $emails = [];

        foreach (explode(',', (string)($config['notify_email'] ?? '')) as $raw) {
            $email = trim($raw);
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $emails[strtolower($email)] = $email;
            }
        }

        foreach (explode(',', (string)($config['notify_users'] ?? '')) as $rawId) {
            $userId = (int)trim($rawId);
            if ($userId <= 0) {
                continue;
            }
            $user = new \User();
            if (!$user->getFromDB($userId)) {
                Toolbox::logInFile('tanium', "[Tanium] Usuario de notificacao id={$userId} nao encontrado no GLPI (removido/excluido?).\n");
                continue;
            }
            $email = $user->getDefaultEmail();
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $login = (string) ($user->fields['name'] ?? $userId);
                Toolbox::logInFile('tanium', "[Tanium] Usuario de notificacao '{$login}' nao tem e-mail cadastrado no GLPI -- nao vai receber alertas ate isso ser corrigido (Administracao > Usuarios > {$login} > E-mails).\n");
                continue;
            }
            $emails[strtolower($email)] = $email;
        }

        return array_values($emails);
    }

    /**
     * Among the picked notification users, the ones that will silently NOT
     * receive anything because their GLPI account has no (valid) email.
     * Returns [id => login] so callers can build actionable warnings.
     *
     * @return array<int,string>
     */
    public static function usersWithoutEmail(array $userIds): array {
        $out = [];
        foreach ($userIds as $userId) {
            $userId = (int)$userId;
            if ($userId <= 0) {
                continue;
            }
            $user = new \User();
            if (!$user->getFromDB($userId)) {
                $out[$userId] = "#{$userId}";
                continue;
            }
            $email = $user->getDefaultEmail();
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $out[$userId] = (string)($user->fields['name'] ?? "#{$userId}");
            }
        }
        return $out;
    }

    /**
     * Active, non-deleted GLPI users as [id => "Realname Firstname (login)"],
     * for the notification recipients multi-select.
     *
     * @return array<int,string>
     */
    private static function activeUserOptions(): array {
        global $DB;

        $options = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'name', 'realname', 'firstname'],
            'FROM'   => 'glpi_users',
            'WHERE'  => ['is_active' => 1, 'is_deleted' => 0],
            'ORDER'  => ['realname', 'firstname', 'name'],
        ]) as $row) {
            $fullName = trim(($row['realname'] ?? '') . ' ' . ($row['firstname'] ?? ''));
            $options[(int)$row['id']] = $fullName !== '' ? "{$fullName} ({$row['name']})" : $row['name'];
        }

        return $options;
    }

    public static function updateLastSync(int $count, string $cursor = ''): void {
        global $DB;

        $config = self::getConfig();
        if (($config['id'] ?? 0) > 0) {
            $upd = [
                'last_sync'       => date('Y-m-d H:i:s'),
                'last_sync_count' => $count,
            ];
            if ($cursor) {
                $upd['last_sync_cursor'] = $cursor;
            }
            $DB->update('glpi_plugin_tanium_configs', $upd, ['id' => $config['id']]);
        }
    }

    public function showConfigForm(): void {
        $config = self::getConfig();
        $target = Plugin::getWebDir('tanium') . '/front/config.form.php';

        echo '<div class="tanium-card">';
        echo '<div class="tanium-card-header">';
        echo '<img src="' . $this->getTaniumLogoUrl() . '" alt="Tanium" class="tanium-header-logo"/>';
        echo '<span>' . __('API &amp; Sync Configuration', 'tanium') . '</span>';
        echo '</div>';
        echo '<div class="tanium-card-body">';
        echo "<form method='post' action='{$target}'>";
        echo '<input type="hidden" name="_glpi_csrf_token" value="' . Session::getNewCSRFToken() . '">';

        // ── Connection ────────────────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Connection', 'tanium') . "</div>";

        $this->renderField(
            __('Tanium Cloud API URL', 'tanium'),
            "<input type='url' name='api_url' class='tanium-input' value='" . htmlspecialchars($config['api_url']) . "' placeholder='https://your-instance-api.cloud.tanium.com' required/>",
            __('Base URL of your Tanium Cloud instance, without trailing slash.', 'tanium')
        );

        $tokenPlaceholder = !empty($config['api_token']) ? '••••••••••••••••' : '';
        $this->renderField(
            __('API Token', 'tanium'),
            "<input type='password' name='api_token' class='tanium-input' value='' placeholder='{$tokenPlaceholder}' autocomplete='new-password'/>",
            __('Leave blank to keep the existing token. Generate tokens in Tanium → Administration → API Tokens.', 'tanium')
        );

        // ── Data to synchronize ───────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Data to synchronize', 'tanium') . "</div>";

        $this->renderCheckbox('sync_computers',       __('Endpoints / Computers', 'tanium'),                              $config['sync_computers']);
        $this->renderCheckbox('sync_hardware',        __('Hardware details (CPU, RAM)', 'tanium'),                        $config['sync_hardware']);
        $this->renderCheckbox('sync_network',         __('Network adapters (IP &amp; MAC address)', 'tanium'),            $config['sync_network'] ?? 1);
        $this->renderCheckbox('sync_os_details',      __('OS details (version, build, architecture)', 'tanium'),          $config['sync_os_details'] ?? 1);
        $this->renderCheckbox('sync_software',        __('Installed software inventory', 'tanium'),                       $config['sync_software']);
        $this->renderCheckbox('sync_vulnerabilities', __('Vulnerabilities / CVEs (requires Tanium Comply)', 'tanium'),    $config['sync_vulnerabilities']);
        $this->renderCheckbox('sync_patches',         __('Missing patches (requires Tanium Patch)', 'tanium'),            $config['sync_patches'] ?? 0);
        $this->renderCheckbox('sync_compliance',      __('Compliance benchmarks CIS/DISA (requires Tanium Comply — daily cron)', 'tanium'), $config['sync_compliance'] ?? 0);

        // ── Sync behaviour ────────────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Sync behaviour', 'tanium') . "</div>";

        $this->renderCheckbox('sync_incremental', __('Incremental sync (only changed endpoints per run)', 'tanium'), $config['sync_incremental'] ?? 1);

        $this->renderField(
            __('Cron frequency (hours)', 'tanium'),
            "<input type='number' name='cron_frequency' class='tanium-input tanium-input-sm' value='" . intval($config['cron_frequency']) . "' min='1' max='168'/>",
            __('How often the automatic sync runs. Minimum 1 hour.', 'tanium')
        );

        $this->renderField(
            __('Endpoint import limit per run', 'tanium'),
            "<input type='number' name='import_limit' class='tanium-input tanium-input-sm' value='" . intval($config['import_limit']) . "' min='10' max='5000'/>",
            __('Max endpoints fetched per API page. Tanium REST API v2 max is 500.', 'tanium')
        );

        $this->renderField(
            __('Default entity for new computers', 'tanium'),
            self::entitySelect('default_entity_id', (int)($config['default_entity_id'] ?? 0)),
            __('New computers created by the sync are placed in this entity. A Tanium group mapped to an entity (Computer Groups page) takes precedence.', 'tanium')
        );

        $this->renderCheckbox(
            'sync_group_membership',
            __('Fetch computer group membership per endpoint (experimental — enables group → entity mapping)', 'tanium'),
            (int)($config['sync_group_membership'] ?? 0)
        );

        // ── Agent health ──────────────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Agent health', 'tanium') . "</div>";

        $this->renderField(
            __('Silent agent threshold (days)', 'tanium'),
            "<input type='number' name='agent_stale_days' class='tanium-input tanium-input-sm' value='" . intval($config['agent_stale_days'] ?? 7) . "' min='1' max='365'/>",
            __('An endpoint not seen for this long is flagged as a silent agent (service stopped, uninstalled, isolated…).', 'tanium')
        );

        $this->renderCheckbox(
            'agent_health_ticket',
            __('Open a consolidated ticket automatically when silent agents are detected (daily check)', 'tanium'),
            (int)($config['agent_health_ticket'] ?? 0)
        );

        // ── Threat Response ───────────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Threat Response', 'tanium') . "</div>";

        $this->renderCheckbox(
            'sync_threats',
            __('Import threat alerts (requires Tanium Threat Response — every 15 min)', 'tanium'),
            (int)($config['sync_threats'] ?? 0)
        );

        $this->renderCheckbox(
            'threat_ticket',
            __('Open a GLPI ticket for each NEW alert at or above the minimum severity', 'tanium'),
            (int)($config['threat_ticket'] ?? 1)
        );

        $sevSel = '';
        foreach (['info', 'low', 'medium', 'high', 'critical'] as $sev) {
            $sel     = ($config['threat_min_severity'] ?? 'high') === $sev ? ' selected' : '';
            $sevSel .= "<option value='{$sev}'{$sel}>" . ucfirst($sev) . "</option>";
        }
        $this->renderField(
            __('Minimum alert severity for tickets', 'tanium'),
            "<select name='threat_min_severity' class='tanium-input tanium-select'>{$sevSel}</select>"
        );

        // ── Data & automation (v2.1) ──────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Data &amp; automation', 'tanium') . "</div>";

        $this->renderField(
            __('API token expiry date', 'tanium'),
            "<input type='date' name='token_expires_at' class='tanium-input tanium-input-sm' value='" . htmlspecialchars((string)($config['token_expires_at'] ?? '')) . "'/>",
            __('Tanium tokens expire. Set the expiry date to get a warning before the sync silently stops.', 'tanium')
        );
        $this->renderField(
            __('History retention (days)', 'tanium'),
            "<input type='number' name='retention_days' class='tanium-input tanium-input-sm' value='" . intval($config['retention_days'] ?? 365) . "' min='30' max='3650'/>",
            __('Rows older than this are purged daily from risk/CVE history, sync logs and resolved threat alerts.', 'tanium')
        );
        $this->renderField(
            __('Custom sensors to sync', 'tanium'),
            "<input type='text' name='custom_sensors' class='tanium-input' value='" . htmlspecialchars((string)($config['custom_sensors'] ?? '')) . "' placeholder='Chassis Type, Uptime, Logged In Users'/>",
            __('Comma-separated Tanium sensor names collected per endpoint during sync and shown on the endpoint page.', 'tanium')
        );
        $this->renderCheckbox(
            'auto_deploy_kev',
            __('Auto-open patch-deployment tickets for endpoints exposed to KEV (actively exploited) CVEs', 'tanium'),
            (int)($config['auto_deploy_kev'] ?? 0)
        );

        // ── Remote actions (approval-gated) ───────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Remote actions (approval-gated)', 'tanium') . "</div>";

        $this->renderField(
            __('Quarantine package name', 'tanium'),
            "<input type='text' name='quarantine_package' class='tanium-input' value='" . htmlspecialchars($config['quarantine_package'] ?? '') . "' placeholder='" . htmlspecialchars(\GlpiPlugin\Tanium\RemoteAction::ACTIONS['quarantine']['default']) . "'/>",
            __('Tanium package run when a quarantine request is approved. Leave empty to use the default. Package names are tenant-specific — check your Tanium console.', 'tanium')
        );
        $this->renderField(
            __('Client restart package name', 'tanium'),
            "<input type='text' name='restart_package' class='tanium-input' value='" . htmlspecialchars($config['restart_package'] ?? '') . "' placeholder='" . htmlspecialchars(\GlpiPlugin\Tanium\RemoteAction::ACTIONS['restart_client']['default']) . "'/>",
            __('Tanium package run when a client-restart request is approved. Leave empty to use the default.', 'tanium')
        );

        // ── Last sync status ──────────────────────────────────────────────
        if (!empty($config['last_sync'])) {
            $lastSync = Html::convDateTime($config['last_sync']);
            $count    = intval($config['last_sync_count']);
            echo "<div class='tanium-last-sync'>";
            echo "<span class='tanium-badge-success'>&#10003;</span> ";
            printf(__('Last sync: %s — %d endpoints processed', 'tanium'), $lastSync, $count);
            if (!empty($config['last_sync_cursor'])) {
                echo " &nbsp;<span class='tanium-badge tanium-badge-warning'>" . __('Incremental', 'tanium') . "</span>";
            }
            echo "</div>";
        }

        // ── Notifications & Webhook ───────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Notifications &amp; Webhook', 'tanium') . "</div>";

        $this->renderCheckbox('webhook_enabled', __('Enable webhook on sync completion', 'tanium'), (int)($config['webhook_enabled'] ?? 0));
        $this->renderField(
            __('Webhook URL', 'tanium'),
            "<input type='url' name='webhook_url' class='tanium-input' value='" . htmlspecialchars($config['webhook_url'] ?? '') . "' placeholder='https://hooks.slack.com/services/... or Teams webhook URL'/>",
            __('Slack, Microsoft Teams, or any HTTP endpoint that accepts JSON POST. Compatible with Slack incoming webhooks and Teams connectors.', 'tanium')
        );

        $this->renderCheckbox('webhook_sla', __('Webhook daily alert while findings breach the remediation SLA', 'tanium'), (int)($config['webhook_sla'] ?? 0));
        $this->renderCheckbox('webhook_deploy', __('Webhook on patch deployment events (started / completed / failed)', 'tanium'), (int)($config['webhook_deploy'] ?? 0));

        $this->renderCheckbox('notify_critical', __('Notify when new Critical CVEs are detected', 'tanium'), (int)($config['notify_critical'] ?? 1));
        $this->renderCheckbox('auto_ticket_critical', __('Open a consolidated GLPI ticket when new Critical CVEs are detected', 'tanium'), (int)($config['auto_ticket_critical'] ?? 0));

        $notifyUserIds = array_filter(array_map('intval', explode(',', (string)($config['notify_users'] ?? ''))));
        ob_start();
        \Dropdown::showFromArray('notify_users', self::activeUserOptions(), [
            'values'   => $notifyUserIds,
            'multiple' => true,
            'width'    => '100%',
            'comments' => false,
        ]);
        $notifyUsersDropdown = ob_get_clean();

        $this->renderField(
            __('Notification recipients (GLPI users)', 'tanium'),
            $notifyUsersDropdown,
            __('Pick registered GLPI users — their account email is used automatically.', 'tanium')
        );

        // Visible warning for picked users that would be silently skipped
        $noEmail = self::usersWithoutEmail($notifyUserIds);
        if ($noEmail !== []) {
            $logins = implode(', ', array_map('htmlspecialchars', $noEmail));
            echo "<div style='background:rgba(232,196,42,.12);border:1px solid rgba(232,196,42,.5);border-left:4px solid #e8c42a;"
               . "border-radius:6px;padding:10px 14px;margin:0 0 14px;font-size:.85rem;color:#e8c42a'>"
               . '&#9888;&#65039; '
               . sprintf(
                   __('These users have no email registered in GLPI and will NOT receive alerts or reports: %s. Add an email in Administration &gt; Users.', 'tanium'),
                   "<strong>{$logins}</strong>"
               )
               . '</div>';
        }

        $this->renderField(
            __('Additional notification email(s)', 'tanium'),
            "<input type='text' name='notify_email' class='tanium-input' value='" . htmlspecialchars($config['notify_email'] ?? '') . "' placeholder='security@company.com, admin@company.com'/>",
            __('Comma-separated list of extra emails (e.g. distribution lists not registered as GLPI users). Leave both fields blank to disable email alerts.', 'tanium')
        );

        // ── Weekly report schedule ────────────────────────────────────────
        $dayNames = [
            0 => __('Sunday', 'tanium'),
            1 => __('Monday', 'tanium'),
            2 => __('Tuesday', 'tanium'),
            3 => __('Wednesday', 'tanium'),
            4 => __('Thursday', 'tanium'),
            5 => __('Friday', 'tanium'),
            6 => __('Saturday', 'tanium'),
        ];
        $curDay  = max(0, min(6, (int)($config['report_day'] ?? 1)));
        $curHour = max(0, min(23, (int)($config['report_hour'] ?? 8)));

        $daySelect = "<select name='report_day' class='tanium-input tanium-select' style='width:auto'>";
        foreach ($dayNames as $d => $label) {
            $sel = $d === $curDay ? ' selected' : '';
            $daySelect .= "<option value='{$d}'{$sel}>{$label}</option>";
        }
        $daySelect .= '</select>';

        $hourSelect = "<select name='report_hour' class='tanium-input tanium-select' style='width:auto'>";
        for ($h = 0; $h < 24; $h++) {
            $sel = $h === $curHour ? ' selected' : '';
            $hourSelect .= sprintf("<option value='%d'%s>%02d:00</option>", $h, $sel, $h);
        }
        $hourSelect .= '</select>';

        $lastReport = !empty($config['last_weekly_report'])
            ? date('d/m/Y H:i', strtotime($config['last_weekly_report']))
            : __('never', 'tanium');

        $this->renderField(
            __('Weekly report schedule', 'tanium'),
            "<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap'>{$daySelect}{$hourSelect}</div>",
            sprintf(__('The weekly report is sent on the selected day, from the selected hour on. Last sent: %s.', 'tanium'), "<strong>{$lastReport}</strong>")
        );

        // ── SLA Remediation ───────────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('SLA — Remediation Deadlines', 'tanium') . "</div>";
        echo "<p style='font-size:.82rem;color:var(--t-muted);margin:0 0 12px'>" . __('Maximum days allowed before a CVE is flagged as overdue. Overdue CVEs are highlighted in red throughout the plugin.', 'tanium') . "</p>";
        echo "<div style='display:flex;gap:20px;flex-wrap:wrap'>";
        foreach (['critical' => [__('Critical CVEs', 'tanium'), 7, '#e8212a'], 'high' => [__('High CVEs', 'tanium'), 30, '#f97316'], 'medium' => [__('Medium CVEs', 'tanium'), 90, '#f59e0b']] as $sev => [$label, $default, $color]):
            $val = (int)($config["sla_{$sev}_days"] ?? $default);
            echo "<div style='flex:1;min-width:140px'>
                <label class='tanium-form-label' style='color:{$color}'>{$label}</label>
                <div style='display:flex;align-items:center;gap:6px'>
                    <input type='number' name='sla_{$sev}_days' class='tanium-input' style='width:80px' min='1' max='365' value='{$val}'>
                    <span style='color:var(--t-muted);font-size:.83rem'>" . __('days', 'tanium') . "</span>
                </div>
            </div>";
        endforeach;
        echo "</div><br>";

        // ── Patch Deployment ──────────────────────────────────────────────
        echo "<div class='tanium-section-title'>" . __('Patch Deployment', 'tanium') . "</div>";
        $this->renderField(
            __('Patch deployment scope group (ID — fallback)', 'tanium'),
            "<input type='number' name='patch_limiting_group_id' class='tanium-input tanium-input-sm' value='" . (int)($config['patch_limiting_group_id'] ?? 0) . "' min='0'/>",
            __('ID de fallback usado quando nenhum grupo é selecionado no modal de deploy. Com a lista de grupos sincronizada, este campo raramente é necessário.', 'tanium')
            . ' &nbsp;<a href="' . Plugin::getWebDir('tanium') . '/front/computergroups.php" class="tanium-link">Gerenciar grupos ↗</a>'
        );

        ob_start();
        \Entity::dropdown([
            'name'                => 'ticket_entity_id',
            'value'               => (int)($config['ticket_entity_id'] ?? 0),
            'entity'              => $_SESSION['glpiactiveentities'] ?? [],
            'class'               => 'tanium-input',
            'display_emptychoice' => false,
        ]);
        $entityDropdown = ob_get_clean();

        $this->renderField(
            __('Ticket entity', 'tanium'),
            $entityDropdown,
            __('Entity where Tanium tickets (CVE, patch remediation) will be created. Choose the entity that owns the security team or service desk queue.', 'tanium')
        );

        echo "<div class='tanium-actions'>";
        echo "<button type='submit' name='save' class='tanium-btn tanium-btn-primary'>&#128190; " . __('Save configuration', 'tanium') . "</button> ";
        echo "<button type='submit' name='test' class='tanium-btn tanium-btn-secondary'>&#128268; " . __('Test connection', 'tanium') . "</button> ";
        echo "<button type='submit' name='test_webhook' class='tanium-btn tanium-btn-secondary'>&#128279; " . __('Test webhook', 'tanium') . "</button> ";
        echo "<button type='submit' name='test_email' class='tanium-btn tanium-btn-secondary'>&#9993;&#65039; " . __('Test email', 'tanium') . "</button> ";
        echo "<button type='submit' name='send_report' class='tanium-btn tanium-btn-secondary'>&#128200; " . __('Send report now', 'tanium') . "</button> ";
        echo "<a href='" . Plugin::getWebDir('tanium') . "/front/sync.form.php' class='tanium-btn tanium-btn-success'>&#9654; " . __('Sync now', 'tanium') . "</a>";
        echo "</div>";
        echo "</form>";
        echo "</div></div>";
    }

    /**
     * Plain <select> of active entities. -1 renders an extra "no mapping"
     * option (used by the per-group mapping UI); the config default uses 0+.
     */
    public static function entitySelect(string $name, ?int $selected, bool $allowNone = false): string {
        global $DB;

        $html = "<select name='" . htmlspecialchars($name) . "' class='tanium-input tanium-select'>";
        if ($allowNone) {
            $sel   = $selected === null ? ' selected' : '';
            $html .= "<option value='-1'{$sel}>" . __('— no mapping —', 'tanium') . "</option>";
        }
        foreach ($DB->request(['SELECT' => ['id', 'completename'], 'FROM' => 'glpi_entities', 'ORDER' => 'completename ASC']) as $e) {
            $sel   = ($selected !== null && (int)$e['id'] === $selected) ? ' selected' : '';
            $html .= "<option value='" . (int)$e['id'] . "'{$sel}>" . htmlspecialchars($e['completename'] ?: __('Root entity')) . "</option>";
        }
        $html .= "</select>";
        return $html;
    }

    private function renderField(string $label, string $input, string $hint = ''): void {
        echo "<div class='tanium-field'>";
        echo "<label class='tanium-label'>{$label}</label>";
        echo "<div class='tanium-input-wrap'>{$input}";
        if ($hint) {
            echo "<span class='tanium-hint'>{$hint}</span>";
        }
        echo "</div></div>";
    }

    private function renderCheckbox(string $name, string $label, int $checked): void {
        $chk = $checked ? 'checked' : '';
        echo "<div class='tanium-checkbox-row'>";
        echo "<label class='tanium-checkbox-label'>";
        echo "<input type='checkbox' name='{$name}' value='1' {$chk} class='tanium-checkbox'/>";
        echo "<span class='tanium-toggle-slider'></span> {$label}";
        echo "</label></div>";
    }

    private function getTaniumLogoUrl(): string {
        return Plugin::getWebDir('tanium') . '/public/img/tanium-logo.svg';
    }
}
