<?php

namespace GlpiPlugin\Tanium;

use CommonDBTM;
use Html;
use Plugin;
use Session;

class Config extends CommonDBTM {

    public static $rightname = 'config';

    public static function getTypeName($nb = 0): string {
        return __('Tanium Configuration', 'tanium');
    }

    public static function getConfig(): array {
        global $DB;

        $row = $DB->request(['FROM' => 'glpi_plugin_tanium_configs', 'LIMIT' => 1])->current();

        return $row ?? [
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
        ];
    }

    public static function saveConfig(array $data): void {
        global $DB;

        $config = self::getConfig();

        if (empty($data['api_token']) && !empty($config['api_token'])) {
            unset($data['api_token']);
        }

        $data['date_mod'] = date('Y-m-d H:i:s');

        if (($config['id'] ?? 0) > 0) {
            $DB->update('glpi_plugin_tanium_configs', $data, ['id' => $config['id']]);
        } else {
            $DB->insert('glpi_plugin_tanium_configs', $data);
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
            if ($user->getFromDB($userId)) {
                $email = $user->getDefaultEmail();
                if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $emails[strtolower($email)] = $email;
                }
            }
        }

        return array_values($emails);
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

        $this->renderCheckbox('notify_critical', __('Notify when new Critical CVEs are detected', 'tanium'), (int)($config['notify_critical'] ?? 1));

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

        $this->renderField(
            __('Additional notification email(s)', 'tanium'),
            "<input type='text' name='notify_email' class='tanium-input' value='" . htmlspecialchars($config['notify_email'] ?? '') . "' placeholder='security@company.com, admin@company.com'/>",
            __('Comma-separated list of extra emails (e.g. distribution lists not registered as GLPI users). Leave both fields blank to disable email alerts.', 'tanium')
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
        echo "<a href='" . Plugin::getWebDir('tanium') . "/front/sync.form.php' class='tanium-btn tanium-btn-success'>&#9654; " . __('Sync now', 'tanium') . "</a>";
        echo "</div>";
        echo "</form>";
        echo "</div></div>";
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
