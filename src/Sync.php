<?php

namespace GlpiPlugin\Tanium;

use CommonGLPI;
use Computer;
use DeviceMemory;
use DeviceProcessor;
use Domain;
use IPAddress;
use Item_DeviceMemory;
use Item_DeviceProcessor;
use Item_SoftwareVersion;
use NetworkName;
use NetworkPort;
use OperatingSystem;
use OperatingSystemVersion;
use OperatingSystemArchitecture;
use Plugin;
use Session;
use Software;
use SoftwareVersion;
use Toolbox;
use User;

class Sync extends CommonGLPI {

    public static $rightname = 'plugin_tanium_sync';

    private static int $newCriticalCves = 0;

    public static function getTypeName($nb = 0): string {
        return __('Tanium Sync', 'tanium');
    }

    public static function getMenuName(): string {
        return __('Tanium', 'tanium');
    }

    public static function getMenuContent(): array {
        $menu = [];
        if (Session::haveRight('config', UPDATE)) {
            $menu['title']   = self::getMenuName();
            $menu['page']    = Plugin::getWebDir('tanium') . '/front/dashboard.php';
            $menu['icon']    = self::getIcon();
            $menu['options'] = [
                'dashboard'       => [
                    'title' => __('Dashboard', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/dashboard.php',
                    'icon'  => 'ti ti-layout-dashboard',
                ],
                'endpoints'       => [
                    'title' => __('Endpoints', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/endpoints.php',
                    'icon'  => 'ti ti-devices',
                ],
                'vulnerabilities' => [
                    'title' => __('Vulnerabilities', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/vulnerabilities.php',
                    'icon'  => 'ti ti-shield-exclamation',
                ],
                'patches'         => [
                    'title' => __('Patch Remediation', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/patches.php',
                    'icon'  => 'ti ti-rocket',
                ],
                'coverage'        => [
                    'title' => __('Coverage', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/coverage.php',
                    'icon'  => 'ti ti-radar',
                ],
                'exceptions'      => [
                    'title' => __('CVE Exceptions', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/exceptions.php',
                    'icon'  => 'ti ti-shield-off',
                ],
                'assignments'     => [
                    'title' => __('Assignments', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/assignments.php',
                    'icon'  => 'ti ti-user-check',
                ],
                'heatmap'         => [
                    'title' => __('Risk Heatmap', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/heatmap.php',
                    'icon'  => 'ti ti-layout-grid',
                ],
                'search'          => [
                    'title' => __('Search', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/search.php',
                    'icon'  => 'ti ti-search',
                ],
                'compare'         => [
                    'title' => __('Compare', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/compare.php',
                    'icon'  => 'ti ti-git-compare',
                ],
                'report'          => [
                    'title' => __('Global Report', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/report.php',
                    'icon'  => 'ti ti-printer',
                ],
                'sync'            => [
                    'title' => __('Synchronize', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/sync.form.php',
                    'icon'  => 'ti ti-refresh',
                ],
                'config'          => [
                    'title' => __('Configuration', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/config.form.php',
                    'icon'  => 'ti ti-settings',
                ],
            ];
        }
        return $menu;
    }

    public static function getIcon(): string {
        return 'ti ti-cpu';
    }

    // ── Main sync entry point ─────────────────────────────────────────────

    public static function run(): array {
        $config = Config::getConfig();

        if (empty($config['api_url']) || empty($config['api_token'])) {
            return self::result(0, 0, 0, 1, 'Tanium API URL or token is not configured.');
        }

        self::$newCriticalCves = 0;
        $logId = self::startLog();
        $api   = new Api($config['api_url'], $config['api_token']);

        $created = 0;
        $updated = 0;
        $errors  = 0;
        $total   = 0;

        try {
            // ── Incremental or full sync ──────────────────────────────────
            $incremental = (bool) ($config['sync_incremental'] ?? false);
            $cursor      = $config['last_sync_cursor'] ?? null;

            if ($incremental && $cursor) {
                $endpoints = $api->getAllEndpointsIncremental($cursor, (int) $config['import_limit']);
            } else {
                $endpoints = $api->getAllEndpoints((int) $config['import_limit']);
            }

            $total = count($endpoints);

            // ── Software ──────────────────────────────────────────────────
            $softwareByEid = [];
            if ($config['sync_software']) {
                $software      = $api->getAllSoftware((int) $config['import_limit']);
                $softwareByEid = self::indexByField($software, 'eid');
            }

            // ── CVE findings ──────────────────────────────────────────────
            $cveByEid = [];
            if (!empty($config['sync_vulnerabilities'])) {
                $cves     = $api->getAllCVEFindings((int) $config['import_limit']);
                $cveByEid = self::indexByField($cves, 'computerName');
                self::syncCVESummary($cves);
            }

            // ── Patch findings ────────────────────────────────────────────
            $patchByEid = [];
            if (!empty($config['sync_patches'])) {
                $patches    = $api->getAllPatchFindings((int) $config['import_limit']);
                $patchByEid = self::indexByField($patches, 'computerName');
            }

            foreach ($endpoints as $endpoint) {
                try {
                    $eid = (string) ($endpoint['eid'] ?? $endpoint['id'] ?? '');
                    if ($eid === '') {
                        continue;
                    }

                    $result = self::syncEndpoint(
                        $endpoint,
                        $softwareByEid[$eid] ?? [],
                        $cveByEid[$eid]      ?? [],
                        $patchByEid[$eid]    ?? [],
                        $config
                    );

                    if ($result === 'created') {
                        $created++;
                    } elseif ($result === 'updated') {
                        $updated++;
                    }
                } catch (\Throwable $e) {
                    $errors++;
                    Toolbox::logError('[Tanium] Error syncing endpoint: ' . $e->getMessage());
                }
            }

            // Save cursor for next incremental run
            $newCursor = date('Y-m-d\TH:i:s\Z');
            Config::updateLastSync($total, $newCursor);

        } catch (\Throwable $e) {
            $errors++;
            self::finishLog($logId, 'error', $total, $created, $updated, $errors, $e->getMessage());
            return self::result($total, $created, $updated, $errors, $e->getMessage());
        }

        self::finishLog($logId, 'success', $total, $created, $updated, $errors);

        // Save snapshot to risk history
        self::saveRiskHistory($logId);

        // Webhook notification on sync completion
        $config = Config::getConfig();
        if (!empty($config['webhook_enabled']) && !empty($config['webhook_url'])) {
            $result  = self::result($total, $created, $updated, $errors);
            $payload = Notification::buildSyncPayload($result, self::$newCriticalCves);
            Notification::sendWebhook($config['webhook_url'], $payload);
        }

        // Email on new critical CVEs
        if (!empty($config['notify_critical']) && self::$newCriticalCves > 0 && !empty($config['notify_email'])) {
            global $CFG_GLPI;
            $subject = sprintf('[Tanium] %d new critical CVE(s) detected', self::$newCriticalCves);
            $body    = Notification::buildCriticalEmailBody(self::$newCriticalCves, [], $CFG_GLPI['url_base'] ?? '');
            Notification::sendEmail($config['notify_email'], $subject, $body);
        }

        self::$newCriticalCves = 0;
        return self::result($total, $created, $updated, $errors);
    }

    // ── Per-endpoint sync ─────────────────────────────────────────────────

    private static function syncEndpoint(
        array $endpoint,
        array $software,
        array $cves,
        array $patches,
        array $config
    ): string {
        global $DB;

        $eid          = (string) ($endpoint['eid'] ?? $endpoint['id'] ?? '');
        $computerName = $endpoint['computerName'] ?? $endpoint['name'] ?? 'Unknown';

        $mappingRow = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_assets',
            'WHERE' => ['tanium_eid' => $eid],
        ])->current();

        $computerId = $mappingRow['computers_id'] ?? null;
        $isNew      = ($computerId === null);

        $computer = new Computer();

        if ($isNew) {
            $existing = $DB->request([
                'FROM'  => 'glpi_computers',
                'WHERE' => ['name' => $computerName, 'is_deleted' => 0],
                'LIMIT' => 1,
            ])->current();

            if ($existing) {
                $computerId = (int) $existing['id'];
                $isNew      = false;
            }
        }

        $fields = self::buildComputerFields($endpoint, $config);

        if ($isNew) {
            $computerId = $computer->add($fields);
            if (!$computerId) {
                throw new \RuntimeException("Failed to create GLPI computer for EID {$eid}");
            }
        } else {
            $computer->update(array_merge($fields, ['id' => $computerId]));
        }

        if ($config['sync_hardware']) {
            self::syncHardware($computerId, $endpoint);
        }

        if (!empty($config['sync_network'])) {
            self::syncNetworkAdapters($computerId, $endpoint);
        }

        if ($config['sync_software'] && !empty($software)) {
            self::syncSoftware($computerId, $software);
        }

        if (!empty($config['sync_vulnerabilities']) && !empty($cves)) {
            self::syncEndpointCVEs($eid, $computerId, $cves);
        }

        if (!empty($config['sync_patches']) && !empty($patches)) {
            self::syncEndpointPatches($eid, $computerId, $patches);
        }

        // Recalculate risk score after CVE/patch data is saved
        self::updateRiskScore($eid);

        $now         = date('Y-m-d H:i:s');
        $lastSeenRaw = $endpoint['lastRegistrationTime'] ?? $endpoint['lastSeen'] ?? null;
        $lastSeen    = $lastSeenRaw ? date('Y-m-d H:i:s', strtotime($lastSeenRaw)) : $now;

        $assetData = [
            'tanium_name'  => $computerName,
            'computers_id' => $computerId,
            'ip_address'   => $endpoint['ipAddresses'][0] ?? $endpoint['ipAddress'] ?? null,
            'mac_address'  => $endpoint['macAddresses'][0] ?? $endpoint['macAddress'] ?? null,
            'os_name'      => $endpoint['os']['name']     ?? null,
            'os_version'   => $endpoint['os']['version']  ?? null,
            'os_build'     => $endpoint['os']['build']    ?? null,
            'os_platform'  => $endpoint['os']['platform'] ?? null,
            'is_virtual'   => (int) ($endpoint['isVirtual'] ?? 0),
            'last_seen'    => $lastSeen,
            'sync_status'  => 'ok',
            'sync_message' => null,
            'date_mod'     => $now,
        ];

        if ($mappingRow) {
            $DB->update('glpi_plugin_tanium_assets', $assetData, ['tanium_eid' => $eid]);
        } else {
            $DB->insert('glpi_plugin_tanium_assets', array_merge($assetData, ['tanium_eid' => $eid]));
        }

        return $isNew ? 'created' : 'updated';
    }

    // ── Field builders ────────────────────────────────────────────────────

    private static function buildComputerFields(array $e, array $config): array {
        $fields = [
            'name'        => $e['computerName'] ?? $e['name'] ?? 'Unknown',
            'entities_id' => 0,
            'is_dynamic'  => 1,
        ];

        if (!empty($e['domainName'])) {
            $fields['domains_id'] = self::getOrCreateDomain($e['domainName']);
        }

        // OS name
        $osName = $e['os']['name'] ?? '';
        if ($osName) {
            $fields['operatingsystems_id'] = self::getOrCreate('OperatingSystem', $osName);
        }

        // OS version
        if (!empty($config['sync_os_details'])) {
            $osVersion = $e['os']['version'] ?? '';
            if ($osVersion) {
                $fields['operatingsystemversions_id'] = self::getOrCreate('OperatingSystemVersion', $osVersion);
            }
            $osArch = $e['os']['architecture'] ?? $e['os']['generation'] ?? '';
            if ($osArch) {
                $fields['operatingsystemarchitectures_id'] = self::getOrCreate('OperatingSystemArchitecture', $osArch);
            }
        }

        if ($config['sync_hardware']) {
            $manufacturer = $e['manufacturer'] ?? '';
            $model        = $e['model']        ?? '';

            if ($manufacturer) {
                $fields['manufacturers_id'] = self::getOrCreate('Manufacturer', $manufacturer);
            }
            if ($model) {
                $fields['computermodels_id'] = self::getOrCreate('ComputerModel', $model);
            }
        }

        if (!empty($e['serialNumber'])) {
            $fields['serial'] = $e['serialNumber'];
        }

        // Last logged user
        $lastUser = $e['lastLoggedInUser'] ?? $e['loggedInUsers'][0]['name'] ?? '';
        if ($lastUser) {
            $userId = self::findUserId($lastUser);
            if ($userId) {
                $fields['users_id'] = $userId;
            }
        }

        return $fields;
    }

    // ── Hardware sync ─────────────────────────────────────────────────────

    private static function syncHardware(int $computerId, array $e): void {
        $memTotal = (int) ($e['memory']['total'] ?? 0);
        if ($memTotal > 0) {
            self::upsertMemory($computerId, $memTotal);
        }

        $cpuName  = $e['processor']['name']      ?? ($e['cpu']['name']      ?? '');
        $cpuSpeed = (int) ($e['processor']['speed']['mhz'] ?? ($e['cpu']['speed'] ?? 0));
        $cpuCores = (int) ($e['processor']['core']['count'] ?? ($e['cpu']['coreCount'] ?? 0));
        if ($cpuName) {
            self::upsertProcessor($computerId, $cpuName, $cpuSpeed, $cpuCores);
        }
    }

    // ── Network adapters sync ─────────────────────────────────────────────

    private static function syncNetworkAdapters(int $computerId, array $e): void {
        global $DB;

        $ips  = $e['ipAddresses']  ?? (isset($e['ipAddress'])  ? [$e['ipAddress']]  : []);
        $macs = $e['macAddresses'] ?? (isset($e['macAddress']) ? [$e['macAddress']] : []);

        if (empty($ips) && empty($macs)) {
            return;
        }

        // Check existing port
        $portRow = $DB->request([
            'FROM'  => 'glpi_networkports',
            'WHERE' => ['items_id' => $computerId, 'itemtype' => 'Computer', 'name' => 'Tanium'],
            'LIMIT' => 1,
        ])->current();

        $port = new NetworkPort();
        $mac  = $macs[0] ?? '';
        $ip   = $ips[0]  ?? '';

        if ($portRow) {
            $portId = (int) $portRow['id'];
            $port->update(['id' => $portId, 'mac' => $mac]);
        } else {
            $portId = (int) $port->add([
                'items_id'           => $computerId,
                'itemtype'           => 'Computer',
                'instantiation_type' => 'NetworkPortEthernet',
                'name'               => 'Tanium',
                'mac'                => $mac,
                'is_dynamic'         => 1,
            ]);
        }

        if ($ip && $portId) {
            $nameRow = $DB->request([
                'FROM'  => 'glpi_networknames',
                'WHERE' => ['items_id' => $portId, 'itemtype' => 'NetworkPort'],
                'LIMIT' => 1,
            ])->current();

            $netName = new NetworkName();
            if (!$nameRow) {
                $nameId = (int) $netName->add([
                    'items_id'   => $portId,
                    'itemtype'   => 'NetworkPort',
                    'is_dynamic' => 1,
                ]);
            } else {
                $nameId = (int) $nameRow['id'];
            }

            $ipRow = $DB->request([
                'FROM'  => 'glpi_ipaddresses',
                'WHERE' => ['items_id' => $nameId, 'itemtype' => 'NetworkName'],
                'LIMIT' => 1,
            ])->current();

            $ipAddr = new IPAddress();
            if ($ipRow) {
                $ipAddr->update(['id' => $ipRow['id'], 'name' => $ip]);
            } else {
                $ipAddr->add([
                    'items_id'   => $nameId,
                    'itemtype'   => 'NetworkName',
                    'name'       => $ip,
                    'is_dynamic' => 1,
                ]);
            }
        }
    }

    // ── Software sync ─────────────────────────────────────────────────────

    private static function syncSoftware(int $computerId, array $softwareList): void {
        foreach ($softwareList as $app) {
            $name    = $app['name']    ?? ($app['applicationName'] ?? '');
            $version = $app['version'] ?? '';
            if (empty($name)) {
                continue;
            }
            self::linkSoftware($computerId, $name, $version);
        }
    }

    // ── CVE sync ─────────────────────────────────────────────────────────

    private static function syncCVESummary(array $cves): void {
        global $DB;

        $summary = [];
        foreach ($cves as $finding) {
            $cveId = $finding['cveId'] ?? $finding['cve'] ?? $finding['id'] ?? '';
            if (!$cveId) {
                continue;
            }
            if (!isset($summary[$cveId])) {
                $summary[$cveId] = [
                    'cve_id'      => $cveId,
                    'cvss_score'  => $finding['cvssScore']  ?? $finding['cvss'] ?? null,
                    'severity'    => strtolower($finding['severity'] ?? 'unknown'),
                    'title'       => $finding['title']       ?? $finding['name'] ?? $cveId,
                    'description' => $finding['description'] ?? null,
                    'count'       => 0,
                ];
            }
            $summary[$cveId]['count']++;
        }

        foreach ($summary as $cveId => $data) {
            $existing = $DB->request([
                'FROM'  => 'glpi_plugin_tanium_vulnerabilities',
                'WHERE' => ['cve_id' => $cveId],
                'LIMIT' => 1,
            ])->current();

            $now    = date('Y-m-d H:i:s');
            $record = [
                'cvss_score'    => $data['cvss_score'],
                'severity'      => $data['severity'],
                'title'         => substr($data['title'], 0, 500),
                'description'   => $data['description'],
                'affected_count'=> $data['count'],
                'last_detected' => $now,
                'date_mod'      => $now,
            ];

            if ($existing) {
                $DB->update('glpi_plugin_tanium_vulnerabilities', $record, ['cve_id' => $cveId]);
            } else {
                $DB->insert('glpi_plugin_tanium_vulnerabilities', array_merge($record, [
                    'cve_id'         => $cveId,
                    'first_detected' => $now,
                ]));
            }
        }
    }

    private static function syncEndpointCVEs(string $eid, int $computerId, array $cves): void {
        global $DB;

        $now = date('Y-m-d H:i:s');
        foreach ($cves as $finding) {
            $cveId = $finding['cveId'] ?? $finding['cve'] ?? $finding['id'] ?? '';
            if (!$cveId) {
                continue;
            }

            $existing = $DB->request([
                'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
                'WHERE' => ['tanium_eid' => $eid, 'cve_id' => $cveId],
                'LIMIT' => 1,
            ])->current();

            $record = [
                'computers_id' => $computerId,
                'cvss_score'   => $finding['cvssScore'] ?? $finding['cvss'] ?? null,
                'severity'     => strtolower($finding['severity'] ?? 'unknown'),
                'status'       => $finding['state'] ?? $finding['status'] ?? 'open',
                'detected_at'  => isset($finding['detectedAt']) ? date('Y-m-d H:i:s', strtotime($finding['detectedAt'])) : $now,
                'date_mod'     => $now,
            ];

            if ($existing) {
                // Detect status change → write to CVE history
                if ($existing['status'] !== $record['status']) {
                    $DB->insert('glpi_plugin_tanium_cve_history', [
                        'tanium_eid'   => $eid,
                        'cve_id'       => $cveId,
                        'computers_id' => $computerId,
                        'old_status'   => $existing['status'],
                        'new_status'   => $record['status'],
                        'changed_at'   => $now,
                    ]);
                }
                $DB->update('glpi_plugin_tanium_endpoint_cves', $record, [
                    'tanium_eid' => $eid,
                    'cve_id'     => $cveId,
                ]);
            } else {
                // New CVE finding
                if (($record['severity'] ?? '') === 'critical') {
                    self::$newCriticalCves++;
                }
                $DB->insert('glpi_plugin_tanium_cve_history', [
                    'tanium_eid'   => $eid,
                    'cve_id'       => $cveId,
                    'computers_id' => $computerId,
                    'old_status'   => null,
                    'new_status'   => $record['status'],
                    'changed_at'   => $now,
                ]);
                $DB->insert('glpi_plugin_tanium_endpoint_cves', array_merge($record, [
                    'tanium_eid' => $eid,
                    'cve_id'     => $cveId,
                ]));
            }
        }
    }

    // ── Patch sync ────────────────────────────────────────────────────────

    private static function syncEndpointPatches(string $eid, int $computerId, array $patches): void {
        global $DB;

        $now = date('Y-m-d H:i:s');
        foreach ($patches as $patch) {
            $patchId = $patch['patchId'] ?? $patch['id'] ?? $patch['kb'] ?? '';
            if (!$patchId) {
                continue;
            }

            $existing = $DB->request([
                'FROM'  => 'glpi_plugin_tanium_patches',
                'WHERE' => ['tanium_eid' => $eid, 'patch_id' => $patchId],
                'LIMIT' => 1,
            ])->current();

            $releaseDate = null;
            if (!empty($patch['releaseDate'])) {
                $releaseDate = date('Y-m-d', strtotime($patch['releaseDate']));
            }

            $record = [
                'computers_id' => $computerId,
                'patch_title'  => substr($patch['title'] ?? $patch['name'] ?? $patchId, 0, 500),
                'severity'     => strtolower($patch['severity'] ?? 'unknown'),
                'status'       => $patch['status'] ?? 'missing',
                'kb_id'        => $patch['kb'] ?? $patch['kbId'] ?? null,
                'release_date' => $releaseDate,
                'date_mod'     => $now,
            ];

            if ($existing) {
                $DB->update('glpi_plugin_tanium_patches', $record, [
                    'tanium_eid' => $eid,
                    'patch_id'   => $patchId,
                ]);
            } else {
                $DB->insert('glpi_plugin_tanium_patches', array_merge($record, [
                    'tanium_eid' => $eid,
                    'patch_id'   => $patchId,
                ]));
            }
        }
    }

    // ── Risk score ────────────────────────────────────────────────────────

    public static function updateRiskScore(string $eid): void {
        global $DB;

        $score = 0.0;

        // CVE contribution: Critical=10, High=5, Medium=2, Low=0.5
        $cveWeights = ['critical' => 10, 'high' => 5, 'medium' => 2, 'low' => 0.5];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE' => ['tanium_eid' => $eid, 'status' => ['!=', 'remediated']],
        ]) as $cve) {
            $sev    = strtolower($cve['severity'] ?? 'low');
            $score += (float) ($cveWeights[$sev] ?? 0.5);
        }

        // Missing patch contribution: Critical=5, Important=3, Moderate=1, Low=0.3
        $patchWeights = ['critical' => 5, 'important' => 3, 'moderate' => 1, 'low' => 0.3];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_patches',
            'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'],
        ]) as $patch) {
            $sev    = strtolower($patch['severity'] ?? 'low');
            $score += (float) ($patchWeights[$sev] ?? 0.3);
        }

        $capped = min(100, (int) round($score));
        $DB->update('glpi_plugin_tanium_assets', ['risk_score' => $capped], ['tanium_eid' => $eid]);
    }

    // ── GLPI helpers ──────────────────────────────────────────────────────

    private static function getOrCreate(string $itemtype, string $name): int {
        global $DB;

        $item = new $itemtype();
        $row  = $DB->request([
            'FROM'  => $item->getTable(),
            'WHERE' => ['name' => $name],
            'LIMIT' => 1,
        ])->current();

        if ($row) {
            return (int) $row['id'];
        }

        return (int) $item->add(['name' => $name]);
    }

    private static function getOrCreateDomain(string $name): int {
        global $DB;

        $row = $DB->request(['FROM' => 'glpi_domains', 'WHERE' => ['name' => $name], 'LIMIT' => 1])->current();
        if ($row) {
            return (int) $row['id'];
        }

        $domain = new Domain();
        return (int) $domain->add(['name' => $name, 'entities_id' => 0]);
    }

    private static function findUserId(string $username): int {
        global $DB;

        $clean = trim(strstr($username . '\\', '\\', true) ?: $username);
        $row   = $DB->request([
            'FROM'  => 'glpi_users',
            'WHERE' => ['name' => $clean, 'is_deleted' => 0],
            'LIMIT' => 1,
        ])->current();

        return $row ? (int) $row['id'] : 0;
    }

    private static function upsertMemory(int $computerId, int $totalMb): void {
        global $DB;

        $row = $DB->request([
            'FROM'  => 'glpi_items_devicememories',
            'WHERE' => ['items_id' => $computerId, 'itemtype' => 'Computer'],
            'LIMIT' => 1,
        ])->current();

        $sizeType = self::getOrCreate('DeviceMemoryType', 'RAM');
        $memModel = new DeviceMemory();
        $modelId  = $memModel->add([
            'designation'          => "RAM {$totalMb} MB",
            'devicememorytypes_id' => $sizeType,
            'size_default'         => $totalMb,
        ]);

        if ($row) {
            $item = new Item_DeviceMemory();
            $item->update(['id' => $row['id'], 'size' => $totalMb]);
        } else {
            $item = new Item_DeviceMemory();
            $item->add([
                'devicememories_id' => $modelId,
                'items_id'          => $computerId,
                'itemtype'          => 'Computer',
                'size'              => $totalMb,
                'is_dynamic'        => 1,
            ]);
        }
    }

    private static function upsertProcessor(int $computerId, string $name, int $speedMhz, int $cores): void {
        global $DB;

        $row = $DB->request([
            'FROM'  => 'glpi_items_deviceprocessors',
            'WHERE' => ['items_id' => $computerId, 'itemtype' => 'Computer'],
            'LIMIT' => 1,
        ])->current();

        $proc   = new DeviceProcessor();
        $procId = $proc->add([
            'designation'     => $name,
            'frequence'       => $speedMhz,
            'nbcores_default' => $cores ?: 1,
        ]);

        if ($row) {
            $item = new Item_DeviceProcessor();
            $item->update(['id' => $row['id'], 'frequency' => $speedMhz, 'nbcores' => $cores ?: 1]);
        } else {
            $item = new Item_DeviceProcessor();
            $item->add([
                'deviceprocessors_id' => $procId,
                'items_id'            => $computerId,
                'itemtype'            => 'Computer',
                'frequency'           => $speedMhz,
                'nbcores'             => $cores ?: 1,
                'is_dynamic'          => 1,
            ]);
        }
    }

    private static function linkSoftware(int $computerId, string $name, string $version): void {
        global $DB;

        $softId = self::getOrCreate('Software', $name);

        $versionRow = $DB->request([
            'FROM'  => 'glpi_softwareversions',
            'WHERE' => ['softwares_id' => $softId, 'name' => $version],
            'LIMIT' => 1,
        ])->current();

        if ($versionRow) {
            $versionId = (int) $versionRow['id'];
        } else {
            $sv        = new SoftwareVersion();
            $versionId = (int) $sv->add([
                'softwares_id' => $softId,
                'name'         => $version ?: '—',
                'is_dynamic'   => 1,
            ]);
        }

        $linked = $DB->request([
            'FROM'  => 'glpi_items_softwareversions',
            'WHERE' => [
                'items_id'            => $computerId,
                'itemtype'            => 'Computer',
                'softwareversions_id' => $versionId,
            ],
            'LIMIT' => 1,
        ])->current();

        if (!$linked) {
            $isv = new Item_SoftwareVersion();
            $isv->add([
                'items_id'            => $computerId,
                'itemtype'            => 'Computer',
                'softwareversions_id' => $versionId,
                'is_dynamic'          => 1,
            ]);
        }
    }

    // ── Risk history snapshot ─────────────────────────────────────────────

    private static function saveRiskHistory(int $logId): void {
        global $DB;

        $row = $DB->doQuery("
            SELECT
                COUNT(*) AS total_endpoints,
                ROUND(AVG(risk_score), 2) AS avg_risk,
                COUNT(CASE WHEN risk_score >= 70 THEN 1 END) AS critical_count,
                COUNT(CASE WHEN risk_score >= 40 AND risk_score < 70 THEN 1 END) AS high_count,
                COUNT(CASE WHEN risk_score >= 15 AND risk_score < 40 THEN 1 END) AS medium_count,
                COUNT(CASE WHEN risk_score < 15 THEN 1 END) AS low_count
            FROM glpi_plugin_tanium_assets
        ")->current();

        if (!$row || (int)$row['total_endpoints'] === 0) {
            return;
        }

        $cveRow = $DB->doQuery("
            SELECT COUNT(*) AS total_cves,
                   COUNT(CASE WHEN severity='critical' THEN 1 END) AS critical_cves
            FROM glpi_plugin_tanium_vulnerabilities
        ")->current();

        $patchRow = $DB->doQuery("
            SELECT COUNT(*) AS patches_missing
            FROM glpi_plugin_tanium_patches WHERE status='missing'
        ")->current();

        $DB->insert('glpi_plugin_tanium_risk_history', [
            'sync_log_id'     => $logId,
            'total_endpoints' => (int)$row['total_endpoints'],
            'avg_risk'        => (float)($row['avg_risk'] ?? 0),
            'critical_count'  => (int)$row['critical_count'],
            'high_count'      => (int)$row['high_count'],
            'medium_count'    => (int)$row['medium_count'],
            'low_count'       => (int)$row['low_count'],
            'total_cves'      => (int)($cveRow['total_cves'] ?? 0),
            'critical_cves'   => (int)($cveRow['critical_cves'] ?? 0),
            'patches_missing' => (int)($patchRow['patches_missing'] ?? 0),
            'recorded_at'     => date('Y-m-d H:i:s'),
        ]);
    }

    // ── Log helpers ───────────────────────────────────────────────────────

    private static function startLog(): int {
        global $DB;
        $DB->insert('glpi_plugin_tanium_sync_logs', [
            'started_at' => date('Y-m-d H:i:s'),
            'status'     => 'running',
        ]);
        return (int) $DB->insertId();
    }

    private static function finishLog(int $logId, string $status, int $total, int $created, int $updated, int $errors, string $message = ''): void {
        global $DB;
        $DB->update('glpi_plugin_tanium_sync_logs', [
            'finished_at' => date('Y-m-d H:i:s'),
            'status'      => $status,
            'total'       => $total,
            'created'     => $created,
            'updated'     => $updated,
            'errors'      => $errors,
            'message'     => $message,
        ], ['id' => $logId]);
    }

    private static function result(int $total, int $created, int $updated, int $errors, string $message = ''): array {
        return compact('total', 'created', 'updated', 'errors', 'message');
    }

    private static function indexByField(array $items, string $field): array {
        $index = [];
        foreach ($items as $item) {
            $key = (string) ($item[$field] ?? '');
            if ($key !== '') {
                $index[$key][] = $item;
            }
        }
        return $index;
    }

    public static function getRecentLogs(int $limit = 10): array {
        global $DB;
        $rows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_sync_logs',
            'ORDER' => 'started_at DESC',
            'LIMIT' => $limit,
        ]) as $row) {
            $rows[] = $row;
        }
        return $rows;
    }
}
