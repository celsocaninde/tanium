<?php

namespace GlpiPlugin\Tanium;

use CommonGLPI;
use Computer;
use CronTask;
use DeviceMemory;
use DeviceProcessor;
use Domain;
use IPAddress;
use ITILSolution;
use Item_DeviceMemory;
use Item_DeviceProcessor;
use Item_SoftwareVersion;
use Item_Ticket;
use Ticket;
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

    /** @var array<int,array{cve_id:string,endpoint:string,cvss:mixed}> */
    private static array $newCriticalCveDetails = [];

    /** @var array<int,array{cve_id:string,endpoint:string,eid:string,severity:string,cvss:mixed,detected_at:?string,days_open:?int}> CVE findings closed during this run */
    private static array $remediatedCves = [];

    /** @var array<int,array{patch_id:string,title:string,endpoint:string,eid:string,severity:string}> patches that left the "missing" state during this run */
    private static array $installedPatches = [];

    public static function getTypeName($nb = 0): string {
        return __('Tanium Sync', 'tanium');
    }

    public static function getMenuName(): string {
        return __('Tanium', 'tanium');
    }

    public static function canView(): bool {
        return Profile::hasReadRight();
    }

    public static function getMenuContent(): array {
        $menu = [];
        if (self::canView()) {
            $menu['title']   = self::getMenuName();
            $menu['page']    = Plugin::getWebDir('tanium') . '/front/dashboard.php';
            $menu['icon']    = self::getIcon();
            $menu['options'] = [
                'dashboard'       => [
                    'title' => __('Dashboard', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/dashboard.php',
                    'icon'  => 'ti ti-layout-dashboard',
                ],
                'actionplan'      => [
                    'title' => __('Action Plan', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/actionplan.php',
                    'icon'  => 'ti ti-list-check',
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
                'sla'             => [
                    'title' => __('SLA Compliance', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/sla.php',
                    'icon'  => 'ti ti-clock-check',
                ],
                'trend'           => [
                    'title' => __('Trend', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/trend.php',
                    'icon'  => 'ti ti-trending-up',
                ],
                'remediation'     => [
                    'title' => __('Remediation', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/remediation.php',
                    'icon'  => 'ti ti-shield-check',
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
                'healthreport'    => [
                    'title' => __('Fleet Health Report', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/healthreport.php',
                    'icon'  => 'ti ti-heart-rate-monitor',
                ],
                'report'          => [
                    'title' => __('Global Report', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/report.php',
                    'icon'  => 'ti ti-printer',
                ],
                'campaigns'       => [
                    'title' => __('Campaigns', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/campaigns.php',
                    'icon'  => 'ti ti-target-arrow',
                ],
                'burndown'        => [
                    'title' => __('Burn-down', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/burndown.php',
                    'icon'  => 'ti ti-chart-line',
                ],
                'outliers'        => [
                    'title' => __('Outliers', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/outliers.php',
                    'icon'  => 'ti ti-alert-hexagon',
                ],
                'sync'            => [
                    'title' => __('Synchronize', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/sync.form.php',
                    'icon'  => 'ti ti-refresh',
                ],
                'diagnostics'     => [
                    'title' => __('Diagnostics', 'tanium'),
                    'page'  => Plugin::getWebDir('tanium') . '/front/diagnostics.php',
                    'icon'  => 'ti ti-stethoscope',
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

        // This is a long, memory-heavy job. Give it headroom (helps both the CLI
        // cron and the web trigger) without ever lowering an already-higher limit.
        $memBytes = self::iniBytes(ini_get('memory_limit'));
        if ($memBytes !== -1 && $memBytes < 1024 * 1024 * 1024) {
            @ini_set('memory_limit', '1024M');
        }
        @set_time_limit(0);

        self::$newCriticalCves = 0;
        self::$newCriticalCveDetails = [];
        self::$remediatedCves = [];
        self::$installedPatches = [];
        $logId = self::startLog();

        // If a fatal (OOM/timeout) kills the request mid-sync, don't leave a
        // permanent "running" row — record it as an error so the UI is honest.
        register_shutdown_function(static function () use ($logId): void {
            $err = error_get_last();
            if (!$err || !in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
                return;
            }
            global $DB;
            $row = $DB->request([
                'FROM'  => 'glpi_plugin_tanium_sync_logs',
                'WHERE' => ['id' => $logId],
            ])->current();
            if ($row && ($row['status'] ?? '') === 'running') {
                $DB->update('glpi_plugin_tanium_sync_logs', [
                    'finished_at' => date('Y-m-d H:i:s'),
                    'status'      => 'error',
                    'errors'      => 1,
                    'message'     => 'Fatal: ' . substr($err['message'], 0, 300),
                ], ['id' => $logId]);
            }
        });

        $api   = new Api($config['api_url'], $config['api_token']);

        $created = 0;
        $updated = 0;
        $errors  = 0;
        $total   = 0;

        try {
            // ── Incremental or full sync ──────────────────────────────────
            // CVEs (Tanium Comply) and installed software are sub-fields of each
            // endpoint node, so they are fetched together with the endpoints when
            // their toggles are on — no separate product calls.
            $incremental = (bool) ($config['sync_incremental'] ?? false);
            $cursor      = $config['last_sync_cursor'] ?? null;
            $withCves    = !empty($config['sync_vulnerabilities']);
            $withApps    = !empty($config['sync_software']);
            $withPatches = !empty($config['sync_patches']);
            $limit       = (int) $config['import_limit'];
            // CVE severity floor: keep only findings at/above this level. Default is
            // 'all' (ingest every severity, incl. Medium/Low). Set 'cve_min_severity'
            // to high/critical to trim volume if a large fleet floods GLPI.
            $minSev      = strtolower((string) ($config['cve_min_severity'] ?? 'all'));
            $sinceTs     = ($incremental && $cursor) ? (strtotime($cursor) ?: 0) : 0;

            // Stream the fleet page-by-page and free each page before fetching the
            // next. Holding the whole fleet plus CVE/software/patch enrichment in
            // memory at once can exceed 1 GB and take the container down — this
            // keeps peak memory bounded regardless of fleet size.
            $fleetSize  = 0;
            $seenEids   = [];
            $withGroups = !empty($config['sync_group_membership']);
            $sensors    = array_values(array_filter(array_map('trim', explode(',', (string)($config['custom_sensors'] ?? '')))));
            // The reboot sensor has its own setting but rides the same custom-sensor
            // channel, so the admin doesn't have to remember to list it twice.
            $rebootSensor = trim((string)($config['reboot_sensor'] ?? ''));
            if ($rebootSensor !== '' && !in_array($rebootSensor, $sensors, true)) {
                $sensors[] = $rebootSensor;
            }
            $pageOpts   = ['sensors' => $sensors];
            // Skip the optional blocks this Gateway already rejected, unless the
            // cache is stale — then ask for everything again, so a module
            // installed since the last probe comes back on its own.
            $capsFullProbe = self::capsProbeDue($config);
            if (!$capsFullProbe) {
                $pageOpts['extrasLevel'] = (int)($config['caps_extras_level'] ?? 2);
                $pageOpts['groups']      = !empty($config['caps_groups']);
            }
            if ($sinceTs > 0) {
                // Server-side incremental: unchanged endpoints never leave Tanium.
                // The client-side filter below stays as a safety net.
                $pageOpts['since'] = gmdate('Y-m-d\TH:i:s\Z', $sinceTs);
            }
            $api->eachEndpointPage($limit, $withCves, $withApps, $withPatches,
                function (array $page, int $totalRecords) use (
                    &$created, &$updated, &$errors, &$total, &$fleetSize, &$seenEids,
                    $withCves, $withApps, $withPatches, $minSev, $sinceTs, $config, $logId
                ): void {
                    if ($fleetSize === 0 && $totalRecords > 0) {
                        $fleetSize = $totalRecords;
                    }

                    // Incremental: keep only endpoints seen since the cursor.
                    if ($sinceTs > 0) {
                        $page = array_values(array_filter(
                            $page,
                            static fn(array $e): bool => (strtotime($e['lastRegistrationTime'] ?? '') ?: 0) > $sinceTs
                        ));
                    }
                    if (!$page) {
                        return;
                    }

                    // CVE severity floor + per-page summary upsert (the fleet-wide
                    // affected_count is recomputed once at the end).
                    if ($withCves) {
                        $pageCves = [];
                        foreach ($page as $i => $e) {
                            $page[$i]['cves'] = self::filterCvesBySeverity($e['cves'] ?? [], $minSev);
                            foreach ($page[$i]['cves'] as $c) {
                                $pageCves[] = $c;
                            }
                        }
                        if ($pageCves) {
                            self::syncCVESummary($pageCves);
                        }
                    }

                    foreach ($page as $endpoint) {
                        try {
                            $eid = (string) ($endpoint['eid'] ?? $endpoint['id'] ?? '');
                            if ($eid === '') {
                                continue;
                            }
                            $seenEids[$eid] = true;
                            $total++;
                            $result = self::syncEndpoint(
                                $endpoint,
                                $withApps    ? ($endpoint['software'] ?? []) : [],
                                $withCves    ? ($endpoint['cves']     ?? []) : [],
                                $withPatches ? ($endpoint['patches']  ?? []) : [],
                                $config
                            );
                            if ($result === 'created') {
                                $created++;
                            } elseif ($result === 'updated') {
                                $updated++;
                            }
                        } catch (\Throwable $e) {
                            $errors++;
                            Toolbox::logInFile('tanium', '[Tanium] Error syncing endpoint: ' . $e->getMessage() . "\n");
                        }
                    }

                    self::updateLogProgress($logId, $total, $fleetSize ?: $total);
                },
                $withGroups,
                $pageOpts
            );

            self::persistCapabilities($api->discoveredCapabilities(), $capsFullProbe);

            // Fleet-wide CVE impact count (per-page upserts only see their page).
            if ($withCves) {
                self::recomputeCveAffectedCounts();
            }

            // Endpoints Tanium no longer returns.
            //
            // A full run already saw the whole fleet, so its own seen-set is
            // authoritative. An INCREMENTAL run never can be — it returns only
            // what changed — and since the cursor is written after every
            // successful run, incremental is the steady state. That left
            // retirement detection dead from the second sync onward: on the
            // reference fleet, 27 machines last seen in May and June still
            // carried retired_at = NULL in late July, inflating the fleet
            // average and the coverage KPI, with purgeretired finding nothing
            // to purge. The id-only sweep below closes that, cheaply and on
            // its own schedule.
            //
            // A run with errors is never trusted for this either way: an
            // incomplete picture would retire the entire estate.
            if ($errors === 0) {
                if ($sinceTs === 0 && $seenEids !== []) {
                    self::reconcileRetiredAssets($seenEids);
                    self::stampRetireSweep();
                } elseif (self::retireSweepDue($config)) {
                    self::sweepRetiredAssets($api);
                }
            }

            // Save cursor for next incremental run — but only when every
            // endpoint went through. Advancing past a failed endpoint drops it
            // from every future incremental run until something changes it in
            // Tanium, so its data silently rots. Holding the cursor makes the
            // next run retry them; a permanently-failing endpoint therefore
            // keeps incremental syncs wide, which is the loud failure mode we
            // want over the silent one.
            if ($errors === 0) {
                Config::updateLastSync($total, date('Y-m-d\TH:i:s\Z'));
            } else {
                // Empty cursor = leave last_sync_cursor untouched (see updateLastSync).
                Config::updateLastSync($total, '');
                Toolbox::logInFile('tanium', sprintf(
                    "[Tanium] %d endpoint(s) failed — incremental cursor held at %s so they are retried next run.\n",
                    $errors,
                    $cursor ?: 'none (full sync)'
                ));
            }

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

        // Enriched details shared by the email alert and the auto-ticket below
        $critDetails = [];
        if (self::$newCriticalCves > 0
            && (!empty($config['notify_critical']) || !empty($config['auto_ticket_critical']))) {
            $critDetails = self::enrichCriticalCveDetails(self::$newCriticalCveDetails);
        }

        // Email on new critical CVEs — split into workstations (notebook/desktop)
        // vs. servers/VMs, each with its own PDF report, in a single email.
        if (!empty($config['notify_critical']) && self::$newCriticalCves > 0) {
            $recipients = Config::resolveNotifyRecipients($config);
            if ($recipients !== []) {
                global $CFG_GLPI;
                $glpiUrl = $CFG_GLPI['url_base'] ?? '';

                $workstations = array_values(array_filter($critDetails, static fn(array $d): bool => empty($d['is_virtual'])));
                $servers      = array_values(array_filter($critDetails, static fn(array $d): bool => !empty($d['is_virtual'])));

                $subject = sprintf('[Tanium] %d new critical CVE(s) detected', self::$newCriticalCves);
                $body    = Notification::buildCriticalEmailBody(self::$newCriticalCves, $workstations, $servers, $glpiUrl);

                $attachments = [];
                if ($workstations !== []) {
                    $wsPdf = PdfReport::critical($workstations, count($workstations), $glpiUrl, 'Estações de Trabalho (Notebooks/Desktops)');
                    if ($wsPdf !== null) {
                        $attachments[] = [
                            'filename' => 'tanium-cves-criticos-estacoes-' . date('Y-m-d') . '.pdf',
                            'content'  => $wsPdf,
                            'mime'     => 'application/pdf',
                        ];
                    }
                }
                if ($servers !== []) {
                    $srvPdf = PdfReport::critical($servers, count($servers), $glpiUrl, 'Servidores (VM)');
                    if ($srvPdf !== null) {
                        $attachments[] = [
                            'filename' => 'tanium-cves-criticos-servidores-' . date('Y-m-d') . '.pdf',
                            'content'  => $srvPdf,
                            'mime'     => 'application/pdf',
                        ];
                    }
                }

                foreach ($recipients as $to) {
                    Notification::sendEmail($to, $subject, $body, $attachments);
                }
            }
        }

        // Consolidated GLPI ticket for the new critical CVEs (opt-in setting)
        if (!empty($config['auto_ticket_critical']) && self::$newCriticalCves > 0) {
            self::openCriticalCveTicket($critDetails, $config);
        }

        // Auto-solve previously opened critical-CVE tickets whose findings
        // have all been remediated since.
        self::resolveClearedCriticalCveTickets();

        // Remediation digest — one email per sync run that recorded fixes
        // (never one per finding), with the PDF report attached.
        $remediationEvents = count(self::$remediatedCves) + count(self::$installedPatches);
        if (!empty($config['notify_remediation']) && $remediationEvents > 0) {
            $recipients = Config::resolveNotifyRecipients($config);
            if ($recipients !== []) {
                global $CFG_GLPI;
                $glpiUrl = $CFG_GLPI['url_base'] ?? '';

                $subject = sprintf(
                    '[Tanium] %d correção(ões) registrada(s) — %d CVE(s) remediado(s), %d patch(es) instalado(s)',
                    $remediationEvents,
                    count(self::$remediatedCves),
                    count(self::$installedPatches)
                );
                $body = Notification::buildRemediationEmailBody(self::$remediatedCves, self::$installedPatches, $glpiUrl);

                $attachments = [];
                $pdf = PdfReport::remediation(self::$remediatedCves, self::$installedPatches, $glpiUrl);
                if ($pdf !== null) {
                    $attachments[] = [
                        'filename' => 'tanium-remediacao-' . date('Y-m-d-Hi') . '.pdf',
                        'content'  => $pdf,
                        'mime'     => 'application/pdf',
                    ];
                }

                foreach ($recipients as $to) {
                    Notification::sendEmail($to, $subject, $body, $attachments);
                }
            }
        }

        // Audit ticket per endpoint that finished remediating (opt-in). Runs
        // after the digest so a failure here never costs the email.
        if (!empty($config['remediation_ticket']) && $remediationEvents > 0) {
            try {
                self::openRemediationTickets($config);
            } catch (\Throwable $e) {
                Toolbox::logInFile('tanium', '[Tanium] Remediation ticket error: ' . $e->getMessage() . "\n");
            }
        }

        self::$newCriticalCves = 0;
        self::$newCriticalCveDetails = [];
        self::$remediatedCves = [];
        self::$installedPatches = [];
        return self::result($total, $created, $updated, $errors);
    }

    /**
     * One "remediation completed" ticket per endpoint whose findings closed in
     * this run — the user-visible counterpart of the auto-close: someone
     * patched a machine and rebooted it, Tanium stopped reporting the items,
     * and the ticket records exactly what was fixed and the history that led
     * there. Opened already SOLVED, because nothing is left to do; it exists as
     * the audit trail the digest email cannot provide.
     *
     * Capped per run: the first sync after enabling the auto-close can close
     * months of backlog at once, and that must not flood the helpdesk.
     *
     * @return int tickets opened
     */
    private static function openRemediationTickets(array $config, int $maxPerRun = 20): int {
        global $DB, $CFG_GLPI;

        /** @var array<string,array{label:string,cves:array,patches:array}> */
        $byEndpoint = [];
        foreach (self::$remediatedCves as $ev) {
            $eid = (string)($ev['eid'] ?? '');
            if ($eid === '') {
                continue;
            }
            $byEndpoint[$eid] ??= ['label' => (string)$ev['endpoint'], 'cves' => [], 'patches' => []];
            $byEndpoint[$eid]['cves'][] = $ev;
        }
        foreach (self::$installedPatches as $ev) {
            $eid = (string)($ev['eid'] ?? '');
            if ($eid === '') {
                continue;
            }
            $byEndpoint[$eid] ??= ['label' => (string)$ev['endpoint'], 'cves' => [], 'patches' => []];
            $byEndpoint[$eid]['patches'][] = $ev;
        }

        if ($byEndpoint === []) {
            return 0;
        }

        // Busiest endpoints first, so the cap keeps the most meaningful ones.
        uasort($byEndpoint, static fn(array $a, array $b): int
            => (count($b['cves']) + count($b['patches'])) <=> (count($a['cves']) + count($a['patches'])));

        $skipped = max(0, count($byEndpoint) - $maxPerRun);
        $glpiUrl = $CFG_GLPI['url_base'] ?? '';
        $opened  = 0;

        foreach (array_slice($byEndpoint, 0, $maxPerRun, true) as $eid => $data) {
            $asset = $DB->request([
                'SELECT' => ['computers_id'],
                'FROM'   => 'glpi_plugin_tanium_assets',
                'WHERE'  => ['tanium_eid' => $eid],
                'LIMIT'  => 1,
            ])->current();
            $computerId = (int)($asset['computers_id'] ?? 0);

            // The ticket belongs where the asset lives, unless an entity is
            // pinned in the plugin settings.
            $entityId = (int)($config['ticket_entity_id'] ?? 0);
            if ($entityId === 0 && $computerId > 0) {
                $row = $DB->request([
                    'SELECT' => ['entities_id'],
                    'FROM'   => 'glpi_computers',
                    'WHERE'  => ['id' => $computerId],
                    'LIMIT'  => 1,
                ])->current();
                $entityId = (int)($row['entities_id'] ?? 0);
            }

            $cveCount   = count($data['cves']);
            $patchCount = count($data['patches']);
            $html       = Notification::buildRemediationTicketHtml(
                $data['label'],
                (string)$eid,
                $data['cves'],
                $data['patches'],
                self::remediationTimeline((string)$eid),
                $glpiUrl
            );

            $ticket   = new Ticket();
            $ticketData = [
                'name'        => sprintf(
                    '[Tanium] Remediação concluída — %s (%d CVE(s), %d patch(es))',
                    $data['label'],
                    $cveCount,
                    $patchCount
                ),
                'content'     => $html,
                'entities_id' => $entityId,
                'type'        => Ticket::INCIDENT_TYPE,
                // Informational record: never competes with real incidents.
                'urgency'     => 2,
                'impact'      => 2,
                'priority'    => 2,
            ];
            $ticketData = Config::applyTicketDefaults($ticketData, 'patch', $config);

            $ticketId = (int)$ticket->add($ticketData);
            if (!$ticketId) {
                continue;
            }
            $opened++;

            if ($computerId > 0) {
                (new Item_Ticket())->add([
                    'tickets_id' => $ticketId,
                    'itemtype'   => 'Computer',
                    'items_id'   => $computerId,
                ]);
            }

            (new ITILSolution())->add([
                'itemtype'         => 'Ticket',
                'items_id'         => $ticketId,
                'content'          => Notification::autoSolutionHtml(
                    '✅ Remediação confirmada pelo Tanium',
                    sprintf(
                        'O Tanium deixou de reportar <strong>%d CVE(s)</strong> e <strong>%d patch(es)</strong> neste endpoint, '
                        . 'confirmando que as atualizações foram aplicadas. Este chamado é apenas o registro da correção.',
                        $cveCount,
                        $patchCount
                    )
                ),
                'solutiontypes_id' => 0,
                'users_id'         => Config::automationUserId($config),
            ]);
        }

        if ($skipped > 0) {
            Toolbox::logInFile('tanium', sprintf(
                "[Tanium] Remediation tickets capped at %d this run — %d endpoint(s) skipped (still recorded in the history tables).\n",
                $maxPerRun,
                $skipped
            ));
        }

        return $opened;
    }

    /**
     * Recorded status transitions for one endpoint, newest first, merged from
     * the CVE and patch history tables. Both are purged by the retention cron,
     * so this is "everything still on record", not necessarily all time.
     *
     * @return array<int,array{kind:string,ref:string,title:?string,old_status:?string,new_status:string,changed_at:string}>
     */
    private static function remediationTimeline(string $eid, int $limit = 40): array {
        global $DB;

        $timeline = [];
        foreach ($DB->request([
            'SELECT' => ['cve_id', 'old_status', 'new_status', 'changed_at'],
            'FROM'   => 'glpi_plugin_tanium_cve_history',
            'WHERE'  => ['tanium_eid' => $eid],
            'ORDER'  => 'changed_at DESC',
            'LIMIT'  => $limit,
        ]) as $r) {
            $timeline[] = [
                'kind'       => 'cve',
                'ref'        => (string)$r['cve_id'],
                'title'      => null,
                'old_status' => $r['old_status'] !== null ? (string)$r['old_status'] : null,
                'new_status' => (string)$r['new_status'],
                'changed_at' => (string)$r['changed_at'],
            ];
        }
        foreach ($DB->request([
            'SELECT' => ['patch_id', 'patch_title', 'old_status', 'new_status', 'changed_at'],
            'FROM'   => 'glpi_plugin_tanium_patch_history',
            'WHERE'  => ['tanium_eid' => $eid],
            'ORDER'  => 'changed_at DESC',
            'LIMIT'  => $limit,
        ]) as $r) {
            $timeline[] = [
                'kind'       => 'patch',
                'ref'        => (string)$r['patch_id'],
                'title'      => (string)$r['patch_title'],
                'old_status' => $r['old_status'] !== null ? (string)$r['old_status'] : null,
                'new_status' => (string)$r['new_status'],
                'changed_at' => (string)$r['changed_at'],
            ];
        }

        usort($timeline, static fn(array $a, array $b): int => strcmp($b['changed_at'], $a['changed_at']));

        return array_slice($timeline, 0, $limit);
    }

    /**
     * Open ONE consolidated ticket listing the critical CVEs found by this
     * sync (never one per finding). Skips while a previous auto-opened ticket
     * is still unresolved, so reruns don't flood the helpdesk.
     */
    private static function openCriticalCveTicket(array $details, array $config): int {
        global $DB;

        $title = '[Tanium] Novos CVEs críticos detectados';

        $open = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_tickets',
            'WHERE'  => [
                'name'       => $title,
                'is_deleted' => 0,
                'NOT'        => ['status' => [Ticket::SOLVED, Ticket::CLOSED]],
            ],
            'LIMIT'  => 1,
        ])->current();
        if ($open) {
            return 0;
        }

        $ticketData = [
            'name'        => $title,
            'content'     => Notification::buildCriticalTicketHtml(self::$newCriticalCves, $details),
            'entities_id' => (int)($config['ticket_entity_id'] ?? 0),
            'type'        => Ticket::INCIDENT_TYPE,
            'priority'    => 5,
            'urgency'     => 5,
            'impact'      => 5,
        ];
        $ticketData = Config::applyTicketDefaults($ticketData, 'cve', $config);

        $ticket   = new Ticket();
        $ticketId = (int)$ticket->add($ticketData);
        if (!$ticketId) {
            return 0;
        }

        // Link the affected computers so the ticket lands on the right assets
        $eids = array_values(array_unique(array_column($details, 'eid')));
        if ($eids !== []) {
            $linked = [];
            foreach ($DB->request([
                'SELECT' => ['computers_id'],
                'FROM'   => 'glpi_plugin_tanium_assets',
                'WHERE'  => ['tanium_eid' => $eids, ['computers_id' => ['>', 0]]],
            ]) as $r) {
                $cid = (int)$r['computers_id'];
                if ($cid > 0 && !isset($linked[$cid])) {
                    $linked[$cid] = true;
                    (new Item_Ticket())->add([
                        'tickets_id' => $ticketId,
                        'itemtype'   => 'Computer',
                        'items_id'   => $cid,
                    ]);
                }
            }
        }

        // Tag the covered findings so a later sync can auto-solve this ticket
        // once every one of them has been remediated.
        foreach ($details as $d) {
            if (!empty($d['eid']) && !empty($d['cve_id'])) {
                $DB->update(
                    'glpi_plugin_tanium_endpoint_cves',
                    ['tickets_id' => $ticketId],
                    ['tanium_eid' => $d['eid'], 'cve_id' => $d['cve_id']]
                );
            }
        }

        return $ticketId;
    }

    /**
     * Counterpart of openCriticalCveTicket(): once every finding tagged to a
     * consolidated critical-CVE ticket is remediated, solve the ticket with an
     * explanatory solution. Tickets solved/closed by hand only get their tag
     * cleared, so the check never repeats.
     */
    private static function resolveClearedCriticalCveTickets(): void {
        global $DB;

        $ticketIds = [];
        foreach ($DB->request([
            'SELECT'   => 'tickets_id',
            'DISTINCT' => true,
            'FROM'     => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE'    => [['tickets_id' => ['>', 0]]],
        ]) as $r) {
            $ticketIds[] = (int)$r['tickets_id'];
        }

        foreach ($ticketIds as $tid) {
            $pending = $DB->request([
                'COUNT' => 'cpt',
                'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
                'WHERE' => ['tickets_id' => $tid, 'NOT' => ['status' => 'remediated']],
            ])->current();
            if ((int)($pending['cpt'] ?? 0) > 0) {
                continue;
            }

            $ticket = new Ticket();
            if ($ticket->getFromDB($tid)
                && !$ticket->fields['is_deleted']
                && !in_array((int)$ticket->fields['status'], [Ticket::SOLVED, Ticket::CLOSED], true)) {
                (new ITILSolution())->add([
                    'itemtype'         => 'Ticket',
                    'items_id'         => $tid,
                    'content'          => Notification::autoSolutionHtml(
                        '✅ Todos os CVEs críticos deste chamado foram remediados',
                        'A sincronização com o Tanium confirmou que todos os findings críticos listados neste chamado foram <strong>remediados</strong>. Este chamado foi <strong>encerrado automaticamente</strong>.'
                    ),
                    'solutiontypes_id' => 0,
                    'users_id'         => Config::automationUserId(),
                ]);
            }

            // Clear the tag either way so the check doesn't repeat forever.
            $DB->update('glpi_plugin_tanium_endpoint_cves', ['tickets_id' => 0], ['tickets_id' => $tid]);
        }
    }

    /**
     * Adds title/affected_count (from glpi_plugin_tanium_vulnerabilities) and
     * ip/os_name (from glpi_plugin_tanium_assets) to each newly-detected
     * critical CVE, for richer email/PDF content.
     *
     * @param array<int,array{cve_id:string,endpoint:string,eid:string,cvss:mixed}> $details
     * @return array<int,array{cve_id:string,endpoint:string,eid:string,cvss:mixed,title:string,affected_count:int,ip:string,os_name:string,is_virtual:bool}>
     */
    private static function enrichCriticalCveDetails(array $details): array {
        if ($details === []) {
            return [];
        }

        global $DB;

        $cveIds = array_values(array_unique(array_column($details, 'cve_id')));
        $eids   = array_values(array_unique(array_column($details, 'eid')));

        $vulnByCve = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_vulnerabilities', 'WHERE' => ['cve_id' => $cveIds]]) as $row) {
            $vulnByCve[$row['cve_id']] = $row;
        }

        $assetByEid = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'WHERE' => ['tanium_eid' => $eids]]) as $row) {
            $assetByEid[$row['tanium_eid']] = $row;
        }

        foreach ($details as &$detail) {
            $vuln  = $vulnByCve[$detail['cve_id']] ?? null;
            $asset = $assetByEid[$detail['eid']] ?? null;

            $detail['title']          = trim((string)($vuln['title'] ?? ''));
            $detail['affected_count'] = (int)($vuln['affected_count'] ?? 0);
            $detail['ip']             = trim((string)($asset['ip_address'] ?? ''));
            $detail['os_name']        = trim((string)($asset['os_name'] ?? ''));
            // Tanium's own VM flag: drives the workstation-vs-server/VM report split below.
            $detail['is_virtual']     = (bool) ($asset['is_virtual'] ?? false);
        }
        unset($detail);

        return $details;
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

        // Correlate against an existing computer (e.g. one already inventoried by
        // the GLPI agent) so Tanium enriches a single record instead of creating
        // a duplicate. Matching order: serial → system UUID → hostname.
        if ($isNew) {
            $found = self::findExistingComputer($endpoint, $computerName);
            if ($found !== null) {
                $computerId = $found;
                $isNew      = false;
            }
        }

        $fields = self::buildComputerFields($endpoint, $config);

        // Entity: mapped Tanium group wins, otherwise the configured default.
        // Only applied on creation — never re-home an existing computer.
        if ($isNew) {
            $groupEntity = ComputerGroup::entityForGroups($endpoint['computerGroups'] ?? []);
            if ($groupEntity !== null) {
                $fields['entities_id'] = $groupEntity;
            }
        }

        if ($isNew) {
            $computerId = $computer->add($fields);
            if (!$computerId) {
                throw new \RuntimeException("Failed to create GLPI computer for EID {$eid}");
            }
            \Log::history($computerId, 'Computer', [0, '', sprintf(
                __('Created by Tanium sync (EID %s)', 'tanium'),
                $eid
            )], 0, \Log::HISTORY_LOG_SIMPLE_MESSAGE);
        } else {
            // Merge, don't clobber: only fill fields that are empty on the existing
            // record, so authoritative agent data is never overwritten by Tanium.
            $fill = self::onlyEmptyFields($computerId, $fields);
            if ($fill) {
                $computer->update($fill + ['id' => $computerId]);
            }
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

        // Data-present flags let the reconciliation run even on an EMPTY list —
        // a fully-remediated machine legitimately reports zero findings, and
        // that's exactly when its open findings must be closed.
        if (!empty($config['sync_vulnerabilities'])
            && (!empty($cves) || !empty($endpoint['cveDataPresent']))) {
            self::syncEndpointCVEs($eid, $computerId, $cves, $computerName, !empty($endpoint['cveDataPresent']), $config);
        }

        if (!empty($config['sync_patches'])
            && (!empty($patches) || !empty($endpoint['patchDataPresent']))) {
            self::syncEndpointPatches($eid, $computerId, $patches, !empty($endpoint['patchDataPresent']), $computerName, $config);
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

        // Hygiene / attack-surface / stability extras — only overwrite when
        // the tenant returned them (null means "not provided", not "cleared").
        foreach ([
            'is_encrypted'     => $endpoint['isEncrypted']     ?? null,
            'chassis_type'     => $endpoint['chassisType']     ?? null,
            'defender_healthy' => $endpoint['defenderHealthy'] ?? null,
            'defender_av_on'   => $endpoint['defenderAvOn']    ?? null,
            'defender_sig_age' => $endpoint['defenderSigAge']  ?? null,
            'sccm_health'      => $endpoint['sccmHealth']      ?? null,
            'nat_ip'           => $endpoint['natIp']           ?? null,
            'discover_method'  => $endpoint['discoverMethod']  ?? null,
            'event_crashes'    => $endpoint['eventCrashes']    ?? null,
            'event_total'      => $endpoint['eventTotal']      ?? null,
        ] as $col => $value) {
            if ($value !== null) {
                $assetData[$col] = $value;
            }
        }
        if (is_array($endpoint['openPorts'] ?? null)) {
            $assetData['open_ports'] = json_encode(array_values(array_map('intval', $endpoint['openPorts'])));
        }
        if (!empty($endpoint['customSensors'])) {
            $assetData['sensor_data'] = json_encode($endpoint['customSensors'], JSON_UNESCAPED_UNICODE);
        }

        if ($mappingRow) {
            $DB->update('glpi_plugin_tanium_assets', $assetData, ['tanium_eid' => $eid]);
        } else {
            $DB->insert('glpi_plugin_tanium_assets', array_merge($assetData, ['tanium_eid' => $eid]));
        }

        return $isNew ? 'created' : 'updated';
    }

    // ── Correlation with existing inventory ───────────────────────────────

    /**
     * Find an already-existing GLPI computer that corresponds to this Tanium
     * endpoint, so we enrich it instead of creating a duplicate. Tries the most
     * reliable keys first: hardware serial, then system UUID, then hostname
     * (FQDN or short form, case-insensitive). Returns null when nothing matches.
     */
    private static function findExistingComputer(array $endpoint, string $computerName): ?int {
        global $DB;

        $serial = trim((string) ($endpoint['serialNumber'] ?? ''));
        if ($serial !== '') {
            $row = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_computers',
                'WHERE'  => ['serial' => $serial, 'is_deleted' => 0],
                'LIMIT'  => 1,
            ])->current();
            if ($row) {
                return (int) $row['id'];
            }
        }

        $uuid = trim((string) ($endpoint['systemUUID'] ?? ''));
        if ($uuid !== '') {
            $row = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_computers',
                'WHERE'  => ['uuid' => $uuid, 'is_deleted' => 0],
                'LIMIT'  => 1,
            ])->current();
            if ($row) {
                return (int) $row['id'];
            }
        }

        // Hostname: Tanium sends the FQDN (host.domain.tld); the agent may store
        // either the FQDN or just the short hostname. Try both, using GLPI's
        // parameterized query builder. glpi_computers.name uses a case-insensitive
        // collation, so a plain '=' already matches regardless of case.
        $fqdn  = trim($computerName);
        $short = (string) strtok($fqdn, '.');
        foreach (array_unique(array_filter([$fqdn, $short])) as $candidate) {
            $row = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_computers',
                'WHERE'  => ['name' => $candidate, 'is_deleted' => 0],
                'LIMIT'  => 1,
            ])->current();
            if ($row) {
                return (int) $row['id'];
            }
        }

        return null;
    }

    /**
     * Reduce a set of desired field values to only those that are currently empty
     * on the existing computer, so a correlated agent record is never overwritten.
     * Identity/structural fields are never touched.
     */
    private static function onlyEmptyFields(int $computerId, array $fields): array {
        global $DB;

        $protected = ['name', 'entities_id', 'is_dynamic'];

        $current = $DB->request([
            'FROM'  => 'glpi_computers',
            'WHERE' => ['id' => $computerId],
            'LIMIT' => 1,
        ])->current() ?? [];

        $fill = [];
        foreach ($fields as $key => $value) {
            if (in_array($key, $protected, true)) {
                continue;
            }
            if ($value === null || $value === '' || $value === 0 || $value === '0') {
                continue; // nothing meaningful to write
            }
            $cur = $current[$key] ?? null;
            $isEmpty = ($cur === null || $cur === '' || $cur === 0 || $cur === '0');
            if ($isEmpty) {
                $fill[$key] = $value;
            }
        }
        return $fill;
    }

    // ── Field builders ────────────────────────────────────────────────────

    private static function buildComputerFields(array $e, array $config): array {
        $fields = [
            'name'        => $e['computerName'] ?? $e['name'] ?? 'Unknown',
            'entities_id' => (int)($config['default_entity_id'] ?? 0),
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

    /**
     * Reconcile one endpoint's installed software in a bounded number of
     * queries, instead of a handful per application.
     *
     * The old loop called linkSoftware() per app, and that did four queries
     * each: find Software, find SoftwareVersion, find the link, insert. A
     * machine with 200 applications cost ~800 round-trips, and a 420-endpoint
     * fleet ran into the hundreds of thousands — which is what made a full
     * sync take a quarter of an hour and what killed the run that wedged the
     * scheduler in July 2026. Everything an endpoint needs is now read in
     * three queries up front; only genuinely new rows are written.
     *
     * It also removes what is no longer installed. The previous version only
     * ever added, so uninstalled software stayed attached to the asset
     * forever and the inventory drifted further from reality with every sync.
     * Only links this plugin created (is_dynamic) are removed — an entry a
     * human or another inventory source added is never touched.
     */
    private static function syncSoftware(int $computerId, array $softwareList): void {
        global $DB;

        // Normalise and de-duplicate first: the sensor happily reports the
        // same product twice, and both copies would race for the same row.
        $wanted = [];
        foreach ($softwareList as $app) {
            $name    = trim((string)($app['name'] ?? $app['applicationName'] ?? ''));
            $version = trim((string)($app['version'] ?? ''));
            if ($name === '') {
                continue;
            }
            $wanted[$name . "\0" . $version] = ['name' => $name, 'version' => $version];
        }
        if ($wanted === []) {
            return;
        }

        $names = array_values(array_unique(array_column($wanted, 'name')));

        // 1. Software rows that already exist.
        $softIds = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'name'],
            'FROM'   => 'glpi_softwares',
            'WHERE'  => ['name' => $names],
        ]) as $row) {
            $softIds[(string)$row['name']] = (int)$row['id'];
        }
        foreach ($names as $name) {
            if (!isset($softIds[$name])) {
                $softIds[$name] = self::getOrCreate('Software', $name, ['entities_id' => 0, 'is_recursive' => 1]);
            }
        }

        // 2. Versions of exactly those Software rows.
        $versionIds = [];
        $ids        = array_values(array_filter($softIds));
        if ($ids !== []) {
            foreach ($DB->request([
                'SELECT' => ['id', 'softwares_id', 'name'],
                'FROM'   => 'glpi_softwareversions',
                'WHERE'  => ['softwares_id' => $ids],
            ]) as $row) {
                $versionIds[(int)$row['softwares_id'] . "\0" . (string)$row['name']] = (int)$row['id'];
            }
        }

        // 3. Links this computer already has.
        $linked = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'softwareversions_id', 'is_dynamic'],
            'FROM'   => 'glpi_items_softwareversions',
            'WHERE'  => ['items_id' => $computerId, 'itemtype' => 'Computer'],
        ]) as $row) {
            $linked[(int)$row['softwareversions_id']] = [
                'id'         => (int)$row['id'],
                'is_dynamic' => (int)$row['is_dynamic'],
            ];
        }

        $keep = [];
        foreach ($wanted as $app) {
            $softId = $softIds[$app['name']] ?? 0;
            if ($softId <= 0) {
                continue;
            }
            $versionName = $app['version'] !== '' ? $app['version'] : '—';
            $vkey        = $softId . "\0" . $versionName;

            $versionId = $versionIds[$vkey] ?? 0;
            if ($versionId <= 0) {
                $sv        = new SoftwareVersion();
                $versionId = (int)$sv->add([
                    'softwares_id' => $softId,
                    'name'         => $versionName,
                    'entities_id'  => 0,
                    'is_recursive' => 1,
                    'is_dynamic'   => 1,
                ]);
                if ($versionId <= 0) {
                    continue;
                }
                $versionIds[$vkey] = $versionId;
            }

            $keep[$versionId] = true;
            if (!isset($linked[$versionId])) {
                (new Item_SoftwareVersion())->add([
                    'items_id'            => $computerId,
                    'itemtype'            => 'Computer',
                    'softwareversions_id' => $versionId,
                    'is_dynamic'          => 1,
                ]);
            }
        }

        // Uninstalled: present on the asset, absent from this report, and ours
        // to remove. A link someone added by hand has is_dynamic = 0 and stays.
        foreach ($linked as $versionId => $link) {
            if (!isset($keep[$versionId]) && $link['is_dynamic'] === 1) {
                (new Item_SoftwareVersion())->delete(['id' => $link['id']], true);
            }
        }
    }

    // ── CVE sync ─────────────────────────────────────────────────────────

    private static function syncCVESummary(array $cves): void {
        global $DB;

        $summary = [];
        foreach ($cves as $finding) {
            $cveId = $finding['cveId'] ?? $finding['cve'] ?? $finding['id'] ?? '';
            // Sensors can emit artifacts like "[no results]" — only real CVE ids enter.
            if (!preg_match('/^CVE-\d{4}-\d+$/i', (string)$cveId)) {
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

    private static function syncEndpointCVEs(
        string $eid,
        int $computerId,
        array $cves,
        string $computerName = '',
        bool $dataPresent = false,
        array $config = []
    ): void {
        global $DB;

        $newFindings    = 0;
        $statusChanges  = 0;

        // One round-trip for this endpoint's entire current state. The previous
        // implementation ran a SELECT per finding: a 500-machine fleet with 40
        // findings each meant ~40k queries per sync, which is what makes a long
        // cron run die with "MySQL server has gone away".
        $existingRows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE' => ['tanium_eid' => $eid],
        ]) as $row) {
            $existingRows[strtoupper((string)$row['cve_id'])] = $row;
        }

        $now  = date('Y-m-d H:i:s');
        $seen = [];
        foreach ($cves as $finding) {
            $cveId = $finding['cveId'] ?? $finding['cve'] ?? $finding['id'] ?? '';
            // Sensors can emit artifacts like "[no results]" — only real CVE ids enter.
            if (!preg_match('/^CVE-\d{4}-\d+$/i', (string)$cveId)) {
                continue;
            }

            $key        = strtoupper((string)$cveId);
            $seen[$key] = true;
            $existing   = $existingRows[$key] ?? null;

            $record = [
                'computers_id' => $computerId,
                'cvss_score'   => $finding['cvssScore'] ?? $finding['cvss'] ?? null,
                'severity'     => strtolower($finding['severity'] ?? 'unknown'),
                'status'       => $finding['state'] ?? $finding['status'] ?? 'open',
                'detected_at'  => isset($finding['detectedAt']) ? date('Y-m-d H:i:s', strtotime($finding['detectedAt'])) : $now,
            ];

            if ($existing) {
                // Detect status change → write to CVE history
                if ($existing['status'] !== $record['status']) {
                    $statusChanges++;
                    $DB->insert('glpi_plugin_tanium_cve_history', [
                        'tanium_eid'   => $eid,
                        'cve_id'       => $cveId,
                        'computers_id' => $computerId,
                        'old_status'   => $existing['status'],
                        'new_status'   => $record['status'],
                        'changed_at'   => $now,
                    ]);
                    // Explicit remediation reported by Tanium itself
                    if ($record['status'] === 'remediated') {
                        self::$remediatedCves[] = self::remediationEvent($existing, $computerName, $eid);
                    }
                }
                // Steady state is "nothing moved": skip the UPDATE unless a
                // field the plugin actually reads changed. date_mod alone is
                // not worth a write — nothing queries it.
                if (self::recordChanged($existing, $record)) {
                    $DB->update(
                        'glpi_plugin_tanium_endpoint_cves',
                        $record + ['date_mod' => $now],
                        ['id' => (int)$existing['id']]
                    );
                }
                // Keep the in-memory state authoritative for the auto-close below.
                $existingRows[$key] = array_merge($existing, $record);
            } else {
                $newFindings++;
                // New CVE finding
                if (($record['severity'] ?? '') === 'critical') {
                    self::$newCriticalCves++;
                    self::$newCriticalCveDetails[] = [
                        'cve_id'   => $cveId,
                        'endpoint' => $computerName !== '' ? $computerName : $eid,
                        'eid'      => $eid,
                        'cvss'     => $record['cvss_score'],
                    ];
                }
                $DB->insert('glpi_plugin_tanium_cve_history', [
                    'tanium_eid'   => $eid,
                    'cve_id'       => $cveId,
                    'computers_id' => $computerId,
                    'old_status'   => null,
                    'new_status'   => $record['status'],
                    'changed_at'   => $now,
                ]);
                $DB->insert('glpi_plugin_tanium_endpoint_cves', $record + [
                    'tanium_eid' => $eid,
                    'cve_id'     => $cveId,
                    'date_mod'   => $now,
                ]);
                // Same guard as the patch sync: a cveId repeated inside one
                // payload must update the row just inserted, never insert twice
                // against the eid_cve unique key.
                $existingRows[$key] = $record + [
                    'id'         => (int)$DB->insertId(),
                    'tanium_eid' => $eid,
                    'cve_id'     => $cveId,
                ];
            }
        }

        // Auto-close: findings that vanished from the feed were fixed. Only
        // runs when the CVE module actually answered for this endpoint (never
        // on a sensor hiccup) and the toggle is on.
        $autoClosed = 0;
        if ($dataPresent && !empty($config['auto_close_cves'])) {
            $autoClosed = self::autoCloseVanishedCves($eid, $computerId, $existingRows, $seen, $computerName, $config);
        }

        // One line in the Computer's native history tab per sync that changed
        // something — auditors see Tanium touched the asset without opening the
        // plugin. Silent runs (no delta) write nothing to avoid log spam.
        if ($computerId > 0 && ($newFindings > 0 || $statusChanges > 0 || $autoClosed > 0)) {
            \Log::history($computerId, 'Computer', [0, '', sprintf(
                __('Tanium sync: %1$d new CVE finding(s), %2$d status change(s), %3$d remediated', 'tanium'),
                $newFindings,
                $statusChanges,
                $autoClosed
            )], 0, \Log::HISTORY_LOG_SIMPLE_MESSAGE);
        }
    }

    /**
     * Flag assets Tanium stopped returning, and un-flag any that came back.
     *
     * Nothing is deleted here: a decommissioned machine keeps inflating the
     * fleet risk average, the coverage KPI and the MTTR until someone acts, but
     * silently dropping rows would be worse. `retired_at` is the marker; the
     * `purgeretired` cron does the removal, and only if the admin sets a
     * retention window.
     *
     * MUST only be called after a full, error-free sync — see the caller.
     *
     * @param array<string,bool> $seenEids EIDs returned by this run
     */
    private static function reconcileRetiredAssets(array $seenEids): void {
        global $DB;

        $now      = date('Y-m-d H:i:s');
        $retired  = 0;
        $returned = 0;

        foreach ($DB->request([
            'SELECT' => ['id', 'tanium_eid', 'tanium_name', 'retired_at'],
            'FROM'   => 'glpi_plugin_tanium_assets',
        ]) as $row) {
            $seen       = isset($seenEids[(string)$row['tanium_eid']]);
            $isRetired  = !empty($row['retired_at']);

            if (!$seen && !$isRetired) {
                $DB->update('glpi_plugin_tanium_assets', ['retired_at' => $now], ['id' => (int)$row['id']]);
                $retired++;
            } elseif ($seen && $isRetired) {
                // Came back (re-imaged, agent reinstalled, scope restored).
                $DB->update('glpi_plugin_tanium_assets', ['retired_at' => null], ['id' => (int)$row['id']]);
                $returned++;
            }
        }

        if ($retired > 0 || $returned > 0) {
            Toolbox::logInFile('tanium', sprintf(
                "[Tanium] Retirement reconcile: %d endpoint(s) no longer reported by Tanium, %d back online.\n",
                $retired,
                $returned
            ));
        }
    }

    /** Hours between fleet-wide id sweeps when the sync runs incrementally. */
    private const RETIRE_SWEEP_HOURS = 24;

    /** True when no sweep has run recently enough to still be trusted. */
    private static function retireSweepDue(array $config): bool {
        $last = $config['last_retire_sweep'] ?? null;
        if (empty($last)) {
            return true;
        }
        $ts = strtotime((string)$last);
        return $ts === false || $ts < strtotime('-' . self::RETIRE_SWEEP_HOURS . ' hours');
    }

    private static function stampRetireSweep(): void {
        global $DB;

        $row = $DB->request(['SELECT' => ['id'], 'FROM' => 'glpi_plugin_tanium_configs', 'LIMIT' => 1])->current();
        if ($row !== null) {
            $DB->update(
                'glpi_plugin_tanium_configs',
                ['last_retire_sweep' => date('Y-m-d H:i:s')],
                ['id' => (int)$row['id']]
            );
        }
    }

    /**
     * Ask Tanium for the fleet's ids alone, then reconcile retirement.
     *
     * Deliberately a separate, cheap request rather than widening the sync:
     * forcing a full enrichment pass just to learn who left would undo the
     * whole point of syncing incrementally.
     *
     * An empty answer is treated as a failure, never as "the fleet is gone" —
     * that is the one mistake here that would retire every asset at once.
     */
    private static function sweepRetiredAssets(Api $api): void {
        try {
            $ids = $api->allEndpointIds();
        } catch (\Throwable $e) {
            Toolbox::logInFile('tanium', '[Tanium] Retirement sweep failed (' . $e->getMessage() . ") — nothing retired.\n");
            return;
        }

        if ($ids === []) {
            Toolbox::logInFile('tanium', "[Tanium] Retirement sweep returned no endpoints — refusing to retire the whole fleet.\n");
            return;
        }

        self::reconcileRetiredAssets($ids);
        self::stampRetireSweep();
    }

    // ── Gateway capability cache ──────────────────────────────────────────

    /** Days before the plugin re-asks the Gateway for the optional blocks. */
    private const CAPS_REPROBE_DAYS = 7;

    /**
     * True when the cached capabilities are absent or old enough to re-test.
     *
     * Without the re-probe a tenant that later deploys the event sensors (or
     * grants the missing module permission) would stay degraded forever; with
     * it, the cost of discovering that is one rejected query per week instead
     * of one per sync run.
     */
    private static function capsProbeDue(array $config): bool {
        $probedAt = $config['caps_probed_at'] ?? null;
        if (empty($probedAt)) {
            return true;
        }
        $ts = strtotime((string)$probedAt);
        return $ts === false || $ts < strtotime('-' . self::CAPS_REPROBE_DAYS . ' days');
    }

    /**
     * Store what the Gateway actually accepted on this sweep.
     *
     * `caps_probed_at` is stamped only after a FULL probe — stamping it on
     * every run would keep pushing the re-probe deadline forward and the
     * plugin would never ask again.
     *
     * @param array{extrasLevel:int,groups:bool} $caps
     */
    private static function persistCapabilities(array $caps, bool $fullProbe): void {
        global $DB;

        $row = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => 'glpi_plugin_tanium_configs',
            'LIMIT'  => 1,
        ])->current();
        if ($row === null) {
            return;
        }

        $update = [
            'caps_extras_level' => (int)$caps['extrasLevel'],
            'caps_groups'       => !empty($caps['groups']) ? 1 : 0,
        ];
        if ($fullProbe) {
            $update['caps_probed_at'] = date('Y-m-d H:i:s');
        }
        $DB->update('glpi_plugin_tanium_configs', $update, ['id' => (int)$row['id']]);

        self::notifyCapabilityChange($update + ['id' => (int)$row['id']]);
    }

    /**
     * Tell someone when the Gateway starts (or stops) refusing a data block.
     *
     * Degrading silently is the dangerous part: the sync keeps succeeding, the
     * screens keep rendering, and whole columns are simply absent — hygiene
     * data missing makes the health grade quietly incomplete, and nobody knows
     * to go looking. The log line the degradation already wrote is not enough,
     * because nobody reads logs until something is visibly broken.
     *
     * Fires on the TRANSITION only. Re-notifying every hour would train
     * everyone to ignore it, and a recovery is worth knowing about too.
     *
     * @param array{id:int,caps_extras_level:int,caps_groups:int} $current
     */
    private static function notifyCapabilityChange(array $current): void {
        global $DB;

        $config    = Config::getConfig();
        $signature = Diagnostics::capabilitySignature([
            'caps_extras_level' => $current['caps_extras_level'],
            'caps_groups'       => $current['caps_groups'],
        ]);

        $previous = (string)($config['caps_notified'] ?? '');
        if ($signature === $previous) {
            return;
        }

        $DB->update('glpi_plugin_tanium_configs', ['caps_notified' => $signature], ['id' => $current['id']]);

        // First observation: record the baseline without crying wolf about a
        // tenant that simply never exposed those blocks.
        if ($previous === '') {
            return;
        }

        $degraded = Diagnostics::capabilityChecks([
            'caps_extras_level' => $current['caps_extras_level'],
            'caps_groups'       => $current['caps_groups'],
        ]);
        $problems = array_values(array_filter(
            $degraded,
            static fn(array $c): bool => ($c['status'] ?? '') !== Diagnostics::OK
        ));

        if ($problems === []) {
            $subject = __('[Tanium] The Gateway is answering every data block again', 'tanium');
            $body    = '<p>' . __('A block the Tanium Gateway had been refusing is available again. The data it feeds is being collected once more.', 'tanium') . '</p>';
        } else {
            $lines = '';
            foreach ($problems as $p) {
                $lines .= '<li><strong>' . htmlspecialchars($p['label']) . '</strong> — ' . htmlspecialchars($p['detail']) . '</li>';
            }
            $subject = __('[Tanium] The Gateway stopped answering part of the sync', 'tanium');
            $body    = '<p>' . __('The sync still completes, but the Tanium Gateway refused the blocks below, so that data is now missing from GLPI:', 'tanium')
                     . '</p><ul>' . $lines . '</ul>'
                     . '<p>' . __('This is usually a missing module permission on the API token, or sensors not deployed in the tenant.', 'tanium') . '</p>';
        }

        foreach (Config::resolveNotifyRecipients($config) as $to) {
            Notification::sendEmail($to, $subject, $body);
        }
        if (!empty($config['webhook_enabled']) && !empty($config['webhook_url'])) {
            Notification::sendWebhook($config['webhook_url'], [
                'username'   => 'Tanium + GLPI',
                'icon_emoji' => ':warning:',
                'title'      => $subject,
                'text'       => strip_tags(str_replace(['</li>', '</p>'], ["\n", "\n"], $body)),
            ]);
        }
    }

    /**
     * True when writing $record over $existing would actually change something.
     *
     * The DB hands every column back as a string while the payload carries
     * ints, floats and nulls, so a raw !== comparison always reports a change
     * and defeats the purpose — both sides are normalised to strings first,
     * with null and '' treated as the same "empty".
     *
     * @param array<string,mixed> $existing row as read from the database
     * @param array<string,mixed> $record   fields about to be written
     */
    private static function recordChanged(array $existing, array $record): bool {
        foreach ($record as $field => $value) {
            $old = $existing[$field] ?? null;
            if ($old === null && ($value === null || $value === '')) {
                continue;
            }
            // Numeric columns (cvss_score is decimal(4,1)) must compare by value:
            // "9.8" and 9.8 are equal, "9.80" and "9.8" too.
            if (is_numeric($old) && is_numeric($value)) {
                if ((float)$old !== (float)$value) {
                    return true;
                }
                continue;
            }
            if ((string)$old !== (string)$value) {
                return true;
            }
        }
        return false;
    }

    /** Normalized remediation-event entry from an endpoint_cves row. */
    private static function remediationEvent(array $row, string $computerName, string $eid): array {
        $detectedAt = !empty($row['detected_at']) ? (string)$row['detected_at'] : null;
        return [
            'cve_id'      => (string)$row['cve_id'],
            'endpoint'    => $computerName !== '' ? $computerName : $eid,
            'eid'         => $eid,
            'severity'    => strtolower((string)($row['severity'] ?? 'unknown')),
            'cvss'        => $row['cvss_score'] ?? null,
            'detected_at' => $detectedAt,
            'days_open'   => $detectedAt !== null ? max(0, (int)floor((time() - strtotime($detectedAt)) / 86400)) : null,
        ];
    }

    /**
     * Marks as "remediated" every open finding of this endpoint that is absent
     * from the current sync payload, writing the transition to cve_history so
     * MTTR and the remediation reports see it. Findings below the configured
     * severity floor never enter the payload, so their absence proves nothing —
     * they are left untouched.
     *
     * @return int findings closed
     */
    private static function autoCloseVanishedCves(
        string $eid,
        int $computerId,
        array $existingRows,
        array $present,
        string $computerName,
        array $config
    ): int {
        global $DB;

        $rank   = ['unknown' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $minSev = strtolower((string)($config['cve_min_severity'] ?? 'all'));
        $min    = $rank[$minSev] ?? 0; // 'all' (or unknown) keeps every severity eligible

        $closed = 0;
        $now    = date('Y-m-d H:i:s');
        // Reuses the state already loaded by the caller — no second scan of the
        // endpoint's findings.
        foreach ($existingRows as $key => $row) {
            if (isset($present[$key]) || ($row['status'] ?? '') === 'remediated') {
                continue;
            }
            if ($min > 0 && ($rank[strtolower((string)($row['severity'] ?? 'unknown'))] ?? 0) < $min) {
                continue;
            }

            $DB->update('glpi_plugin_tanium_endpoint_cves', [
                'status'   => 'remediated',
                'date_mod' => $now,
            ], ['id' => $row['id']]);
            $DB->insert('glpi_plugin_tanium_cve_history', [
                'tanium_eid'   => $eid,
                'cve_id'       => $row['cve_id'],
                'computers_id' => $computerId,
                'old_status'   => $row['status'],
                'new_status'   => 'remediated',
                'changed_at'   => $now,
            ]);
            // Tanium no longer reports the finding — that is the only evidence
            // the plugin ever gets that a CVE is actually fixed, so this is the
            // one place allowed to close its assignment.
            $DB->update('glpi_plugin_tanium_cve_assignments', [
                'status'   => 'resolved',
                'date_mod' => $now,
            ], [
                'tanium_eid' => $eid,
                'cve_id'     => $row['cve_id'],
                'ref_type'   => 'cve',
                'NOT'        => ['status' => 'resolved'],
            ]);
            self::$remediatedCves[] = self::remediationEvent($row, $computerName, $eid);
            $closed++;
        }

        return $closed;
    }

    // ── Patch sync ────────────────────────────────────────────────────────

    private static function syncEndpointPatches(
        string $eid,
        int $computerId,
        array $patches,
        bool $dataPresent = false,
        string $computerName = '',
        array $config = []
    ): void {
        global $DB;

        // Same single-round-trip treatment as the CVE sync: load the endpoint's
        // patch state once and diff in memory instead of a SELECT per patch.
        $existingRows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_patches',
            'WHERE' => ['tanium_eid' => $eid],
        ]) as $row) {
            $existingRows[(string)$row['patch_id']] = $row;
        }

        $now = date('Y-m-d H:i:s');
        $seenIds = [];
        foreach ($patches as $patch) {
            $patchId = $patch['patchId'] ?? $patch['id'] ?? $patch['kb'] ?? '';
            if (!$patchId) {
                continue;
            }
            $seenIds[(string)$patchId] = true;

            $existing = $existingRows[(string)$patchId] ?? null;

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
            ];

            if ($existing) {
                // Status transition (e.g. a deployed patch resurfacing as
                // missing) → patch_history, mirroring the CVE history.
                if ($existing['status'] !== $record['status']) {
                    $DB->insert('glpi_plugin_tanium_patch_history', [
                        'tanium_eid'   => $eid,
                        'patch_id'     => $patchId,
                        'patch_title'  => $record['patch_title'],
                        'severity'     => $record['severity'],
                        'computers_id' => $computerId,
                        'old_status'   => $existing['status'],
                        'new_status'   => $record['status'],
                        'changed_at'   => $now,
                    ]);
                }
                if (self::recordChanged($existing, $record)) {
                    $DB->update(
                        'glpi_plugin_tanium_patches',
                        $record + ['date_mod' => $now],
                        ['id' => (int)$existing['id']]
                    );
                }
                $existingRows[(string)$patchId] = array_merge($existing, $record);
            } else {
                $DB->insert('glpi_plugin_tanium_patches', $record + [
                    'tanium_eid' => $eid,
                    'patch_id'   => $patchId,
                    'date_mod'   => $now,
                ]);
                // Register the row just created: one advisory can cover several
                // packages (ALSA/RHSA/USN), and the sensor then answers with one
                // row per package all carrying the same patch_id. Without this,
                // the repeat would take the INSERT branch again and hit the
                // eid_patch unique key, aborting the whole endpoint's sync.
                $existingRows[(string)$patchId] = $record + [
                    'id'         => (int)$DB->insertId(),
                    'tanium_eid' => $eid,
                    'patch_id'   => $patchId,
                ];
                $DB->insert('glpi_plugin_tanium_patch_history', [
                    'tanium_eid'   => $eid,
                    'patch_id'     => $patchId,
                    'patch_title'  => $record['patch_title'],
                    'severity'     => $record['severity'],
                    'computers_id' => $computerId,
                    'old_status'   => null,
                    'new_status'   => $record['status'],
                    'changed_at'   => $now,
                ]);
            }
        }

        // Reconciliation: the Applicable Patches sensor lists what is still
        // MISSING, so a previously-missing patch absent from the list (with the
        // sensor having answered) was installed. Same toggle as the CVE
        // auto-close; deploy-remediated rows are already out of "missing".
        if (!$dataPresent || empty($config['auto_close_cves'])) {
            return;
        }

        // Reuses the state loaded at the top — no second scan.
        foreach ($existingRows as $row) {
            if (($row['status'] ?? '') !== 'missing') {
                continue;
            }
            if (isset($seenIds[(string)$row['patch_id']])) {
                continue;
            }

            $DB->update('glpi_plugin_tanium_patches', [
                'status'   => 'installed',
                'date_mod' => $now,
            ], ['id' => $row['id']]);
            $DB->insert('glpi_plugin_tanium_patch_history', [
                'tanium_eid'   => $eid,
                'patch_id'     => $row['patch_id'],
                'patch_title'  => (string)$row['patch_title'],
                'severity'     => strtolower((string)($row['severity'] ?? 'unknown')),
                'computers_id' => $computerId,
                'old_status'   => 'missing',
                'new_status'   => 'installed',
                'changed_at'   => $now,
            ]);
            self::$installedPatches[] = [
                'patch_id' => (string)$row['patch_id'],
                'title'    => (string)$row['patch_title'],
                'endpoint' => $computerName !== '' ? $computerName : $eid,
                'eid'      => $eid,
                'severity' => strtolower((string)($row['severity'] ?? 'unknown')),
            ];
        }
    }

    // ── Risk score ────────────────────────────────────────────────────────

    /**
     * Recompute an endpoint's 0-100 risk score and record it when it moved.
     *
     * The weighted-sum-then-clamp model this replaced saturated: a real
     * endpoint summed ~4.400 against a ceiling of 100, so remediating every
     * critical and every high CVE left the badge reading "100 Crítico". See
     * Risk for the model that replaced it.
     */
    public static function updateRiskScore(string $eid): void {
        global $DB;

        $cves = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        $kev  = 0;

        $kevSet = Enrichment::kevSet();
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE' => ['tanium_eid' => $eid, 'status' => ['!=', 'remediated']],
        ]) as $cve) {
            $sev = strtolower((string) ($cve['severity'] ?? 'low'));
            if (!isset($cves[$sev])) {
                $sev = 'low';   // unknown severity is not a free pass
            }
            $cves[$sev]++;
            if (isset($kevSet[strtoupper((string) ($cve['cve_id'] ?? ''))])) {
                $kev++;
            }
        }

        $patches = ['critical' => 0, 'important' => 0, 'moderate' => 0, 'low' => 0];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_patches',
            'WHERE' => ['tanium_eid' => $eid, 'status' => 'missing'],
        ]) as $patch) {
            if (self::isSensorNoise((string) ($patch['patch_title'] ?? ''), (string) ($patch['patch_id'] ?? ''))) {
                continue;
            }
            $sev = strtolower((string) ($patch['severity'] ?? 'low'));
            if (!isset($patches[$sev])) {
                $sev = 'low';
            }
            $patches[$sev]++;
        }

        $previous = $DB->request([
            'SELECT' => ['risk_score', 'computers_id', 'os_name', 'os_version'],
            'FROM'   => 'glpi_plugin_tanium_assets',
            'WHERE'  => ['tanium_eid' => $eid],
        ])->current();

        $result = Risk::score(Risk::tierCounts($cves, $kev, $patches));
        // An end-of-support OS cannot be patched out of its risk, so it must
        // not be able to read as low just because the finding list is short.
        $result = Risk::applyLifecycleFloor(
            $result,
            Lifecycle::status($previous['os_name'] ?? null, $previous['os_version'] ?? null)['state']
        );
        $score = $result['score'];
        $previousScore = $previous !== null && $previous['risk_score'] !== null
            ? (int) $previous['risk_score']
            : null;

        $DB->update('glpi_plugin_tanium_assets', ['risk_score' => $score], ['tanium_eid' => $eid]);

        self::recordEndpointRisk(
            $eid,
            (int) ($previous['computers_id'] ?? 0) ?: null,
            $score,
            $previousScore,
            $cves,
            $kev,
            array_sum($patches)
        );
    }

    /**
     * Is this "patch" actually the patch sensor reporting that it failed?
     *
     * Tanium answers a machine it could not scan with a literal row such as
     * "No Scan Results Found" instead of an empty result, and the importer
     * stored it as a missing patch. On the reference fleet 37 endpoints each
     * carried one, inflating their missing-patch count and their risk score
     * with the *absence* of data. An unscanned machine is a visibility gap,
     * not a vulnerability — it must not score as one.
     */
    public static function isSensorNoise(string $title, string $patchId = ''): bool {
        $haystack = strtolower(trim($title . ' ' . $patchId));
        if ($haystack === '') {
            return true;
        }
        foreach (['no scan results', 'no results found', 'tse-error', 'error:', 'not applicable'] as $marker) {
            if (str_contains($haystack, $marker)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Append to the per-endpoint risk history — but only on a transition.
     *
     * An hourly sync over a steady fleet would otherwise write one row per
     * endpoint per run and bury the actual movements. The first observation of
     * an endpoint is always recorded so the history has a starting point.
     *
     * @param array<string,int> $cves keyed critical/high/medium/low
     */
    private static function recordEndpointRisk(
        string $eid,
        ?int $computerId,
        int $score,
        ?int $previousScore,
        array $cves,
        int $kev,
        int $patchesMissing
    ): void {
        global $DB;

        if ($previousScore !== null && $previousScore === $score) {
            return;
        }

        $DB->insert('glpi_plugin_tanium_endpoint_risk_history', [
            'tanium_eid'      => $eid,
            'computers_id'    => $computerId,
            'risk_score'      => $score,
            'previous_score'  => $previousScore,
            'cves_critical'   => (int) ($cves['critical'] ?? 0),
            'cves_high'       => (int) ($cves['high'] ?? 0),
            'cves_medium'     => (int) ($cves['medium'] ?? 0),
            'cves_low'        => (int) ($cves['low'] ?? 0),
            'cves_kev'        => $kev,
            'patches_missing' => $patchesMissing,
            'recorded_at'     => date('Y-m-d H:i:s'),
        ]);
    }

    // ── GLPI helpers ──────────────────────────────────────────────────────

    private static function getOrCreate(string $itemtype, string $name, array $extra = []): int {
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

        // $extra carries entity fields for entity-aware dropdowns (e.g. Software),
        // which otherwise trigger "Missing entity ID!" on add().
        return (int) $item->add(['name' => $name] + $extra);
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
        ")->fetch_assoc();

        if (!$row || (int)$row['total_endpoints'] === 0) {
            return;
        }

        $cveRow = $DB->doQuery("
            SELECT COUNT(*) AS total_cves,
                   COUNT(CASE WHEN severity='critical' THEN 1 END) AS critical_cves
            FROM glpi_plugin_tanium_vulnerabilities
        ")->fetch_assoc();

        $patchRow = $DB->doQuery("
            SELECT COUNT(*) AS patches_missing
            FROM glpi_plugin_tanium_patches WHERE status='missing'
        ")->fetch_assoc();

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

    // ── Recovery from a run killed outside PHP's control ──────────────────

    /**
     * A run killed outside PHP's control — OOM kill, container restart, worker
     * timeout — leaves two things behind, and neither ever clears on its own:
     *
     *   • the GLPI cron task pinned in STATE_RUNNING. `getNeedToRun()` only
     *     ever selects STATE_WAITING, so the scheduler silently stops picking
     *     the sync up — forever.
     *   • this plugin's own log row stuck at 'running', which is what the
     *     sync screen reports as progress, so the UI shows a frozen percentage
     *     as if the job were still working.
     *
     * The shutdown handler in run() covers PHP fatals only; it never fires for
     * a process that was killed. In July 2026 that left taniumsync wedged at
     * 45% for 26 days while every other Tanium task kept running normally.
     */
    private const STALE_RUN_HOURS = 2;

    /**
     * Release a wedged run so the scheduler can schedule the sync again.
     *
     * A live run must never be touched — clearing the state of a sync that is
     * genuinely working would let a second one start on top of it. So nothing
     * is recovered until the run is older than STALE_RUN_HOURS; a full sync of
     * the reference fleet takes around 20 minutes.
     *
     * @return array{task:bool,logs:int} whether the cron task was released,
     *                                   and how many orphan log rows closed
     */
    public static function recoverWedgedRun(): array {
        global $DB;

        $cutoff = date('Y-m-d H:i:s', strtotime('-' . self::STALE_RUN_HOURS . ' hours'));

        $logs = 0;
        foreach ($DB->request([
            'SELECT' => ['id', 'started_at'],
            'FROM'   => 'glpi_plugin_tanium_sync_logs',
            'WHERE'  => ['status' => 'running', 'started_at' => ['<', $cutoff]],
        ]) as $row) {
            $DB->update('glpi_plugin_tanium_sync_logs', [
                'finished_at' => date('Y-m-d H:i:s'),
                'status'      => 'error',
                'errors'      => 1,
                'message'     => sprintf(
                    __('Interrupted run: the process died without finishing (started %s).', 'tanium'),
                    (string) ($row['started_at'] ?? '?')
                ),
            ], ['id' => (int) $row['id']]);
            $logs++;
        }

        $task     = new CronTask();
        $released = false;
        if (
            $task->getFromDBByCrit(['itemtype' => Cron::class, 'name' => 'taniumsync'])
            && (int) ($task->fields['state'] ?? 0) === CronTask::STATE_RUNNING
            && !self::taskLooksAlive($task)
        ) {
            $released = (bool) $task->update([
                'id'    => (int) $task->fields['id'],
                'state' => CronTask::STATE_WAITING,
            ]);
        }

        if ($released || $logs > 0) {
            Toolbox::logInFile('tanium', sprintf(
                "[Tanium] Recovered a wedged sync: cron task released=%s, orphan log rows closed=%d.\n",
                $released ? 'yes' : 'no',
                $logs
            ));
        }

        return ['task' => $released, 'logs' => $logs];
    }

    /**
     * True while a RUNNING cron task is still young enough that it could
     * plausibly be doing work. `lastrun` is stamped when the task starts, so
     * its age is how long the current run has been going.
     */
    private static function taskLooksAlive(CronTask $task): bool {
        $startedAt = strtotime((string) ($task->fields['lastrun'] ?? '')) ?: 0;
        if ($startedAt === 0) {
            return false;   // no start time recorded — it cannot be running
        }
        return $startedAt >= strtotime('-' . self::STALE_RUN_HOURS . ' hours');
    }

    /** Is the sync task currently held by a run that still looks alive? */
    public static function isRunning(): bool {
        $task = new CronTask();
        return $task->getFromDBByCrit(['itemtype' => Cron::class, 'name' => 'taniumsync'])
            && (int) ($task->fields['state'] ?? 0) === CronTask::STATE_RUNNING
            && self::taskLooksAlive($task);
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

    private static function updateLogProgress(int $logId, int $processed, int $totalEstimated): void {
        global $DB;
        $DB->update('glpi_plugin_tanium_sync_logs', [
            'processed'       => $processed,
            'total_estimated' => $totalEstimated,
        ], ['id' => $logId]);
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

    /** Recompute each CVE's affected-endpoint count from the per-endpoint table. */
    private static function recomputeCveAffectedCounts(): void {
        global $DB;
        $DB->doQuery(
            "UPDATE glpi_plugin_tanium_vulnerabilities v
             SET v.affected_count = (
                 SELECT COUNT(DISTINCT ec.tanium_eid)
                 FROM glpi_plugin_tanium_endpoint_cves ec
                 WHERE ec.cve_id = v.cve_id
             )"
        );
    }

    /** Keep only CVE findings at or above a minimum severity. */
    private static function filterCvesBySeverity(array $cves, string $minSeverity): array {
        $rank = ['unknown' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $min  = $rank[$minSeverity] ?? 0; // unknown key (e.g. 'all') keeps everything
        if ($min <= 0) {
            return $cves;
        }
        return array_values(array_filter(
            $cves,
            static fn(array $c): bool => ($rank[strtolower((string) ($c['severity'] ?? 'unknown'))] ?? 0) >= $min
        ));
    }

    /** Parse a PHP ini size string ("512M", "1G", "-1") into bytes. */
    private static function iniBytes($value): int {
        $value = trim((string) $value);
        if ($value === '' || $value === '-1') {
            return -1;
        }
        $unit = strtolower($value[strlen($value) - 1]);
        $num  = (int) $value;
        return match ($unit) {
            'g'     => $num * 1024 * 1024 * 1024,
            'm'     => $num * 1024 * 1024,
            'k'     => $num * 1024,
            default => $num,
        };
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
