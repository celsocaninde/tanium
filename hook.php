<?php

/**
 * Tanium Plugin — install/uninstall hooks.
 * GLPI 11 requires `timestamp` for all date columns.
 */

function plugin_tanium_install(): bool {
    global $DB;

    $charset   = DBConnection::getDefaultCharset();
    $collation = DBConnection::getDefaultCollation();
    $sign      = DBConnection::getDefaultPrimaryKeySignOption();

    // ── Configuration table ───────────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_configs')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_configs` (
                `id`                    int {$sign} NOT NULL AUTO_INCREMENT,
                `api_url`               varchar(500) NOT NULL DEFAULT '',
                `api_token`             text NOT NULL,
                `sync_computers`        tinyint(1) NOT NULL DEFAULT 1,
                `sync_software`         tinyint(1) NOT NULL DEFAULT 1,
                `sync_vulnerabilities`  tinyint(1) NOT NULL DEFAULT 0,
                `sync_hardware`         tinyint(1) NOT NULL DEFAULT 1,
                `sync_network`          tinyint(1) NOT NULL DEFAULT 1,
                `sync_os_details`       tinyint(1) NOT NULL DEFAULT 1,
                `sync_patches`          tinyint(1) NOT NULL DEFAULT 0,
                `sync_incremental`      tinyint(1) NOT NULL DEFAULT 1,
                `cron_frequency`        int NOT NULL DEFAULT 24,
                `import_limit`          int NOT NULL DEFAULT 500,
                `last_sync`             timestamp NULL DEFAULT NULL,
                `last_sync_count`       int NOT NULL DEFAULT 0,
                `last_sync_cursor`      varchar(50) DEFAULT NULL,
                `webhook_enabled`       tinyint(1) NOT NULL DEFAULT 0,
                `webhook_url`           varchar(1000) NOT NULL DEFAULT '',
                `notify_critical`       tinyint(1) NOT NULL DEFAULT 1,
                `notify_email`          varchar(500) NOT NULL DEFAULT '',
                `notify_users`          varchar(500) NOT NULL DEFAULT '',
                `sla_critical_days`     int NOT NULL DEFAULT 7,
                `sla_high_days`         int NOT NULL DEFAULT 30,
                `sla_medium_days`       int NOT NULL DEFAULT 90,
                `patch_limiting_group_id` int unsigned NOT NULL DEFAULT 0,
                `ticket_entity_id`      int unsigned NOT NULL DEFAULT 0,
                `ticket_requester_id`   int unsigned NOT NULL DEFAULT 0,
                `kiosk_enabled`         tinyint(1) NOT NULL DEFAULT 0,
                `kiosk_token`           varchar(64) NOT NULL DEFAULT '',
                `caps_extras_level`     tinyint NOT NULL DEFAULT 2,
                `caps_groups`           tinyint(1) NOT NULL DEFAULT 1,
                `caps_probed_at`        timestamp NULL DEFAULT NULL,
                `date_mod`              timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );

        $DB->insert('glpi_plugin_tanium_configs', [
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
            'webhook_enabled'      => 0,
            'webhook_url'          => '',
            'notify_critical'      => 1,
            'notify_email'         => '',
            'sla_critical_days'    => 7,
            'sla_high_days'        => 30,
            'sla_medium_days'      => 90,
        ]);
    }

    // Columns added after the CREATE TABLE above ships. Reconciled on every
    // install — not only on upgrades — otherwise a fresh install is born
    // missing every setting introduced since the original schema.
    {
        $missing = [
            'sync_network'       => "tinyint(1) NOT NULL DEFAULT 1",
            'sync_os_details'    => "tinyint(1) NOT NULL DEFAULT 1",
            'sync_patches'       => "tinyint(1) NOT NULL DEFAULT 0",
            'sync_incremental'   => "tinyint(1) NOT NULL DEFAULT 1",
            'last_sync_cursor'   => "varchar(50) DEFAULT NULL",
            'webhook_enabled'    => "tinyint(1) NOT NULL DEFAULT 0",
            'webhook_url'        => "varchar(1000) NOT NULL DEFAULT ''",
            'notify_critical'    => "tinyint(1) NOT NULL DEFAULT 1",
            'notify_email'       => "varchar(500) NOT NULL DEFAULT ''",
            'notify_users'       => "varchar(500) NOT NULL DEFAULT ''",
            'sla_critical_days'  => "int NOT NULL DEFAULT 7",
            'sla_high_days'      => "int NOT NULL DEFAULT 30",
            'sla_medium_days'    => "int NOT NULL DEFAULT 90",
            'patch_limiting_group_id' => "int unsigned NOT NULL DEFAULT 0",
            'ticket_entity_id'        => "int unsigned NOT NULL DEFAULT 0",
            'ticket_requester_id'     => "int unsigned NOT NULL DEFAULT 0",
            'default_entity_id'       => "int unsigned NOT NULL DEFAULT 0",
            'sync_group_membership'   => "tinyint(1) NOT NULL DEFAULT 0",
            'agent_stale_days'        => "int NOT NULL DEFAULT 7",
            'agent_health_ticket'     => "tinyint(1) NOT NULL DEFAULT 0",
            'sync_compliance'         => "tinyint(1) NOT NULL DEFAULT 0",
            'sync_threats'            => "tinyint(1) NOT NULL DEFAULT 0",
            'threat_ticket'           => "tinyint(1) NOT NULL DEFAULT 1",
            'threat_min_severity'     => "varchar(20) NOT NULL DEFAULT 'high'",
            'webhook_sla'             => "tinyint(1) NOT NULL DEFAULT 0",
            'webhook_deploy'          => "tinyint(1) NOT NULL DEFAULT 0",
            'auto_ticket_critical'    => "tinyint(1) NOT NULL DEFAULT 0",
            'quarantine_package'      => "varchar(255) NOT NULL DEFAULT ''",
            'restart_package'         => "varchar(255) NOT NULL DEFAULT ''",
            'token_encrypted'         => "tinyint(1) NOT NULL DEFAULT 0",
            'token_expires_at'        => "date DEFAULT NULL",
            'retention_days'          => "int NOT NULL DEFAULT 365",
            'custom_sensors'          => "varchar(500) NOT NULL DEFAULT ''",
            'auto_deploy_kev'         => "tinyint(1) NOT NULL DEFAULT 0",
            'report_day'              => "tinyint NOT NULL DEFAULT 1",
            'report_hour'             => "tinyint NOT NULL DEFAULT 8",
            'last_weekly_report'      => "timestamp NULL DEFAULT NULL",
            'auto_close_cves'         => "tinyint(1) NOT NULL DEFAULT 1",
            'notify_remediation'      => "tinyint(1) NOT NULL DEFAULT 0",
            'remediation_ticket'      => "tinyint(1) NOT NULL DEFAULT 0",
            'retire_after_days'       => "int NOT NULL DEFAULT 0",
            'reboot_sensor'           => "varchar(255) NOT NULL DEFAULT ''",
            'monthly_report_day'      => "tinyint NOT NULL DEFAULT 1",
            'last_monthly_report'     => "timestamp NULL DEFAULT NULL",
            'kiosk_enabled'           => "tinyint(1) NOT NULL DEFAULT 0",
            'kiosk_token'             => "varchar(64) NOT NULL DEFAULT ''",
            // Gateway capability cache: what the tenant actually answered last
            // time, so the sync stops re-probing blocks it already knows are
            // rejected. Re-probed periodically — a module installed later must
            // still be picked up. See Api::eachEndpointPage().
            'caps_extras_level'       => "tinyint NOT NULL DEFAULT 2",
            'caps_groups'             => "tinyint(1) NOT NULL DEFAULT 1",
            'caps_probed_at'          => "timestamp NULL DEFAULT NULL",
            // Last capability set the admin was told about, so the degradation
            // notice fires on the transition instead of on every sync.
            'caps_notified'           => "varchar(20) NOT NULL DEFAULT ''",
            // Findings that are closed carry no operational value, only history:
            // they get their own, shorter retention than the live tables, which
            // are never purged. 0 = keep forever (previous behaviour).
            'retention_closed_days'   => "int NOT NULL DEFAULT 0",
            // Kiosk breaks out of the carousel when something needs eyes now.
            'kiosk_alerts'            => "tinyint(1) NOT NULL DEFAULT 1",
            // CVE severity floor for ingestion. Read by Sync since v2.6 but
            // never stored or exposed, so it was permanently 'all'.
            'cve_min_severity'        => "varchar(20) NOT NULL DEFAULT 'all'",
            // Set by the "Run synchronization now" button so an explicit
            // request outranks the configured cron frequency exactly once.
            'sync_requested_at'       => "timestamp NULL DEFAULT NULL",
            // Last fleet-wide id sweep — the only way an incremental sync can
            // learn which endpoints left.
            'last_retire_sweep'       => "timestamp NULL DEFAULT NULL",
            // Ticket defaults: what every ticket the plugin opens should already
            // carry (category, assignee, source, type). Before these, a cron
            // ticket landed with no category and was assigned to the automation
            // account, so the service desk had to triage each one by hand.
            // 0 everywhere = previous behaviour.
            'ticket_category_id'        => "int unsigned NOT NULL DEFAULT 0",
            'ticket_category_cve_id'    => "int unsigned NOT NULL DEFAULT 0",
            'ticket_category_patch_id'  => "int unsigned NOT NULL DEFAULT 0",
            'ticket_category_agent_id'  => "int unsigned NOT NULL DEFAULT 0",
            'ticket_category_threat_id' => "int unsigned NOT NULL DEFAULT 0",
            'ticket_category_action_id' => "int unsigned NOT NULL DEFAULT 0",
            'ticket_tech_id'            => "int unsigned NOT NULL DEFAULT 0",
            'ticket_group_id'           => "int unsigned NOT NULL DEFAULT 0",
            'ticket_requesttype_id'     => "int unsigned NOT NULL DEFAULT 0",
            'ticket_type'               => "tinyint NOT NULL DEFAULT 0",
        ];
        foreach ($missing as $col => $def) {
            $res = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_configs` LIKE '{$col}'");
            if ($res && $DB->numrows($res) === 0) {
                $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_configs` ADD COLUMN `{$col}` {$def}");
            }
        }
        foreach (['last_sync', 'date_mod'] as $col) {
            _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_configs', $col, 'timestamp NULL DEFAULT NULL');
        }

        // v2.3.0: the weekly-report cron now runs hourly and the code decides
        // when to send (configured day/hour). CronTask::register() never
        // updates an existing row, so upgrades need an explicit UPDATE.
        $DB->doQuery(
            "UPDATE `glpi_crontasks` SET `frequency` = " . HOUR_TIMESTAMP . "
             WHERE `name` = 'weeklyreport' AND `itemtype` LIKE '%Tanium%' AND `frequency` = 604800"
        );
    }

    // ── Asset mapping table ───────────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_assets')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_assets` (
                `id`              int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`      varchar(100) NOT NULL DEFAULT '',
                `tanium_name`     varchar(255) NOT NULL DEFAULT '',
                `computers_id`    int {$sign} DEFAULT NULL,
                `ip_address`      varchar(100) DEFAULT NULL,
                `mac_address`     varchar(50)  DEFAULT NULL,
                `os_name`         varchar(255) DEFAULT NULL,
                `os_version`      varchar(100) DEFAULT NULL,
                `os_build`        varchar(100) DEFAULT NULL,
                `os_platform`     varchar(50)  DEFAULT NULL,
                `is_virtual`      tinyint(1) NOT NULL DEFAULT 0,
                `risk_score`      tinyint(3) UNSIGNED NOT NULL DEFAULT 0,
                `last_seen`       timestamp NULL DEFAULT NULL,
                `sync_status`     varchar(50) NOT NULL DEFAULT 'ok',
                `sync_message`    text DEFAULT NULL,
                `retired_at`      timestamp NULL DEFAULT NULL,
                `date_mod`        timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `tanium_eid` (`tanium_eid`),
                KEY `computers_id` (`computers_id`),
                KEY `risk_score` (`risk_score`),
                KEY `retired_at` (`retired_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
        $missing = [
            'ip_address'  => "varchar(100) DEFAULT NULL",
            'mac_address' => "varchar(50) DEFAULT NULL",
            'os_name'     => "varchar(255) DEFAULT NULL",
            'os_version'  => "varchar(100) DEFAULT NULL",
            'os_build'    => "varchar(100) DEFAULT NULL",
            'os_platform' => "varchar(50) DEFAULT NULL",
            'is_virtual'  => "tinyint(1) NOT NULL DEFAULT 0",
            'risk_score'  => "tinyint(3) UNSIGNED NOT NULL DEFAULT 0",
            // Hygiene / attack-surface / stability data (v2.1)
            'is_encrypted'     => "tinyint(1) DEFAULT NULL",
            'chassis_type'     => "varchar(50) DEFAULT NULL",
            'defender_healthy' => "varchar(50) DEFAULT NULL",
            'defender_av_on'   => "varchar(50) DEFAULT NULL",
            'defender_sig_age' => "varchar(50) DEFAULT NULL",
            'sccm_health'      => "varchar(100) DEFAULT NULL",
            'open_ports'       => "text DEFAULT NULL",
            'nat_ip'           => "varchar(64) DEFAULT NULL",
            'discover_method'  => "varchar(64) DEFAULT NULL",
            'event_crashes'    => "int DEFAULT NULL",
            'event_total'      => "int DEFAULT NULL",
            'sensor_data'      => "text DEFAULT NULL",
            // Endpoint stopped being returned by a full sync (decommissioned,
            // reinstalled, out of scope). Kept as a marker rather than deleted
            // so nothing disappears without the admin opting in — the
            // purgeretired cron does the actual removal.
            'retired_at'       => "timestamp NULL DEFAULT NULL",
        ];
        foreach ($missing as $col => $def) {
            $res = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_assets` LIKE '{$col}'");
            if ($res && $DB->numrows($res) === 0) {
                $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_assets` ADD COLUMN `{$col}` {$def}");
            }
        }
        foreach (['last_seen', 'date_mod'] as $col) {
            _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_assets', $col, 'timestamp NULL DEFAULT NULL');
        }
    }

    // ── Sync log table ────────────────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_sync_logs')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_sync_logs` (
                `id`           int {$sign} NOT NULL AUTO_INCREMENT,
                `started_at`   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `finished_at`  timestamp NULL DEFAULT NULL,
                `status`       varchar(20) NOT NULL DEFAULT 'running',
                `total`        int NOT NULL DEFAULT 0,
                `created`      int NOT NULL DEFAULT 0,
                `updated`      int NOT NULL DEFAULT 0,
                `errors`       int NOT NULL DEFAULT 0,
                `message`      text DEFAULT NULL,
                `processed`    int NOT NULL DEFAULT 0,
                `total_estimated` int NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
        _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_sync_logs', 'started_at',  'timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP');
        _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_sync_logs', 'finished_at', 'timestamp NULL DEFAULT NULL');
        $syncCol = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_sync_logs` LIKE 'processed'")->fetch_assoc();
        if (!$syncCol) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_sync_logs` ADD `processed` int NOT NULL DEFAULT 0, ADD `total_estimated` int NOT NULL DEFAULT 0");
        }
    }

    // ── Risk history table (trend data per sync) ──────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_risk_history')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_risk_history` (
                `id`                int {$sign} NOT NULL AUTO_INCREMENT,
                `sync_log_id`       int {$sign} DEFAULT NULL,
                `total_endpoints`   int NOT NULL DEFAULT 0,
                `avg_risk`          decimal(5,2) NOT NULL DEFAULT 0.00,
                `critical_count`    int NOT NULL DEFAULT 0,
                `high_count`        int NOT NULL DEFAULT 0,
                `medium_count`      int NOT NULL DEFAULT 0,
                `low_count`         int NOT NULL DEFAULT 0,
                `total_cves`        int NOT NULL DEFAULT 0,
                `critical_cves`     int NOT NULL DEFAULT 0,
                `patches_missing`   int NOT NULL DEFAULT 0,
                `recorded_at`       timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                KEY `recorded_at` (`recorded_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── Per-endpoint risk history ─────────────────────────────────────────
    // One row per *change* of an endpoint's risk score, not one per sync: the
    // fleet is hourly-synced and mostly steady, so writing unconditionally
    // would add ~10k rows/day of "nothing moved". What the before/after UI
    // needs is exactly the transitions.
    if (!$DB->tableExists('glpi_plugin_tanium_endpoint_risk_history')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_endpoint_risk_history` (
                `id`               int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`       varchar(100) NOT NULL DEFAULT '',
                `computers_id`     int {$sign} DEFAULT NULL,
                `risk_score`       int NOT NULL DEFAULT 0,
                `previous_score`   int DEFAULT NULL,
                `cves_critical`    int NOT NULL DEFAULT 0,
                `cves_high`        int NOT NULL DEFAULT 0,
                `cves_medium`      int NOT NULL DEFAULT 0,
                `cves_low`         int NOT NULL DEFAULT 0,
                `cves_kev`         int NOT NULL DEFAULT 0,
                `patches_missing`  int NOT NULL DEFAULT 0,
                `recorded_at`      timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                KEY `tanium_eid`  (`tanium_eid`),
                KEY `recorded_at` (`recorded_at`),
                KEY `eid_recorded` (`tanium_eid`, `recorded_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── CVE status history table ──────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_cve_history')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_cve_history` (
                `id`           int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`   varchar(100) NOT NULL DEFAULT '',
                `cve_id`       varchar(50)  NOT NULL DEFAULT '',
                `computers_id` int {$sign} DEFAULT NULL,
                `old_status`   varchar(30)  DEFAULT NULL,
                `new_status`   varchar(30)  NOT NULL DEFAULT 'open',
                `changed_at`   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `cve_id`     (`cve_id`),
                KEY `changed_at` (`changed_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── Vulnerabilities / CVEs table ──────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_vulnerabilities')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_vulnerabilities` (
                `id`               int {$sign} NOT NULL AUTO_INCREMENT,
                `cve_id`           varchar(50) NOT NULL DEFAULT '',
                `cvss_score`       decimal(4,1) DEFAULT NULL,
                `severity`         varchar(20) NOT NULL DEFAULT 'unknown',
                `title`            varchar(500) NOT NULL DEFAULT '',
                `description`      text DEFAULT NULL,
                `affected_count`   int NOT NULL DEFAULT 0,
                `first_detected`   timestamp NULL DEFAULT NULL,
                `last_detected`    timestamp NULL DEFAULT NULL,
                `date_mod`         timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `cve_id` (`cve_id`),
                KEY `severity` (`severity`),
                KEY `cvss_score` (`cvss_score`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
        foreach (['first_detected', 'last_detected', 'date_mod'] as $col) {
            _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_vulnerabilities', $col, 'timestamp NULL DEFAULT NULL');
        }
    }

    // ── Endpoint <-> CVE link table ───────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_endpoint_cves')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_endpoint_cves` (
                `id`               int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`       varchar(100) NOT NULL DEFAULT '',
                `cve_id`           varchar(50) NOT NULL DEFAULT '',
                `computers_id`     int {$sign} DEFAULT NULL,
                `cvss_score`       decimal(4,1) DEFAULT NULL,
                `severity`         varchar(20) NOT NULL DEFAULT 'unknown',
                `status`           varchar(30) NOT NULL DEFAULT 'open',
                `detected_at`      timestamp NULL DEFAULT NULL,
                `tickets_id`       int {$sign} NOT NULL DEFAULT 0,
                `date_mod`         timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `eid_cve` (`tanium_eid`, `cve_id`),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `cve_id` (`cve_id`),
                KEY `computers_id` (`computers_id`),
                KEY `tickets_id` (`tickets_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
        $res = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_endpoint_cves` LIKE 'tickets_id'");
        if ($res && $DB->numrows($res) === 0) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_endpoint_cves` ADD COLUMN `tickets_id` int {$sign} NOT NULL DEFAULT 0, ADD KEY `tickets_id` (`tickets_id`)");
        }
        foreach (['detected_at', 'date_mod'] as $col) {
            _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_endpoint_cves', $col, 'timestamp NULL DEFAULT NULL');
        }
    }

    // ── Patch status table ────────────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_patches')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_patches` (
                `id`               int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`       varchar(100) NOT NULL DEFAULT '',
                `computers_id`     int {$sign} DEFAULT NULL,
                `patch_id`         text NOT NULL,
                `patch_title`      varchar(500) NOT NULL DEFAULT '',
                `severity`         varchar(20) NOT NULL DEFAULT 'unknown',
                `status`           varchar(30) NOT NULL DEFAULT 'missing',
                `kb_id`            text DEFAULT NULL,
                `release_date`     date DEFAULT NULL,
                `date_mod`         timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `eid_patch` (`tanium_eid`, `patch_id`(191)),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `computers_id` (`computers_id`),
                KEY `severity` (`severity`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
        _tanium_migrate_to_timestamp($DB, 'glpi_plugin_tanium_patches', 'date_mod', 'timestamp NULL DEFAULT NULL');
        // Widen kb_id to TEXT — Linux patches can carry many USN advisory IDs, exceeding varchar(50)
        $col = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_patches` LIKE 'kb_id'")->fetch_assoc();
        if ($col && stripos($col['Type'], 'varchar') !== false) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_patches` MODIFY `kb_id` text DEFAULT NULL");
        }
        // Widen patch_id to TEXT — same overflow (Launchpad patches concatenate every
        // advisory ID). It belongs to the UNIQUE index, so the index must be dropped
        // and recreated with a key-length prefix (TEXT cannot be indexed in full).
        $pcol = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_patches` LIKE 'patch_id'")->fetch_assoc();
        if ($pcol && stripos($pcol['Type'], 'text') === false) {
            $hasIdx = $DB->doQuery("SHOW INDEX FROM `glpi_plugin_tanium_patches` WHERE Key_name = 'eid_patch'")->fetch_assoc();
            $drop   = $hasIdx ? "DROP INDEX `eid_patch`, " : "";
            $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_patches` {$drop}MODIFY `patch_id` text NOT NULL, ADD UNIQUE KEY `eid_patch` (`tanium_eid`, `patch_id`(191))");
        }
    }

    // ── v2.18.0: one severity vocabulary ──────────────────────────────────
    //
    // Severity is normalised at ingest from now on, but rows already stored
    // still carry whatever spelling their vendor used, plus the unrated ones
    // ('', 'none', '[no results]') that used to fold silently into "low".
    // Rewrite them once so every count groups on the same words. Idempotent:
    // the canonical values map to themselves and match nothing on re-run.
    if ($DB->tableExists('glpi_plugin_tanium_patches')) {
        foreach ([
            'high'        => 'important',
            'medium'      => 'moderate',
            'negligible'  => 'low',
            'none'        => 'unknown',
            'unspecified' => 'unknown',
            'untriaged'   => 'unknown',
            'n/a'         => 'unknown',
            ''            => 'unknown',
            '[no results]' => 'unknown',
        ] as $from => $to) {
            $DB->doQuery(sprintf(
                "UPDATE `glpi_plugin_tanium_patches` SET `severity` = '%s' WHERE LOWER(TRIM(`severity`)) = '%s'",
                $DB->escape($to),
                $DB->escape($from)
            ));
        }
        // Anything left in mixed case ("Critical") becomes lower case without
        // needing to be listed above.
        $DB->doQuery("UPDATE `glpi_plugin_tanium_patches` SET `severity` = LOWER(TRIM(`severity`)) WHERE `severity` <> LOWER(TRIM(`severity`))");

        // v2.19.0: drop sensor-failure rows stored as missing patches.
        //
        // Deleted rather than closed on purpose. Letting the next sync
        // auto-close them would write "installed" into patch_history for
        // something that was never a patch, inflating the remediation counts
        // and the MTTR with a machine nobody managed to scan. They are not
        // findings, so they leave no history.
        $DB->doQuery(
            "DELETE FROM `glpi_plugin_tanium_patches`
              WHERE LOWER(CONCAT(COALESCE(patch_title,''), ' ', COALESCE(patch_id,''))) REGEXP
                    'no scan results|no results found|tse-error|error:|not applicable'"
        );
    }

    // ── v2.19.0: indexes for the status filters used on every screen ──────
    //
    // "status != 'remediated'" and "status = 'missing'" appear in a dozen
    // queries across the dashboard, the kiosk, the health report and the SLA
    // screens. At 84k CVE rows a scan is still fast; it stops being fast well
    // before anyone notices it got slow.
    foreach ([
        'glpi_plugin_tanium_endpoint_cves' => ['status_eid' => '(`status`, `tanium_eid`)'],
        'glpi_plugin_tanium_patches'       => ['status_eid' => '(`status`, `tanium_eid`)'],
    ] as $table => $indexes) {
        if (!$DB->tableExists($table)) {
            continue;
        }
        foreach ($indexes as $name => $cols) {
            $has = $DB->doQuery("SHOW INDEX FROM `{$table}` WHERE Key_name = '{$name}'");
            if ($has && $DB->numrows($has) === 0) {
                $DB->doQuery("ALTER TABLE `{$table}` ADD KEY `{$name}` {$cols}");
            }
        }
    }

    // ── Patch status history (v2.6.0) ─────────────────────────────────────
    // Mirrors cve_history for patches: every status transition (missing →
    // installed/remediated) is recorded here, feeding the remediation trend
    // page and the weekly/monthly reports. Purged by the retention cron.
    if (!$DB->tableExists('glpi_plugin_tanium_patch_history')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_patch_history` (
                `id`           int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`   varchar(100) NOT NULL DEFAULT '',
                `patch_id`     text NOT NULL,
                `patch_title`  varchar(500) NOT NULL DEFAULT '',
                `severity`     varchar(20) NOT NULL DEFAULT 'unknown',
                `computers_id` int {$sign} DEFAULT NULL,
                `old_status`   varchar(30)  DEFAULT NULL,
                `new_status`   varchar(30)  NOT NULL DEFAULT 'missing',
                `changed_at`   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `changed_at` (`changed_at`),
                KEY `new_status` (`new_status`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── CVE exceptions table (accepted risk) ─────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_cve_exceptions')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_cve_exceptions` (
                `id`           int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`   varchar(100) NOT NULL DEFAULT '',
                `cve_id`       varchar(50)  NOT NULL DEFAULT '',
                `computers_id` int {$sign} DEFAULT NULL,
                `reason`       varchar(1000) NOT NULL DEFAULT '',
                `accepted_by`  int {$sign} DEFAULT NULL,
                `expires_at`   timestamp NULL DEFAULT NULL,
                `created_at`   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                UNIQUE KEY `eid_cve` (`tanium_eid`, `cve_id`),
                KEY `cve_id`   (`cve_id`),
                KEY `expires_at` (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── CVE assignments table ─────────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_cve_assignments')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_cve_assignments` (
                `id`           int {$sign} NOT NULL AUTO_INCREMENT,
                `tanium_eid`   varchar(100) NOT NULL DEFAULT '',
                `cve_id`       varchar(50)  NOT NULL DEFAULT '',
                `computers_id` int {$sign} DEFAULT NULL,
                `ref_type`     varchar(10)  NOT NULL DEFAULT 'cve',
                `assigned_to`  int {$sign} DEFAULT NULL,
                `assigned_by`  int {$sign} DEFAULT NULL,
                `due_date`     timestamp NULL DEFAULT NULL,
                `status`       varchar(30) NOT NULL DEFAULT 'open',
                `notes`        text DEFAULT NULL,
                `created_at`   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `date_mod`     timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `eid_cve_type` (`tanium_eid`, `cve_id`, `ref_type`),
                KEY `tanium_eid`  (`tanium_eid`),
                KEY `assigned_to` (`assigned_to`),
                KEY `status`      (`status`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── Saved filters table ───────────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_saved_filters')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_saved_filters` (
                `id`           int {$sign} NOT NULL AUTO_INCREMENT,
                `users_id`     int {$sign} NOT NULL DEFAULT 0,
                `name`         varchar(100) NOT NULL DEFAULT '',
                `filter_type`  varchar(30)  NOT NULL DEFAULT 'endpoints',
                `filter_data`  text NOT NULL,
                `created_at`   timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                KEY `users_id`    (`users_id`),
                KEY `filter_type` (`filter_type`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── Campaigns ─────────────────────────────────────────────────────────
    //
    // The Action Plan answers "what do I do first"; a campaign is the follow
    // through: one advisory picked, a target date, and the eradication tracked
    // across the fleet until it is gone. Progress is never stored — it is
    // derived from the live patch/CVE tables, so it can never drift from
    // reality the way a cached counter would.
    if (!$DB->tableExists('glpi_plugin_tanium_campaigns')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_campaigns` (
                `id`             int {$sign} NOT NULL AUTO_INCREMENT,
                `name`           varchar(255) NOT NULL DEFAULT '',
                `target_type`    varchar(20)  NOT NULL DEFAULT 'patch',
                `target_key`     varchar(255) NOT NULL DEFAULT '',
                `baseline_count` int NOT NULL DEFAULT 0,
                `due_date`       date DEFAULT NULL,
                `owner_id`       int {$sign} DEFAULT NULL,
                `status`         varchar(20) NOT NULL DEFAULT 'active',
                `notes`          text DEFAULT NULL,
                `created_by`     int {$sign} DEFAULT NULL,
                `created_at`     timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `closed_at`      timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `status`      (`status`),
                KEY `target_type` (`target_type`),
                KEY `owner_id`    (`owner_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // ── Patch deployments table ───────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_patch_deployments')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_patch_deployments` (
                `id`                    int {$sign} NOT NULL AUTO_INCREMENT,
                `ticket_id`             int {$sign} DEFAULT NULL,
                `tanium_eid`            varchar(100) NOT NULL DEFAULT '',
                `computers_id`          int {$sign} DEFAULT NULL,
                `patch_ids`             text NOT NULL,
                `limiting_group_id`     int unsigned NOT NULL DEFAULT 0,
                `tanium_deployment_id`  varchar(255) DEFAULT NULL,
                `status`                varchar(30) NOT NULL DEFAULT 'pending_approval',
                `requested_by`          int {$sign} DEFAULT NULL,
                `approved_by`           int {$sign} DEFAULT NULL,
                `approved_at`           timestamp NULL DEFAULT NULL,
                `deployed_at`           timestamp NULL DEFAULT NULL,
                `error_message`         text DEFAULT NULL,
                `created_at`            timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `updated_at`            timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                KEY `ticket_id`  (`ticket_id`),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `status`     (`status`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
        $res = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_tanium_patch_deployments` LIKE 'limiting_group_id'");
        if ($res && $DB->numrows($res) === 0) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_tanium_patch_deployments` ADD COLUMN `limiting_group_id` int unsigned NOT NULL DEFAULT 0 AFTER `patch_ids`");
        }
    }

    if (!$DB->tableExists('glpi_plugin_tanium_computer_groups')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_computer_groups` (
                `id`                int unsigned NOT NULL AUTO_INCREMENT,
                `tanium_group_id`   int unsigned NOT NULL DEFAULT 0,
                `tanium_group_name` varchar(255) NOT NULL DEFAULT '',
                `label`             varchar(255) NOT NULL DEFAULT '',
                `date_mod`          timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `tanium_group_id` (`tanium_group_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    }

    // Register profile rights
    if (class_exists('GlpiPlugin\Tanium\Profile')) {
        \GlpiPlugin\Tanium\Profile::ensureProfileRights();
    }

    // Encrypt a clear-text API token left by versions < 2.1
    \GlpiPlugin\Tanium\Config::migrateTokenEncryption();

    // Purge sensor artifacts imported as CVEs by versions < 2.2.1
    // (e.g. "[no results]"); the sync now rejects non-CVE ids on entry.
    foreach (['glpi_plugin_tanium_vulnerabilities', 'glpi_plugin_tanium_endpoint_cves', 'glpi_plugin_tanium_cve_history'] as $cveTable) {
        if ($DB->tableExists($cveTable)) {
            $DB->doQuery("DELETE FROM `{$cveTable}` WHERE cve_id NOT REGEXP '^CVE-[0-9]{4}-[0-9]+$'");
        }
    }

    return true;
}

function plugin_tanium_uninstall(): bool {
    global $DB;

    foreach ([
        'glpi_plugin_tanium_configs',
        'glpi_plugin_tanium_assets',
        'glpi_plugin_tanium_sync_logs',
        'glpi_plugin_tanium_risk_history',
        'glpi_plugin_tanium_cve_history',
        'glpi_plugin_tanium_vulnerabilities',
        'glpi_plugin_tanium_endpoint_cves',
        'glpi_plugin_tanium_patches',
        'glpi_plugin_tanium_patch_history',
        'glpi_plugin_tanium_cve_exceptions',
        'glpi_plugin_tanium_cve_assignments',
        'glpi_plugin_tanium_saved_filters',
        'glpi_plugin_tanium_patch_deployments',
        'glpi_plugin_tanium_computer_groups',
        'glpi_plugin_tanium_cve_enrichment',
        'glpi_plugin_tanium_compliance',
        'glpi_plugin_tanium_threat_alerts',
        'glpi_plugin_tanium_remote_actions',
        'glpi_plugin_tanium_campaigns',
    ] as $table) {
        if ($DB->tableExists($table)) {
            $DB->dropTable($table);
        }
    }

    CronTask::unregister('tanium');

    return true;
}

/**
 * Expose Tanium data as native GLPI search options on Computer.
 *
 * Until now the risk score lived only inside the plugin's own screens, so it
 * could not be a column in a saved search, a filter in the native list, a
 * criterion in a GLPI business rule, or a field in an export. Registering it
 * here hands all of that to the parts of GLPI that already do it well, at the
 * cost of one LEFT JOIN — no new code to maintain, no second search engine.
 *
 * IDs are in the 5100-5199 band reserved for this plugin. They must stay
 * stable: GLPI persists them inside saved searches and dashboards, so
 * renumbering an option silently repoints every saved search that used it.
 *
 * @param string $itemtype
 * @return array<int,array<string,mixed>>
 */
function plugin_tanium_getAddSearchOptionsNew($itemtype): array {
    if ($itemtype !== 'Computer') {
        return [];
    }

    $join = [
        'glpi_plugin_tanium_assets' => [
            'ON' => [
                'glpi_plugin_tanium_assets' => 'computers_id',
                'glpi_computers'            => 'id',
            ],
        ],
    ];

    return [
        [
            'id'            => 5100,
            'table'         => 'glpi_plugin_tanium_assets',
            'field'         => 'risk_score',
            'name'          => __('Tanium risk score', 'tanium'),
            'datatype'      => 'number',
            'massiveaction' => false,
            'joinparams'    => $join,
        ],
        [
            'id'            => 5101,
            'table'         => 'glpi_plugin_tanium_assets',
            'field'         => 'last_seen',
            'name'          => __('Tanium last seen', 'tanium'),
            'datatype'      => 'datetime',
            'massiveaction' => false,
            'joinparams'    => $join,
        ],
        [
            'id'            => 5102,
            'table'         => 'glpi_plugin_tanium_assets',
            'field'         => 'tanium_name',
            'name'          => __('Tanium endpoint name', 'tanium'),
            'datatype'      => 'string',
            'massiveaction' => false,
            'joinparams'    => $join,
        ],
        [
            'id'            => 5103,
            'table'         => 'glpi_plugin_tanium_assets',
            'field'         => 'is_encrypted',
            'name'          => __('Tanium disk encrypted', 'tanium'),
            'datatype'      => 'bool',
            'massiveaction' => false,
            'joinparams'    => $join,
        ],
        [
            'id'            => 5104,
            'table'         => 'glpi_plugin_tanium_assets',
            'field'         => 'retired_at',
            'name'          => __('Tanium retired on', 'tanium'),
            'datatype'      => 'datetime',
            'massiveaction' => false,
            'joinparams'    => $join,
        ],
        [
            'id'            => 5105,
            'table'         => 'glpi_plugin_tanium_assets',
            'field'         => 'os_platform',
            'name'          => __('Tanium OS platform', 'tanium'),
            'datatype'      => 'string',
            'massiveaction' => false,
            'joinparams'    => $join,
        ],
    ];
}

// Helper: ALTER column from datetime to timestamp only if still datetime
function _tanium_migrate_to_timestamp($DB, string $table, string $col, string $def): void {
    $res = $DB->doQuery("SHOW COLUMNS FROM `{$table}` LIKE '{$col}'");
    if ($res && ($row = $res->fetch_assoc()) && stripos((string)($row['Type'] ?? ''), 'datetime') !== false) {
        $DB->doQuery("ALTER TABLE `{$table}` MODIFY `{$col}` {$def}");
    }
}
