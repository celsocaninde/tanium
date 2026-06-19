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
                `sla_critical_days`     int NOT NULL DEFAULT 7,
                `sla_high_days`         int NOT NULL DEFAULT 30,
                `sla_medium_days`       int NOT NULL DEFAULT 90,
                `patch_limiting_group_id` int NOT NULL DEFAULT 0,
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
    } else {
        // Add missing columns
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
            'sla_critical_days'  => "int NOT NULL DEFAULT 7",
            'sla_high_days'      => "int NOT NULL DEFAULT 30",
            'sla_medium_days'    => "int NOT NULL DEFAULT 90",
            'patch_limiting_group_id' => "int NOT NULL DEFAULT 0",
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
                `date_mod`        timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `tanium_eid` (`tanium_eid`),
                KEY `computers_id` (`computers_id`),
                KEY `risk_score` (`risk_score`)
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
                `date_mod`         timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `eid_cve` (`tanium_eid`, `cve_id`),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `cve_id` (`cve_id`),
                KEY `computers_id` (`computers_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation}"
        );
    } else {
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

    // ── Patch deployments table ───────────────────────────────────────────
    if (!$DB->tableExists('glpi_plugin_tanium_patch_deployments')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_tanium_patch_deployments` (
                `id`                    int {$sign} NOT NULL AUTO_INCREMENT,
                `ticket_id`             int {$sign} DEFAULT NULL,
                `tanium_eid`            varchar(100) NOT NULL DEFAULT '',
                `computers_id`          int {$sign} DEFAULT NULL,
                `patch_ids`             text NOT NULL,
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
    }

    // Register profile rights
    if (class_exists('GlpiPlugin\Tanium\Profile')) {
        \GlpiPlugin\Tanium\Profile::ensureProfileRights();
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
        'glpi_plugin_tanium_cve_exceptions',
        'glpi_plugin_tanium_cve_assignments',
        'glpi_plugin_tanium_saved_filters',
        'glpi_plugin_tanium_patch_deployments',
    ] as $table) {
        if ($DB->tableExists($table)) {
            $DB->dropTable($table);
        }
    }

    CronTask::unregister('tanium');

    return true;
}

// Helper: ALTER column from datetime to timestamp only if still datetime
function _tanium_migrate_to_timestamp($DB, string $table, string $col, string $def): void {
    $res = $DB->doQuery("SHOW COLUMNS FROM `{$table}` LIKE '{$col}'");
    if ($res && ($row = $res->fetch_assoc()) && stripos((string)($row['Type'] ?? ''), 'datetime') !== false) {
        $DB->doQuery("ALTER TABLE `{$table}` MODIFY `{$col}` {$def}");
    }
}
