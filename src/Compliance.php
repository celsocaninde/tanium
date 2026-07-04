<?php

namespace GlpiPlugin\Tanium;

use Toolbox;

/**
 * Tanium Comply — compliance benchmark results (CIS/DISA hardening checks),
 * the counterpart of the CVE view: "how hardened is this endpoint", not just
 * "how vulnerable". One row per (endpoint, benchmark rule); score per endpoint
 * is pass / (pass + fail).
 */
class Compliance {

    public static $table = 'glpi_plugin_tanium_compliance';

    public static function ensureTable(): void {
        global $DB;

        if ($DB->tableExists(self::$table)) {
            return;
        }

        $DB->doQuery(
            "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
                `id`          int unsigned NOT NULL AUTO_INCREMENT,
                `tanium_eid`  varchar(100) NOT NULL DEFAULT '',
                `benchmark`   varchar(255) NOT NULL DEFAULT '',
                `rule_title`  varchar(500) NOT NULL DEFAULT '',
                `state`       varchar(20)  NOT NULL DEFAULT 'unknown',
                `severity`    varchar(20)  NOT NULL DEFAULT 'unknown',
                `checked_at`  timestamp NULL DEFAULT NULL,
                `date_mod`    timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `eid_rule` (`tanium_eid`, `benchmark`, `rule_title`(180)),
                KEY `tanium_eid` (`tanium_eid`),
                KEY `state` (`state`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    /**
     * Pull compliance findings from Tanium Comply and upsert locally.
     * Field names vary across Comply versions, so every key is probed
     * defensively; unusable rows are skipped, never fatal.
     */
    public static function syncFromApi(Api $api): int {
        self::ensureTable();

        try {
            $findings = $api->getComplianceFindings();
        } catch (\Throwable $e) {
            Toolbox::logInFile('tanium', '[Tanium] Compliance sync failed: ' . $e->getMessage() . "\n");
            return 0;
        }

        $count = 0;
        $now   = date('Y-m-d H:i:s');
        foreach ($findings as $f) {
            $eid   = (string)($f['eid'] ?? $f['endpointId'] ?? $f['computerId'] ?? '');
            $rule  = trim((string)($f['ruleTitle'] ?? $f['rule'] ?? $f['title'] ?? $f['checkName'] ?? ''));
            if ($eid === '' || $rule === '') {
                continue;
            }

            $stateRaw = strtolower((string)($f['state'] ?? $f['status'] ?? $f['result'] ?? ''));
            $state    = match (true) {
                str_contains($stateRaw, 'pass')                                    => 'pass',
                str_contains($stateRaw, 'fail')                                    => 'fail',
                str_contains($stateRaw, 'error'), str_contains($stateRaw, 'unkn') => 'unknown',
                default                                                            => 'unknown',
            };

            self::upsert([
                'tanium_eid' => $eid,
                'benchmark'  => substr((string)($f['benchmark'] ?? $f['profile'] ?? $f['standard'] ?? ''), 0, 255),
                'rule_title' => substr($rule, 0, 500),
                'state'      => $state,
                'severity'   => strtolower((string)($f['severity'] ?? 'unknown')),
                'checked_at' => !empty($f['lastScan']) ? date('Y-m-d H:i:s', strtotime($f['lastScan'])) : $now,
                'date_mod'   => $now,
            ]);
            $count++;
        }

        return $count;
    }

    private static function upsert(array $row): void {
        global $DB;

        $existing = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => self::$table,
            'WHERE'  => [
                'tanium_eid' => $row['tanium_eid'],
                'benchmark'  => $row['benchmark'],
                'rule_title' => $row['rule_title'],
            ],
            'LIMIT'  => 1,
        ])->current();

        if ($existing) {
            $DB->update(self::$table, $row, ['id' => $existing['id']]);
        } else {
            $DB->insert(self::$table, $row);
        }
    }

    /** Compliance % for one endpoint (null when no checks recorded). */
    public static function scoreForEndpoint(string $eid): ?int {
        global $DB;
        self::ensureTable();

        $row = $DB->doQuery(
            "SELECT SUM(state='pass') AS ok, SUM(state IN ('pass','fail')) AS total
             FROM `" . self::$table . "` WHERE tanium_eid = '" . $DB->escape($eid) . "'"
        )->fetch_assoc();

        $total = (int)($row['total'] ?? 0);
        return $total > 0 ? (int)round((int)$row['ok'] / $total * 100) : null;
    }

    /** Fleet-wide compliance % (null when no checks recorded). */
    public static function fleetScore(): ?int {
        global $DB;
        self::ensureTable();

        $row = $DB->doQuery(
            "SELECT SUM(state='pass') AS ok, SUM(state IN ('pass','fail')) AS total
             FROM `" . self::$table . "`"
        )->fetch_assoc();

        $total = (int)($row['total'] ?? 0);
        return $total > 0 ? (int)round((int)$row['ok'] / $total * 100) : null;
    }

    /** Failed rules for one endpoint, most severe first. */
    public static function failedRules(string $eid, int $limit = 20): array {
        global $DB;
        self::ensureTable();

        $limit = max(1, $limit);
        $rows  = [];
        // Raw SQL: the query-builder ORDER clause cannot express FIELD().
        foreach ($DB->doQuery(
            "SELECT * FROM `" . self::$table . "`
             WHERE tanium_eid = '" . $DB->escape($eid) . "' AND state = 'fail'
             ORDER BY FIELD(severity,'critical','high','medium','low','unknown'), rule_title ASC
             LIMIT {$limit}"
        ) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }
}
