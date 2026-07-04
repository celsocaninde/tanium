<?php

namespace GlpiPlugin\Tanium;

use Toolbox;

/**
 * CVE enrichment from public threat-intelligence feeds:
 *
 *  - EPSS (FIRST.org): probability [0..1] that the CVE is exploited in the
 *    wild within 30 days. Bulk daily CSV, filtered to the CVEs we track.
 *  - CISA KEV: catalog of vulnerabilities with CONFIRMED active exploitation.
 *
 * Together they shift prioritization from "high CVSS" to "high CVSS AND being
 * exploited right now". Refreshed daily by the `epsskev` cron task.
 */
class Enrichment {

    public static $table = 'glpi_plugin_tanium_cve_enrichment';

    private const EPSS_BULK_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
    private const KEV_URL       = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    public static function ensureTable(): void {
        global $DB;

        if ($DB->tableExists(self::$table)) {
            return;
        }

        $DB->doQuery(
            "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
                `id`              int unsigned NOT NULL AUTO_INCREMENT,
                `cve_id`          varchar(50) NOT NULL DEFAULT '',
                `epss_score`      decimal(6,5) DEFAULT NULL,
                `epss_percentile` decimal(6,5) DEFAULT NULL,
                `is_kev`          tinyint(1) NOT NULL DEFAULT 0,
                `kev_date`        date DEFAULT NULL,
                `kev_ransomware`  tinyint(1) NOT NULL DEFAULT 0,
                `date_mod`        timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `cve_id` (`cve_id`),
                KEY `is_kev` (`is_kev`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    /**
     * Refresh EPSS + KEV data for every CVE in the local catalog.
     * Returns ['epss' => n, 'kev' => n] with the number of rows touched.
     */
    public static function refresh(): array {
        global $DB;
        self::ensureTable();

        $tracked = [];
        foreach ($DB->request(['SELECT' => ['cve_id'], 'FROM' => 'glpi_plugin_tanium_vulnerabilities']) as $r) {
            $tracked[strtoupper($r['cve_id'])] = true;
        }
        if (!$tracked) {
            return ['epss' => 0, 'kev' => 0];
        }

        $epssCount = self::refreshEpss($tracked);
        $kevCount  = self::refreshKev($tracked);

        return ['epss' => $epssCount, 'kev' => $kevCount];
    }

    /** @param array<string,bool> $tracked upper-cased CVE ids we care about */
    private static function refreshEpss(array $tracked): int {
        global $DB;

        $raw = self::download(self::EPSS_BULK_URL);
        if ($raw === null) {
            return 0;
        }

        $csv = @gzdecode($raw);
        if ($csv === false || $csv === '') {
            // Some proxies deliver it already decompressed
            $csv = $raw;
        }

        $count = 0;
        $now   = date('Y-m-d H:i:s');
        foreach (explode("\n", $csv) as $line) {
            // Format: cve,epss,percentile — with a #comment header block
            if ($line === '' || $line[0] === '#' || str_starts_with($line, 'cve,')) {
                continue;
            }
            $parts = explode(',', trim($line));
            if (count($parts) < 3) {
                continue;
            }
            $cve = strtoupper($parts[0]);
            if (!isset($tracked[$cve])) {
                continue;
            }

            self::upsert($cve, [
                'epss_score'      => (float)$parts[1],
                'epss_percentile' => (float)$parts[2],
                'date_mod'        => $now,
            ]);
            $count++;
        }

        return $count;
    }

    /** @param array<string,bool> $tracked upper-cased CVE ids we care about */
    private static function refreshKev(array $tracked): int {
        global $DB;

        $raw = self::download(self::KEV_URL);
        if ($raw === null) {
            return 0;
        }

        $data = json_decode($raw, true);
        if (!is_array($data) || empty($data['vulnerabilities'])) {
            return 0;
        }

        // Reset first: a CVE removed from the KEV catalog loses its flag.
        $DB->doQuery("UPDATE `" . self::$table . "` SET is_kev = 0, kev_ransomware = 0");

        $count = 0;
        $now   = date('Y-m-d H:i:s');
        foreach ($data['vulnerabilities'] as $v) {
            $cve = strtoupper((string)($v['cveID'] ?? ''));
            if ($cve === '' || !isset($tracked[$cve])) {
                continue;
            }

            self::upsert($cve, [
                'is_kev'         => 1,
                'kev_date'       => !empty($v['dateAdded']) ? date('Y-m-d', strtotime($v['dateAdded'])) : null,
                'kev_ransomware' => (stripos((string)($v['knownRansomwareCampaignUse'] ?? ''), 'known') !== false) ? 1 : 0,
                'date_mod'       => $now,
            ]);
            $count++;
        }

        return $count;
    }

    private static function upsert(string $cveId, array $fields): void {
        global $DB;

        $existing = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => self::$table,
            'WHERE'  => ['cve_id' => $cveId],
            'LIMIT'  => 1,
        ])->current();

        if ($existing) {
            $DB->update(self::$table, $fields, ['id' => $existing['id']]);
        } else {
            $DB->insert(self::$table, $fields + ['cve_id' => $cveId]);
        }
    }

    /**
     * Enrichment rows keyed by CVE id for a set of CVEs (empty array → []).
     *
     * @return array<string,array{epss_score:?string,epss_percentile:?string,is_kev:int,kev_date:?string,kev_ransomware:int}>
     */
    public static function forCves(array $cveIds): array {
        global $DB;

        $cveIds = array_values(array_filter($cveIds));
        if (!$cveIds) {
            return [];
        }
        self::ensureTable();

        $map = [];
        foreach ($DB->request(['FROM' => self::$table, 'WHERE' => ['cve_id' => $cveIds]]) as $r) {
            $map[strtoupper($r['cve_id'])] = $r;
        }
        return $map;
    }

    /**
     * Upper-cased ids of tracked CVEs present in the KEV catalog.
     * Memoized: updateRiskScore calls this once per endpoint in the sync loop.
     */
    public static function kevSet(): array {
        global $DB;
        static $cache = null;

        if ($cache !== null) {
            return $cache;
        }
        self::ensureTable();

        $cache = [];
        foreach ($DB->request(['SELECT' => ['cve_id'], 'FROM' => self::$table, 'WHERE' => ['is_kev' => 1]]) as $r) {
            $cache[strtoupper($r['cve_id'])] = true;
        }
        return $cache;
    }

    /** Last refresh timestamp, or null when never refreshed. */
    public static function lastRefresh(): ?string {
        global $DB;
        self::ensureTable();

        $row = $DB->doQuery("SELECT MAX(date_mod) AS m FROM `" . self::$table . "`")->fetch_assoc();
        return $row['m'] ?? null;
    }

    private static function download(string $url): ?string {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'GLPI-Tanium-Plugin',
        ]);
        $body  = curl_exec($ch);
        $error = curl_error($ch);
        $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error !== '' || $code >= 400 || !is_string($body) || $body === '') {
            Toolbox::logInFile('tanium', "[Tanium] Enrichment download failed ({$url}): HTTP {$code} {$error}\n");
            return null;
        }
        return $body;
    }
}
