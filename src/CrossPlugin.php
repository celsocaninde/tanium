<?php

namespace GlpiPlugin\Tanium;

use Plugin;

/**
 * Cross-plugin CVE correlation ("dedup"): flags CVEs that other security
 * plugins installed on this GLPI also report, so analysts see at a glance
 * that a finding is confirmed by more than one scanner and avoid opening
 * duplicated remediation work.
 *
 * Supported peers:
 *  - nessusglpi  (Tenable Nessus)  — glpi_plugin_nessusglpi_vulnerabilities
 *  - sentinelone (SentinelOne)     — glpi_plugin_sentinelone_cves
 */
class CrossPlugin {

    /** Peer plugins that are active AND have their data table in place. */
    public static function sources(): array {
        global $DB;
        static $cache = null;

        if ($cache !== null) {
            return $cache;
        }

        $cache = [
            'nessus'      => Plugin::isPluginActive('nessusglpi')
                && $DB->tableExists('glpi_plugin_nessusglpi_vulnerabilities'),
            'sentinelone' => Plugin::isPluginActive('sentinelone')
                && $DB->tableExists('glpi_plugin_sentinelone_cves'),
        ];
        return $cache;
    }

    public static function hasAnySource(): bool {
        return in_array(true, self::sources(), true);
    }

    /**
     * Correlate a set of CVE ids against the peer plugins' open findings.
     *
     * @param string[] $cveIds
     * @return array<string,array{nessus:int,sentinelone:int}> keyed by
     *         upper-cased CVE id; only CVEs seen by at least one peer appear.
     */
    public static function forCves(array $cveIds): array {
        $cveIds = array_values(array_unique(array_filter(array_map('strtoupper', $cveIds))));
        if ($cveIds === []) {
            return [];
        }

        $map     = [];
        $sources = self::sources();

        if ($sources['nessus']) {
            foreach (self::nessusCounts($cveIds) as $cve => $n) {
                $map[$cve]['nessus'] = $n;
            }
        }
        if ($sources['sentinelone']) {
            foreach (self::sentineloneCounts($cveIds) as $cve => $n) {
                $map[$cve]['sentinelone'] = $n;
            }
        }

        foreach ($map as &$row) {
            $row += ['nessus' => 0, 'sentinelone' => 0];
        }
        unset($row);

        return $map;
    }

    /**
     * Nessus stores the CVE list as free text (possibly several ids per
     * finding), so aggregate per raw value once and explode locally.
     *
     * @return array<string,int> CVE id → open current findings
     */
    private static function nessusCounts(array $cveIds): array {
        global $DB;

        $wanted = array_fill_keys($cveIds, true);
        $counts = [];

        $res = $DB->doQuery("
            SELECT cve, COUNT(*) AS cpt
            FROM glpi_plugin_nessusglpi_vulnerabilities
            WHERE is_current = 1 AND status = 'open'
              AND cve IS NOT NULL AND cve != ''
            GROUP BY cve
        ");
        if (!$res) {
            return [];
        }

        while ($r = $res->fetch_assoc()) {
            foreach (preg_split('/[\s,;]+/', strtoupper($r['cve'])) ?: [] as $cve) {
                if ($cve !== '' && isset($wanted[$cve])) {
                    $counts[$cve] = ($counts[$cve] ?? 0) + (int)$r['cpt'];
                }
            }
        }
        return $counts;
    }

    /** @return array<string,int> CVE id → agents reporting it */
    private static function sentineloneCounts(array $cveIds): array {
        global $DB;

        $counts = [];
        foreach ($DB->request([
            'SELECT'  => ['cve_id', 'COUNT' => 'id AS cpt'],
            'FROM'    => 'glpi_plugin_sentinelone_cves',
            'WHERE'   => ['cve_id' => $cveIds],
            'GROUPBY' => 'cve_id',
        ]) as $r) {
            $counts[strtoupper($r['cve_id'])] = (int)$r['cpt'];
        }
        return $counts;
    }

    /** Small inline badges ("Nessus ×n", "S1 ×n") for a correlated CVE row. */
    public static function badgesHtml(?array $row): string {
        if (!$row) {
            return '';
        }

        $html = '';
        if (!empty($row['nessus'])) {
            $html .= '<span class="tanium-badge tanium-badge-muted" style="font-size:.62rem;margin-left:4px;background:#00263e;color:#fff"'
                   . ' title="' . sprintf(__('Also reported by Tenable Nessus on %d finding(s)', 'tanium'), (int)$row['nessus']) . '">'
                   . 'Nessus ×' . (int)$row['nessus'] . '</span>';
        }
        if (!empty($row['sentinelone'])) {
            $html .= '<span class="tanium-badge tanium-badge-muted" style="font-size:.62rem;margin-left:4px;background:#6b46e5;color:#fff"'
                   . ' title="' . sprintf(__('Also reported by SentinelOne on %d agent(s)', 'tanium'), (int)$row['sentinelone']) . '">'
                   . 'S1 ×' . (int)$row['sentinelone'] . '</span>';
        }
        return $html;
    }
}
