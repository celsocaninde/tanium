<?php

namespace GlpiPlugin\Tanium;

/**
 * Fleet health report ("boletim de saúde"): one verdict + grade per endpoint,
 * combining everything the plugin knows — open CVEs by severity, KEV
 * exposure, missing patches, agent freshness, disk encryption and Defender
 * health. An endpoint with nothing wrong reads "Saudável" with grade 10.
 */
class HealthReport {

    /** Grade bands: [min score, label, color]. Order matters (first match). */
    public const BANDS = [
        [9.0, 'Saudável', '#1eb464'],
        [7.0, 'Bom',      '#7ac74f'],
        [5.0, 'Atenção',  '#e8c42a'],
        [3.0, 'Ruim',     '#f97316'],
        [0.0, 'Crítico',  '#e8212a'],
    ];

    /**
     * One row per endpoint with aggregated posture counters.
     * Ordered worst-first after scoring.
     */
    public static function getFleet(): array {
        global $DB;

        $sql = "
            SELECT a.tanium_eid, a.tanium_name, a.computers_id, a.ip_address, a.os_name,
                   a.last_seen, a.risk_score, a.is_encrypted, a.defender_healthy,
                   a.defender_av_on, a.sccm_health, a.event_crashes,
                   DATEDIFF(NOW(), a.last_seen) AS days_silent,
                   COALESCE(cv.crit, 0) AS cves_critical,
                   COALESCE(cv.high, 0) AS cves_high,
                   COALESCE(cv.med,  0) AS cves_medium,
                   COALESCE(cv.low,  0) AS cves_low,
                   COALESCE(cv.kev,  0) AS cves_kev,
                   COALESCE(p.missing, 0) AS missing_patches
            FROM glpi_plugin_tanium_assets a
            LEFT JOIN (
                SELECT ec.tanium_eid,
                       SUM(LOWER(v.severity) = 'critical') AS crit,
                       SUM(LOWER(v.severity) = 'high')     AS high,
                       SUM(LOWER(v.severity) = 'medium')   AS med,
                       SUM(LOWER(v.severity) = 'low')      AS low,
                       SUM(COALESCE(e.is_kev, 0))          AS kev
                FROM glpi_plugin_tanium_endpoint_cves ec
                JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
                LEFT JOIN glpi_plugin_tanium_cve_enrichment e ON e.cve_id = ec.cve_id
                WHERE ec.status != 'remediated'
                GROUP BY ec.tanium_eid
            ) cv ON cv.tanium_eid = a.tanium_eid
            LEFT JOIN (
                SELECT tanium_eid, COUNT(*) AS missing
                FROM glpi_plugin_tanium_patches
                WHERE status = 'missing'
                GROUP BY tanium_eid
            ) p ON p.tanium_eid = a.tanium_eid
        ";

        $staleDays = (int)(Config::getConfig()['agent_stale_days'] ?? 7);

        $rows = [];
        foreach ($DB->doQuery($sql) as $r) {
            $rows[] = self::score($r, $staleDays);
        }

        usort($rows, static fn(array $a, array $b): int => $a['score'] <=> $b['score']);
        return $rows;
    }

    /**
     * Grade an endpoint 0–10 and attach verdict + issue list.
     * Unknown hygiene data (nulls) never penalizes — only confirmed problems.
     */
    public static function score(array $r, int $staleDays): array {
        $score  = 10.0;
        $issues = [];

        $crit = (int)$r['cves_critical'];
        $high = (int)$r['cves_high'];
        $med  = (int)$r['cves_medium'];
        $kev  = (int)$r['cves_kev'];
        $pat  = (int)$r['missing_patches'];

        if ($crit > 0) {
            $score -= min(5.0, $crit * 1.5);
            $issues[] = sprintf(_n('%d critical CVE', '%d critical CVEs', $crit, 'tanium'), $crit);
        }
        if ($high > 0) {
            $score -= min(2.5, $high * 0.4);
            $issues[] = sprintf(_n('%d high CVE', '%d high CVEs', $high, 'tanium'), $high);
        }
        if ($med > 0) {
            $score -= min(1.0, $med * 0.05);
        }
        if ($kev > 0) {
            $score -= 1.0;
            $issues[] = sprintf(__('%d actively exploited (KEV)', 'tanium'), $kev);
        }
        if ($pat > 0) {
            $score -= min(1.0, $pat * 0.1);
            $issues[] = sprintf(_n('%d missing patch', '%d missing patches', $pat, 'tanium'), $pat);
        }

        $silent = $r['days_silent'] !== null ? (int)$r['days_silent'] : null;
        if ($silent !== null && $silent > $staleDays) {
            $score -= 2.0;
            $issues[] = sprintf(__('agent silent for %d days', 'tanium'), $silent);
        }

        if ($r['is_encrypted'] !== null && (int)$r['is_encrypted'] === 0) {
            $score -= 1.0;
            $issues[] = __('disk not encrypted', 'tanium');
        }

        $defHealthy = strtolower(trim((string)($r['defender_healthy'] ?? '')));
        if ($defHealthy !== '' && !in_array($defHealthy, ['true', 'yes', 'healthy', '1'], true)) {
            $score -= 1.0;
            $issues[] = __('Defender unhealthy', 'tanium');
        }

        $score = round(max(0.0, min(10.0, $score)), 1);

        foreach (self::BANDS as [$min, $label, $color]) {
            if ($score >= $min) {
                $r['verdict']       = $label;
                $r['verdict_color'] = $color;
                break;
            }
        }

        $r['score']  = $score;
        $r['issues'] = $issues;
        $r['message'] = $issues === []
            ? __('Healthy — no issues found', 'tanium')
            : implode(' · ', $issues);

        return $r;
    }

    /** Verdict counts + fleet average for the report header. */
    public static function summary(array $rows): array {
        $out = ['total' => count($rows), 'avg' => null, 'bands' => []];
        foreach (self::BANDS as [, $label]) {
            $out['bands'][$label] = 0;
        }

        $sum = 0.0;
        foreach ($rows as $r) {
            $sum += (float)$r['score'];
            $out['bands'][$r['verdict']]++;
        }
        if ($rows !== []) {
            $out['avg'] = round($sum / count($rows), 1);
        }
        return $out;
    }
}
