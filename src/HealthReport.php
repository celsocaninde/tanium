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
                   a.os_platform, a.os_version,
                   a.last_seen, a.risk_score, a.is_encrypted, a.defender_healthy,
                   a.defender_av_on, a.sccm_health, a.event_crashes,
                   DATEDIFF(NOW(), a.last_seen) AS days_silent,
                   COALESCE(cv.crit, 0) AS cves_critical,
                   COALESCE(cv.high, 0) AS cves_high,
                   COALESCE(cv.med,  0) AS cves_medium,
                   COALESCE(cv.low,  0) AS cves_low,
                   COALESCE(cv.kev,  0) AS cves_kev,
                   COALESCE(p.missing, 0) AS missing_patches,
                   COALESCE(p.p_crit, 0)  AS patches_critical,
                   COALESCE(p.p_imp,  0)  AS patches_important,
                   COALESCE(p.p_mod,  0)  AS patches_moderate,
                   COALESCE(p.p_low,  0)  AS patches_low
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
                SELECT tanium_eid,
                       COUNT(*) AS missing,
                       SUM(LOWER(severity) = 'critical')  AS p_crit,
                       SUM(LOWER(severity) = 'important') AS p_imp,
                       SUM(LOWER(severity) = 'moderate')  AS p_mod,
                       SUM(LOWER(severity) NOT IN ('critical','important','moderate')) AS p_low
                FROM glpi_plugin_tanium_patches
                WHERE status = 'missing'
                GROUP BY tanium_eid
            ) p ON p.tanium_eid = a.tanium_eid
            WHERE 1=1" . Profile::entityRestrictSql('a') . "
        ";

        $staleDays = (int)(Config::getConfig()['agent_stale_days'] ?? 7);

        $rows = [];
        foreach ($DB->doQuery($sql) as $r) {
            $rows[] = self::score($r, $staleDays);
        }

        usort($rows, static fn(array $a, array $b): int => $a['score'] <=> $b['score']);

        self::attachTrend($rows);

        return $rows;
    }

    /**
     * Grade an endpoint 0–10 and attach verdict + issue list.
     * Unknown hygiene data (nulls) never penalizes — only confirmed problems.
     */
    public static function score(array $r, int $staleDays): array {
        $issues = [];

        $crit = (int)$r['cves_critical'];
        $high = (int)$r['cves_high'];
        $med  = (int)$r['cves_medium'];
        $low  = (int)($r['cves_low'] ?? 0);
        $kev  = (int)$r['cves_kev'];
        $pat  = (int)$r['missing_patches'];

        if ($crit > 0) {
            $issues[] = sprintf(_n('%d critical CVE', '%d critical CVEs', $crit, 'tanium'), $crit);
        }
        if ($high > 0) {
            $issues[] = sprintf(_n('%d high CVE', '%d high CVEs', $high, 'tanium'), $high);
        }
        if ($kev > 0) {
            $issues[] = sprintf(__('%d actively exploited (KEV)', 'tanium'), $kev);
        }
        if ($pat > 0) {
            $issues[] = sprintf(_n('%d missing patch', '%d missing patches', $pat, 'tanium'), $pat);
        }

        // The grade is derived from the same 0-100 risk model the endpoint page
        // shows, so the two screens can never disagree about one machine. The
        // severity of the findings sets 7 of the 10 points; hygiene owns 3.
        $risk = Risk::score(Risk::tierCounts(
            ['critical' => $crit, 'high' => $high, 'medium' => $med, 'low' => $low],
            $kev,
            [
                'critical'  => (int)($r['patches_critical']  ?? 0),
                'important' => (int)($r['patches_important'] ?? 0),
                'moderate'  => (int)($r['patches_moderate']  ?? 0),
                'low'       => (int)($r['patches_low']       ?? 0),
            ]
        ));

        // Vendor support state. An EOL machine keeps accumulating CVEs that no
        // patch will ever close, so it gets a risk floor rather than being
        // allowed to look calm because its finding list happens to be short.
        $lifecycle   = Lifecycle::status($r['os_name'] ?? null, $r['os_version'] ?? null);
        $risk        = Risk::applyLifecycleFloor($risk, $lifecycle['state']);
        $r['lifecycle'] = $lifecycle;

        $hygiene = [];

        if ($lifecycle['state'] === 'eol') {
            $hygiene['os_eol'] = true;
            $issues[] = sprintf(
                __('%s is past end of support', 'tanium'),
                (string) $lifecycle['product']
            );
        }

        $silent = $r['days_silent'] !== null ? (int)$r['days_silent'] : null;
        if ($silent !== null && $silent > $staleDays) {
            $hygiene['agent_silent'] = true;
            $issues[] = sprintf(__('agent silent for %d days', 'tanium'), $silent);
        }

        if ($r['is_encrypted'] !== null && (int)$r['is_encrypted'] === 0) {
            $hygiene['not_encrypted'] = true;
            $issues[] = __('disk not encrypted', 'tanium');
        }

        // Only judge Defender where Defender can exist. Tanium fills this field
        // on Linux hosts too, and the old code docked a point from every
        // AlmaLinux/Ubuntu box for a missing Windows agent.
        $defHealthy = strtolower(trim((string)($r['defender_healthy'] ?? '')));
        if ($defHealthy !== ''
            && !in_array($defHealthy, ['true', 'yes', 'healthy', '1'], true)
            && Risk::usesDefender($r['os_name'] ?? null, $r['os_platform'] ?? null)
        ) {
            $hygiene['defender_bad'] = true;
            $issues[] = __('Defender unhealthy', 'tanium');
        }

        $graded = Risk::grade($risk['score'], $hygiene);
        $score  = $graded['grade'];

        foreach (self::BANDS as [$min, $label, $color]) {
            if ($score >= $min) {
                $r['verdict']       = $label;
                $r['verdict_color'] = $color;
                break;
            }
        }

        $r['score']       = $score;
        $r['risk_score']  = $risk['score'];
        $r['risk_steps']  = $risk['steps'];
        $r['grade_steps'] = $graded['steps'];
        $r['issues']      = $issues;
        $r['message'] = $issues === []
            ? __('Healthy — no issues found', 'tanium')
            : implode(' · ', $issues);

        return $r;
    }

    /**
     * Attach each endpoint's risk movement over the trend window.
     *
     * One grouped query for the whole fleet rather than one per row — the
     * report renders 400+ endpoints and this used to be exactly the kind of
     * place an N+1 crept in.
     *
     * @param array<int,array<string,mixed>> $rows modified in place
     */
    private static function attachTrend(array &$rows): void {
        global $DB;

        foreach ($rows as &$r) {
            $r['risk_from']  = null;
            $r['risk_delta'] = null;
        }
        unset($r);

        if ($rows === [] || !$DB->tableExists('glpi_plugin_tanium_endpoint_risk_history')) {
            return;
        }

        $since = date('Y-m-d H:i:s', strtotime('-' . RiskHistory::WINDOW_DAYS . ' days'));

        // Oldest row per endpoint inside the window: that row's previous_score
        // is where the endpoint stood when the window opened.
        $baseline = [];
        $sql = "
            SELECT h.tanium_eid,
                   COALESCE(h.previous_score, h.risk_score) AS from_score
            FROM glpi_plugin_tanium_endpoint_risk_history h
            JOIN (
                SELECT tanium_eid, MIN(recorded_at) AS first_at
                FROM glpi_plugin_tanium_endpoint_risk_history
                WHERE recorded_at >= '" . $DB->escape($since) . "'
                GROUP BY tanium_eid
            ) f ON f.tanium_eid = h.tanium_eid AND f.first_at = h.recorded_at
        ";
        foreach ($DB->doQuery($sql) as $row) {
            $baseline[(string)$row['tanium_eid']] = (int)$row['from_score'];
        }

        if ($baseline === []) {
            return;
        }

        foreach ($rows as &$r) {
            $eid = (string)($r['tanium_eid'] ?? '');
            if (!isset($baseline[$eid])) {
                continue;
            }
            $current         = (int)($r['risk_score'] ?? 0);
            $r['risk_from']  = $baseline[$eid];
            $r['risk_delta'] = $current - $baseline[$eid];
        }
        unset($r);
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
