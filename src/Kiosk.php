<?php

namespace GlpiPlugin\Tanium;

/**
 * Data provider for the TV/kiosk dashboard (front/kiosk.php). Session-free:
 * numbers are fleet-wide (no entity restriction) because the kiosk is opened
 * by a wall TV with a token, not by a logged-in profile.
 */
class Kiosk {

    public static function getData(): array {
        global $DB;

        $config = Config::getConfig();
        $days   = (int)($config['agent_stale_days'] ?? 7);

        $endpoints = (int)($DB->doQuery(
            "SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_assets"
        )->fetch_assoc()['cpt'] ?? 0);

        $severity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($DB->doQuery("
            SELECT LOWER(v.severity) AS sev, COUNT(*) AS cpt
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
            WHERE ec.status != 'remediated'
            GROUP BY LOWER(v.severity)
        ") as $r) {
            if (isset($severity[$r['sev']])) {
                $severity[$r['sev']] = (int)$r['cpt'];
            }
        }

        $kev        = 0;
        $ransomware = 0;
        $topEpss    = [];
        if ($DB->tableExists(Enrichment::$table)) {
            $row = $DB->doQuery("
                SELECT COALESCE(SUM(e.is_kev = 1), 0) AS kev,
                       COALESCE(SUM(e.kev_ransomware = 1), 0) AS ransomware
                FROM glpi_plugin_tanium_endpoint_cves ec
                JOIN `" . Enrichment::$table . "` e ON e.cve_id = ec.cve_id
                WHERE ec.status != 'remediated'
            ")->fetch_assoc();
            $kev        = (int)($row['kev'] ?? 0);
            $ransomware = (int)($row['ransomware'] ?? 0);

            foreach ($DB->doQuery("
                SELECT e.cve_id, MAX(e.epss_score) AS epss, MAX(e.is_kev) AS is_kev,
                       MAX(e.kev_ransomware) AS ransomware,
                       COUNT(DISTINCT ec.tanium_eid) AS affected,
                       MAX(v.severity) AS severity
                FROM glpi_plugin_tanium_endpoint_cves ec
                JOIN `" . Enrichment::$table . "` e ON e.cve_id = ec.cve_id
                LEFT JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
                WHERE ec.status != 'remediated' AND e.epss_score IS NOT NULL
                GROUP BY e.cve_id
                ORDER BY epss DESC
                LIMIT 8
            ") as $r) {
                $topEpss[] = $r;
            }
        }

        $topRisk = [];
        foreach ($DB->doQuery("
            SELECT tanium_name, os_name, risk_score
            FROM glpi_plugin_tanium_assets
            WHERE risk_score > 0
            ORDER BY risk_score DESC, tanium_name ASC
            LIMIT 10
        ") as $r) {
            $topRisk[] = $r;
        }

        $recentCritical = [];
        foreach ($DB->doQuery("
            SELECT ec.cve_id, ec.detected_at, a.tanium_name, v.cvss_score
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
            LEFT JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = ec.tanium_eid
            WHERE ec.status != 'remediated' AND LOWER(v.severity) = 'critical'
            ORDER BY ec.detected_at DESC
            LIMIT 8
        ") as $r) {
            $recentCritical[] = $r;
        }

        // CVEs with the widest fleet impact (open critical/high findings)
        $widestCves = [];
        foreach ($DB->doQuery("
            SELECT v.cve_id, v.title, LOWER(v.severity) AS severity, v.cvss_score,
                   COUNT(DISTINCT ec.tanium_eid) AS affected
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
            WHERE ec.status != 'remediated' AND LOWER(v.severity) IN ('critical', 'high')
            GROUP BY v.cve_id, v.title, LOWER(v.severity), v.cvss_score
            ORDER BY affected DESC
            LIMIT 8
        ") as $r) {
            $widestCves[] = $r;
        }

        // Missing patches
        $patches = ['total' => 0, 'critical' => 0, 'high' => 0];
        foreach ($DB->doQuery("
            SELECT LOWER(severity) AS sev, COUNT(*) AS cpt
            FROM glpi_plugin_tanium_patches
            WHERE status = 'missing'
            GROUP BY LOWER(severity)
        ") as $r) {
            $patches['total'] += (int)$r['cpt'];
            if (isset($patches[$r['sev']])) {
                $patches[$r['sev']] = (int)$r['cpt'];
            }
        }

        $patchTopEndpoints = [];
        foreach ($DB->doQuery("
            SELECT a.tanium_name, a.os_name,
                   COUNT(*) AS missing,
                   SUM(LOWER(p.severity) = 'critical') AS crit
            FROM glpi_plugin_tanium_patches p
            JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = p.tanium_eid
            WHERE p.status = 'missing' AND LOWER(p.severity) IN ('critical', 'high')
            GROUP BY p.tanium_eid, a.tanium_name, a.os_name
            ORDER BY crit DESC, missing DESC
            LIMIT 8
        ") as $r) {
            $patchTopEndpoints[] = $r;
        }

        $patchTopTitles = [];
        foreach ($DB->doQuery("
            SELECT patch_title, LOWER(severity) AS severity, COUNT(*) AS affected
            FROM glpi_plugin_tanium_patches
            WHERE status = 'missing' AND patch_title != ''
            GROUP BY patch_title, LOWER(severity)
            ORDER BY affected DESC
            LIMIT 8
        ") as $r) {
            $patchTopTitles[] = $r;
        }

        $deploysActive = (int)($DB->doQuery("
            SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_patch_deployments
            WHERE status NOT IN ('deployed', 'failed', 'rejected')
        ")->fetch_assoc()['cpt'] ?? 0);

        $recentDeploys = [];
        foreach ($DB->doQuery("
            SELECT d.status, d.created_at, d.deployed_at, a.tanium_name
            FROM glpi_plugin_tanium_patch_deployments d
            LEFT JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = d.tanium_eid
            ORDER BY d.created_at DESC
            LIMIT 6
        ") as $r) {
            $recentDeploys[] = $r;
        }

        // Remediation: last 7 days + weekly series for the trend bars
        $remediated7d = (int)($DB->doQuery("
            SELECT COUNT(*) AS cpt FROM glpi_plugin_tanium_cve_history
            WHERE new_status = 'remediated' AND changed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ")->fetch_assoc()['cpt'] ?? 0);

        $weeklyRemediation = [];
        foreach ($DB->doQuery("
            SELECT YEARWEEK(changed_at, 3) AS wk, MIN(DATE(changed_at)) AS week_start, COUNT(*) AS cpt
            FROM glpi_plugin_tanium_cve_history
            WHERE new_status = 'remediated' AND changed_at >= DATE_SUB(NOW(), INTERVAL 56 DAY)
            GROUP BY YEARWEEK(changed_at, 3)
            ORDER BY wk ASC
        ") as $r) {
            $weeklyRemediation[] = $r;
        }

        // Fleet risk trend, one point per day (last snapshot of each day)
        $riskTrend = [];
        foreach ($DB->doQuery("
            SELECT DATE(recorded_at) AS day,
                   SUBSTRING_INDEX(GROUP_CONCAT(avg_risk ORDER BY recorded_at DESC), ',', 1) AS avg_risk,
                   SUBSTRING_INDEX(GROUP_CONCAT(critical_cves ORDER BY recorded_at DESC), ',', 1) AS critical_cves
            FROM glpi_plugin_tanium_risk_history
            WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(recorded_at)
            ORDER BY day ASC
        ") as $r) {
            $riskTrend[] = $r;
        }

        ThreatResponse::ensureTable();
        $recentThreats = [];
        foreach ($DB->doQuery("
            SELECT t.title, t.severity, t.detected_at, a.tanium_name
            FROM `" . ThreatResponse::$table . "` t
            LEFT JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = t.tanium_eid
            WHERE t.status NOT IN ('resolved', 'closed', 'suppressed')
            ORDER BY t.detected_at DESC
            LIMIT 8
        ") as $r) {
            $recentThreats[] = $r;
        }

        $stale = AgentHealth::countStale($days);

        return [
            'endpoints'          => $endpoints,
            'severity'           => $severity,
            'kev'                => $kev,
            'ransomware'         => $ransomware,
            'top_epss'           => $topEpss,
            'sla'                => Sla::getStats(),
            'mttr'               => Sla::getMttr(90),
            'most_overdue'       => Sla::getMostOverdue(8),
            'platform'           => Sla::getPlatformBenchmark(),
            'stale'              => $stale,
            'stale_list'         => array_slice(AgentHealth::getStale($days), 0, 8),
            'stale_days'         => $days,
            'coverage_pct'       => $endpoints > 0 ? (int)round(($endpoints - $stale) * 100 / $endpoints) : null,
            'threats'            => ThreatResponse::countOpen(),
            'recent_threats'     => $recentThreats,
            'top_risk'           => $topRisk,
            'recent_critical'    => $recentCritical,
            'widest_cves'        => $widestCves,
            'patches'            => $patches,
            'patch_top_endpoints' => $patchTopEndpoints,
            'patch_top_titles'   => $patchTopTitles,
            'deploys_active'     => $deploysActive,
            'recent_deploys'     => $recentDeploys,
            'remediated_7d'      => $remediated7d,
            'weekly_remediation' => $weeklyRemediation,
            'risk_trend'         => $riskTrend,
            'last_sync'          => $config['last_sync'] ?? null,
        ];
    }
}
