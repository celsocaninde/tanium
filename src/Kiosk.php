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

        $kev = 0;
        if ($DB->tableExists(Enrichment::$table)) {
            $kev = (int)($DB->doQuery("
                SELECT COUNT(*) AS cpt
                FROM glpi_plugin_tanium_endpoint_cves ec
                JOIN `" . Enrichment::$table . "` e ON e.cve_id = ec.cve_id AND e.is_kev = 1
                WHERE ec.status != 'remediated'
            ")->fetch_assoc()['cpt'] ?? 0);
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

        return [
            'endpoints'       => $endpoints,
            'severity'        => $severity,
            'kev'             => $kev,
            'sla'             => Sla::getStats(),
            'stale'           => AgentHealth::countStale($days),
            'stale_days'      => $days,
            'threats'         => ThreatResponse::countOpen(),
            'top_risk'        => $topRisk,
            'recent_critical' => $recentCritical,
            'last_sync'       => $config['last_sync'] ?? null,
        ];
    }
}
