<?php

namespace GlpiPlugin\Tanium;

use Plugin;

/**
 * Native GLPI dashboard cards (Assistência/Central → Dashboards → add card),
 * registered through the `dashboard_cards` plugin hook. Complements the
 * plugin's own dashboard page: these cards live inside the dashboards users
 * already look at every day.
 */
class DashboardCards {

    /** `dashboard_cards` hook entry point — receives/returns the card list. */
    public static function register($cards) {
        if (!is_array($cards)) {
            $cards = [];
        }

        $group = 'Tanium';

        $cards['plugin_tanium_endpoints'] = [
            'widgettype' => ['bigNumber'],
            'group'      => $group,
            'label'      => __('Tanium — Synced endpoints', 'tanium'),
            'provider'   => self::class . '::cardEndpoints',
        ];
        $cards['plugin_tanium_critical_findings'] = [
            'widgettype' => ['bigNumber'],
            'group'      => $group,
            'label'      => __('Tanium — Open critical findings', 'tanium'),
            'provider'   => self::class . '::cardCriticalFindings',
        ];
        $cards['plugin_tanium_kev_findings'] = [
            'widgettype' => ['bigNumber'],
            'group'      => $group,
            'label'      => __('Tanium — KEV exposure (actively exploited)', 'tanium'),
            'provider'   => self::class . '::cardKevFindings',
        ];
        $cards['plugin_tanium_sla_compliance'] = [
            'widgettype' => ['bigNumber'],
            'group'      => $group,
            'label'      => __('Tanium — SLA compliance (%)', 'tanium'),
            'provider'   => self::class . '::cardSlaCompliance',
        ];
        $cards['plugin_tanium_stale_agents'] = [
            'widgettype' => ['bigNumber'],
            'group'      => $group,
            'label'      => __('Tanium — Silent agents', 'tanium'),
            'provider'   => self::class . '::cardStaleAgents',
        ];
        $cards['plugin_tanium_open_threats'] = [
            'widgettype' => ['bigNumber'],
            'group'      => $group,
            'label'      => __('Tanium — Open threat alerts', 'tanium'),
            'provider'   => self::class . '::cardOpenThreats',
        ];
        $cards['plugin_tanium_findings_by_severity'] = [
            'widgettype' => ['pie', 'donut', 'halfpie', 'halfdonut', 'bar', 'hbar', 'summaryNumbers', 'multipleNumber'],
            'group'      => $group,
            'label'      => __('Tanium — Open findings by severity', 'tanium'),
            'provider'   => self::class . '::cardFindingsBySeverity',
        ];

        return $cards;
    }

    private static function frontUrl(string $page): string {
        return Plugin::getWebDir('tanium') . '/front/' . $page;
    }

    // ── Providers ──────────────────────────────────────────────────────────

    public static function cardEndpoints(array $params = []): array {
        global $DB;

        $row = $DB->request(['FROM' => 'glpi_plugin_tanium_assets', 'COUNT' => 'cpt'])->current();

        return [
            'number' => (int)($row['cpt'] ?? 0),
            'url'    => self::frontUrl('endpoints.php'),
            'label'  => __('Tanium endpoints', 'tanium'),
            'icon'   => 'ti ti-devices',
        ];
    }

    public static function cardCriticalFindings(array $params = []): array {
        return [
            'number' => self::openFindings('critical'),
            'url'    => self::frontUrl('vulnerabilities.php?severity=critical'),
            'label'  => __('Open critical findings', 'tanium'),
            'icon'   => 'ti ti-alert-octagon',
        ];
    }

    public static function cardKevFindings(array $params = []): array {
        global $DB;

        $count = 0;
        if ($DB->tableExists(Enrichment::$table)) {
            $row = $DB->doQuery("
                SELECT COUNT(*) AS cpt
                FROM glpi_plugin_tanium_endpoint_cves ec
                JOIN `" . Enrichment::$table . "` e
                     ON e.cve_id = ec.cve_id AND e.is_kev = 1
                WHERE ec.status != 'remediated'
            ")->fetch_assoc();
            $count = (int)($row['cpt'] ?? 0);
        }

        return [
            'number' => $count,
            'url'    => self::frontUrl('vulnerabilities.php'),
            'label'  => __('KEV exposure', 'tanium'),
            'icon'   => 'ti ti-flame',
        ];
    }

    public static function cardSlaCompliance(array $params = []): array {
        $stats = Sla::getStats();

        return [
            'number' => $stats['compliance'] ?? 0,
            'url'    => self::frontUrl('sla.php'),
            'label'  => __('SLA compliance (%)', 'tanium'),
            'icon'   => 'ti ti-clock-check',
        ];
    }

    public static function cardStaleAgents(array $params = []): array {
        $config = Config::getConfig();
        $days   = (int)($config['agent_stale_days'] ?? 7);

        return [
            'number' => AgentHealth::countStale($days),
            'url'    => self::frontUrl('endpoints.php'),
            'label'  => sprintf(__('Agents silent > %d days', 'tanium'), $days),
            'icon'   => 'ti ti-wifi-off',
        ];
    }

    public static function cardOpenThreats(array $params = []): array {
        return [
            'number' => ThreatResponse::countOpen(),
            'url'    => self::frontUrl('dashboard.php'),
            'label'  => __('Open threat alerts', 'tanium'),
            'icon'   => 'ti ti-shield-x',
        ];
    }

    public static function cardFindingsBySeverity(array $params = []): array {
        global $DB;

        $colors = [
            'critical' => '#e8212a',
            'high'     => '#f97316',
            'medium'   => '#e8c42a',
            'low'      => '#1eb464',
        ];

        $counts = array_fill_keys(array_keys($colors), 0);
        foreach ($DB->doQuery("
            SELECT LOWER(v.severity) AS sev, COUNT(*) AS cpt
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
            WHERE ec.status != 'remediated'
            GROUP BY LOWER(v.severity)
        ") as $r) {
            if (isset($counts[$r['sev']])) {
                $counts[$r['sev']] = (int)$r['cpt'];
            }
        }

        $data = [];
        foreach ($counts as $sev => $n) {
            $data[] = [
                'number' => $n,
                'label'  => ucfirst($sev),
                'url'    => self::frontUrl('vulnerabilities.php?severity=' . $sev),
                'color'  => $colors[$sev],
            ];
        }

        return [
            'data'  => $data,
            'label' => __('Open findings by severity', 'tanium'),
            'icon'  => 'ti ti-bug',
        ];
    }

    /** Count open (non-remediated) findings, optionally for one severity. */
    private static function openFindings(?string $severity = null): int {
        global $DB;

        $sevSql = $severity !== null
            ? " AND LOWER(v.severity) = '" . $DB->escape(strtolower($severity)) . "'"
            : '';

        $row = $DB->doQuery("
            SELECT COUNT(*) AS cpt
            FROM glpi_plugin_tanium_endpoint_cves ec
            JOIN glpi_plugin_tanium_vulnerabilities v ON v.cve_id = ec.cve_id
            WHERE ec.status != 'remediated'{$sevSql}
        ")->fetch_assoc();

        return (int)($row['cpt'] ?? 0);
    }
}
