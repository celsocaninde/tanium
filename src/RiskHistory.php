<?php

namespace GlpiPlugin\Tanium;

/**
 * Read access to the per-endpoint risk history.
 *
 * Kept apart from Risk on purpose: Risk is pure arithmetic the test suite can
 * mirror without a database, this is the part that talks to $DB.
 *
 * Rows are written by Sync::updateRiskScore() only when an endpoint's score
 * actually moves, so a gap between two rows means "nothing changed", not
 * "no data".
 */
class RiskHistory {

    /** Default window for the "before → after" comparison, in days. */
    public const WINDOW_DAYS = 30;

    /**
     * Recent score transitions for one endpoint, oldest first.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function forEndpoint(string $eid, int $limit = 30): array {
        global $DB;

        $rows = [];
        foreach ($DB->request([
            'FROM'   => 'glpi_plugin_tanium_endpoint_risk_history',
            'WHERE'  => ['tanium_eid' => $eid],
            'ORDER'  => 'recorded_at DESC',
            'LIMIT'  => max(1, $limit),
        ]) as $row) {
            $rows[] = $row;
        }

        return array_reverse($rows);
    }

    /**
     * Where this endpoint stood at the start of the window versus now.
     *
     * Returns null when there is nothing to compare against — a brand new
     * endpoint, or one whose score has never moved since the plugin started
     * recording. The UI must say "sem histórico ainda" in that case rather
     * than imply a flat line that was never observed.
     *
     * @return array{from:int,to:int,delta:int,since:string,points:array<int,int>}|null
     */
    public static function delta(string $eid, int $currentScore, int $days = self::WINDOW_DAYS): ?array {
        global $DB;

        $since = date('Y-m-d H:i:s', strtotime('-' . max(1, $days) . ' days'));

        $rows = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_tanium_endpoint_risk_history',
            'WHERE' => ['tanium_eid' => $eid, 'recorded_at' => ['>=', $since]],
            'ORDER' => 'recorded_at ASC',
        ]) as $row) {
            $rows[] = $row;
        }

        if ($rows === []) {
            return null;
        }

        // The oldest row in the window records the score it *moved to*; what the
        // endpoint looked like before the window opened is its previous_score.
        $first = $rows[0];
        $from  = $first['previous_score'] !== null
            ? (int) $first['previous_score']
            : (int) $first['risk_score'];

        $points = [];
        foreach ($rows as $row) {
            $points[] = (int) $row['risk_score'];
        }
        $points[] = $currentScore;

        return [
            'from'   => $from,
            'to'     => $currentScore,
            'delta'  => $currentScore - $from,
            'since'  => (string) $first['recorded_at'],
            'points' => $points,
        ];
    }

    /**
     * What was actually fixed on this endpoint inside the window — the number
     * behind the delta, so nobody has to take the score movement on faith.
     *
     * @return array{cves:int,patches:int}
     */
    public static function fixedSince(string $eid, int $days = self::WINDOW_DAYS): array {
        global $DB;

        $since = date('Y-m-d H:i:s', strtotime('-' . max(1, $days) . ' days'));

        $cves = $DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_plugin_tanium_cve_history',
            'WHERE' => [
                'tanium_eid' => $eid,
                'new_status' => 'remediated',
                'changed_at' => ['>=', $since],
            ],
        ])->current();

        $patches = $DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_plugin_tanium_patch_history',
            'WHERE' => [
                'tanium_eid' => $eid,
                'new_status' => 'installed',
                'changed_at' => ['>=', $since],
            ],
        ])->current();

        return [
            'cves'    => (int) ($cves['cpt'] ?? 0),
            'patches' => (int) ($patches['cpt'] ?? 0),
        ];
    }

    /**
     * Inline SVG sparkline of a score series (0-100, higher is worse).
     *
     * Deliberately dependency-free and inline, like the other charts in this
     * plugin — the report has to survive being printed and mailed as PDF.
     */
    public static function sparkline(array $points, int $width = 150, int $height = 34): string {
        $points = array_values(array_map('intval', $points));
        if (count($points) < 2) {
            return '';
        }

        $max  = 100.0;
        $step = $width / (count($points) - 1);

        $coords = [];
        foreach ($points as $i => $value) {
            $x = round($i * $step, 2);
            $y = round($height - ($value / $max) * $height, 2);
            $coords[] = $x . ',' . $y;
        }

        $last   = end($points);
        $colour = match (Risk::band((int) $last)) {
            'critical' => '#e8212a',
            'high'     => '#f97316',
            'medium'   => '#e8c42a',
            default    => '#1eb464',
        };

        return sprintf(
            '<svg viewBox="0 0 %d %d" width="%d" height="%d" preserveAspectRatio="none" role="img">'
            . '<polyline fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" points="%s"/>'
            . '</svg>',
            $width,
            $height,
            $width,
            $height,
            $colour,
            implode(' ', $coords)
        );
    }

    /** Drop history past the configured retention. Used by the purge cron. */
    public static function purge(int $retentionDays): int {
        global $DB;

        $cutoff = date('Y-m-d H:i:s', strtotime('-' . max(30, $retentionDays) . ' days'));
        $DB->delete('glpi_plugin_tanium_endpoint_risk_history', ['recorded_at' => ['<', $cutoff]]);

        return $DB->affectedRows();
    }
}
