<?php

namespace GlpiPlugin\Tanium;

/**
 * Ranks what to do next by how much fleet risk each action actually removes.
 *
 * The gap this closes: the plugin was very good at saying *how bad* things are
 * and useless at saying *what to do first*. One reference endpoint listed
 * 1.233 open CVEs; the fleet had 114 endpoints in the critical band. No
 * ordering, no batching, no notion that one Windows cumulative update was
 * missing on 99 machines at once.
 *
 * So instead of ranking findings by severity — which just reproduces the same
 * flat list — this simulates each candidate action against the real risk model
 * and sorts by the points it removes across the whole fleet. Applying one KB to
 * 99 machines and closing one exotic CVE on one machine are finally comparable.
 *
 * Three kinds of action are considered:
 *
 *   patch    — deploy one patch everywhere it is missing
 *   cve      — remediate one CVE everywhere it is open
 *   migrate  — replace an operating system that is past end of support
 *
 * Migration is included because on an EOL host the other two do not exist as
 * options: no patch is coming. Leaving it out of the ranking is what let a
 * Server 2012 R2 box sit at 204 open critical CVEs while the team worked the
 * patch queue.
 */
class ActionPlan {

    /** Actions returned by default. */
    public const DEFAULT_LIMIT = 25;

    /**
     * Recompute one endpoint's score with some findings taken away.
     *
     * Pure on purpose — this is the heart of the ranking and the test suite
     * mirrors it.
     *
     * `lifecycle` is the full array from Lifecycle::status(), which is what
     * buildState() stores and what rank() already reads as
     * `$s['lifecycle']['state']`. This method used to cast that array straight
     * to string: PHP turned it into the literal "Array", so the end-of-support
     * floor never matched and every simulation on an unsupported host came out
     * lower than the truth — the exact hosts where no patch will ever help.
     * It also emitted one "Array to string conversion" warning per call, which
     * on a debug instance inflated the Action Plan page to 22 MB. The mirrored
     * test passed throughout because it fed the documented string instead of
     * the shape production actually stores.
     *
     * @param array{cves:array<string,int>,kev:int,patches:array<string,int>,lifecycle:array{state:string}} $state
     * @param array{cves?:array<string,int>,kev?:int,patches?:array<string,int>}                            $remove
     */
    public static function simulate(array $state, array $remove): int {
        $cves    = $state['cves'];
        $patches = $state['patches'];
        $kev     = (int) $state['kev'];

        foreach (($remove['cves'] ?? []) as $sev => $n) {
            if (isset($cves[$sev])) {
                $cves[$sev] = max(0, $cves[$sev] - (int) $n);
            }
        }
        foreach (($remove['patches'] ?? []) as $sev => $n) {
            if (isset($patches[$sev])) {
                $patches[$sev] = max(0, $patches[$sev] - (int) $n);
            }
        }
        $kev = max(0, $kev - (int) ($remove['kev'] ?? 0));

        $result = Risk::score(Risk::tierCounts($cves, $kev, $patches));
        $result = Risk::applyLifecycleFloor($result, (string) ($state['lifecycle']['state'] ?? ''));

        return (int) $result['score'];
    }

    /**
     * Order actions by fleet risk removed, then by blast radius.
     *
     * The tie-break matters: two actions that free the same number of points
     * are not equal if one touches 40 machines and the other touches 2 — the
     * broad one is usually a single deployment, the narrow one is 2 separate
     * investigations.
     *
     * @param array<int,array<string,mixed>> $actions
     * @return array<int,array<string,mixed>>
     */
    public static function rank(array $actions, int $limit = self::DEFAULT_LIMIT): array {
        usort($actions, static function (array $a, array $b): int {
            return [$b['risk_removed'], $b['endpoints']] <=> [$a['risk_removed'], $a['endpoints']];
        });

        return array_slice($actions, 0, max(1, $limit));
    }

    /**
     * Build the ranked plan from live data.
     *
     * @return array{actions:array<int,array<string,mixed>>,fleet:array<string,mixed>}
     */
    public static function build(int $limit = self::DEFAULT_LIMIT): array {
        global $DB;

        $state = self::fleetState();
        if ($state === []) {
            return ['actions' => [], 'fleet' => ['endpoints' => 0, 'risk_total' => 0, 'avg' => 0.0]];
        }

        $riskTotal = 0;
        foreach ($state as $s) {
            $riskTotal += $s['score'];
        }

        $actions = array_merge(
            self::patchActions($state),
            self::cveActions($state),
            self::migrationActions($state)
        );

        foreach ($actions as &$a) {
            $a['avg_impact'] = $riskTotal > 0
                ? round($a['risk_removed'] / count($state), 2)
                : 0.0;
        }
        unset($a);

        return [
            'actions' => self::rank($actions, $limit),
            'fleet'   => [
                'endpoints'  => count($state),
                'risk_total' => $riskTotal,
                'avg'        => round($riskTotal / count($state), 1),
            ],
        ];
    }

    /**
     * Current composition and score of every endpoint, keyed by EID.
     *
     * Four grouped queries for the whole fleet — never one per endpoint. The
     * previous version of the sync learned that lesson the hard way.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function fleetState(): array {
        global $DB;

        $state = [];
        foreach ($DB->doQuery(
            "SELECT a.tanium_eid, a.tanium_name, a.os_name, a.os_version, a.computers_id
               FROM glpi_plugin_tanium_assets a
              WHERE 1=1" . Profile::entityRestrictSql('a')
        ) as $a) {
            $eid = (string) $a['tanium_eid'];
            $state[$eid] = [
                'name'      => (string) ($a['tanium_name'] ?: $eid),
                'os_name'   => (string) ($a['os_name'] ?? ''),
                'computers_id' => $a['computers_id'] !== null ? (int) $a['computers_id'] : null,
                'cves'      => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
                'kev'       => 0,
                'patches'   => ['critical' => 0, 'important' => 0, 'moderate' => 0, 'low' => 0],
                'lifecycle' => Lifecycle::status($a['os_name'] ?? null, $a['os_version'] ?? null),
                'score'     => 0,
            ];
        }

        $kevSet = Enrichment::kevSet();

        foreach ($DB->request([
            'SELECT' => ['tanium_eid', 'cve_id', 'severity'],
            'FROM'   => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE'  => ['status' => ['!=', 'remediated']],
        ]) as $c) {
            $eid = (string) $c['tanium_eid'];
            if (!isset($state[$eid])) {
                continue;
            }
            $sev = strtolower((string) ($c['severity'] ?? 'low'));
            if (!isset($state[$eid]['cves'][$sev])) {
                $sev = 'low';
            }
            $state[$eid]['cves'][$sev]++;
            if (isset($kevSet[strtoupper((string) $c['cve_id'])])) {
                $state[$eid]['kev']++;
            }
        }

        foreach ($DB->request([
            'SELECT' => ['tanium_eid', 'patch_id', 'patch_title', 'severity'],
            'FROM'   => 'glpi_plugin_tanium_patches',
            'WHERE'  => ['status' => 'missing'],
        ]) as $p) {
            $eid = (string) $p['tanium_eid'];
            if (!isset($state[$eid])
                || Sync::isSensorNoise((string) ($p['patch_title'] ?? ''), (string) ($p['patch_id'] ?? ''))
            ) {
                continue;
            }
            $sev = strtolower((string) ($p['severity'] ?? 'low'));
            if (!isset($state[$eid]['patches'][$sev])) {
                $sev = 'low';
            }
            $state[$eid]['patches'][$sev]++;
        }

        foreach ($state as $eid => $s) {
            $result = Risk::score(Risk::tierCounts($s['cves'], $s['kev'], $s['patches']));
            $result = Risk::applyLifecycleFloor($result, $s['lifecycle']['state']);
            $state[$eid]['score'] = $result['score'];
        }

        return $state;
    }

    /**
     * One action per patch, scored by deploying it everywhere it is missing.
     *
     * @param array<string,array<string,mixed>> $state
     * @return array<int,array<string,mixed>>
     */
    private static function patchActions(array $state): array {
        global $DB;

        $groups = [];
        foreach ($DB->request([
            'SELECT' => ['tanium_eid', 'patch_id', 'patch_title', 'severity'],
            'FROM'   => 'glpi_plugin_tanium_patches',
            'WHERE'  => ['status' => 'missing'],
        ]) as $p) {
            $eid = (string) $p['tanium_eid'];
            $id  = trim((string) $p['patch_id']);
            if ($id === '' || !isset($state[$eid])
                || Sync::isSensorNoise((string) ($p['patch_title'] ?? ''), $id)
            ) {
                continue;
            }
            $sev = strtolower((string) ($p['severity'] ?? 'low'));
            if (!isset($state[$eid]['patches'][$sev])) {
                $sev = 'low';
            }

            $groups[$id]['title']      ??= (string) ($p['patch_title'] ?? $id);
            $groups[$id]['severity']   ??= $sev;
            $groups[$id]['targets'][]    = ['eid' => $eid, 'severity' => $sev];
        }

        $actions = [];
        foreach ($groups as $id => $g) {
            $removed = 0;
            $eids    = [];
            foreach ($g['targets'] as $t) {
                $eid   = $t['eid'];
                $after = self::simulate($state[$eid], ['patches' => [$t['severity'] => 1]]);
                $removed += $state[$eid]['score'] - $after;
                $eids[$eid] = true;
            }

            $actions[] = [
                'type'         => 'patch',
                'key'          => $id,
                'title'        => $g['title'],
                'severity'     => $g['severity'],
                'endpoints'    => count($eids),
                'findings'     => count($g['targets']),
                'risk_removed' => $removed,
                'eids'         => array_slice(array_keys($eids), 0, 5),
            ];
        }

        return $actions;
    }

    /**
     * One action per CVE, scored by remediating it everywhere it is open.
     *
     * @param array<string,array<string,mixed>> $state
     * @return array<int,array<string,mixed>>
     */
    private static function cveActions(array $state): array {
        global $DB;

        $kevSet = Enrichment::kevSet();

        $groups = [];
        foreach ($DB->request([
            'SELECT' => ['tanium_eid', 'cve_id', 'severity'],
            'FROM'   => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE'  => ['status' => ['!=', 'remediated']],
        ]) as $c) {
            $eid = (string) $c['tanium_eid'];
            $id  = strtoupper(trim((string) $c['cve_id']));
            if ($id === '' || !isset($state[$eid])) {
                continue;
            }
            $sev = strtolower((string) ($c['severity'] ?? 'low'));
            if (!isset($state[$eid]['cves'][$sev])) {
                $sev = 'low';
            }

            $groups[$id]['severity'] ??= $sev;
            $groups[$id]['kev']        = isset($kevSet[$id]);
            $groups[$id]['targets'][]  = ['eid' => $eid, 'severity' => $sev];
        }

        $actions = [];
        foreach ($groups as $id => $g) {
            $removed = 0;
            $eids    = [];
            foreach ($g['targets'] as $t) {
                $eid    = $t['eid'];
                $remove = ['cves' => [$t['severity'] => 1]];
                if ($g['kev']) {
                    $remove['kev'] = 1;
                }
                $after    = self::simulate($state[$eid], $remove);
                $removed += $state[$eid]['score'] - $after;
                $eids[$eid] = true;
            }

            $actions[] = [
                'type'         => 'cve',
                'key'          => $id,
                'title'        => $id,
                'severity'     => $g['severity'],
                'kev'          => (bool) $g['kev'],
                'endpoints'    => count($eids),
                'findings'     => count($g['targets']),
                'risk_removed' => $removed,
                'eids'         => array_slice(array_keys($eids), 0, 5),
            ];
        }

        return $actions;
    }

    /**
     * One action per end-of-support product still in the fleet.
     *
     * Scored as the *whole* current risk of those endpoints, not as a partial
     * reduction: migrating replaces the operating system, so the findings that
     * belong to it go with it. That is also the honest comparison — on these
     * machines the patch and CVE actions above are not available at all.
     *
     * @param array<string,array<string,mixed>> $state
     * @return array<int,array<string,mixed>>
     */
    private static function migrationActions(array $state): array {
        $groups = [];
        foreach ($state as $eid => $s) {
            if (($s['lifecycle']['state'] ?? '') !== 'eol') {
                continue;
            }
            $product = (string) ($s['lifecycle']['product'] ?? 'desconhecido');
            $groups[$product]['eol_date'] ??= (string) ($s['lifecycle']['eol_date'] ?? '');
            $groups[$product]['days']     ??= (int) ($s['lifecycle']['days'] ?? 0);
            $groups[$product]['eids'][]     = $eid;
            $groups[$product]['risk']       = ($groups[$product]['risk'] ?? 0) + $s['score'];
        }

        $actions = [];
        foreach ($groups as $product => $g) {
            $actions[] = [
                'type'         => 'migrate',
                'key'          => $product,
                'title'        => $product,
                'severity'     => 'critical',
                'eol_date'     => $g['eol_date'],
                'days_overdue' => abs($g['days']),
                'endpoints'    => count($g['eids']),
                'findings'     => count($g['eids']),
                'risk_removed' => $g['risk'],
                'eids'         => array_slice($g['eids'], 0, 5),
            ];
        }

        return $actions;
    }
}
