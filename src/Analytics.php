<?php

namespace GlpiPlugin\Tanium;

/**
 * Questions the plugin could not answer before: is the queue shrinking, does
 * work stay done, and which machines are worse than their own peers.
 *
 * The dashboard reports the stock of findings. Stock alone cannot tell a team
 * that is winning slowly from one that is losing slowly — both look like "a lot
 * of open CVEs". These read the history tables the sync has been filling all
 * along and report the FLOW.
 *
 * The arithmetic lives in small pure functions so the suite can pin the edge
 * cases (a backlog that never clears, a peer group of one) without a database.
 */
class Analytics {

    // ── Pure arithmetic (mirrored by tests) ──────────────────────────────

    /**
     * Weeks until the backlog reaches zero at the current net closure rate.
     *
     * Returns null when it never gets there — which is the answer that matters
     * most and the one a naive division hides by returning a negative number
     * that reads like a date. A team closing 10 and opening 12 a week is not
     * "8 weeks away", it is going backwards, and the caller must be able to say
     * so out loud.
     *
     * @param int   $backlog    open findings right now
     * @param float $netPerWeek closed minus opened, averaged per week
     * @return int|null weeks to zero, or null when the backlog is not shrinking
     */
    public static function weeksToZero(int $backlog, float $netPerWeek): ?int {
        if ($backlog <= 0) {
            return 0;
        }
        if ($netPerWeek <= 0) {
            return null;
        }
        return (int) ceil($backlog / $netPerWeek);
    }

    /**
     * Share of completed work that did not stay completed, 0..1.
     *
     * Zero closures means zero rate, not a division by zero: a period where
     * nothing was fixed has no reincidence to measure.
     */
    public static function reincidenceRate(int $reopened, int $closed): float {
        if ($closed <= 0) {
            return 0.0;
        }
        return min(1.0, $reopened / $closed);
    }

    /**
     * Median of a list of numbers. Empty list is 0.
     *
     * Median, not mean: one machine with 400 findings would drag a mean up far
     * enough to make itself look normal, which defeats the whole point of
     * comparing against peers.
     *
     * @param array<int,int|float> $values
     */
    public static function median(array $values): float {
        $values = array_values(array_filter($values, static fn($v) => $v !== null));
        sort($values);
        $n = count($values);
        if ($n === 0) {
            return 0.0;
        }
        $mid = intdiv($n, 2);
        return $n % 2 === 1
            ? (float) $values[$mid]
            : ((float) $values[$mid - 1] + (float) $values[$mid]) / 2;
    }

    /**
     * How far above its peers an endpoint sits, as a multiple of the median.
     *
     * A peer median of zero means the whole group is clean, so any finding at
     * all is the endpoint standing alone: report the raw count as the multiple
     * rather than dividing by zero.
     */
    public static function outlierRatio(int $findings, float $peerMedian): float {
        if ($peerMedian <= 0) {
            return $findings > 0 ? (float) $findings : 0.0;
        }
        return $findings / $peerMedian;
    }

    /** A peer group smaller than this cannot establish a normal to deviate from. */
    public const MIN_PEERS = 4;

    /** Multiple of the peer median above which an endpoint is worth a look. */
    public const OUTLIER_THRESHOLD = 2.0;

    // ── Burn-down ────────────────────────────────────────────────────────

    /**
     * Opened vs closed per ISO week, oldest first.
     *
     * @return array<int,array{week:string,cve_opened:int,cve_closed:int,patch_opened:int,patch_closed:int}>
     */
    public static function weeklyFlow(int $weeks = 12): array {
        global $DB;

        $weeks  = max(2, min(52, $weeks));
        $buckets = [];
        for ($i = $weeks - 1; $i >= 0; $i--) {
            $buckets[date('o-W', strtotime("-{$i} weeks"))] = [
                'week'         => date('o-W', strtotime("-{$i} weeks")),
                'cve_opened'   => 0,
                'cve_closed'   => 0,
                'patch_opened' => 0,
                'patch_closed' => 0,
            ];
        }

        $since = date('Y-m-d 00:00:00', strtotime('monday this week -' . ($weeks - 1) . ' weeks'));

        $sources = [
            ['glpi_plugin_tanium_cve_history',   'cve',   ['open'], ['remediated']],
            ['glpi_plugin_tanium_patch_history', 'patch', ['missing'], ['installed', 'remediated']],
        ];

        foreach ($sources as [$table, $prefix, $openStates, $closedStates]) {
            if (!$DB->tableExists($table)) {
                continue;
            }
            $res = $DB->doQuery(sprintf(
                "SELECT DATE_FORMAT(changed_at, '%%x-%%v') AS wk, new_status, COUNT(*) AS cpt
                   FROM `%s`
                  WHERE changed_at >= '%s'
                  GROUP BY wk, new_status",
                $table,
                $DB->escape($since)
            ));
            while ($res && ($row = $res->fetch_assoc())) {
                $wk = (string) $row['wk'];
                if (!isset($buckets[$wk])) {
                    continue;
                }
                $status = (string) $row['new_status'];
                if (in_array($status, $openStates, true)) {
                    $buckets[$wk][$prefix . '_opened'] += (int) $row['cpt'];
                } elseif (in_array($status, $closedStates, true)) {
                    $buckets[$wk][$prefix . '_closed'] += (int) $row['cpt'];
                }
            }
        }

        return array_values($buckets);
    }

    /**
     * Backlog, net weekly movement and the resulting forecast.
     *
     * The most recent week is excluded from the average: it is still in
     * progress, so counting it always drags the rate down and makes every
     * forecast look worse than it is.
     *
     * @return array{cve:array,patch:array,flow:array}
     */
    public static function burndown(int $weeks = 12): array {
        global $DB;

        $flow     = self::weeklyFlow($weeks);
        $complete = count($flow) > 1 ? array_slice($flow, 0, -1) : $flow;
        $n        = max(1, count($complete));

        $openCve = (int) ($DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
            'WHERE' => ['NOT' => ['status' => 'remediated']],
        ])->current()['cpt'] ?? 0);

        $openPatch = (int) ($DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_plugin_tanium_patches',
            'WHERE' => ['status' => 'missing'],
        ])->current()['cpt'] ?? 0);

        $build = static function (string $prefix, int $backlog) use ($complete, $n): array {
            $opened = array_sum(array_column($complete, $prefix . '_opened'));
            $closed = array_sum(array_column($complete, $prefix . '_closed'));
            $net    = ($closed - $opened) / $n;

            return [
                'backlog'        => $backlog,
                'opened_total'   => $opened,
                'closed_total'   => $closed,
                'opened_weekly'  => round($opened / $n, 1),
                'closed_weekly'  => round($closed / $n, 1),
                'net_weekly'     => round($net, 1),
                'weeks_to_zero'  => self::weeksToZero($backlog, $net),
                'direction'      => $net > 0 ? 'shrinking' : ($net < 0 ? 'growing' : 'flat'),
            ];
        };

        return [
            'cve'   => $build('cve', $openCve),
            'patch' => $build('patch', $openPatch),
            'flow'  => $flow,
        ];
    }

    // ── Reincidence ──────────────────────────────────────────────────────

    /**
     * Work that did not stay done: a patch installed and later missing again,
     * or a CVE remediated and later open again on the same endpoint.
     *
     * A high rate is rarely the team's fault — it points at a base image that
     * still ships the old package, a GPO putting it back, or a repository that
     * serves an outdated version. Buried inside raw volume, that pattern is
     * invisible; on its own it is a root cause worth one fix instead of
     * hundreds of repeated ones.
     *
     * @return array{patch:array,cve:array,offenders:array}
     */
    public static function reincidence(int $days = 90): array {
        global $DB;

        $days  = max(7, min(365, $days));
        $since = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        $count = static function (string $table, string $from, string $to) use ($DB, $since): int {
            if (!$DB->tableExists($table)) {
                return 0;
            }
            $row = $DB->doQuery(sprintf(
                "SELECT COUNT(*) AS cpt FROM `%s`
                  WHERE changed_at >= '%s' AND old_status = '%s' AND new_status = '%s'",
                $table,
                $DB->escape($since),
                $DB->escape($from),
                $DB->escape($to)
            ));
            return $row ? (int) ($row->fetch_assoc()['cpt'] ?? 0) : 0;
        };

        $patchReopened = $count('glpi_plugin_tanium_patch_history', 'installed', 'missing');
        $patchClosed   = $count('glpi_plugin_tanium_patch_history', 'missing', 'installed');
        $cveReopened   = $count('glpi_plugin_tanium_cve_history', 'remediated', 'open');
        $cveClosed     = $count('glpi_plugin_tanium_cve_history', 'open', 'remediated');

        // Endpoints where the same item bounced most often — the machines whose
        // configuration is undoing the work.
        $offenders = [];
        if ($DB->tableExists('glpi_plugin_tanium_patch_history')) {
            $res = $DB->doQuery(sprintf(
                "SELECT h.tanium_eid, a.tanium_name, a.os_name, a.computers_id,
                        COUNT(*) AS reopened, COUNT(DISTINCT h.patch_id) AS distinct_patches
                   FROM `glpi_plugin_tanium_patch_history` h
                   LEFT JOIN `glpi_plugin_tanium_assets` a ON a.tanium_eid = h.tanium_eid
                  WHERE h.changed_at >= '%s' AND h.old_status = 'installed' AND h.new_status = 'missing'
                  GROUP BY h.tanium_eid, a.tanium_name, a.os_name, a.computers_id
                  ORDER BY reopened DESC
                  LIMIT 25",
                $DB->escape($since)
            ));
            while ($res && ($row = $res->fetch_assoc())) {
                $offenders[] = $row;
            }
        }

        return [
            'days'  => $days,
            'patch' => [
                'reopened' => $patchReopened,
                'closed'   => $patchClosed,
                'rate'     => self::reincidenceRate($patchReopened, $patchClosed),
            ],
            'cve' => [
                'reopened' => $cveReopened,
                'closed'   => $cveClosed,
                'rate'     => self::reincidenceRate($cveReopened, $cveClosed),
            ],
            'offenders' => $offenders,
        ];
    }

    // ── Peer outliers ────────────────────────────────────────────────────

    /**
     * Endpoints carrying far more open findings than machines just like them.
     *
     * Peers are same OS family and same virtual/physical nature — close enough
     * that a large gap points at configuration drift on that one host rather
     * than at a fleet-wide gap. A machine with twice its group's median is not
     * "missing patches", it is different from its siblings, and that is a
     * different fix.
     *
     * @return array{groups:int,outliers:array<int,array<string,mixed>>}
     */
    public static function outliers(int $limit = 40): array {
        global $DB;

        $rows = [];
        $res  = $DB->doQuery("
            SELECT a.tanium_eid, a.tanium_name, a.os_name, a.is_virtual, a.risk_score, a.computers_id,
                   (SELECT COUNT(*) FROM glpi_plugin_tanium_endpoint_cves ec
                     WHERE ec.tanium_eid = a.tanium_eid AND ec.status != 'remediated') AS open_cves,
                   (SELECT COUNT(*) FROM glpi_plugin_tanium_patches p
                     WHERE p.tanium_eid = a.tanium_eid AND p.status = 'missing') AS missing_patches
              FROM glpi_plugin_tanium_assets a
             WHERE a.retired_at IS NULL" . Profile::entityRestrictSql('a') . "
        ");
        while ($res && ($row = $res->fetch_assoc())) {
            $rows[] = $row;
        }

        // Group by OS family + virtualisation. The family is the first two
        // words of the OS name, so "Ubuntu 22.04" and "Ubuntu 24.04" compare
        // against each other instead of each forming a group of one.
        $groups = [];
        foreach ($rows as $r) {
            $key = self::peerKey((string) ($r['os_name'] ?? ''), (int) ($r['is_virtual'] ?? 0));
            $groups[$key][] = $r;
        }

        $out = [];
        foreach ($groups as $key => $members) {
            if (count($members) < self::MIN_PEERS) {
                continue;
            }
            $median = self::median(array_map(
                static fn(array $m): int => (int) $m['open_cves'] + (int) $m['missing_patches'],
                $members
            ));

            foreach ($members as $m) {
                $findings = (int) $m['open_cves'] + (int) $m['missing_patches'];
                $ratio    = self::outlierRatio($findings, $median);
                if ($ratio < self::OUTLIER_THRESHOLD || $findings === 0) {
                    continue;
                }
                $out[] = $m + [
                    'peer_key'    => $key,
                    'peer_count'  => count($members),
                    'peer_median' => $median,
                    'findings'    => $findings,
                    'ratio'       => round($ratio, 1),
                ];
            }
        }

        usort($out, static fn(array $a, array $b): int => $b['ratio'] <=> $a['ratio']);

        return [
            'groups'   => count(array_filter($groups, static fn(array $g): bool => count($g) >= self::MIN_PEERS)),
            'outliers' => array_slice($out, 0, max(1, $limit)),
        ];
    }

    /**
     * Peer bucket label: product, major version, and virtual vs physical.
     *
     * The product is the leading words before the first number; the major
     * version is that number up to its first dot. So minor releases share a
     * group ("Ubuntu 22.04.3" with "Ubuntu 22.04.5") while major generations
     * do not.
     *
     * Keeping the major version matters more than it looks. On the reference
     * fleet, dropping it put 22 freshly-built AlmaLinux 10 VMs carrying one
     * finding each into the same bucket as the legacy AlmaLinux 8 servers
     * carrying sixteen hundred. The median collapsed to 1, and every 8.x
     * server was reported as a 1700x outlier — when in truth they were
     * perfectly normal for their own generation, and the comparison itself
     * was the bug. A major version is a different baseline, not a variation.
     */
    public static function peerKey(string $osName, int $isVirtual): string {
        $product = [];
        $major   = '';
        foreach (preg_split('/\s+/', trim($osName)) ?: [] as $word) {
            if ($word === '') {
                continue;
            }
            if (preg_match('/^(\d+)/', $word, $m)) {
                $major = $m[1];
                break;
            }
            $product[] = $word;
        }

        $label = trim(implode(' ', $product));
        if ($label === '') {
            $label = 'unknown';
        }
        if ($major !== '') {
            $label .= ' ' . $major;
        }

        return $label . ($isVirtual ? ' (virtual)' : ' (physical)');
    }
}
