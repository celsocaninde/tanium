<?php

namespace GlpiPlugin\Tanium;

use Session;

/**
 * Eradicating one thing across the fleet, tracked until it is gone.
 *
 * The Action Plan answers "what should I do first" and re-answers it every
 * time the data moves — which is right for triage and useless for follow
 * through. Nothing in the plugin could say "we decided to kill this advisory,
 * here is how far we got, here is the date we said". A campaign is that
 * commitment: a target, an owner, a due date, and progress measured against
 * where it stood when the decision was made.
 *
 * Progress is never stored. It is recomputed from the live patch/CVE tables on
 * every read, so it cannot drift the way a cached counter does — the number on
 * screen is always what the fleet actually looks like right now, not what some
 * job last wrote down.
 */
class Campaign {

    public static $table = 'glpi_plugin_tanium_campaigns';

    /** A campaign targets either a patch (by patch_id) or a CVE (by cve_id). */
    public const TYPES = ['patch', 'cve'];

    // ── CRUD ─────────────────────────────────────────────────────────────

    /**
     * Open a campaign against a target, snapshotting today's spread as the
     * baseline. Without that snapshot, progress could only ever be "how many
     * are left", which says nothing about how much was done.
     *
     * @return array{success:bool,id?:int,error?:string}
     */
    public static function create(string $type, string $key, array $opts = []): array {
        global $DB;

        $type = in_array($type, self::TYPES, true) ? $type : 'patch';
        $key  = trim($key);
        if ($key === '') {
            return ['success' => false, 'error' => __('No target selected for the campaign.', 'tanium')];
        }

        // Reopening the same fight twice splits the progress in two and neither
        // half tells the truth.
        $dup = $DB->request([
            'FROM'  => self::$table,
            'WHERE' => ['target_type' => $type, 'target_key' => $key, 'status' => 'active'],
            'LIMIT' => 1,
        ])->current();
        if ($dup) {
            return ['success' => false, 'error' => __('An active campaign already targets this item.', 'tanium')];
        }

        $affected = self::affectedCount($type, $key);
        if ($affected === 0) {
            return ['success' => false, 'error' => __('Nothing in the fleet is affected by this target — there is nothing to eradicate.', 'tanium')];
        }

        $due = trim((string)($opts['due_date'] ?? ''));
        $DB->insert(self::$table, [
            'name'           => mb_substr(trim((string)($opts['name'] ?? '')) ?: $key, 0, 255),
            'target_type'    => $type,
            'target_key'     => mb_substr($key, 0, 255),
            'baseline_count' => $affected,
            'due_date'       => preg_match('/^\d{4}-\d{2}-\d{2}$/', $due) ? $due : null,
            'owner_id'       => (int)($opts['owner_id'] ?? 0) ?: null,
            'notes'          => trim((string)($opts['notes'] ?? '')) ?: null,
            'status'         => 'active',
            'created_by'     => (int)Session::getLoginUserID() ?: null,
            'created_at'     => date('Y-m-d H:i:s'),
        ]);

        return ['success' => true, 'id' => (int)$DB->insertId()];
    }

    /** Close a campaign by hand (abandoned, superseded, or simply done). */
    public static function close(int $id, string $status = 'closed'): bool {
        global $DB;

        $status = in_array($status, ['closed', 'cancelled'], true) ? $status : 'closed';
        return (bool)$DB->update(self::$table, [
            'status'    => $status,
            'closed_at' => date('Y-m-d H:i:s'),
        ], ['id' => $id, 'status' => 'active']);
    }

    // ── Progress ─────────────────────────────────────────────────────────

    /**
     * How many endpoints still carry the target.
     *
     * Sensor-noise rows are excluded for patches: a machine nobody could scan
     * is not a machine that still needs the patch, and counting it would make
     * a campaign look permanently stuck at the same handful of hosts.
     */
    public static function affectedCount(string $type, string $key): int {
        global $DB;

        if ($type === 'cve') {
            $row = $DB->request([
                'COUNT' => 'cpt',
                'FROM'  => 'glpi_plugin_tanium_endpoint_cves',
                'WHERE' => ['cve_id' => $key, 'NOT' => ['status' => 'remediated']],
            ])->current();
            return (int)($row['cpt'] ?? 0);
        }

        $n   = 0;
        $res = $DB->doQuery(sprintf(
            "SELECT patch_title, patch_id FROM `glpi_plugin_tanium_patches`
              WHERE patch_id = '%s' AND status = 'missing'",
            $DB->escape($key)
        ));
        while ($res && ($r = $res->fetch_assoc())) {
            if (!Sync::isSensorNoise((string)$r['patch_title'], (string)$r['patch_id'])) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * Endpoints still affected, for the drill-down.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function remainingEndpoints(string $type, string $key, int $limit = 200): array {
        global $DB;

        $sql = $type === 'cve'
            ? sprintf(
                "SELECT a.tanium_eid, a.tanium_name, a.os_name, a.risk_score, a.computers_id, ec.detected_at AS since
                   FROM glpi_plugin_tanium_endpoint_cves ec
                   JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = ec.tanium_eid
                  WHERE ec.cve_id = '%s' AND ec.status != 'remediated'
                  ORDER BY a.risk_score DESC LIMIT %d",
                $DB->escape($key),
                $limit
            )
            : sprintf(
                "SELECT a.tanium_eid, a.tanium_name, a.os_name, a.risk_score, a.computers_id, p.date_mod AS since
                   FROM glpi_plugin_tanium_patches p
                   JOIN glpi_plugin_tanium_assets a ON a.tanium_eid = p.tanium_eid
                  WHERE p.patch_id = '%s' AND p.status = 'missing'
                  ORDER BY a.risk_score DESC LIMIT %d",
                $DB->escape($key),
                $limit
            );

        $out = [];
        $res = $DB->doQuery($sql);
        while ($res && ($r = $res->fetch_assoc())) {
            $out[] = $r;
        }
        return $out;
    }

    /**
     * A campaign plus its live progress.
     *
     * `done` can exceed the baseline when new machines appeared and were fixed
     * too, and can go negative-ish when the target spread to hosts that did not
     * have it on day one. Both are real, so the percentage is clamped for
     * display while the raw counts stay honest underneath.
     *
     * @return array<string,mixed>
     */
    public static function withProgress(array $row): array {
        $baseline  = max(0, (int)$row['baseline_count']);
        $remaining = self::affectedCount((string)$row['target_type'], (string)$row['target_key']);
        $done      = max(0, $baseline - $remaining);
        $pct       = $baseline > 0 ? (int)round(min(100, $done * 100 / $baseline)) : 100;

        $dueTs      = !empty($row['due_date']) ? strtotime((string)$row['due_date']) : null;
        $daysLeft   = $dueTs !== null ? (int)floor(($dueTs - time()) / 86400) : null;
        $isComplete = $remaining === 0;

        return $row + [
            'remaining'   => $remaining,
            'done'        => $done,
            'percent'     => $pct,
            'days_left'   => $daysLeft,
            'is_complete' => $isComplete,
            // Overdue only means something while there is work left: a campaign
            // finished after its date was still finished.
            'is_overdue'  => !$isComplete && $daysLeft !== null && $daysLeft < 0,
        ];
    }

    /**
     * All campaigns with progress, active first, then most recent.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function all(bool $includeClosed = false): array {
        global $DB;

        $where = $includeClosed ? [] : ['status' => 'active'];
        $out   = [];
        foreach ($DB->request([
            'FROM'  => self::$table,
            'WHERE' => $where,
            'ORDER' => ['status ASC', 'created_at DESC'],
        ]) as $row) {
            $out[] = self::withProgress($row);
        }
        return $out;
    }

    public static function get(int $id): ?array {
        global $DB;

        $row = $DB->request(['FROM' => self::$table, 'WHERE' => ['id' => $id], 'LIMIT' => 1])->current();
        return $row ? self::withProgress($row) : null;
    }

    /**
     * Targets worth opening a campaign against: what is missing on the most
     * machines right now, excluding anything already under campaign.
     *
     * @return array<int,array{type:string,key:string,label:string,endpoints:int}>
     */
    public static function suggestions(int $limit = 15): array {
        global $DB;

        $taken = [];
        foreach ($DB->request([
            'SELECT' => ['target_type', 'target_key'],
            'FROM'   => self::$table,
            'WHERE'  => ['status' => 'active'],
        ]) as $r) {
            $taken[$r['target_type'] . '|' . $r['target_key']] = true;
        }

        $out = [];
        $res = $DB->doQuery(sprintf(
            "SELECT patch_id, MAX(patch_title) AS title, MAX(severity) AS severity, COUNT(*) AS eps
               FROM `glpi_plugin_tanium_patches`
              WHERE status = 'missing'
              GROUP BY patch_id
              ORDER BY eps DESC
              LIMIT %d",
            $limit * 3
        ));
        while ($res && ($r = $res->fetch_assoc())) {
            $key = (string)$r['patch_id'];
            if (isset($taken['patch|' . $key])) {
                continue;
            }
            if (Sync::isSensorNoise((string)$r['title'], $key)) {
                continue;
            }
            $out[] = [
                'type'      => 'patch',
                'key'       => $key,
                'label'     => (string)$r['title'],
                'severity'  => (string)$r['severity'],
                'endpoints' => (int)$r['eps'],
            ];
            if (count($out) >= $limit) {
                break;
            }
        }
        return $out;
    }
}
