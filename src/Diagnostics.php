<?php

namespace GlpiPlugin\Tanium;

/**
 * Self-report: what state is the plugin actually in?
 *
 * Everything here was already knowable — in the cron table, in the config row,
 * in the log file — and none of it was visible anywhere in the interface. That
 * gap has a cost: in July 2026 the sync task sat wedged in STATE_RUNNING for 26
 * days while every other Tanium task kept running, and nothing on screen said
 * so. The fleet data simply stopped moving.
 *
 * Everything is derived on read. Nothing here is cached or stored, so the page
 * cannot itself go stale and start lying — which is the failure mode it exists
 * to prevent.
 */
class Diagnostics {

    /**
     * How far past its own configured interval a sync may drift.
     *
     * Measured as a multiple of `cron_frequency` rather than a fixed window: a
     * tenant syncing once a day is not late at hour seven, and a tenant syncing
     * hourly is late long before hour six. A fixed six-hour threshold called a
     * daily sync stale for eighteen hours out of every twenty-four — the check
     * cried wolf about a schedule that was being honoured exactly, which is how
     * a diagnostics page teaches people to ignore it.
     */
    private const SYNC_LATE_WARN  = 1.5;
    private const SYNC_LATE_ERROR = 3.0;

    /** Floor for the warning window, so an hourly sync is not judged by the minute. */
    private const SYNC_LATE_MIN_HOURS = 2;

    /** Cron whose last run is older than this many times its own frequency. */
    private const CRON_LATE_FACTOR = 3;

    public const OK    = 'ok';
    public const WARN  = 'warn';
    public const ERROR = 'error';

    /**
     * Worst status across every check, so callers can render one badge.
     *
     * @param array<int,array{status:string}> $checks
     */
    public static function worst(array $checks): string {
        foreach ([self::ERROR, self::WARN] as $level) {
            foreach ($checks as $c) {
                if (($c['status'] ?? self::OK) === $level) {
                    return $level;
                }
            }
        }
        return self::OK;
    }

    /**
     * Headline checks, worst first when rendered.
     *
     * @return array<int,array{key:string,label:string,status:string,value:string,detail:string}>
     */
    public static function checks(): array {
        $config = Config::getConfig();

        return array_merge(
            [self::checkSync($config), self::checkToken($config), self::checkRecipients($config)],
            self::capabilityChecks($config),
            [self::checkUnratedFindings(), self::checkSensorNoise()]
        );
    }

    /**
     * Missing patches the vendor never rated.
     *
     * They still count toward risk — at the lowest tier, because an unrated
     * finding must not be a free pass — but they are guesses, and a fleet with
     * many of them has a risk number resting partly on an assumption. Saying so
     * is the honest thing; hiding it inside the "low" bucket is not.
     */
    private static function checkUnratedFindings(): array {
        global $DB;

        $row = $DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_plugin_tanium_patches',
            'WHERE' => ['status' => 'missing', 'severity' => 'unknown'],
        ])->current();
        $n = (int) ($row['cpt'] ?? 0);

        if ($n === 0) {
            return self::row('unrated', __('Patches without a severity', 'tanium'), self::OK, '0', '');
        }

        return self::row('unrated', __('Patches without a severity', 'tanium'), self::WARN,
            number_format($n),
            __('The vendor shipped no rating for these, so they count at the lowest tier. Their contribution to the risk score is an assumption, not a measurement.', 'tanium'));
    }

    /**
     * Rows that are the patch sensor reporting its own failure.
     *
     * "No Scan Results Found" is not a missing patch, it is a machine nobody
     * managed to scan — a visibility gap. It is excluded from the risk score
     * and the action plan, but it still sits in the patch list inflating
     * counts, so it is worth stating how much of the list is not real.
     */
    private static function checkSensorNoise(): array {
        global $DB;

        $res = $DB->doQuery(
            "SELECT COUNT(*) AS cpt FROM `glpi_plugin_tanium_patches`
              WHERE status = 'missing'
                AND LOWER(CONCAT(patch_title, ' ', patch_id)) REGEXP
                    'no scan results|no results found|tse-error|error:|not applicable'"
        );
        $n = $res ? (int) ($res->fetch_assoc()['cpt'] ?? 0) : 0;

        if ($n === 0) {
            return self::row('noise', __('Unscanned endpoints in the patch list', 'tanium'), self::OK, '0', '');
        }

        return self::row('noise', __('Unscanned endpoints in the patch list', 'tanium'), self::WARN,
            number_format($n),
            __('These rows are the Tanium patch sensor reporting that it could not scan the machine. They are excluded from the risk score, but they are a visibility gap worth chasing.', 'tanium'));
    }

    private static function checkSync(array $config): array {
        global $DB;

        $last = $DB->request([
            'FROM'  => 'glpi_plugin_tanium_sync_logs',
            'WHERE' => ['status' => 'success'],
            'ORDER' => 'started_at DESC',
            'LIMIT' => 1,
        ])->current();

        if (!$last) {
            return self::row('sync', __('Last successful sync', 'tanium'), self::ERROR,
                __('never', 'tanium'),
                __('No sync has ever completed successfully. Check the API URL, the token and the cron.', 'tanium'));
        }

        $ageHours = (int) floor((time() - (strtotime((string) $last['started_at']) ?: time())) / 3600);

        // A sync currently in flight is not late — it is working.
        if (Sync::isRunning()) {
            return self::row('sync', __('Last successful sync', 'tanium'), self::OK,
                sprintf(__('%dh ago', 'tanium'), $ageHours),
                __('A synchronization is running right now.', 'tanium'));
        }

        // Judged against the interval the tenant actually asked for — the same
        // value `Cron::crontaniumsync()` uses to decide whether a run is due.
        $interval = max(1, (int) ($config['cron_frequency'] ?? 24));
        $status   = self::syncStatus($ageHours, $interval);

        return self::row('sync', __('Last successful sync', 'tanium'), $status,
            sprintf(__('%dh ago', 'tanium'), $ageHours),
            $status === self::OK
                ? sprintf(__('%d endpoint(s) on the last run.', 'tanium'), (int) $last['total'])
                : sprintf(__('The fleet data is no longer refreshing — a sync is expected every %dh. Check the sync task below.', 'tanium'), $interval));
    }

    /**
     * Where a sync age falls against the interval that was configured for it.
     *
     * Kept separate from the database read so the thresholds can be exercised
     * directly — the surrounding check short-circuits whenever a sync happens
     * to be in flight, which is precisely when the boundaries cannot be tested.
     */
    public static function syncStatus(int $ageHours, int $intervalHours): string {
        $interval = max(1, $intervalHours);
        $warnAt   = max(self::SYNC_LATE_MIN_HOURS, (int) ceil($interval * self::SYNC_LATE_WARN));
        $errorAt  = max($warnAt + 1, (int) ceil($interval * self::SYNC_LATE_ERROR));

        return $ageHours >= $errorAt
            ? self::ERROR
            : ($ageHours >= $warnAt ? self::WARN : self::OK);
    }

    private static function checkToken(array $config): array {
        if (empty($config['api_url']) || empty($config['api_token'])) {
            return self::row('token', __('API credentials', 'tanium'), self::ERROR,
                __('not configured', 'tanium'),
                __('Set the Tanium API URL and token in the plugin configuration.', 'tanium'));
        }

        if (empty($config['token_expires_at'])) {
            return self::row('token', __('API token', 'tanium'), self::WARN,
                __('no expiry set', 'tanium'),
                __('Tanium tokens expire. Record the expiry date so the plugin can warn before the sync stops.', 'tanium'));
        }

        $daysLeft = (int) floor((strtotime((string) $config['token_expires_at']) - time()) / 86400);
        $status   = $daysLeft < 0 ? self::ERROR : ($daysLeft <= 14 ? self::WARN : self::OK);

        return self::row('token', __('API token', 'tanium'), $status,
            $daysLeft < 0
                ? sprintf(__('expired %d day(s) ago', 'tanium'), abs($daysLeft))
                : sprintf(__('%d day(s) left', 'tanium'), $daysLeft),
            $status === self::OK ? '' : __('Renew the token in the Tanium console and update it here.', 'tanium'));
    }

    private static function checkRecipients(array $config): array {
        $wantsMail = !empty($config['notify_critical'])
            || !empty($config['notify_remediation'])
            || !empty($config['notify_email'])
            || !empty($config['notify_users']);

        if (!$wantsMail) {
            return self::row('mail', __('Email recipients', 'tanium'), self::OK,
                __('alerts off', 'tanium'), '');
        }

        $recipients = Config::resolveNotifyRecipients($config);
        if ($recipients === []) {
            return self::row('mail', __('Email recipients', 'tanium'), self::WARN,
                __('none', 'tanium'),
                __('Email alerts are enabled but no recipient resolves to an address — every alert is silently dropped.', 'tanium'));
        }

        return self::row('mail', __('Email recipients', 'tanium'), self::OK,
            sprintf(__('%d configured', 'tanium'), count($recipients)), '');
    }

    /**
     * What the Gateway refused last time the plugin asked.
     *
     * These are recorded by the sync and were, until now, visible only in the
     * log file — so a tenant could be missing whole blocks of data with no
     * indication on screen that anything was absent.
     *
     * @return array<int,array{key:string,label:string,status:string,value:string,detail:string}>
     */
    public static function capabilityChecks(array $config): array {
        $out   = [];
        $level = (int) ($config['caps_extras_level'] ?? 2);

        if ($level < 2) {
            $out[] = self::row('caps_events', __('Gateway: stability data', 'tanium'), self::WARN,
                __('not available', 'tanium'),
                __('The Gateway rejected eventCounts, so application-crash data is missing. It usually needs the event sensors deployed in the tenant.', 'tanium'));
        }
        if ($level < 1) {
            $out[] = self::row('caps_hygiene', __('Gateway: hygiene data', 'tanium'), self::WARN,
                __('not available', 'tanium'),
                __('The Gateway rejected the hygiene block, so disk encryption and Defender health are missing — and the health grade cannot judge them.', 'tanium'));
        }
        // Only worth warning about while the admin still wants the feature.
        // A missing capability nobody asked for is not a problem, and a warning
        // that cannot be acted on is the kind that teaches people to skim past
        // this whole page. Turning group sync off is the action — respect it.
        if (empty($config['caps_groups']) && !empty($config['sync_group_membership'])) {
            $out[] = self::row('caps_groups', __('Gateway: computer groups', 'tanium'), self::WARN,
                __('not available', 'tanium'),
                __('The Gateway does not expose computerGroupMemberships, so group-to-entity mapping cannot run. Turn off "Sync Tanium group membership" in the settings if you do not need it — the documented alternative is to filter endpoints per group with memberOf, which this plugin does not do.', 'tanium'));
        }

        if ($out === []) {
            $out[] = self::row('caps', __('Gateway capabilities', 'tanium'), self::OK,
                __('all available', 'tanium'), '');
        }

        return $out;
    }

    /** Compact label for the capability set, used to detect a transition. */
    public static function capabilitySignature(array $config): string {
        return 'e' . (int) ($config['caps_extras_level'] ?? 2)
             . 'g' . (empty($config['caps_groups']) ? 0 : 1);
    }

    /**
     * Every plugin cron, with whether it is running late.
     *
     * "Late" is measured against each task's own frequency rather than a fixed
     * window, so a 5-minute poller and a daily report are judged fairly.
     *
     * @return array<int,array{name:string,state:string,lastrun:?string,frequency:int,status:string,late_hours:?int}>
     */
    public static function cronTasks(): array {
        global $DB;

        $states = [0 => 'disabled', 1 => 'waiting', 2 => 'running'];
        $rows   = [];

        foreach ($DB->request([
            'SELECT' => ['name', 'state', 'lastrun', 'frequency'],
            'FROM'   => 'glpi_crontasks',
            'WHERE'  => ['itemtype' => ['LIKE', 'GlpiPlugin\\\\Tanium\\\\%']],
            'ORDER'  => 'name',
        ]) as $row) {
            $freq    = max(1, (int) $row['frequency']);
            $lastTs  = strtotime((string) ($row['lastrun'] ?? '')) ?: 0;
            $ageSecs = $lastTs > 0 ? time() - $lastTs : null;
            $state   = (int) $row['state'];

            $status = self::OK;
            if ($state === 0) {
                $status = self::WARN;              // disabled on purpose, but worth seeing
            } elseif ($ageSecs !== null && $ageSecs > $freq * self::CRON_LATE_FACTOR) {
                // A task stuck in RUNNING is the wedge that stops it forever.
                $status = $state === 2 ? self::ERROR : self::WARN;
            }

            $rows[] = [
                'name'       => (string) $row['name'],
                'state'      => $states[$state] ?? (string) $state,
                'lastrun'    => $row['lastrun'] ?? null,
                'frequency'  => $freq,
                'status'     => $status,
                'late_hours' => $ageSecs !== null ? (int) floor($ageSecs / 3600) : null,
            ];
        }

        return $rows;
    }

    /**
     * Row counts for the plugin's tables, so growth and emptiness are both
     * obvious — an empty table usually means a feature nobody turned on.
     *
     * @return array<int,array{table:string,rows:int}>
     */
    public static function tableSizes(): array {
        global $DB;

        $out = [];
        foreach ([
            'assets', 'endpoint_cves', 'patches', 'vulnerabilities', 'cve_enrichment',
            'cve_history', 'patch_history', 'cve_assignments', 'cve_exceptions',
            'patch_deployments', 'remote_actions', 'compliance', 'threat_alerts',
            'campaigns', 'sync_logs',
        ] as $short) {
            $table = 'glpi_plugin_tanium_' . $short;
            if (!$DB->tableExists($table)) {
                continue;
            }
            $row   = $DB->request(['COUNT' => 'cpt', 'FROM' => $table])->current();
            $out[] = ['table' => $short, 'rows' => (int) ($row['cpt'] ?? 0)];
        }
        return $out;
    }

    /** Most recent sync runs, newest first. */
    public static function recentRuns(int $limit = 8): array {
        return Sync::getRecentLogs($limit);
    }

    /** Tail of the plugin log file, newest line last. Empty when absent. */
    public static function logTail(int $lines = 25): array {
        $path = GLPI_LOG_DIR . '/tanium.log';
        if (!is_readable($path)) {
            return [];
        }
        // Read the tail only: the file can grow large and nothing here needs
        // the whole of it.
        $size   = filesize($path) ?: 0;
        $offset = max(0, $size - 64 * 1024);
        $chunk  = (string) @file_get_contents($path, false, null, $offset);
        $all    = array_values(array_filter(explode("\n", $chunk), static fn($l) => trim($l) !== ''));

        return array_slice($all, -$lines);
    }

    private static function row(string $key, string $label, string $status, string $value, string $detail): array {
        return compact('key', 'label', 'status', 'value', 'detail');
    }
}
