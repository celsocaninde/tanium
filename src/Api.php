<?php

namespace GlpiPlugin\Tanium;

class Api {

    private string $baseUrl;
    private string $token;
    private int    $timeout = 30;

    /** Optional blocks this tenant still accepted on the last endpoint sweep. */
    private int  $capsExtrasLevel = 2;
    private bool $capsGroups      = true;

    public function __construct(string $baseUrl, string $token) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->token   = $token;
    }

    /**
     * What eachEndpointPage() ended up being able to ask for, after any
     * progressive degradation. The caller persists it so the next run starts
     * there instead of re-probing blocks the Gateway already rejected.
     *
     * @return array{extrasLevel:int,groups:bool}
     */
    public function discoveredCapabilities(): array {
        return ['extrasLevel' => $this->capsExtrasLevel, 'groups' => $this->capsGroups];
    }

    // ── Endpoints ────────────────────────────────────────────────────────────
    //
    // Endpoint inventory lives in the Tanium GraphQL gateway, NOT in the REST
    // API. There is no `/api/v2/endpoints` route — hitting it returns HTTP 400
    // ("Invalid object route: endpoints"). We query the `endpoints` connection
    // and map each node back to the flat array shape the Sync layer consumes.

    private const GRAPHQL_PATH = '/plugin/products/gateway/graphql';

    // CVE findings (Tanium Comply) and installed software both hang off each
    // endpoint node — they are NOT separate REST products. They are pulled in
    // the same query via @include directives, gated per sync so we don't fetch
    // heavy data nobody asked for.
    private const ENDPOINT_QUERY = <<<'GQL'
query($first: Int!, $after: Cursor, $filter: EndpointFieldFilter, $withCves: Boolean!, $withApps: Boolean!, $withPatches: Boolean!) {
  endpoints(first: $first, after: $after, filter: $filter) {
    totalRecords
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id name domainName serialNumber systemUUID manufacturer model
        ipAddress ipAddresses macAddresses lastLoggedInUser isVirtual eidLastSeen
        os { name generation platform language windows { majorVersion releaseId type } }
        memory { total ram }
        processor { cpu speed logicalProcessors architecture }
        compliance @include(if: $withCves) {
          cveFindings { cveId severity severityV3 cvssScore cvssScoreV3 summary firstFound lastFound excepted }
        }
        installedApplications @include(if: $withApps) { name version }
        sensorReadings(sensors: [{name: "Applicable Patches"}]) @include(if: $withPatches) {
          columns { name values }
        }
        /*GROUPS*/
        /*EXTRAS*/
        /*SENSORS*/
      }
    }
  }
}
GQL;

    /**
     * Optional blocks are NOT gated with @include like the stable ones:
     * GraphQL validates every field in the document even when its @include
     * flag is false, so a tenant whose Gateway lacks a field (schemas vary
     * per version — verified by introspection) would reject the WHOLE sync
     * query with HTTP 400 "Cannot query field". Each optional block is only
     * spliced into the document text when actually requested, and
     * eachEndpointPage retries without them on schema errors.
     *
     * @param string[] $sensors extra Tanium sensor names to collect
     */
    private static function endpointQuery(bool $withGroups, int $extrasLevel = 0, array $sensors = []): string {
        $groups = $withGroups
            ? "computerGroupMemberships {\n          computerGroup { id name }\n        }"
            : '';

        // Hygiene / attack-surface / stability data. Level 2 adds the fragile
        // blocks: eventCounts needs the event sensors deployed and sccmClient
        // needs an extra module permission — both degrade first, keeping the
        // widely-available level-1 fields (encryption, Defender, Discover).
        $extras = '';
        if ($extrasLevel >= 1) {
            $sentinelFields = "windowsDefender { installed healthy antivirusEnabled antivirusSignatureUpdateAge }";
            if ($extrasLevel >= 2) {
                $sentinelFields = "sccmClient { health } " . $sentinelFields;
            }
            $extras = "isEncrypted chassisType\n"
                . "        sentinel { {$sentinelFields} }\n"
                . "        discover { discoverMethod natIpAddress openPorts }";
        }
        if ($extrasLevel >= 2) {
            $extras .= "\n        eventCounts { appCrash all }";
        }

        $sensorBlock = '';
        if ($sensors !== []) {
            $list = implode(', ', array_map(
                static fn(string $s): string => '{name: ' . json_encode($s) . '}',
                $sensors
            ));
            $sensorBlock = "customSensors: sensorReadings(sensors: [{$list}]) {\n          columns { name values }\n        }";
        }

        return str_replace(
            ['/*GROUPS*/', '/*EXTRAS*/', '/*SENSORS*/'],
            [$groups, $extras, $sensorBlock],
            self::ENDPOINT_QUERY
        );
    }

    // Enriched pages (with CVEs/apps) carry far more data per node, so use a
    // smaller page size to keep each response well within memory.
    private const ENRICHED_PAGE_SIZE = 50;
    private const MAX_ENDPOINTS       = 200000; // hard safety cap

    public function getEndpoints(int $limit = 500, int $offset = 0): array {
        // $offset is ignored — the GraphQL connection is cursor-paginated.
        $data = $this->graphql(self::endpointQuery(false), [
            'first' => $limit, 'after' => null,
            'withCves' => false, 'withApps' => false, 'withPatches' => false,
        ]);
        $edges = $data['endpoints']['edges'] ?? [];
        return array_map(fn($e) => self::mapEndpointNode($e['node'] ?? []), $edges);
    }

    /**
     * Stream the endpoint connection page-by-page, invoking $onPage(array $page)
     * for each page of mapped endpoints. Nothing is accumulated here, so the
     * caller controls peak memory — essential for large fleets with CVE/software
     * enrichment, which would otherwise hold 1 GB+ at once.
     */
    /**
     * @param array $opts extras (bool, hygiene block — default true),
     *                    sensors (string[], custom sensor names),
     *                    since (?string ISO-8601 — server-side eidLastSeen > since)
     */
    public function eachEndpointPage(int $pageSize, bool $withCves, bool $withApps, bool $withPatches, callable $onPage, bool $withGroups = false, array $opts = []): void {
        if ($withCves || $withApps || $withPatches) {
            $pageSize = min($pageSize, self::ENRICHED_PAGE_SIZE);
        }

        // Start from what the tenant answered last time instead of always
        // asking for everything: a Gateway without the event sensors rejected
        // eventCounts on every single run, burning one failed round-trip and
        // one log line per sync, forever. The caller re-probes periodically so
        // a module installed later is still picked up.
        $extrasLevel = ($opts['extras'] ?? true) ? (int)($opts['extrasLevel'] ?? 2) : 0;
        $withGroups  = $withGroups && ($opts['groups'] ?? true);
        $sensors     = array_values(array_filter((array)($opts['sensors'] ?? [])));
        $since       = $opts['since'] ?? null;

        $this->capsExtrasLevel = $extrasLevel;
        $this->capsGroups      = $withGroups;

        $after = null;
        $count = 0;
        do {
            $variables = [
                'first'       => $pageSize,
                'after'       => $after,
                'filter'      => $since !== null
                    ? ['path' => 'eidLastSeen', 'op' => 'GT', 'value' => $since]
                    : null,
                'withCves'    => $withCves,
                'withApps'    => $withApps,
                'withPatches' => $withPatches,
            ];

            // Progressive degradation: schema/sensor errors disable the
            // optional block that caused them and retry, instead of failing
            // the sync. Order: groups (explicit) → eventCounts → custom
            // sensors → remaining extras.
            for ($attempt = 0; ; $attempt++) {
                try {
                    $data = $this->graphql(self::endpointQuery($withGroups, $extrasLevel, $sensors), $variables);
                    break;
                } catch (\RuntimeException $e) {
                    $msg         = $e->getMessage();
                    $schemaError = str_contains($msg, 'Cannot query field');
                    // "must refer to an existing sensor": eventCounts or a
                    // misnamed custom sensor. "missing required permissions":
                    // a module block (e.g. sccmClient) the token cannot read.
                    // None of these may kill the sync.
                    $sensorError = stripos($msg, 'sensor') !== false;
                    $permError   = stripos($msg, 'missing required permissions') !== false;

                    if ($attempt >= 4 || (!$schemaError && !$sensorError && !$permError)) {
                        throw $e;
                    }
                    if ($schemaError && $withGroups && str_contains($msg, 'computerGroupMemberships')) {
                        \Toolbox::logInFile('tanium', "[Tanium] Gateway does not expose computerGroupMemberships — group sync skipped.\n");
                        $withGroups            = false;
                        $this->capsGroups      = false;
                    } elseif ($extrasLevel === 2) {
                        \Toolbox::logInFile('tanium', "[Tanium] Gateway rejected eventCounts ({$msg}) — stability data skipped.\n");
                        $extrasLevel           = 1;
                        $this->capsExtrasLevel = 1;
                    } elseif ($sensors !== []) {
                        \Toolbox::logInFile('tanium', "[Tanium] Custom sensors rejected ({$msg}) — skipped. Check the sensor names in the plugin settings.\n");
                        $sensors = [];
                    } elseif ($extrasLevel === 1) {
                        \Toolbox::logInFile('tanium', "[Tanium] Gateway rejected hygiene fields ({$msg}) — extras skipped.\n");
                        $extrasLevel           = 0;
                        $this->capsExtrasLevel = 0;
                    } else {
                        throw $e;
                    }
                }
            }
            $conn = $data['endpoints'] ?? [];

            $page = [];
            foreach ($conn['edges'] ?? [] as $edge) {
                $page[] = self::mapEndpointNode($edge['node'] ?? []);
            }
            if ($page) {
                $onPage($page, (int)($conn['totalRecords'] ?? 0));
                $count += count($page);
            }

            $hasNext = $conn['pageInfo']['hasNextPage'] ?? false;
            $after   = $conn['pageInfo']['endCursor']   ?? null;
        } while ($hasNext && $after !== null && $count < self::MAX_ENDPOINTS);
    }

    private const ENDPOINT_IDS_QUERY = <<<'GQL'
query($first: Int!, $after: Cursor) {
  endpoints(first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { id } }
  }
}
GQL;

    /**
     * Every endpoint id currently in the fleet, and nothing else.
     *
     * Retirement can only be decided by seeing the WHOLE fleet: an endpoint is
     * gone when Tanium stops listing it, and an incremental sync — which
     * returns only what changed — can never establish that. Asking for ids
     * alone keeps the sweep cheap enough to run on its own schedule instead of
     * forcing a full enrichment pass just to find out who left.
     *
     * @return array<string,bool> set of endpoint ids, keyed for O(1) lookup
     */
    public function allEndpointIds(int $pageSize = 1000): array {
        $ids   = [];
        $after = null;
        $count = 0;

        do {
            $data = $this->graphql(self::ENDPOINT_IDS_QUERY, [
                'first' => $pageSize,
                'after' => $after,
            ]);
            $conn = $data['endpoints'] ?? [];

            foreach ($conn['edges'] ?? [] as $edge) {
                $id = (string)($edge['node']['id'] ?? '');
                if ($id !== '') {
                    $ids[$id] = true;
                    $count++;
                }
            }

            $hasNext = $conn['pageInfo']['hasNextPage'] ?? false;
            $after   = $conn['pageInfo']['endCursor']   ?? null;
        } while ($hasNext && $after !== null && $count < self::MAX_ENDPOINTS);

        return $ids;
    }

    public function getAllEndpoints(int $pageSize = 500, bool $withCves = false, bool $withApps = false, bool $withPatches = false, bool $withGroups = false, array $opts = []): array {
        $all = [];
        $this->eachEndpointPage($pageSize, $withCves, $withApps, $withPatches, function (array $page) use (&$all): void {
            foreach ($page as $endpoint) {
                $all[] = $endpoint;
            }
        }, $withGroups, $opts);
        return $all;
    }

    /**
     * Incremental sync — only endpoints last seen after $since (ISO-8601).
     * Filtered server-side ({path: eidLastSeen, op: GT}) so unchanged
     * endpoints never leave Tanium; if the tenant rejects the filter shape,
     * falls back to paging the fleet and filtering client-side.
     */
    public function getAllEndpointsIncremental(string $since, int $pageSize = 500, bool $withCves = false, bool $withApps = false, bool $withPatches = false, bool $withGroups = false, array $opts = []): array {
        try {
            return $this->getAllEndpoints($pageSize, $withCves, $withApps, $withPatches, $withGroups, ['since' => $since] + $opts);
        } catch (\RuntimeException $e) {
            \Toolbox::logInFile('tanium', '[Tanium] Server-side incremental filter rejected (' . $e->getMessage() . ') — falling back to client-side filtering.' . "\n");
        }

        $sinceTs = strtotime($since) ?: 0;
        return array_values(array_filter(
            $this->getAllEndpoints($pageSize, $withCves, $withApps, $withPatches, $withGroups, $opts),
            function (array $e) use ($sinceTs): bool {
                $seen = strtotime($e['lastRegistrationTime'] ?? '') ?: 0;
                return $seen > $sinceTs;
            }
        ));
    }

    /**
     * Map a GraphQL `Endpoint` node onto the flat array shape the Sync layer
     * already expects (computerName, os.version, memory.total in MB, etc.).
     */
    private static function mapEndpointNode(array $n): array {
        $os   = $n['os']        ?? [];
        $win  = $os['windows']  ?? [];
        $mem  = $n['memory']    ?? [];
        $proc = $n['processor'] ?? [];

        return [
            'eid'                  => $n['id']   ?? '',
            'id'                   => $n['id']   ?? '',
            'computerName'         => $n['name'] ?? '',
            'name'                 => $n['name'] ?? '',
            'domainName'           => $n['domainName']      ?? null,
            'serialNumber'         => $n['serialNumber']    ?? null,
            'systemUUID'           => $n['systemUUID']      ?? null,
            'manufacturer'         => $n['manufacturer']    ?? null,
            'model'                => $n['model']           ?? null,
            'ipAddress'            => $n['ipAddress']        ?? null,
            'ipAddresses'          => $n['ipAddresses']     ?? [],
            'macAddresses'         => $n['macAddresses']    ?? [],
            'lastLoggedInUser'     => $n['lastLoggedInUser'] ?? null,
            'isVirtual'            => !empty($n['isVirtual']) ? 1 : 0,
            'lastRegistrationTime' => $n['eidLastSeen']     ?? null,
            'os' => [
                'name'         => $os['name']           ?? null,
                'version'      => $win['releaseId']     ?? $os['generation'] ?? null,
                'build'        => $win['majorVersion']  ?? null,
                'platform'     => $os['platform']       ?? null,
                'architecture' => self::normalizeArch($proc['architecture'] ?? null),
            ],
            'memory'    => ['total' => self::parseMemoryMb($mem['total'] ?? ($mem['ram'] ?? null))],
            'processor' => [
                'name'  => $proc['cpu'] ?? null,
                'speed' => ['mhz'   => self::parseLeadingInt($proc['speed'] ?? null)],
                'core'  => ['count' => (int) ($proc['logicalProcessors'] ?? 0)],
            ],
            // Enrichment (present only when requested via @include).
            'cves'           => self::mapCveFindings($n['compliance']['cveFindings'] ?? []),
            'software'       => self::mapInstalledApplications($n['installedApplications'] ?? []),
            'patches'        => self::mapApplicablePatches($n['sensorReadings'] ?? []),
            // Data-presence flags: distinguish "endpoint is clean" (module
            // answered with an empty/no-pending list) from "module did not
            // answer" (sensor error, Comply absent). Auto-close of findings
            // that vanished from the feed only runs when these are true —
            // otherwise a sensor hiccup would mass-close open findings.
            'cveDataPresent'   => isset($n['compliance']['cveFindings']) && is_array($n['compliance']['cveFindings']),
            'patchDataPresent' => self::hasPatchSensorData($n['sensorReadings'] ?? []),
            'computerGroups' => self::mapGroupMemberships($n['computerGroupMemberships'] ?? []),
            // Hygiene / attack-surface / stability extras (null when the
            // tenant does not expose them or extras were disabled).
            'isEncrypted'     => array_key_exists('isEncrypted', $n) ? (int)!empty($n['isEncrypted']) : null,
            'chassisType'     => $n['chassisType'] ?? null,
            'defenderHealthy' => $n['sentinel']['windowsDefender']['healthy'] ?? null,
            'defenderAvOn'    => $n['sentinel']['windowsDefender']['antivirusEnabled'] ?? null,
            'defenderSigAge'  => $n['sentinel']['windowsDefender']['antivirusSignatureUpdateAge'] ?? null,
            'sccmHealth'      => $n['sentinel']['sccmClient']['health'] ?? null,
            'openPorts'       => $n['discover']['openPorts'] ?? null,
            'natIp'           => $n['discover']['natIpAddress'] ?? null,
            'discoverMethod'  => $n['discover']['discoverMethod'] ?? null,
            'eventCrashes'    => isset($n['eventCounts']['appCrash']) ? (int)$n['eventCounts']['appCrash'] : null,
            'eventTotal'      => isset($n['eventCounts']['all']) ? (int)$n['eventCounts']['all'] : null,
            'customSensors'   => self::mapCustomSensors($n['customSensors'] ?? []),
        ];
    }

    /** @return array<int,array{id:int,name:string}> */
    private static function mapGroupMemberships(array $memberships): array {
        $groups = [];
        foreach ($memberships as $m) {
            $g = $m['computerGroup'] ?? $m;
            if (!empty($g['id'])) {
                $groups[] = ['id' => (int)$g['id'], 'name' => (string)($g['name'] ?? '')];
            }
        }
        return $groups;
    }

    /**
     * Custom sensor readings → ['Sensor Name' => 'value1, value2', …].
     * Column-oriented like Applicable Patches, but here each sensor's values
     * are just joined for display on the endpoint page.
     */
    private static function mapCustomSensors(array $readings): array {
        $out = [];
        foreach ($readings['columns'] ?? [] as $col) {
            $name = trim((string)($col['name'] ?? ''));
            if ($name === '') {
                continue;
            }
            $values = array_filter(array_map('strval', (array)($col['values'] ?? [])), static fn($v) => $v !== '' && $v !== '[no results]');
            $out[$name] = implode(', ', array_slice($values, 0, 20));
        }
        return $out;
    }

    /**
     * Status of a previously created action (remote action polling).
     * Returns the raw ActionStatus string, or null when unavailable.
     */
    public function getActionStatus(string $actionId): ?string {
        $data = $this->graphql(
            'query($ref: IdRefInput!) { action(ref: $ref) { id status stopped } }',
            ['ref' => ['id' => $actionId]]
        );
        return isset($data['action']['status']) ? (string)$data['action']['status'] : null;
    }

    /**
     * True when the "Applicable Patches" sensor actually answered for this
     * endpoint — a Title column exists, even if every row is the
     * "No Patches Required" marker (fully-patched machine). False means the
     * sensor did not report (error/timeout), so its data must not be trusted
     * for reconciliation.
     */
    private static function hasPatchSensorData(array $sensorReadings): bool {
        foreach ($sensorReadings['columns'] ?? [] as $col) {
            if (($col['name'] ?? '') === 'Title' && !empty($col['values'])) {
                return true;
            }
        }
        return false;
    }

    /**
     * The "Applicable Patches" sensor returns a column-oriented table (parallel
     * value arrays). Transpose it into per-patch rows the Sync layer consumes.
     * Applicable patches are, by definition, the ones still missing.
     */
    private static function mapApplicablePatches(array $sensorReadings): array {
        $byName = [];
        foreach ($sensorReadings['columns'] ?? [] as $col) {
            if (isset($col['name'])) {
                $byName[$col['name']] = $col['values'] ?? [];
            }
        }

        $titles = $byName['Title'] ?? [];
        $out    = [];
        foreach ($titles as $i => $title) {
            // Endpoints with nothing pending report a single "No Patches Required" row.
            if ($title === '' || stripos($title, 'No Patches Required') !== false) {
                continue;
            }
            $kb      = $byName['KB Articles'][$i] ?? '';
            $patchId = $kb !== '' ? $kb : $title;

            // The sensor answers a machine it could not scan with a row like
            // "No Scan Results Found" instead of an empty result. That is a
            // visibility gap, not a missing patch, and it was being stored as
            // one: filtered out of the risk score and the action plan, but
            // still counted in the patch list, the dashboard KPI, the health
            // report and the coverage screen — and still selectable for a
            // deployment that could only ever fail. Dropping it here, at the
            // single point of entry, is the only place that fixes all of them.
            if (Sync::isSensorNoise((string)$title, (string)$patchId)) {
                continue;
            }
            $entry   = [
                'patchId'     => $patchId,
                'title'       => $title,
                // Vendors spell the same three ideas five different ways, and
                // some rows arrive with no rating at all. Normalising here, at
                // the only place patch severity enters the plugin, means every
                // count and filter downstream groups on one vocabulary.
                'severity'    => Severity::patch($byName['Severity'][$i] ?? ''),
                'status'      => 'missing',
                'kb'          => $kb,
                'releaseDate' => $byName['Release Date'][$i] ?: null,
            ];

            // One advisory can cover several packages (ALSA/RHSA/USN), and the
            // sensor answers with a row per package sharing the same KB — i.e.
            // the same patchId. The DB holds one row per (endpoint, patch_id),
            // so collapse them here and keep the most severe: severity drives
            // patch selection in the KEV automation, and letting the last row
            // win would make that selection depend on row order.
            $prev = $out[$patchId] ?? null;
            if ($prev === null || self::patchSeverityRank($entry['severity']) > self::patchSeverityRank($prev['severity'])) {
                $out[$patchId] = $entry;
            }
        }
        return array_values($out);
    }

    /**
     * Order the canonical patch severities, worst first. Unknown sorts lowest.
     *
     * Severity is normalised by Severity::patch() before it reaches here, so
     * only the canonical words can arrive — vendor spellings were already
     * collapsed upstream.
     */
    private static function patchSeverityRank(string $severity): int {
        return match (strtolower(trim($severity))) {
            'critical'  => 4,
            'important' => 3,
            'moderate'  => 2,
            'low'       => 1,
            default     => 0,
        };
    }

    /**
     * Map GraphQL `EndpointComplianceCveFinding` nodes to the flat CVE shape the
     * Sync layer consumes. Prefers CVSS v3 scoring, falling back to the legacy
     * fields. Tanium findings are active detections, so status is "open".
     */
    private static function mapCveFindings(array $findings): array {
        $out = [];
        foreach ($findings as $c) {
            $cveId = $c['cveId'] ?? '';
            if ($cveId === '') {
                continue;
            }
            $out[] = [
                'cveId'       => $cveId,
                'cvssScore'   => $c['cvssScoreV3'] ?? $c['cvssScore'] ?? null,
                'severity'    => strtolower((string) ($c['severityV3'] ?? $c['severity'] ?? 'unknown')),
                'title'       => trim((string) ($c['summary'] ?? '')) !== '' ? $c['summary'] : $cveId,
                'description' => $c['summary'] ?? null,
                'status'      => !empty($c['excepted']) ? 'excepted' : 'open',
                'detectedAt'  => $c['firstFound'] ?? null,
            ];
        }
        return $out;
    }

    /** Map GraphQL `installedApplications` nodes to {name, version} entries. */
    private static function mapInstalledApplications(array $apps): array {
        $out = [];
        foreach ($apps as $a) {
            $name = $a['name'] ?? '';
            if ($name === '') {
                continue;
            }
            $out[] = ['name' => $name, 'version' => $a['version'] ?? ''];
        }
        return $out;
    }

    /** Parse strings like "16384 MB" / "16 GB" into megabytes. */
    private static function parseMemoryMb(?string $raw): int {
        if (!$raw) {
            return 0;
        }
        $value = self::parseLeadingInt($raw);
        if (stripos($raw, 'gb') !== false) {
            $value *= 1024;
        } elseif (stripos($raw, 'kb') !== false) {
            $value = (int) ($value / 1024);
        }
        return $value;
    }

    /** Leading integer of a string, e.g. "2890 Mhz" → 2890. */
    private static function parseLeadingInt(?string $raw): int {
        if (!$raw) {
            return 0;
        }
        return (int) preg_replace('/[^\d].*$/', '', ltrim($raw));
    }

    /** Normalise processor architecture strings to GLPI-friendly labels. */
    private static function normalizeArch(?string $raw): ?string {
        if (!$raw) {
            return null;
        }
        $lower = strtolower($raw);
        if (str_contains($lower, 'x64') || str_contains($lower, 'amd64') || str_contains($lower, '64-bit')) {
            return 'x86_64';
        }
        if (str_contains($lower, 'arm')) {
            return 'arm64';
        }
        if (str_contains($lower, 'x86') || str_contains($lower, '32-bit')) {
            return 'x86';
        }
        return $raw;
    }

    // ── Comply / Threat Response (still REST) ─────────────────────────────
    //
    // The endpoint, CVE and patch inventory all moved to the GraphQL Gateway
    // (they hang off the endpoint node). What remains on REST are these two
    // module feeds, which have no Gateway equivalent. The seven REST readers
    // the migration left behind — getEndpoint, getAllSoftware,
    // getAllVulnerabilities, getAllCVEFindings, getEndpointCVEs,
    // getAllPatchFindings, getEndpointPatches — had no callers left and were
    // removed in v2.19.0. getEndpoint in particular was a trap: it fetched a
    // thousand endpoints and scanned them linearly to find one.

    /**
     * Compliance (benchmark) findings from Tanium Comply. Endpoint shape varies
     * per Comply version; both known paths are tried.
     */
    public function getComplianceFindings(int $pageSize = 500): array {
        try {
            return $this->paginate('/plugin/products/comply/v1/compliance-findings', [], $pageSize);
        } catch (\Throwable $e) {
            return $this->paginate('/plugin/products/comply/v1/findings', ['type' => 'compliance'], $pageSize);
        }
    }

    /** Threat Response alerts (module optional — callers handle failures). */
    public function getThreatAlerts(int $pageSize = 500): array {
        return $this->paginate('/plugin/products/threat-response/api/v1/alerts', [], $pageSize);
    }

    // ── Patch Deployments ─────────────────────────────────────────────────

    /**
     * Create a patch deployment for a single endpoint via the GraphQL API
     * Gateway mutation `patchCreateDeployment` (the REST create endpoint is
     * undocumented and far stricter). Patches are referenced by catalog
     * `taniumUid`, which we resolve from the caller's KB/title identifiers.
     *
     * Targeting: a `questionCriteria` filter "Computer Name == <name>", scoped
     * by a required limiting computer group (configured per tenant).
     *
     * @param string $eid            Tanium endpoint id (reference/logging only)
     * @param array  $patches        Descriptors ['kb'=>, 'title'=>] (or plain strings)
     * @param string $deploymentName Human-readable deployment name
     * @param array  $opts           osType, computerName, limitingGroupId, restart, windowHours, timezone, contentSetId
     * @return array  ['id' => deploymentId]
     */
    public function deployPatches(string $eid, array $patches, string $deploymentName, array $opts = []): array {
        $osType   = strtolower(trim((string)($opts['osType'] ?? 'windows'))) ?: 'windows';
        $computer = trim((string)($opts['computerName'] ?? ''));
        if ($computer === '') {
            throw new \RuntimeException(__('Cannot deploy: the endpoint computer name is unknown. Run a sync first.', 'tanium'));
        }

        $limitingGroupId = (int)($opts['limitingGroupId'] ?? 0);
        if ($limitingGroupId <= 0) {
            throw new \RuntimeException(__('Cannot deploy: set the "Patch deployment scope group" (target limiting group) in the Tanium plugin configuration.', 'tanium'));
        }

        $uids = $this->resolvePatchUids($patches, $osType);

        $platform = match ($osType) {
            'mac', 'macos', 'darwin' => 'MACOS',
            'linux'                  => 'LINUX',
            default                  => 'WINDOWS',
        };
        $tz           = trim((string)($opts['timezone'] ?? '')) ?: (date_default_timezone_get() ?: 'America/Sao_Paulo');
        $windowH      = max(1, (int)($opts['windowHours'] ?? 24));
        $start        = gmdate('Y-m-d\TH:i:s\Z');
        $end          = gmdate('Y-m-d\TH:i:s\Z', time() + $windowH * 3600);
        $contentSetId = isset($opts['contentSetId']) ? (int)$opts['contentSetId'] : $this->detectContentSetId();

        $input = [
            'name'                  => mb_substr($deploymentName, 0, 255),
            'type'                  => 'INSTALL',
            'platform'              => $platform,
            'contentSet'            => ['id' => (string)$contentSetId],
            'contentDeploymentType' => 'MANUAL_SELECTION',
            'patches'               => array_map(static fn(string $u) => ['id' => $u], $uids),
            'targets'               => [
                'questionCriteria' => [
                    'filter'         => [
                        'sensor'  => ['name' => 'Computer Name'],
                        'op'      => 'EQ',
                        'value'   => $computer,
                        'negated' => false,
                        'any'     => false,
                    ],
                    'limitingGroups' => [['id' => (string)$limitingGroupId]],
                ],
            ],
            'schedule'              => [
                'type'                       => 'SINGLE',
                'timeZone'                   => $tz,
                'startTime'                  => $start,
                'endTime'                    => $end,
                // User chose "install immediately after approval".
                'overrideMaintenanceWindows' => true,
            ],
            'downloadImmediately'   => true,
            'overrideBlocklists'    => false,
            'restart'               => (bool)($opts['restart'] ?? true),
        ];

        $mutation = 'mutation($input: PatchCreateDeploymentInput!) {'
                  . ' patchCreateDeployment(input: $input) { deployment { id } error { message } } }';

        $data = $this->graphql($mutation, ['input' => $input]);

        $err = $data['patchCreateDeployment']['error']['message'] ?? null;
        if ($err) {
            throw new \RuntimeException(sprintf(__('Tanium rejected the deployment: %s', 'tanium'), $err));
        }
        $id = $data['patchCreateDeployment']['deployment']['id'] ?? null;
        if (!$id) {
            throw new \RuntimeException(__('Tanium did not return a deployment id.', 'tanium'));
        }

        return ['id' => (string)$id];
    }

    /**
     * Run a Tanium package on a single endpoint via the Gateway mutation
     * `actionCreate` (approval-gated remote actions: quarantine, agent
     * restart…). Targeting mirrors deployPatches: "Computer Name == <name>"
     * scoped by the limiting group.
     *
     * @return array ['id' => actionId]
     */
    public function createAction(string $computerName, string $packageName, string $actionName, int $limitingGroupId): array {
        $computerName = trim($computerName);
        if ($computerName === '') {
            throw new \RuntimeException(__('Cannot run the action: the endpoint computer name is unknown. Run a sync first.', 'tanium'));
        }
        if (trim($packageName) === '') {
            throw new \RuntimeException(__('Cannot run the action: no Tanium package configured for it.', 'tanium'));
        }
        if ($limitingGroupId <= 0) {
            throw new \RuntimeException(__('Cannot run the action: set the "Patch deployment scope group" (target limiting group) in the Tanium plugin configuration.', 'tanium'));
        }

        $input = [
            'name'    => mb_substr($actionName, 0, 255),
            'package' => ['name' => $packageName],
            'targets' => [
                'questionCriteria' => [
                    'filter'         => [
                        'sensor'  => ['name' => 'Computer Name'],
                        'op'      => 'EQ',
                        'value'   => $computerName,
                        'negated' => false,
                        'any'     => false,
                    ],
                    'limitingGroups' => [['id' => (string)$limitingGroupId]],
                ],
            ],
        ];

        $mutation = 'mutation($input: ActionCreateInput!) {'
                  . ' actionCreate(input: $input) { action { id } error { message } } }';

        $data = $this->graphql($mutation, ['input' => $input]);

        $err = $data['actionCreate']['error']['message'] ?? null;
        if ($err) {
            throw new \RuntimeException(sprintf(__('Tanium rejected the action: %s', 'tanium'), $err));
        }
        $id = $data['actionCreate']['action']['id'] ?? null;
        if (!$id) {
            throw new \RuntimeException(__('Tanium did not return an action id.', 'tanium'));
        }

        return ['id' => (string)$id];
    }

    /** Cache so repeated deploys in one request don't re-query. */
    private ?int $contentSetIdCache = null;

    /**
     * Tanium deployments require a contentSetId. It is tenant-specific, so detect
     * it from an existing deployment; fall back to 48 ("Patch Content Set").
     */
    private function detectContentSetId(): int {
        if ($this->contentSetIdCache !== null) {
            return $this->contentSetIdCache;
        }
        try {
            $r  = $this->get('/plugin/products/patch/v1/deployments', ['limit' => 1]);
            $cs = $r['deployments'][0]['contentSetId'] ?? null;
            $this->contentSetIdCache = (int)($cs ?: 48);
        } catch (\Throwable $e) {
            $this->contentSetIdCache = 48;
        }
        return $this->contentSetIdCache;
    }

    /**
     * Resolve patch descriptors to Tanium catalog `taniumUid`s.
     *
     * The catalog has no usable text filter, but DOES honour `?osType=`, which
     * keeps the payload manageable. A single KB article often maps to MANY
     * versioned patches (e.g. KB890830 → v5.131…v5.142), each with its own UID,
     * so we match by exact TITLE first (which carries the version) and only fall
     * back to KB when that KB resolves to exactly one UID. Anything that cannot
     * be resolved unambiguously aborts the deploy — we never guess a version.
     *
     * @param array $patches Each item: ['kb' => string, 'title' => string] (a plain
     *                       string is treated as both kb and title).
     * @return string[] resolved unique taniumUids
     */
    private function resolvePatchUids(array $patches, string $osType): array {
        // Normalise descriptors.
        $want = [];
        foreach ($patches as $p) {
            if (is_array($p)) {
                $kb    = strtoupper(trim((string)($p['kb'] ?? '')));
                $title = strtoupper(trim((string)($p['title'] ?? '')));
            } else {
                $kb = $title = strtoupper(trim((string)$p));
            }
            if ($kb === '' && $title === '') {
                continue;
            }
            $want[] = ['kb' => $kb, 'title' => $title, 'label' => $title ?: $kb];
        }
        if (empty($want)) {
            return [];
        }

        // The osType-filtered catalog can be tens of MB; allow more time/memory.
        if (function_exists('ini_set')) {
            @ini_set('memory_limit', '512M');
        }
        $catalog = $this->get('/plugin/products/patch/v1/patches', ['osType' => $osType], 180);

        // Build lookup maps from the catalog.
        $byTitle = [];          // TITLE => uid
        $byKb    = [];          // KB    => [uid, ...]
        foreach ($catalog['patches'] ?? [] as $patch) {
            $uid = (string)($patch['taniumUid'] ?? '');
            if ($uid === '') {
                continue;
            }
            $title = strtoupper(trim((string)($patch['title'] ?? '')));
            if ($title !== '' && !isset($byTitle[$title])) {
                $byTitle[$title] = $uid;
            }
            foreach (preg_split('/\s+/', (string)($patch['kbArticles'] ?? '')) as $kb) {
                $kb = strtoupper(trim($kb));
                if ($kb !== '' && $kb !== 'N/A' && $kb !== 'AVAILABLE' && stripos($kb, 'KB') === 0) {
                    $byKb[$kb][$uid] = true;
                }
            }
        }

        $resolved   = [];
        $unresolved = [];
        foreach ($want as $w) {
            if ($w['title'] !== '' && isset($byTitle[$w['title']])) {
                $resolved[$byTitle[$w['title']]] = true;
                continue;
            }
            if ($w['kb'] !== '' && isset($byKb[$w['kb']]) && count($byKb[$w['kb']]) === 1) {
                $resolved[array_key_first($byKb[$w['kb']])] = true;
                continue;
            }
            // Ambiguous (KB → many versions) or not found at all.
            $reason = ($w['kb'] !== '' && isset($byKb[$w['kb']]))
                ? sprintf(__('matches %d catalog versions — title required', 'tanium'), count($byKb[$w['kb']]))
                : __('not found in Tanium catalog', 'tanium');
            $unresolved[] = $w['label'] . ' (' . $reason . ')';
        }

        if (!empty($unresolved)) {
            throw new \RuntimeException(sprintf(
                __('Could not resolve these patches to a Tanium UID: %s', 'tanium'),
                implode('; ', $unresolved)
            ));
        }

        return array_keys($resolved);
    }

    /**
     * Get current status of a deployment.
     * Returns data.status: PENDING|IN_PROGRESS|SUCCEEDED|FAILED|CANCELLED
     */
    public function getDeploymentStatus(string $deploymentId): array {
        return $this->get('/plugin/products/patch/v1/deployments/' . urlencode($deploymentId));
    }

    // ── Computer groups ───────────────────────────────────────────────────

    private const COMPUTER_GROUPS_QUERY = <<<'GQL'
query($first: Int!, $after: Cursor) {
  computerGroups(first: $first, after: $after) {
    totalRecords
    pageInfo { hasNextPage endCursor }
    edges { node { id name } }
  }
}
GQL;

    /**
     * Returns [{id, name}] of all Tanium computer groups, following cursor
     * pagination. Returns [] on any error so callers can degrade gracefully.
     */
    public function getComputerGroups(): array {
        $prevTimeout   = $this->timeout;
        $this->timeout = 20;
        try {
            $groups = [];
            $after  = null;
            $guard  = 0;

            do {
                $data = $this->graphql(self::COMPUTER_GROUPS_QUERY, [
                    'first' => 500,
                    'after' => $after,
                ]);
                $conn  = $data['computerGroups'] ?? [];
                $edges = $conn['edges'] ?? [];
                foreach ($edges as $edge) {
                    $node = $edge['node'] ?? null;
                    if ($node && isset($node['id'])) {
                        $groups[] = ['id' => $node['id'], 'name' => $node['name'] ?? ''];
                    }
                }
                $hasNext = (bool)($conn['pageInfo']['hasNextPage'] ?? false);
                $after   = $conn['pageInfo']['endCursor'] ?? null;
            } while ($hasNext && $after !== null && ++$guard < 50);

            usort($groups, static fn($a, $b) => strcmp((string)($a['name'] ?? ''), (string)($b['name'] ?? '')));
            return $groups;
        } catch (\Throwable) {
            return [];
        } finally {
            $this->timeout = $prevTimeout;
        }
    }

    // ── Schema discovery ──────────────────────────────────────────────────
    //
    // Three settings used to be free-text boxes an admin typed from memory:
    // the custom sensor list, the reboot sensor, and the quarantine/restart
    // package names. A typo in any of them is not caught when it is saved —
    // it surfaces later as a rejected sync, or worse, as a quarantine that
    // silently fails at the moment someone needed it. The Gateway can list all
    // three, so the settings can offer a validated choice instead of a guess.
    //
    // Every method here returns [] on any error: these feed optional pickers,
    // and a tenant whose token lacks the permission must still see a working
    // configuration screen with the plain text field as the fallback.

    private const SENSORS_QUERY = <<<'GQL'
query($first: Int!, $after: Cursor) {
  sensors(first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { name description harvested virtual } }
  }
}
GQL;

    /**
     * Sensor names the tenant actually exposes, for the settings pickers.
     *
     * @return array<int,array{name:string,description:string,harvested:bool,virtual:bool}>
     */
    public function getSensors(): array {
        $prevTimeout   = $this->timeout;
        $this->timeout = 25;
        try {
            $sensors = [];
            $after   = null;
            $guard   = 0;

            do {
                $data  = $this->graphql(self::SENSORS_QUERY, ['first' => 500, 'after' => $after]);
                $conn  = $data['sensors'] ?? [];
                foreach ($conn['edges'] ?? [] as $edge) {
                    $node = $edge['node'] ?? null;
                    $name = trim((string)($node['name'] ?? ''));
                    if ($name === '') {
                        continue;
                    }
                    $sensors[$name] = [
                        'name'        => $name,
                        'description' => (string)($node['description'] ?? ''),
                        'harvested'   => (bool)($node['harvested'] ?? false),
                        'virtual'     => (bool)($node['virtual'] ?? false),
                    ];
                }
                $hasNext = (bool)($conn['pageInfo']['hasNextPage'] ?? false);
                $after   = $conn['pageInfo']['endCursor'] ?? null;
            } while ($hasNext && $after !== null && ++$guard < 40);

            ksort($sensors, SORT_NATURAL | SORT_FLAG_CASE);
            return array_values($sensors);
        } catch (\Throwable) {
            return [];
        } finally {
            $this->timeout = $prevTimeout;
        }
    }

    private const PACKAGE_SPECS_QUERY = <<<'GQL'
query($first: Int!, $after: Cursor) {
  packageSpecs(first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { id name contentSetName } }
  }
}
GQL;

    /**
     * Package names available to run as an action (quarantine, restart, …).
     *
     * @return array<int,array{id:string,name:string,contentSet:string}>
     */
    public function getPackageSpecs(): array {
        $prevTimeout   = $this->timeout;
        $this->timeout = 25;
        try {
            $packages = [];
            $after    = null;
            $guard    = 0;

            do {
                $data = $this->graphql(self::PACKAGE_SPECS_QUERY, ['first' => 500, 'after' => $after]);
                $conn = $data['packageSpecs'] ?? [];
                foreach ($conn['edges'] ?? [] as $edge) {
                    $node = $edge['node'] ?? null;
                    $name = trim((string)($node['name'] ?? ''));
                    if ($name === '') {
                        continue;
                    }
                    $packages[$name] = [
                        'id'         => (string)($node['id'] ?? ''),
                        'name'       => $name,
                        'contentSet' => (string)($node['contentSetName'] ?? ''),
                    ];
                }
                $hasNext = (bool)($conn['pageInfo']['hasNextPage'] ?? false);
                $after   = $conn['pageInfo']['endCursor'] ?? null;
            } while ($hasNext && $after !== null && ++$guard < 40);

            ksort($packages, SORT_NATURAL | SORT_FLAG_CASE);
            return array_values($packages);
        } catch (\Throwable) {
            return [];
        } finally {
            $this->timeout = $prevTimeout;
        }
    }

    private const MY_API_TOKENS_QUERY = <<<'GQL'
query {
  myAPITokens {
    tokens { id created expiration lastUsed notes }
    error { message }
  }
}
GQL;

    /**
     * Expiration date of the API token, straight from Tanium.
     *
     * The plugin warns before a token expires, but the date was a `type=date`
     * input somebody filled in by hand — so the warning was only as good as
     * that memory, and on this tenant it was simply never filled.
     *
     * Tanium does not reveal token strings, so there is no way to match the
     * configured token to a row. When the session owns exactly one token the
     * answer is unambiguous; with several, the earliest expiration is the
     * honest choice, since that is the first date the integration can break.
     *
     * @return array{expiration:?string,count:int,notes:string}|null null when
     *         the query is unavailable (permission, older Gateway) so callers
     *         can leave the manual field alone.
     */
    public function getTokenExpiration(): ?array {
        $prevTimeout   = $this->timeout;
        $this->timeout = 15;
        try {
            $data = $this->graphql(self::MY_API_TOKENS_QUERY);
            $node = $data['myAPITokens'] ?? null;
            if (!is_array($node) || !empty($node['error']['message'])) {
                return null;
            }

            $tokens = array_values(array_filter(
                $node['tokens'] ?? [],
                static fn($t) => is_array($t) && !empty($t['expiration'])
            ));
            if ($tokens === []) {
                return null;
            }

            usort($tokens, static fn($a, $b) => strcmp((string)$a['expiration'], (string)$b['expiration']));
            $first = $tokens[0];
            $ts    = strtotime((string)$first['expiration']);

            return [
                'expiration' => $ts ? date('Y-m-d', $ts) : null,
                'count'      => count($tokens),
                'notes'      => (string)($first['notes'] ?? ''),
            ];
        } catch (\Throwable) {
            return null;
        } finally {
            $this->timeout = $prevTimeout;
        }
    }

    // ── Connection test ───────────────────────────────────────────────────

    public function testConnection(): array {
        try {
            $data = $this->graphql('{ endpoints(first: 1) { totalRecords } }');
            if (isset($data['endpoints'])) {
                $total = $data['endpoints']['totalRecords'] ?? '?';
                return [
                    'ok'      => true,
                    'message' => sprintf(__('Connection successful. %s endpoints found in Tanium.', 'tanium'), $total),
                ];
            }
            return ['ok' => false, 'message' => __('Unexpected API response structure.', 'tanium')];
        } catch (\RuntimeException $e) {
            return ['ok' => false, 'message' => $e->getMessage()];
        }
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────

    /**
     * Execute a GraphQL query against the Tanium gateway and return the `data`
     * payload. Throws on transport, HTTP, or GraphQL-level errors.
     */
    private function graphql(string $query, array $variables = []): array {
        $payload = ['query' => $query];
        if ($variables) {
            $payload['variables'] = $variables;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->baseUrl . self::GRAPHQL_PATH,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_HTTPHEADER     => [
                'session: ' . $this->token,
                'Content-Type: application/json',
                'Accept: application/json',
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $body  = curl_exec($ch);
        $error = curl_error($ch);
        $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($error) {
            throw new \RuntimeException(sprintf(__('cURL error: %s', 'tanium'), $error));
        }
        if ($code === 401) {
            throw new \RuntimeException(__('Tanium API authentication failed. Check your API token.', 'tanium') . self::errorDetail($body));
        }
        if ($code === 403) {
            throw new \RuntimeException(__('Tanium API access forbidden. The token may lack required permissions.', 'tanium') . self::errorDetail($body));
        }
        if ($code >= 400) {
            throw new \RuntimeException(sprintf(__('Tanium GraphQL API returned HTTP %d', 'tanium'), $code) . self::errorDetail($body));
        }

        $data = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException(sprintf(__('Invalid JSON from Tanium API: %s', 'tanium'), json_last_error_msg()));
        }

        if (!empty($data['errors'])) {
            $msg = $data['errors'][0]['message'] ?? __('Unknown GraphQL error', 'tanium');
            throw new \RuntimeException(sprintf(__('Tanium GraphQL error: %s', 'tanium'), $msg));
        }

        return $data['data'] ?? [];
    }

    /**
     * Paginate through all pages of a resource, returning merged array.
     */
    private function paginate(string $path, array $baseQuery, int $pageSize): array {
        // Hard safety caps so a misbehaving/cursor-based API can never loop
        // unboundedly and exhaust server memory.
        $maxItems = 20000;
        $maxPages = 500;

        $all    = [];
        $offset = 0;
        $pages  = 0;
        do {
            $query    = array_merge($baseQuery, ['limit' => $pageSize, 'offset' => $offset]);
            $response = $this->get($path, $query);
            $page     = $response['data'] ?? [];
            $all      = array_merge($all, $page);

            // Cursor-style APIs (e.g. Tanium Asset) signal completion explicitly.
            if (($response['meta']['endOfReader'] ?? null) === true) {
                break;
            }

            $total   = $response['meta']['total'] ?? count($page);
            $offset += $pageSize;
            $pages++;

            if (count($all) >= $maxItems || $pages >= $maxPages) {
                break;
            }
        } while ($offset < $total && count($page) > 0);
        return $all;
    }

    /**
     * GETs are idempotent, so transient failures (network error, HTTP 429/5xx)
     * are retried with exponential backoff. POST/GraphQL are NOT retried: the
     * patch-deployment mutation goes through them and a retry could deploy twice.
     */
    private function get(string $path, array $query = [], ?int $timeout = null): array {
        $url = $this->baseUrl . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $maxAttempts = 3;
        $body        = false;
        $error       = '';
        $code        = 0;

        for ($attempt = 1; $attempt <= $maxAttempts; $attempt++) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $timeout ?? $this->timeout,
                CURLOPT_HTTPHEADER     => [
                    'session: ' . $this->token,
                    'Content-Type: application/json',
                    'Accept: application/json',
                ],
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_FOLLOWLOCATION => true,
            ]);

            $body  = curl_exec($ch);
            $error = curl_error($ch);
            $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            $transient = ($error !== '') || $code === 429 || $code >= 500;
            if (!$transient || $attempt === $maxAttempts) {
                break;
            }
            sleep(2 ** ($attempt - 1)); // 1s, 2s
        }

        if ($error) {
            throw new \RuntimeException(sprintf(__('cURL error: %s', 'tanium'), $error));
        }
        if ($code === 401) {
            throw new \RuntimeException(__('Tanium API authentication failed. Check your API token.', 'tanium') . self::errorDetail($body));
        }
        if ($code === 403) {
            throw new \RuntimeException(__('Tanium API access forbidden. The token may lack required permissions.', 'tanium') . self::errorDetail($body));
        }
        if ($code === 404) {
            throw new \RuntimeException(sprintf(__('Tanium API endpoint not found: %s', 'tanium'), $path) . self::errorDetail($body));
        }
        if ($code >= 400) {
            throw new \RuntimeException(sprintf(__('Tanium API returned HTTP %d for %s', 'tanium'), $code, $path) . self::errorDetail($body));
        }

        $data = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException(sprintf(__('Invalid JSON from Tanium API: %s', 'tanium'), json_last_error_msg()));
        }

        return $data ?? [];
    }

    /**
     * Extract a concise, human-readable reason from a Tanium error response body.
     * Tanium error payloads vary in shape, so probe the common keys and fall back
     * to a truncated raw body. Returns an empty string when there is nothing useful.
     */
    private static function errorDetail(?string $body): string {
        if ($body === null || trim($body) === '') {
            return '';
        }

        $decoded = json_decode($body, true);
        if (is_array($decoded)) {
            $msg = $decoded['text']
                ?? $decoded['message']
                ?? $decoded['error']
                ?? ($decoded['errors'][0]['detail'] ?? null)
                ?? ($decoded['errors'][0]['message'] ?? null);
            if (is_string($msg) && trim($msg) !== '') {
                return ' — ' . trim($msg);
            }
        }

        $raw = trim(preg_replace('/\s+/', ' ', strip_tags($body)));
        if ($raw === '') {
            return '';
        }
        return ' — ' . (strlen($raw) > 300 ? substr($raw, 0, 300) . '…' : $raw);
    }
}
