<?php

namespace GlpiPlugin\Tanium;

class Api {

    private string $baseUrl;
    private string $token;
    private int    $timeout = 30;

    public function __construct(string $baseUrl, string $token) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->token   = $token;
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
query($first: Int!, $after: Cursor, $withCves: Boolean!, $withApps: Boolean!, $withPatches: Boolean!) {
  endpoints(first: $first, after: $after) {
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
      }
    }
  }
}
GQL;

    // Enriched pages (with CVEs/apps) carry far more data per node, so use a
    // smaller page size to keep each response well within memory.
    private const ENRICHED_PAGE_SIZE = 50;
    private const MAX_ENDPOINTS       = 200000; // hard safety cap

    public function getEndpoints(int $limit = 500, int $offset = 0): array {
        // $offset is ignored — the GraphQL connection is cursor-paginated.
        $data = $this->graphql(self::ENDPOINT_QUERY, [
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
    public function eachEndpointPage(int $pageSize, bool $withCves, bool $withApps, bool $withPatches, callable $onPage): void {
        if ($withCves || $withApps || $withPatches) {
            $pageSize = min($pageSize, self::ENRICHED_PAGE_SIZE);
        }

        $after = null;
        $count = 0;
        do {
            $data = $this->graphql(self::ENDPOINT_QUERY, [
                'first'       => $pageSize,
                'after'       => $after,
                'withCves'    => $withCves,
                'withApps'    => $withApps,
                'withPatches' => $withPatches,
            ]);
            $conn = $data['endpoints'] ?? [];

            $page = [];
            foreach ($conn['edges'] ?? [] as $edge) {
                $page[] = self::mapEndpointNode($edge['node'] ?? []);
            }
            if ($page) {
                $onPage($page);
                $count += count($page);
            }

            $hasNext = $conn['pageInfo']['hasNextPage'] ?? false;
            $after   = $conn['pageInfo']['endCursor']   ?? null;
        } while ($hasNext && $after !== null && $count < self::MAX_ENDPOINTS);
    }

    public function getAllEndpoints(int $pageSize = 500, bool $withCves = false, bool $withApps = false, bool $withPatches = false): array {
        $all = [];
        $this->eachEndpointPage($pageSize, $withCves, $withApps, $withPatches, function (array $page) use (&$all): void {
            foreach ($page as $endpoint) {
                $all[] = $endpoint;
            }
        });
        return $all;
    }

    /**
     * Incremental sync — only endpoints last seen after $since (ISO-8601).
     * The fleet is paged via GraphQL and filtered client-side on eidLastSeen,
     * which keeps us independent of the EndpointFieldFilter input shape.
     */
    public function getAllEndpointsIncremental(string $since, int $pageSize = 500, bool $withCves = false, bool $withApps = false, bool $withPatches = false): array {
        $sinceTs = strtotime($since) ?: 0;
        return array_values(array_filter(
            $this->getAllEndpoints($pageSize, $withCves, $withApps, $withPatches),
            function (array $e) use ($sinceTs): bool {
                $seen = strtotime($e['lastRegistrationTime'] ?? '') ?: 0;
                return $seen > $sinceTs;
            }
        ));
    }

    public function getEndpoint(string $eid): array {
        foreach ($this->getEndpoints(1000) as $endpoint) {
            if ((string) ($endpoint['eid'] ?? '') === (string) $eid) {
                return $endpoint;
            }
        }
        return [];
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
            'cves'     => self::mapCveFindings($n['compliance']['cveFindings'] ?? []),
            'software' => self::mapInstalledApplications($n['installedApplications'] ?? []),
            'patches'  => self::mapApplicablePatches($n['sensorReadings'] ?? []),
        ];
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
            $kb = $byName['KB Articles'][$i] ?? '';
            $out[] = [
                'patchId'     => $kb !== '' ? $kb : $title,
                'title'       => $title,
                'severity'    => $byName['Severity'][$i]     ?? '',
                'status'      => 'missing',
                'kb'          => $kb,
                'releaseDate' => $byName['Release Date'][$i] ?: null,
            ];
        }
        return $out;
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
                'title'       => $cveId,
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

    // ── Software ─────────────────────────────────────────────────────────────

    public function getAllSoftware(int $pageSize = 500): array {
        // Asset rows carry the full per-machine component inventory and are very
        // large — a single 500-row response decodes to >128 MB and kills the
        // worker. Cap the page size hard so one response can never exhaust memory.
        return $this->paginate('/plugin/products/asset/v1/assets', [], min($pageSize, 50));
    }

    // ── Vulnerabilities (Tanium Comply) ───────────────────────────────────

    public function getAllVulnerabilities(int $pageSize = 500): array {
        return $this->paginate('/plugin/products/comply/v1/findings', [], $pageSize);
    }

    /**
     * CVE-level findings — one record per CVE with list of affected endpoints.
     */
    public function getAllCVEFindings(int $pageSize = 500): array {
        // Try CVE-grouped endpoint first; fall back to raw findings
        try {
            return $this->paginate('/plugin/products/comply/v1/cve-findings', [], $pageSize);
        } catch (\RuntimeException $e) {
            return $this->paginate('/plugin/products/comply/v1/findings', [], $pageSize);
        }
    }

    /**
     * Per-endpoint CVE findings for a single endpoint.
     */
    public function getEndpointCVEs(string $eid, int $pageSize = 500): array {
        try {
            return $this->paginate("/plugin/products/comply/v1/findings", [
                'filter' => "computerName=={$eid}",
            ], $pageSize);
        } catch (\RuntimeException $e) {
            return [];
        }
    }

    // ── Patches (Tanium Patch) ────────────────────────────────────────────

    /**
     * All patch findings — pending/missing patches across all endpoints.
     */
    public function getAllPatchFindings(int $pageSize = 500): array {
        try {
            return $this->paginate('/plugin/products/patch/v1/patch-findings', [], $pageSize);
        } catch (\RuntimeException $e) {
            try {
                return $this->paginate('/plugin/products/patch/v1/endpoints/patches', [], $pageSize);
            } catch (\RuntimeException $e2) {
                return [];
            }
        }
    }

    /**
     * Patches for a specific endpoint.
     */
    public function getEndpointPatches(string $eid, int $pageSize = 200): array {
        try {
            return $this->paginate("/plugin/products/patch/v1/endpoints/{$eid}/patches", [], $pageSize);
        } catch (\RuntimeException $e) {
            return [];
        }
    }

    // ── Patch Deployments ─────────────────────────────────────────────────

    /**
     * Create a patch deployment for a specific endpoint.
     * Returns the full API response (data.id = deployment ID).
     */
    public function deployPatches(string $eid, array $patchIds, string $deploymentName): array {
        $payload = [
            'name'   => $deploymentName,
            'type'   => 'INSTALL',
            'target' => ['endpointIds' => [$eid]],
            'patches' => $patchIds,
            'schedule' => [
                'startTime'           => gmdate('Y-m-d\TH:i:s\Z'),
                'endTime'             => gmdate('Y-m-d\TH:i:s\Z', time() + 86400 * 7),
                'distributeOverTime'  => false,
            ],
        ];
        return $this->post('/plugin/products/patch/v1/deployments', $payload);
    }

    /**
     * Get current status of a deployment.
     * Returns data.status: PENDING|IN_PROGRESS|SUCCEEDED|FAILED|CANCELLED
     */
    public function getDeploymentStatus(string $deploymentId): array {
        return $this->get('/plugin/products/patch/v1/deployments/' . urlencode($deploymentId));
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

    private function post(string $path, array $payload): array {
        $url = $this->baseUrl . $path;

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
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

        if ($error) throw new \RuntimeException(sprintf(__('cURL error: %s', 'tanium'), $error));
        if ($code === 401) throw new \RuntimeException(__('Tanium API authentication failed.', 'tanium') . self::errorDetail($body));
        if ($code === 403) throw new \RuntimeException(__('Tanium API access forbidden.', 'tanium') . self::errorDetail($body));
        if ($code >= 400) throw new \RuntimeException(sprintf(__('Tanium API returned HTTP %d for POST %s', 'tanium'), $code, $path) . self::errorDetail($body));

        $data = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException(sprintf(__('Invalid JSON from Tanium API: %s', 'tanium'), json_last_error_msg()));
        }
        return $data ?? [];
    }

    private function get(string $path, array $query = []): array {
        $url = $this->baseUrl . $path;
        if ($query) {
            $url .= '?' . http_build_query($query);
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
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
