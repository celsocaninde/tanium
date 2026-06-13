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

    public function getEndpoints(int $limit = 500, int $offset = 0): array {
        $response = $this->get('/api/v2/endpoints', ['limit' => $limit, 'offset' => $offset]);
        return $response['data'] ?? [];
    }

    public function getAllEndpoints(int $pageSize = 500): array {
        return $this->paginate('/api/v2/endpoints', [], $pageSize);
    }

    /**
     * Incremental sync — only endpoints that changed since $since (ISO-8601).
     */
    public function getAllEndpointsIncremental(string $since, int $pageSize = 500): array {
        return $this->paginate('/api/v2/endpoints', [
            'filter' => "lastRegistrationTime>{$since}",
        ], $pageSize);
    }

    public function getEndpoint(string $eid): array {
        $response = $this->get("/api/v2/endpoints/{$eid}");
        return $response['data'] ?? [];
    }

    // ── Software ─────────────────────────────────────────────────────────────

    public function getAllSoftware(int $pageSize = 500): array {
        return $this->paginate('/plugin/products/asset/v1/assets', [], $pageSize);
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
            $response = $this->get('/api/v2/endpoints', ['limit' => 1]);
            if (isset($response['data'])) {
                $total = $response['meta']['total'] ?? '?';
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
     * Paginate through all pages of a resource, returning merged array.
     */
    private function paginate(string $path, array $baseQuery, int $pageSize): array {
        $all    = [];
        $offset = 0;
        do {
            $query    = array_merge($baseQuery, ['limit' => $pageSize, 'offset' => $offset]);
            $response = $this->get($path, $query);
            $page     = $response['data'] ?? [];
            $all      = array_merge($all, $page);
            $total    = $response['meta']['total'] ?? count($page);
            $offset  += $pageSize;
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
        if ($code === 401) throw new \RuntimeException(__('Tanium API authentication failed.', 'tanium'));
        if ($code === 403) throw new \RuntimeException(__('Tanium API access forbidden.', 'tanium'));
        if ($code >= 400) throw new \RuntimeException(sprintf(__('Tanium API returned HTTP %d for POST %s', 'tanium'), $code, $path));

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
            throw new \RuntimeException(__('Tanium API authentication failed. Check your API token.', 'tanium'));
        }
        if ($code === 403) {
            throw new \RuntimeException(__('Tanium API access forbidden. The token may lack required permissions.', 'tanium'));
        }
        if ($code === 404) {
            throw new \RuntimeException(sprintf(__('Tanium API endpoint not found: %s', 'tanium'), $path));
        }
        if ($code >= 400) {
            throw new \RuntimeException(sprintf(__('Tanium API returned HTTP %d for %s', 'tanium'), $code, $path));
        }

        $data = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException(sprintf(__('Invalid JSON from Tanium API: %s', 'tanium'), json_last_error_msg()));
        }

        return $data ?? [];
    }
}
