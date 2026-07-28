<?php

/** @mirror src/Api.php::patchSeverityRank */
function patchSeverityRank(string $severity): int {
    return match (strtolower(trim($severity))) {
        'critical'  => 5,
        'important' => 4,
        'high'      => 3,
        'moderate', 'medium' => 2,
        'low'       => 1,
        default     => 0,
    };
}

/** @mirror src/Api.php::mapApplicablePatches */
function mapApplicablePatches(array $sensorReadings): array {
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
        $entry   = [
            'patchId'     => $patchId,
            'title'       => $title,
            'severity'    => $byName['Severity'][$i]     ?? '',
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
        if ($prev === null || patchSeverityRank($entry['severity']) > patchSeverityRank($prev['severity'])) {
            $out[$patchId] = $entry;
        }
    }
    return array_values($out);
}

/** Build the sensorReadings shape from parallel column arrays. */
function sensor(array $titles, array $kbs, array $sevs, array $dates = []): array {
    return ['columns' => [
        ['name' => 'Title',        'values' => $titles],
        ['name' => 'KB Articles',  'values' => $kbs],
        ['name' => 'Severity',     'values' => $sevs],
        ['name' => 'Release Date', 'values' => $dates ?: array_fill(0, count($titles), '2026-07-28')],
    ]];
}

// The bug this guards: an ALSA/RHSA/USN advisory covers several packages, so the
// sensor emits one row per package all carrying the same KB. Those became two
// INSERTs against the (tanium_eid, patch_id) unique key and aborted the sync of
// the whole endpoint with "Duplicate entry '29560-ALSA-2026:47011'".
it('advisory repetido em vários pacotes vira uma linha só', function () {
    $out = mapApplicablePatches(sensor(
        ['Important: kernel security update', 'Important: kernel-headers security update'],
        ['ALSA-2026:47011', 'ALSA-2026:47011'],
        ['Important', 'Important']
    ));
    assertSame(1, count($out), 'linhas devolvidas');
    assertSame('ALSA-2026:47011', $out[0]['patchId']);
});

it('entre duplicatas sobrevive a severidade mais alta', function () {
    $out = mapApplicablePatches(sensor(
        ['pacote a', 'pacote b', 'pacote c'],
        ['ALSA-2026:47011', 'ALSA-2026:47011', 'ALSA-2026:47011'],
        ['Low', 'Critical', 'Moderate']
    ));
    assertSame(1, count($out));
    assertSame('Critical', $out[0]['severity']);
});

it('a ordem das linhas não muda o resultado', function () {
    $a = mapApplicablePatches(sensor(['x', 'y'], ['KB1', 'KB1'], ['Critical', 'Low']));
    $b = mapApplicablePatches(sensor(['y', 'x'], ['KB1', 'KB1'], ['Low', 'Critical']));
    assertSame($a[0]['severity'], $b[0]['severity'], 'severidade estável');
});

it('advisories distintos continuam separados', function () {
    $out = mapApplicablePatches(sensor(
        ['kernel', 'openssl'],
        ['ALSA-2026:47011', 'ALSA-2026:47012'],
        ['Important', 'Critical']
    ));
    assertSame(2, count($out));
});

// Windows patches have one KB per row, so dedupe must not collapse them.
it('KBs diferentes do Windows não são colapsados', function () {
    $out = mapApplicablePatches(sensor(
        ['2026-07 Cumulative Update', '2026-07 .NET Update'],
        ['KB5041585', 'KB5041999'],
        ['Critical', 'Important']
    ));
    assertSame(2, count($out));
});

// Without a KB the title is the identity — two packages with no KB are two patches.
it('sem KB o título vira a identidade do patch', function () {
    $out = mapApplicablePatches(sensor(
        ['docker-ce 5:29.6.1', 'containerd.io 1.7.2'],
        ['', ''],
        ['Low', 'Moderate']
    ));
    assertSame(2, count($out));
    assertSame('docker-ce 5:29.6.1', $out[0]['patchId']);
});

it('linha "No Patches Required" é descartada', function () {
    $out = mapApplicablePatches(sensor(['No Patches Required'], [''], ['']));
    assertSame(0, count($out));
});

it('severidade desconhecida perde para qualquer conhecida', function () {
    $out = mapApplicablePatches(sensor(
        ['a', 'b'],
        ['KB1', 'KB1'],
        ['', 'Low']
    ));
    assertSame('Low', $out[0]['severity']);
});

it('as chaves saem sequenciais para o consumidor iterar', function () {
    $out = mapApplicablePatches(sensor(
        ['a', 'b', 'c'],
        ['KB1', 'KB1', 'KB2'],
        ['Low', 'Critical', 'Low']
    ));
    assertSame([0, 1], array_keys($out));
});
