<?php

/** @mirror src/Sync.php::filterCvesBySeverity */
function filterCvesBySeverity(array $cves, string $minSeverity): array {
    $rank = ['unknown' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
    $min  = $rank[$minSeverity] ?? 0; // unknown key (e.g. 'all') keeps everything
    if ($min <= 0) {
        return $cves;
    }
    return array_values(array_filter(
        $cves,
        static fn(array $c): bool => ($rank[strtolower((string) ($c['severity'] ?? 'unknown'))] ?? 0) >= $min
    ));
}

$fleet = [
    ['cveId' => 'CVE-2024-0001', 'severity' => 'critical'],
    ['cveId' => 'CVE-2024-0002', 'severity' => 'High'],
    ['cveId' => 'CVE-2024-0003', 'severity' => 'medium'],
    ['cveId' => 'CVE-2024-0004', 'severity' => 'low'],
    ['cveId' => 'CVE-2024-0005'],                          // sem severidade
];

it('"all" não filtra nada', function () use ($fleet) {
    assertSame(5, count(filterCvesBySeverity($fleet, 'all')));
});

it('severidade desconhecida também não filtra', function () use ($fleet) {
    assertSame(5, count(filterCvesBySeverity($fleet, 'qualquer-coisa')));
});

it('high mantém critical e high', function () use ($fleet) {
    $r = filterCvesBySeverity($fleet, 'high');
    assertSame(2, count($r));
    assertSame('CVE-2024-0001', $r[0]['cveId']);
    assertSame('CVE-2024-0002', $r[1]['cveId'], 'comparação deve ignorar caixa');
});

it('critical mantém só critical', function () use ($fleet) {
    assertSame(1, count(filterCvesBySeverity($fleet, 'critical')));
});

it('finding sem severidade é tratado como unknown e cortado', function () use ($fleet) {
    $r = filterCvesBySeverity($fleet, 'low');
    assertSame(4, count($r), 'unknown fica de fora a partir de low');
});

it('reindexa as chaves para o array continuar sequencial', function () use ($fleet) {
    $r = filterCvesBySeverity($fleet, 'high');
    assertSame([0, 1], array_keys($r));
});

// Este é o comportamento que faz CVE médio "não fechar nunca": abaixo do piso
// ele nem entra no payload, então autoCloseVanishedCves nunca o vê sumir.
it('o que é cortado aqui nunca chega na reconciliação', function () use ($fleet) {
    $r   = filterCvesBySeverity($fleet, 'critical');
    $ids = array_column($r, 'cveId');
    assertTrue(!in_array('CVE-2024-0003', $ids, true), 'medium não pode passar o piso critical');
});
