<?php

/**
 * The risk model that replaced weighted-sum-then-clamp.
 *
 * The bug being locked down here: the old score summed a fixed weight per
 * finding and clamped with min(100, …). A production endpoint summed ~4.400
 * against that ceiling, so remediating every critical AND every high CVE left
 * the badge frozen on "100 Crítico". Several tests below exist purely to prove
 * the number moves when the work happens.
 */

const TIERS = [
    'critical' => [60.0, 30.0],
    'high'     => [35.0, 24.0],
    'medium'   => [15.0, 14.0],
    'low'      => [5.0,   5.0],
];

const TIER_ORDER = ['critical', 'high', 'medium', 'low'];

const VOLUME_SPAN = 100;

const BREADTH_MAX = 10.0;

const BREADTH_RATE = 3.0;

const BANDS = [
    [70, 'critical', 'tanium-risk-critical'],
    [40, 'high',     'tanium-risk-high'],
    [15, 'medium',   'tanium-risk-medium'],
    [0,  'low',      'tanium-risk-low'],
];

const GRADE_FINDING_WEIGHT = 7.0;

const GRADE_HYGIENE = [
    'agent_silent'  => 1.0,
    'os_eol'        => 0.8,
    'not_encrypted' => 0.6,
    'defender_bad'  => 0.6,
];

const EOL_FLOOR = 40;

/** @mirror src/Risk.php::tierCounts */
function tierCounts(array $cves, int $kev = 0, array $patches = []): array {
    $tiers = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

    foreach (TIER_ORDER as $tier) {
        $tiers[$tier] += max(0, (int) ($cves[$tier] ?? 0));
    }

    $tiers['critical'] += max(0, $kev);

    $tiers['high']   += max(0, (int) ($patches['critical'] ?? 0));
    $tiers['medium'] += max(0, (int) ($patches['important'] ?? 0));
    $tiers['low']    += max(0, (int) ($patches['moderate'] ?? 0))
                      + max(0, (int) ($patches['low'] ?? 0));

    return $tiers;
}

/** @mirror src/Risk.php::score */
function score(array $tiers): array {
    $tiers = [
        'critical' => max(0, (int) ($tiers['critical'] ?? 0)),
        'high'     => max(0, (int) ($tiers['high']     ?? 0)),
        'medium'   => max(0, (int) ($tiers['medium']   ?? 0)),
        'low'      => max(0, (int) ($tiers['low']      ?? 0)),
    ];
    $total = array_sum($tiers);

    $dominant = null;
    foreach (TIER_ORDER as $tier) {
        if ($tiers[$tier] > 0) {
            $dominant = $tier;
            break;
        }
    }

    if ($dominant === null) {
        return [
            'score'          => 0,
            'dominant'       => null,
            'band'           => 'low',
            'steps'          => [],
            'total_findings' => 0,
        ];
    }

    [$base, $growth] = TIERS[$dominant];
    $count  = $tiers[$dominant];
    $volume = $growth * volumeRatio($count);

    $lower = 0;
    $below = false;
    foreach (TIER_ORDER as $tier) {
        if ($tier === $dominant) {
            $below = true;
            continue;
        }
        if ($below) {
            $lower += $tiers[$tier];
        }
    }
    $breadth = $lower > 0
        ? min(BREADTH_MAX, BREADTH_RATE * log10(1 + $lower))
        : 0.0;

    $steps = [
        ['kind' => 'base',   'tier' => $dominant, 'count' => $count, 'points' => round($base, 1)],
        ['kind' => 'volume', 'tier' => $dominant, 'count' => $count, 'points' => round($volume, 1)],
    ];
    if ($lower > 0) {
        $steps[] = ['kind' => 'breadth', 'tier' => null, 'count' => $lower, 'points' => round($breadth, 1)];
    }

    $score = (int) round(min(100.0, $base + $volume + $breadth));

    return [
        'score'          => $score,
        'dominant'       => $dominant,
        'band'           => band($score),
        'steps'          => $steps,
        'total_findings' => $total,
    ];
}

/** @mirror src/Risk.php::applyLifecycleFloor */
function applyLifecycleFloor(array $result, string $state): array {
    if ($state !== 'eol' || (int) $result['score'] >= EOL_FLOOR) {
        return $result;
    }

    $result['steps'][] = [
        'kind'   => 'eol_floor',
        'tier'   => null,
        'count'  => 0,
        'points' => round(EOL_FLOOR - (int) $result['score'], 1),
    ];
    $result['score'] = EOL_FLOOR;
    $result['band']  = band(EOL_FLOOR);

    return $result;
}

/** @mirror src/Risk.php::volumeRatio */
function volumeRatio(int $count): float {
    if ($count <= 0) {
        return 0.0;
    }
    return min(1.0, log10(1 + $count) / log10(1 + VOLUME_SPAN));
}

/** @mirror src/Risk.php::band */
function band(int $score): string {
    foreach (BANDS as [$min, $key, ]) {
        if ($score >= $min) {
            return $key;
        }
    }
    return 'low';
}

/** @mirror src/Risk.php::grade */
function grade(int $riskScore, array $hygiene = []): array {
    $riskScore = max(0, min(100, $riskScore));
    $findingLoss = GRADE_FINDING_WEIGHT * ($riskScore / 100);

    $steps = [];
    if ($findingLoss > 0) {
        $steps[] = ['kind' => 'findings', 'points' => -round($findingLoss, 2), 'risk' => $riskScore];
    }

    $hygieneLoss = 0.0;
    foreach (GRADE_HYGIENE as $key => $cost) {
        if (!empty($hygiene[$key])) {
            $hygieneLoss += $cost;
            $steps[] = ['kind' => $key, 'points' => -$cost];
        }
    }

    $grade = round(max(0.0, 10.0 - $findingLoss - $hygieneLoss), 1);

    return ['grade' => $grade, 'steps' => $steps];
}

/** @mirror src/Risk.php::usesDefender */
function usesDefender(?string $osName, ?string $osPlatform = null): bool {
    $haystack = strtolower(trim((string) $osName . ' ' . (string) $osPlatform));
    if ($haystack === '') {
        return false;
    }
    foreach (['windows', 'win32', 'win64', 'winnt', 'microsoft'] as $marker) {
        if (str_contains($haystack, $marker)) {
            return true;
        }
    }
    return false;
}

// ── Baseline ──────────────────────────────────────────────────────────────

it('sem achado nenhum a nota de risco é zero', function () {
    $r = score(tierCounts([]));
    assertSame(0, $r['score']);
    assertSame('low', $r['band']);
    assertSame(null, $r['dominant']);
});

it('endpoint limpo não inventa etapas de cálculo', function () {
    assertSame([], score(tierCounts([]))['steps']);
});

// ── O caso real que motivou a mudança (endpoint S0222) ────────────────────

$s0222 = ['critical' => 39, 'high' => 557, 'medium' => 615, 'low' => 18];

it('S0222 pontua 93 em vez do 100 saturado', function () use ($s0222) {
    assertSame(93, score(tierCounts($s0222))['score']);
});

it('corrigir os críticos derruba o score e a faixa', function () use ($s0222) {
    $depois = score(tierCounts(['high' => 557, 'medium' => 615, 'low' => 18]));
    assertSame(67, $depois['score'], 'no modelo antigo isto continuava 100');
    assertSame('high', $depois['band']);
});

it('corrigir também os altos derruba de novo', function () {
    $r = score(tierCounts(['medium' => 615, 'low' => 18]));
    assertSame(33, $r['score']);
    assertSame('medium', $r['band']);
});

it('sobrando só os baixos o endpoint fica verde', function () {
    $r = score(tierCounts(['low' => 18]));
    assertSame(8, $r['score']);
    assertSame('low', $r['band']);
});

it('cada etapa da remediação muda o número — nenhuma empata', function () use ($s0222) {
    $etapas = [
        score(tierCounts($s0222))['score'],
        score(tierCounts(['high' => 557, 'medium' => 615, 'low' => 18]))['score'],
        score(tierCounts(['medium' => 615, 'low' => 18]))['score'],
        score(tierCounts(['low' => 18]))['score'],
        score(tierCounts([]))['score'],
    ];
    assertSame($etapas, array_values(array_unique($etapas)), 'valores repetidos = progresso invisível');
    $ordenado = $etapas;
    rsort($ordenado);
    assertSame($ordenado, $etapas, 'a sequência tem que ser estritamente decrescente');
});

// ── Regressão direta da saturação antiga ──────────────────────────────────

it('4 e 204 CVEs críticos não podem dar a mesma nota', function () {
    $poucos = score(tierCounts(['critical' => 4]))['score'];
    $muitos = score(tierCounts(['critical' => 204]))['score'];
    assertTrue($poucos !== $muitos, "ambos deram {$poucos} — é a saturação de volta");
    assertTrue($muitos > $poucos, 'mais CVEs críticos tem que pesar mais');
});

it('o volume dentro do nível cresce logaritmicamente, não linearmente', function () {
    $de1a10  = score(tierCounts(['critical' => 10]))['score']  - score(tierCounts(['critical' => 1]))['score'];
    $de10a19 = score(tierCounts(['critical' => 19]))['score'] - score(tierCounts(['critical' => 10]))['score'];
    assertTrue($de1a10 > $de10a19, 'os primeiros achados têm que doer mais que os últimos');
});

// ── Invariantes de faixa ──────────────────────────────────────────────────

it('sem nenhum crítico o endpoint nunca alcança a faixa crítica', function () {
    $r = score(tierCounts(['high' => 100000, 'medium' => 100000, 'low' => 100000]));
    assertTrue($r['score'] < 70, "chegou a {$r['score']} sem nenhum CVE crítico");
    assertSame('high', $r['band']);
});

it('um único crítico já tira o endpoint da faixa baixa', function () {
    assertTrue(score(tierCounts(['critical' => 1]))['score'] >= 60);
});

it('o score nunca passa de 100', function () {
    $r = score(tierCounts(['critical' => 999999, 'high' => 999999, 'medium' => 999999, 'low' => 999999]));
    assertTrue($r['score'] <= 100, "veio {$r['score']}");
});

it('a severidade dominante é sempre a pior presente', function () {
    assertSame('critical', score(tierCounts(['critical' => 1, 'low' => 900]))['dominant']);
    assertSame('medium',   score(tierCounts(['medium' => 1, 'low' => 900]))['dominant']);
});

it('uma cauda enorme de baixos não supera um único crítico', function () {
    $umCritico = score(tierCounts(['critical' => 1]))['score'];
    $muitoBaixo = score(tierCounts(['low' => 500000]))['score'];
    assertTrue($umCritico > $muitoBaixo, 'volume de ruído não pode passar na frente da severidade');
});

// ── Composição das contagens ──────────────────────────────────────────────

it('KEV soma no nível crítico porque exploração ativa vale mais', function () {
    $t = tierCounts(['high' => 10], 3);
    assertSame(3, $t['critical']);
    assertSame(10, $t['high']);
});

it('patch ausente entra um nível abaixo da própria severidade', function () {
    $t = tierCounts([], 0, ['critical' => 2, 'important' => 3, 'moderate' => 4, 'low' => 5]);
    assertSame(0, $t['critical'], 'patch sozinho não pode criar um endpoint crítico');
    assertSame(2, $t['high']);
    assertSame(3, $t['medium']);
    assertSame(9, $t['low'], 'moderate + low caem juntos no nível baixo');
});

it('contagem negativa é tratada como zero', function () {
    $t = tierCounts(['critical' => -5], -2);
    assertSame(0, $t['critical']);
});

// ── Nota 0-10 derivada ────────────────────────────────────────────────────

it('endpoint impecável tira 10', function () {
    assertSame(10.0, grade(0)['grade']);
});

it('o pior caso possível é zero — e exige risco 100 E toda a higiene falhando', function () {
    $pior = grade(100, [
        'agent_silent'  => true,
        'os_eol'        => true,
        'not_encrypted' => true,
        'defender_bad'  => true,
    ]);
    assertSame(0.0, $pior['grade']);
});

it('a higiene soma exatamente 3,0 — o complemento dos 7 pontos de achados', function () {
    assertSame(3.0, round(array_sum(GRADE_HYGIENE), 2));
    assertSame(10.0, round(GRADE_FINDING_WEIGHT + array_sum(GRADE_HYGIENE), 2));
});

it('risco 100 sozinho não zera a nota — 0.0 volta a significar alguma coisa', function () {
    assertSame(3.0, grade(100)['grade']);
});

it('a nota acompanha a queda do risco', function () {
    $antes  = grade(93, ['not_encrypted' => true])['grade'];
    $depois = grade(67, ['not_encrypted' => true])['grade'];
    assertTrue($depois > $antes, "nota travou: {$antes} → {$depois}");
});

it('higiene sozinha não derruba o endpoint para crítico', function () {
    $g = grade(0, [
        'agent_silent'  => true,
        'os_eol'        => true,
        'not_encrypted' => true,
        'defender_bad'  => true,
    ])['grade'];
    assertSame(7.0, $g);
});

// ── Piso de fim de suporte ────────────────────────────────────────────────

it('SO sem suporte não pode ficar verde nem com zero achados', function () {
    $limpo = applyLifecycleFloor(score(tierCounts([])), 'eol');
    assertSame(EOL_FLOOR, $limpo['score']);
    assertSame('high', $limpo['band'], 'a máquina não tem conserto por patch — não é risco baixo');
});

it('o piso não mexe em quem já está acima dele', function () {
    $grave = score(tierCounts(['critical' => 39, 'high' => 557, 'medium' => 615, 'low' => 18]));
    assertSame($grave['score'], applyLifecycleFloor($grave, 'eol')['score']);
});

it('SO suportado nunca recebe piso', function () {
    foreach (['supported', 'ending_soon', 'unknown'] as $estado) {
        assertSame(0, applyLifecycleFloor(score(tierCounts([])), $estado)['score'], "estado {$estado}");
    }
});

it('o piso aparece como etapa explícita e as etapas continuam somando', function () {
    $r = applyLifecycleFloor(score(tierCounts(['low' => 2])), 'eol');
    $soma = 0.0;
    foreach ($r['steps'] as $s) {
        $soma += (float) $s['points'];
    }
    assertSame($r['score'], (int) round($soma));
    assertSame('eol_floor', end($r['steps'])['kind']);
});

it('a nota registra cada desconto para a tela poder mostrar a conta', function () {
    $g = grade(50, ['not_encrypted' => true]);
    assertSame(2, count($g['steps']));
    assertSame('findings', $g['steps'][0]['kind']);
    assertSame('not_encrypted', $g['steps'][1]['kind']);
});

// ── Defender só onde Defender existe ──────────────────────────────────────

it('AlmaLinux não é penalizado por Windows Defender', function () {
    assertTrue(!usesDefender('AlmaLinux release 8.7 (Stone Smilodon)', 'Linux'));
});

it('"darwin" contém "win" e mesmo assim não é Windows', function () {
    assertTrue(!usesDefender('macOS 14 darwin', 'Darwin'), 'a mesma armadilha que quebrou mapOsType()');
});

it('Windows continua sendo avaliado', function () {
    assertTrue(usesDefender('Windows Server 2019 Datacenter', 'Windows'));
    assertTrue(usesDefender('Microsoft Windows 11 Pro'));
});

it('OS desconhecido não acusa nada', function () {
    assertTrue(!usesDefender(null));
    assertTrue(!usesDefender('', ''));
});

// ── Transparência do cálculo ──────────────────────────────────────────────

it('as etapas somam exatamente o score exibido', function () use ($s0222) {
    $r = score(tierCounts($s0222));
    $soma = 0.0;
    foreach ($r['steps'] as $s) {
        $soma += (float) $s['points'];
    }
    assertSame($r['score'], (int) round($soma), 'a conta mostrada tem que bater com o número');
});

it('a etapa de amplitude só aparece quando existe severidade menor', function () {
    $semCauda = score(tierCounts(['critical' => 5]));
    assertSame(2, count($semCauda['steps']));

    $comCauda = score(tierCounts(['critical' => 5, 'low' => 1]));
    assertSame(3, count($comCauda['steps']));
    assertSame('breadth', $comCauda['steps'][2]['kind']);
});
