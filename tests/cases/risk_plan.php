<?php

/**
 * Ranking of remediation actions by the fleet risk each one removes.
 *
 * The property that matters: an action is worth what it actually frees, so
 * "missing almost everywhere" must not automatically outrank "missing on a few
 * machines that are on fire". The reference fleet proves both directions — one
 * cumulative update on 99 machines is the third best action, while the
 * Malicious Software Removal Tool, missing on 160, barely places.
 *
 * The copies below call score()/tierCounts()/applyLifecycleFloor() with no
 * scope prefix, exactly as mirror.php normalises `Risk::` away. Those live in
 * risk_model.php, which the runner requires first — cases load in alphabetical
 * order and `risk_model` sorts before `risk_plan`. Renaming either file breaks
 * that, which is why the order is spelled out here.
 */

/** @mirror src/ActionPlan.php::simulate */
function simulate(array $state, array $remove): int {
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

    $result = score(tierCounts($cves, $kev, $patches));
    $result = applyLifecycleFloor($result, (string) ($state['lifecycle']['state'] ?? ''));

    return (int) $result['score'];
}

/** @mirror src/ActionPlan.php::rank */
function rank(array $actions, int $limit = 25): array {
    usort($actions, static function (array $a, array $b): int {
        return [$b['risk_removed'], $b['endpoints']] <=> [$a['risk_removed'], $a['endpoints']];
    });

    return array_slice($actions, 0, max(1, $limit));
}

function endpointState(array $over = []): array {
    return array_merge([
        'cves'      => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
        'kev'       => 0,
        'patches'   => ['critical' => 0, 'important' => 0, 'moderate' => 0, 'low' => 0],
        'lifecycle' => ['state' => 'supported'],
    ], $over);
}

// ── Simulação ─────────────────────────────────────────────────────────────

it('remover o último crítico zera o endpoint', function () {
    $e = endpointState(['cves' => ['critical' => 1, 'high' => 0, 'medium' => 0, 'low' => 0]]);
    assertSame(0, simulate($e, ['cves' => ['critical' => 1]]));
});

it('remover um achado de uma pilha grande muda pouco', function () {
    $e = endpointState(['cves' => ['critical' => 100, 'high' => 0, 'medium' => 0, 'low' => 0]]);
    $antes  = simulate($e, []);
    $depois = simulate($e, ['cves' => ['critical' => 1]]);
    assertTrue($antes - $depois <= 1, 'o 100º crítico não pode valer o mesmo que o 1º');
});

it('remover um CVE do KEV desconta nos dois lugares', function () {
    $e = endpointState(['cves' => ['critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 0], 'kev' => 1]);
    assertTrue(simulate($e, []) >= 60, 'um KEV aberto mantém o endpoint no nível crítico');
    assertSame(0, simulate($e, ['cves' => ['high' => 1], 'kev' => 1]));
});

it('não é possível remover mais do que existe', function () {
    $e = endpointState(['cves' => ['critical' => 1, 'high' => 0, 'medium' => 0, 'low' => 0]]);
    assertSame(0, simulate($e, ['cves' => ['critical' => 50]]), 'contagem negativa quebraria o score');
});

it('remover achado inexistente não muda nada', function () {
    $e = endpointState(['cves' => ['critical' => 2, 'high' => 0, 'medium' => 0, 'low' => 0]]);
    assertSame(simulate($e, []), simulate($e, ['patches' => ['moderate' => 3]]));
});

it('patch removido conta um nível abaixo, como no modelo', function () {
    $e = endpointState(['patches' => ['critical' => 3, 'important' => 0, 'moderate' => 0, 'low' => 0]]);
    $antes  = simulate($e, []);
    $depois = simulate($e, ['patches' => ['critical' => 3]]);
    assertTrue($antes >= 35, 'patch crítico entra no nível alto');
    assertSame(0, $depois);
});

// ── Fim de suporte muda o que vale a pena fazer ───────────────────────────

it('em máquina sem suporte o piso segura o ganho da correção', function () {
    $eol = endpointState([
        'cves'      => ['critical' => 2, 'high' => 0, 'medium' => 0, 'low' => 0],
        'lifecycle' => ['state' => 'eol'],
    ]);
    assertSame(40, simulate($eol, ['cves' => ['critical' => 2]]),
        'corrigir tudo num SO morto não pode pintar a máquina de verde');
});

it('a mesma correção numa máquina suportada zera o risco', function () {
    $ok = endpointState(['cves' => ['critical' => 2, 'high' => 0, 'medium' => 0, 'low' => 0]]);
    assertSame(0, simulate($ok, ['cves' => ['critical' => 2]]));
});

it('por isso patch rende menos em host sem suporte que em host suportado', function () {
    $comp = ['cves' => ['critical' => 2, 'high' => 0, 'medium' => 0, 'low' => 0]];
    $ganhoOk  = simulate(endpointState($comp), []) - simulate(endpointState($comp), ['cves' => ['critical' => 2]]);
    $eol      = endpointState($comp + ['lifecycle' => ['state' => 'eol']]);
    $ganhoEol = simulate($eol, []) - simulate($eol, ['cves' => ['critical' => 2]]);
    assertTrue($ganhoOk > $ganhoEol, 'o plano tem que preferir consertar onde o conserto resolve');
});

// ── Ordenação ─────────────────────────────────────────────────────────────

it('ordena pelo risco removido, não pelo número de máquinas', function () {
    $r = rank([
        ['key' => 'msrt',  'risk_removed' => 307,  'endpoints' => 160],
        ['key' => 'cumul', 'risk_removed' => 1343, 'endpoints' => 99],
    ]);
    assertSame('cumul', $r[0]['key'], 'abrangência sozinha não pode liderar a fila');
});

it('empate no risco é desempatado pela abrangência', function () {
    $r = rank([
        ['key' => 'estreita', 'risk_removed' => 500, 'endpoints' => 2],
        ['key' => 'ampla',    'risk_removed' => 500, 'endpoints' => 40],
    ]);
    assertSame('ampla', $r[0]['key'], 'uma implantação vale mais que 2 investigações');
});

it('respeita o limite pedido', function () {
    $muitas = [];
    for ($i = 0; $i < 50; $i++) {
        $muitas[] = ['key' => "a{$i}", 'risk_removed' => $i, 'endpoints' => 1];
    }
    assertSame(5, count(rank($muitas, 5)));
});

it('limite inválido ainda devolve alguma coisa', function () {
    assertSame(1, count(rank([['key' => 'x', 'risk_removed' => 1, 'endpoints' => 1]], 0)));
});

it('plano vazio continua vazio', function () {
    assertSame([], rank([], 10));
});

// Regressão: `lifecycle` guarda o array inteiro de Lifecycle::status(), e
// simulate() fazia (string) nele — virava a string literal "Array", o piso de
// fim de suporte nunca casava, e toda simulação em host morto saía menor que a
// verdade. Passava despercebido porque o teste alimentava a string documentada
// em vez da forma que a produção realmente grava.
it('aceita a forma que buildState() grava de verdade', function () {
    $eol = endpointState([
        'cves'      => ['critical' => 2, 'high' => 0, 'medium' => 0, 'low' => 0],
        'lifecycle' => ['state' => 'eol', 'product' => 'CentOS 7', 'eol_date' => '2024-06-30', 'days' => -400],
    ]);
    assertSame(40, simulate($eol, ['cves' => ['critical' => 2]]),
        'o piso tem que valer mesmo com o array completo do Lifecycle');
});

it('lifecycle ausente ou desconhecido não aplica piso nenhum', function () {
    $semLifecycle = endpointState(['cves' => ['critical' => 1, 'high' => 0, 'medium' => 0, 'low' => 0]]);
    unset($semLifecycle['lifecycle']);
    assertSame(0, simulate($semLifecycle, ['cves' => ['critical' => 1]]),
        'sem informação de suporte não se inventa piso');
});
