<?php

/** @mirror src/Analytics.php::weeksToZero */
function weeksToZero(int $backlog, float $netPerWeek): ?int {
    if ($backlog <= 0) {
        return 0;
    }
    if ($netPerWeek <= 0) {
        return null;
    }
    return (int) ceil($backlog / $netPerWeek);
}

/** @mirror src/Analytics.php::reincidenceRate */
function reincidenceRate(int $reopened, int $closed): float {
    if ($closed <= 0) {
        return 0.0;
    }
    return min(1.0, $reopened / $closed);
}

/** @mirror src/Analytics.php::median */
function median(array $values): float {
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

/** @mirror src/Analytics.php::outlierRatio */
function outlierRatio(int $findings, float $peerMedian): float {
    if ($peerMedian <= 0) {
        return $findings > 0 ? (float) $findings : 0.0;
    }
    return $findings / $peerMedian;
}

/** @mirror src/Analytics.php::peerKey */
function peerKey(string $osName, int $isVirtual): string {
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

// ── weeksToZero ──────────────────────────────────────────────────────────

it('projeta as semanas até zerar arredondando para cima', function () {
    assertSame(10, weeksToZero(100, 10.0));
    assertSame(11, weeksToZero(101, 10.0), 'sobra de uma unidade ainda custa uma semana inteira');
});

it('fila que não encolhe devolve null em vez de número negativo', function () {
    assertSame(null, weeksToZero(500, -12.0), 'abrindo mais do que fecha, nunca zera');
    assertSame(null, weeksToZero(500, 0.0), 'empate também nunca zera');
});

it('fila já vazia é zero semanas, não null', function () {
    assertSame(0, weeksToZero(0, -5.0), 'sem backlog não há o que projetar');
});

// ── reincidenceRate ──────────────────────────────────────────────────────

it('taxa de reincidência é a fração do que não ficou resolvido', function () {
    assertSame(0.25, reincidenceRate(25, 100));
});

it('período sem nenhuma correção tem taxa zero, não divisão por zero', function () {
    assertSame(0.0, reincidenceRate(7, 0));
});

it('taxa satura em 1 quando reabre mais do que fechou no período', function () {
    assertSame(1.0, reincidenceRate(150, 100), 'reaberturas podem vir de fechamentos anteriores à janela');
});

// ── median ───────────────────────────────────────────────────────────────

it('mediana de lista ímpar é o elemento do meio', function () {
    assertSame(5.0, median([1, 5, 100]));
});

it('mediana de lista par é a média dos dois centrais', function () {
    assertSame(3.0, median([1, 2, 4, 40]));
});

it('mediana ignora a ordem de entrada', function () {
    assertSame(5.0, median([100, 1, 5]));
});

it('lista vazia tem mediana zero', function () {
    assertSame(0.0, median([]));
});

it('mediana resiste a um outlier extremo', function () {
    // É exatamente por isso que não se usa média aqui: a média desta lista é
    // 102,25 — acima de TODOS os valores menos um, o que faria a máquina de
    // 400 achados parecer a normal do grupo.
    assertSame(3.5, median([2, 3, 4, 400]));
});

// ── outlierRatio ─────────────────────────────────────────────────────────

it('razão é o múltiplo da mediana dos pares', function () {
    assertSame(2.5, outlierRatio(50, 20.0));
});

it('grupo inteiro limpo faz a contagem virar a própria razão', function () {
    assertSame(7.0, outlierRatio(7, 0.0), 'sem dividir por zero');
});

it('máquina limpa em grupo limpo não é outlier', function () {
    assertSame(0.0, outlierRatio(0, 0.0));
});

// ── peerKey ──────────────────────────────────────────────────────────────

it('releases menores do mesmo SO caem no mesmo balde', function () {
    assertSame('Ubuntu 22 (physical)', peerKey('Ubuntu 22.04.3 LTS', 0));
    assertSame(peerKey('Ubuntu 22.04.3 LTS', 0), peerKey('Ubuntu 22.04.5 LTS', 0));
});

it('gerações diferentes NÃO se misturam', function () {
    // Na frota real, juntar AlmaLinux 8 com AlmaLinux 10 derrubou a mediana
    // para 1 e reportou todo servidor 8.x como outlier de 1700x. Versão maior
    // é outra linha de base, não uma variação.
    assertTrue(peerKey('AlmaLinux release 8.7', 1) !== peerKey('AlmaLinux release 10.2', 1));
    assertSame('AlmaLinux release 8 (virtual)', peerKey('AlmaLinux release 8.7 (Stone Smilodon)', 1));
    assertSame('AlmaLinux release 10 (virtual)', peerKey('AlmaLinux release 10.2 (Lavender Lion)', 1));
});

it('mantém o produto inteiro quando ele tem várias palavras', function () {
    assertSame('Red Hat Enterprise Linux 8 (physical)', peerKey('Red Hat Enterprise Linux 8.10', 0));
});

it('servidor não é comparado com estação', function () {
    assertTrue(peerKey('Windows Server 2019', 0) !== peerKey('Windows 11 Pro', 0), 'servidor e estação não podem cair no mesmo grupo');
    assertSame('Windows Server 2019 (physical)', peerKey('Windows Server 2019', 0));
    assertSame('Windows 11 (physical)', peerKey('Windows 11 Pro', 0));
});

it('Windows 10 e Windows 11 são grupos distintos', function () {
    assertTrue(peerKey('Windows 10 Pro', 0) !== peerKey('Windows 11 Pro', 0));
});

it('separa virtual de físico', function () {
    assertSame('Ubuntu 22 (virtual)', peerKey('Ubuntu 22.04.3 LTS', 1));
    assertSame('Ubuntu 22 (physical)', peerKey('Ubuntu 22.04.3 LTS', 0));
});

it('SO sem nome vira "unknown" em vez de balde vazio', function () {
    assertSame('unknown (physical)', peerKey('   ', 0));
});

it('SO que começa com número mantém a geração mesmo sem produto', function () {
    assertSame('unknown 22 (physical)', peerKey('22.04 LTS', 0));
});
