<?php

/** @mirror src/PatchDeploy.php::kbParts */
function kbParts(?string $kbId): array {
    // Hyphens are NOT separators: USN/DSA/RHSA ids embed them.
    $tokens = preg_split('/[\s,;|]+/', trim((string)$kbId), -1, PREG_SPLIT_NO_EMPTY) ?: [];

    $out = [];
    foreach ($tokens as $token) {
        $label = trim($token, ".,;:()[]'\"");
        if ($label === '') {
            continue;
        }
        $out[] = [
            'label' => $label,
            // The canonical article URL takes the bare number — /kb/KB123 404s.
            'url'   => preg_match('/^KB\d+$/i', $label)
                ? 'https://support.microsoft.com/help/' . preg_replace('/^KB/i', '', $label)
                : null,
        ];
    }
    return $out;
}

it('linka um KB único', function () {
    $p = kbParts('KB5034441');
    assertSame(1, count($p));
    assertSame('https://support.microsoft.com/help/5034441', $p[0]['url']);
});

it('separa cumulativo com vários KBs', function () {
    $p = kbParts('KB5034441, KB5034123');
    assertSame(2, count($p), 'quantidade');
    assertSame('KB5034441', $p[0]['label']);
    assertSame('https://support.microsoft.com/help/5034123', $p[1]['url']);
});

it('aceita espaço como separador', function () {
    assertSame(2, count(kbParts('KB5034441 KB5034123')));
});

it('não linka advisory Linux para a Microsoft', function () {
    $p = kbParts('USN-6013-1');
    assertSame('USN-6013-1', $p[0]['label'], 'hífen não pode ser separador');
    assertSame(null, $p[0]['url']);
});

it('preserva os dois pedaços de um par de USNs', function () {
    $p = kbParts('USN-6013-1 USN-6013-2');
    assertSame(2, count($p));
    assertSame(null, $p[0]['url']);
    assertSame(null, $p[1]['url']);
});

it('não linka RHSA e mantém os dois-pontos internos', function () {
    $p = kbParts('RHSA-2024:0123');
    assertSame('RHSA-2024:0123', $p[0]['label']);
    assertSame(null, $p[0]['url']);
});

it('é case-insensitive no prefixo KB', function () {
    assertSame('https://support.microsoft.com/help/5034441', kbParts('kb5034441')[0]['url']);
});

it('devolve vazio para nulo e string vazia', function () {
    assertSame([], kbParts(null));
    assertSame([], kbParts(''));
    assertSame([], kbParts('   '));
});
