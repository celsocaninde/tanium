<?php

/**
 * End-of-support detection.
 *
 * These dates decide whether an endpoint is told "patch it" or "replace it",
 * so a wrong match here sends real work in the wrong direction. The cases
 * below pin the strings the reference fleet actually reports.
 */

const REVIEWED_ON = '2026-07-25';

const ENDING_SOON_DAYS = 180;

const CATALOGUE = [
    ['/windows server\D*2003/',      'Windows Server 2003',    '2015-07-14'],
    ['/windows server\D*2008 r2/',   'Windows Server 2008 R2', '2020-01-14'],
    ['/windows server\D*2008/',      'Windows Server 2008',    '2020-01-14'],
    ['/windows server\D*2012 r2/',   'Windows Server 2012 R2', '2023-10-10'],
    ['/windows server\D*2012/',      'Windows Server 2012',    '2023-10-10'],
    ['/windows server\D*2016/',      'Windows Server 2016',    '2027-01-12'],
    ['/windows server\D*2019/',      'Windows Server 2019',    '2029-01-09'],
    ['/windows server\D*2022/',      'Windows Server 2022',    '2031-10-14'],
    ['/windows server\D*2025/',      'Windows Server 2025',    '2034-10-10'],
    ['/windows\D*(xp|vista)/',       'Windows XP/Vista',       '2017-04-11'],
    ['/windows\D*7\b/',              'Windows 7',              '2020-01-14'],
    ['/windows\D*8\.1/',             'Windows 8.1',            '2023-01-10'],
    ['/windows\D*8\b/',              'Windows 8',              '2016-01-12'],
    ['/windows\D*10\b/',             'Windows 10',             '2025-10-14'],
    ['/windows\D*11\b/',             'Windows 11',             '2031-10-14'],
    ['/ubuntu\D*16\.04/',            'Ubuntu 16.04 LTS',       '2021-04-30'],
    ['/ubuntu\D*18\.04/',            'Ubuntu 18.04 LTS',       '2023-05-31'],
    ['/ubuntu\D*20\.04/',            'Ubuntu 20.04 LTS',       '2025-05-31'],
    ['/ubuntu\D*22\.04/',            'Ubuntu 22.04 LTS',       '2027-06-01'],
    ['/ubuntu\D*24\.04/',            'Ubuntu 24.04 LTS',       '2029-06-01'],
    ['/ubuntu\D*26\.04/',            'Ubuntu 26.04 LTS',       '2031-06-01'],
    ['/centos\D*stream\D*8/',        'CentOS Stream 8',        '2024-05-31'],
    ['/centos\D*stream\D*9/',        'CentOS Stream 9',        '2027-05-31'],
    ['/centos\D*stream\D*10/',       'CentOS Stream 10',       '2030-05-31'],
    ['/centos\D*6/',                 'CentOS 6',               '2020-11-30'],
    ['/centos\D*7/',                 'CentOS 7',               '2024-06-30'],
    ['/centos\D*8/',                 'CentOS 8',               '2021-12-31'],
    ['/oracle linux\D*5/',           'Oracle Linux 5',         '2017-12-31'],
    ['/oracle linux\D*6/',           'Oracle Linux 6',         '2024-06-30'],
    ['/oracle linux\D*7/',           'Oracle Linux 7',         '2024-12-31'],
    ['/oracle linux\D*8/',           'Oracle Linux 8',         '2029-07-31'],
    ['/oracle linux\D*9/',           'Oracle Linux 9',         '2032-06-30'],
    ['/sles\D*12|suse.*enterprise\D*12/', 'SLES 12',           '2027-10-31'],
    ['/sles\D*15|suse.*enterprise\D*15/', 'SLES 15',           '2031-07-31'],
    ['/(rhel|red hat)\D*7/',         'RHEL 7',                 '2024-06-30'],
    ['/(rhel|red hat)\D*8/',         'RHEL 8',                 '2029-05-31'],
    ['/(rhel|red hat)\D*9/',         'RHEL 9',                 '2032-05-31'],
    ['/(rhel|red hat)\D*10/',        'RHEL 10',                '2035-05-31'],
    ['/(almalinux|rocky)\D*8/',      'AlmaLinux/Rocky 8',      '2029-03-01'],
    ['/(almalinux|rocky)\D*9/',      'AlmaLinux/Rocky 9',      '2032-05-31'],
    ['/(almalinux|rocky)\D*10/',     'AlmaLinux/Rocky 10',     '2035-05-31'],
    ['/debian\D*9/',                 'Debian 9',               '2022-06-30'],
    ['/debian\D*10/',                'Debian 10',              '2024-06-30'],
    ['/debian\D*11/',                'Debian 11',              '2026-08-31'],
    ['/debian\D*12/',                'Debian 12',              '2028-06-30'],
    ['/debian\D*13/',                'Debian 13',              '2030-06-30'],
];

/** @mirror src/Lifecycle.php::status */
function status(?string $osName, ?string $osVersion = null, ?string $today = null): array {
    $haystack = strtolower(trim((string) $osName . ' ' . (string) $osVersion));
    $haystack = preg_replace('/\s+/', ' ', $haystack);

    if ($haystack === '') {
        return ['state' => 'unknown', 'product' => null, 'eol_date' => null, 'days' => null];
    }

    foreach (CATALOGUE as [$pattern, $product, $eol]) {
        if (!preg_match($pattern, $haystack)) {
            continue;
        }

        $now  = strtotime($today ?? 'today');
        $when = strtotime($eol);
        $days = (int) floor(($when - $now) / 86400);

        $state = match (true) {
            $days < 0                        => 'eol',
            $days <= ENDING_SOON_DAYS  => 'ending_soon',
            default                          => 'supported',
        };

        return ['state' => $state, 'product' => $product, 'eol_date' => $eol, 'days' => $days];
    }

    return ['state' => 'unknown', 'product' => null, 'eol_date' => null, 'days' => null];
}

// Data de referência fixa: sem isto a suíte muda de resultado com o calendário.
const HOJE = '2026-07-25';

// ── Strings reais da frota ────────────────────────────────────────────────

it('Windows 10 Pro está fora de suporte', function () {
    $s = status('Windows 10 Pro', '10.0.19045', HOJE);
    assertSame('eol', $s['state']);
    assertSame('Windows 10', $s['product']);
});

it('Windows 11 Pro continua suportado', function () {
    assertSame('supported', status('Windows 11 Pro', '10.0.22631', HOJE)['state']);
});

it('CentOS 7.9 está fora de suporte', function () {
    $s = status('CentOS Linux release 7.9.2009 (Core)', null, HOJE);
    assertSame('eol', $s['state']);
    assertSame('CentOS 7', $s['product']);
});

it('Windows Server 2012 R2 casa antes do 2012 puro', function () {
    assertSame('Windows Server 2012 R2', status('Windows Server 2012 R2 Datacenter', null, HOJE)['product']);
});

it('Ubuntu 20.04 acabou, 22.04 não', function () {
    assertSame('eol',       status('Ubuntu 20.04.4 LTS', null, HOJE)['state']);
    assertSame('supported', status('Ubuntu 22.04.5 LTS', null, HOJE)['state']);
});

it('AlmaLinux 8 e 10 seguem suportados', function () {
    assertSame('supported', status('AlmaLinux release 8.7 (Stone Smilodon)', null, HOJE)['state']);
    assertSame('supported', status('AlmaLinux release 10.2 (Lavender Lion)', null, HOJE)['state']);
});

it('Oracle Linux 5 é reconhecido em vez de virar desconhecido', function () {
    assertSame('eol', status('Oracle Linux Server release 5.11', null, HOJE)['state']);
});

// ── Precedência entre padrões ─────────────────────────────────────────────

it('Windows Server nunca cai no padrão do cliente', function () {
    foreach (['2016', '2019', '2022', '2025'] as $ano) {
        $p = status("Windows Server {$ano} Datacenter", null, HOJE)['product'];
        assertSame("Windows Server {$ano}", $p, "Server {$ano} casou errado");
    }
});

it('a versão do SO no fim da string não confunde o padrão', function () {
    // "Windows 11 Pro 10.0.22631" contém "10." — não pode virar Windows 10.
    assertSame('Windows 11', status('Windows 11 Pro', '10.0.22631', HOJE)['product']);
});

it('Windows 8.1 não é confundido com Windows 8', function () {
    assertSame('Windows 8.1', status('Windows 8.1 Enterprise', null, HOJE)['product']);
});

// ── Não conhecer é uma resposta ───────────────────────────────────────────

it('SO desconhecido não é declarado suportado', function () {
    $s = status('TempleOS 5.03', null, HOJE);
    assertSame('unknown', $s['state'], 'chutar "suportado" esconderia justamente o host exótico');
    assertSame(null, $s['eol_date']);
});

it('SO vazio é desconhecido', function () {
    assertSame('unknown', status(null, null, HOJE)['state']);
    assertSame('unknown', status('', '', HOJE)['state']);
});

// ── Janela de aviso ───────────────────────────────────────────────────────

it('avisa antes de acabar, não só depois', function () {
    // Debian 11 acaba em 31/08/2026; em 25/07/2026 faltam ~37 dias.
    $s = status('Debian GNU/Linux 11 (bullseye)', null, HOJE);
    assertSame('ending_soon', $s['state']);
    assertTrue($s['days'] > 0 && $s['days'] <= ENDING_SOON_DAYS, "faltavam {$s['days']} dias");
});

it('a contagem de dias fica negativa depois do fim', function () {
    assertTrue(status('CentOS Linux release 7.9.2009', null, HOJE)['days'] < 0);
});

it('o mesmo SO muda de estado conforme a data de referência', function () {
    assertSame('supported', status('Windows 10 Pro', null, '2025-01-01')['state']);
    assertSame('eol',       status('Windows 10 Pro', null, '2026-01-01')['state']);
});
