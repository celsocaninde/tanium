<?php

namespace GlpiPlugin\Tanium;

/**
 * Operating-system end-of-support detection.
 *
 * Why this exists: the plugin reported "missing patch" forever on machines
 * whose vendor stopped shipping patches. On the reference fleet that was ~12%
 * of the endpoints — Windows 10, Ubuntu 20.04, CentOS 7 and Server 2012 R2 —
 * and it is why a single Server 2012 R2 box carried 204 open critical CVEs.
 * Those findings are not remediable by patching, so counting them in the same
 * queue as fixable ones sends the team to work on a line that cannot move.
 *
 * The catalogue below is deliberately a plain static table rather than an API
 * call: it must work on an air-gapped GLPI, and a wrong date here is a
 * one-line fix. It needs a review roughly once a year — REVIEWED_ON records
 * when that last happened, and status() degrades to 'unknown' (never to a
 * false "supported") for anything it cannot match.
 */
class Lifecycle {

    /** Last human review of the dates below. Shown in the UI. */
    public const REVIEWED_ON = '2026-07-25';

    /** Within this many days of EOL an endpoint is already a planning problem. */
    public const ENDING_SOON_DAYS = 180;

    /**
     * [regex over the lowercased "os_name os_version" string, product label, EOL date].
     *
     * Order matters — first match wins, so the more specific pattern goes
     * first. Server patterns must precede the plain client ones ("windows
     * server 2012 r2" would otherwise never be reached).
     */
    public const CATALOGUE = [
        // ── Windows Server ────────────────────────────────────────────────
        ['/windows server\D*2003/',      'Windows Server 2003',    '2015-07-14'],
        ['/windows server\D*2008 r2/',   'Windows Server 2008 R2', '2020-01-14'],
        ['/windows server\D*2008/',      'Windows Server 2008',    '2020-01-14'],
        ['/windows server\D*2012 r2/',   'Windows Server 2012 R2', '2023-10-10'],
        ['/windows server\D*2012/',      'Windows Server 2012',    '2023-10-10'],
        ['/windows server\D*2016/',      'Windows Server 2016',    '2027-01-12'],
        ['/windows server\D*2019/',      'Windows Server 2019',    '2029-01-09'],
        ['/windows server\D*2022/',      'Windows Server 2022',    '2031-10-14'],
        ['/windows server\D*2025/',      'Windows Server 2025',    '2034-10-10'],

        // ── Windows client ────────────────────────────────────────────────
        ['/windows\D*(xp|vista)/',       'Windows XP/Vista',       '2017-04-11'],
        ['/windows\D*7\b/',              'Windows 7',              '2020-01-14'],
        ['/windows\D*8\.1/',             'Windows 8.1',            '2023-01-10'],
        ['/windows\D*8\b/',              'Windows 8',              '2016-01-12'],
        ['/windows\D*10\b/',             'Windows 10',             '2025-10-14'],
        ['/windows\D*11\b/',             'Windows 11',             '2031-10-14'],

        // ── Ubuntu (LTS standard support; ESM is a paid extension) ────────
        ['/ubuntu\D*16\.04/',            'Ubuntu 16.04 LTS',       '2021-04-30'],
        ['/ubuntu\D*18\.04/',            'Ubuntu 18.04 LTS',       '2023-05-31'],
        ['/ubuntu\D*20\.04/',            'Ubuntu 20.04 LTS',       '2025-05-31'],
        ['/ubuntu\D*22\.04/',            'Ubuntu 22.04 LTS',       '2027-06-01'],
        ['/ubuntu\D*24\.04/',            'Ubuntu 24.04 LTS',       '2029-06-01'],
        ['/ubuntu\D*26\.04/',            'Ubuntu 26.04 LTS',       '2031-06-01'],

        // ── CentOS ────────────────────────────────────────────────────────
        ['/centos\D*stream\D*8/',        'CentOS Stream 8',        '2024-05-31'],
        ['/centos\D*stream\D*9/',        'CentOS Stream 9',        '2027-05-31'],
        ['/centos\D*stream\D*10/',       'CentOS Stream 10',       '2030-05-31'],
        ['/centos\D*6/',                 'CentOS 6',               '2020-11-30'],
        ['/centos\D*7/',                 'CentOS 7',               '2024-06-30'],
        ['/centos\D*8/',                 'CentOS 8',               '2021-12-31'],

        // ── Oracle Linux ──────────────────────────────────────────────────
        ['/oracle linux\D*5/',           'Oracle Linux 5',         '2017-12-31'],
        ['/oracle linux\D*6/',           'Oracle Linux 6',         '2024-06-30'],
        ['/oracle linux\D*7/',           'Oracle Linux 7',         '2024-12-31'],
        ['/oracle linux\D*8/',           'Oracle Linux 8',         '2029-07-31'],
        ['/oracle linux\D*9/',           'Oracle Linux 9',         '2032-06-30'],

        // ── SUSE Linux Enterprise ─────────────────────────────────────────
        ['/sles\D*12|suse.*enterprise\D*12/', 'SLES 12',           '2027-10-31'],
        ['/sles\D*15|suse.*enterprise\D*15/', 'SLES 15',           '2031-07-31'],

        // ── RHEL and rebuilds (AlmaLinux / Rocky track RHEL) ──────────────
        ['/(rhel|red hat)\D*7/',         'RHEL 7',                 '2024-06-30'],
        ['/(rhel|red hat)\D*8/',         'RHEL 8',                 '2029-05-31'],
        ['/(rhel|red hat)\D*9/',         'RHEL 9',                 '2032-05-31'],
        ['/(rhel|red hat)\D*10/',        'RHEL 10',                '2035-05-31'],
        ['/(almalinux|rocky)\D*8/',      'AlmaLinux/Rocky 8',      '2029-03-01'],
        ['/(almalinux|rocky)\D*9/',      'AlmaLinux/Rocky 9',      '2032-05-31'],
        ['/(almalinux|rocky)\D*10/',     'AlmaLinux/Rocky 10',     '2035-05-31'],

        // ── Debian (including LTS) ────────────────────────────────────────
        ['/debian\D*9/',                 'Debian 9',               '2022-06-30'],
        ['/debian\D*10/',                'Debian 10',              '2024-06-30'],
        ['/debian\D*11/',                'Debian 11',              '2026-08-31'],
        ['/debian\D*12/',                'Debian 12',              '2028-06-30'],
        ['/debian\D*13/',                'Debian 13',              '2030-06-30'],
    ];

    /**
     * End-of-support state for an endpoint.
     *
     * `unknown` is a first-class answer, not a failure: claiming an
     * unrecognised OS is supported would quietly hide exactly the exotic hosts
     * most likely to be abandoned.
     *
     * @return array{state:string,product:?string,eol_date:?string,days:?int}
     */
    public static function status(?string $osName, ?string $osVersion = null, ?string $today = null): array {
        $haystack = strtolower(trim((string) $osName . ' ' . (string) $osVersion));
        $haystack = preg_replace('/\s+/', ' ', $haystack);

        if ($haystack === '') {
            return ['state' => 'unknown', 'product' => null, 'eol_date' => null, 'days' => null];
        }

        foreach (self::CATALOGUE as [$pattern, $product, $eol]) {
            if (!preg_match($pattern, $haystack)) {
                continue;
            }

            $now  = strtotime($today ?? 'today');
            $when = strtotime($eol);
            $days = (int) floor(($when - $now) / 86400);

            $state = match (true) {
                $days < 0                        => 'eol',
                $days <= self::ENDING_SOON_DAYS  => 'ending_soon',
                default                          => 'supported',
            };

            return ['state' => $state, 'product' => $product, 'eol_date' => $eol, 'days' => $days];
        }

        return ['state' => 'unknown', 'product' => null, 'eol_date' => null, 'days' => null];
    }

    /** True when the vendor no longer ships security fixes for this OS. */
    public static function isEol(?string $osName, ?string $osVersion = null, ?string $today = null): bool {
        return self::status($osName, $osVersion, $today)['state'] === 'eol';
    }
}
