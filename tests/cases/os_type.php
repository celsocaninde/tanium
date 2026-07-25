<?php

/** @mirror src/PatchDeploy.php::mapOsType */
function mapOsType(string $os): string {
    $o = strtolower($os);
    // macOS is tested FIRST because "darwin" contains "win": checking
    // Windows first classified every Darwin-reported Mac as Windows.
    if (str_contains($o, 'mac') || str_contains($o, 'darwin'))  return 'mac';
    if (str_contains($o, 'win'))                               return 'windows';

    foreach ([
        'lin', 'ubuntu', 'debian', 'red hat', 'redhat', 'rhel', 'centos',
        'suse', 'sles', 'fedora', 'rocky', 'alma', 'oracle', 'amzn',
    ] as $marker) {
        if (str_contains($o, $marker)) {
            return 'linux';
        }
    }
    return 'windows';
}

// The fallback is 'windows', so every distro whose name lacks "Linux" is a
// regression risk — these are the ones that were being deployed as Windows.
it('RHEL sem a palavra Linux é linux', function () {
    assertSame('linux', mapOsType('RHEL 9'));
    assertSame('linux', mapOsType('RHEL 8.10'));
});

it('Fedora é linux', function () {
    assertSame('linux', mapOsType('Fedora 40'));
});

it('nome completo da Red Hat é linux', function () {
    assertSame('linux', mapOsType('Red Hat Enterprise Linux 9.3'));
});

it('derivados EL são linux', function () {
    assertSame('linux', mapOsType('Rocky Linux 9'));
    assertSame('linux', mapOsType('AlmaLinux 9'));
    assertSame('linux', mapOsType('Oracle Linux Server 8.9'));
    assertSame('linux', mapOsType('CentOS Stream 9'));
});

it('família Debian é linux', function () {
    assertSame('linux', mapOsType('Ubuntu 22.04.4 LTS'));
    assertSame('linux', mapOsType('Debian GNU/Linux 12'));
});

it('SUSE é linux nas duas grafias', function () {
    assertSame('linux', mapOsType('SLES 15 SP5'));
    assertSame('linux', mapOsType('openSUSE Leap 15.5'));
});

it('Amazon Linux é linux', function () {
    assertSame('linux', mapOsType('Amazon Linux 2023'));
});

it('Windows continua windows', function () {
    assertSame('windows', mapOsType('Windows Server 2022'));
    assertSame('windows', mapOsType('Windows 11 Pro'));
});

it('macOS é mac', function () {
    assertSame('mac', mapOsType('macOS Sonoma 14.4'));
    assertSame('mac', mapOsType('Darwin 23.4.0'));
});

it('string vazia cai no fallback windows', function () {
    assertSame('windows', mapOsType(''));
});

it('o campo é montado como platform + name', function () {
    // PatchDeploy passa os dois concatenados; o platform costuma vir "Linux".
    assertSame('linux', mapOsType('Linux RHEL 9'));
});
