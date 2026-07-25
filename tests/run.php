<?php

/**
 * Zero-dependency test runner for the plugin's pure logic.
 *
 * The classes under test pull in GLPI (CommonGLPI, $DB, Session…), which is not
 * bootstrappable outside the container, so each case file re-declares the
 * function under test as a free function — a deliberate copy. That means a test
 * proves the ALGORITHM, not that the copy is in sync with src/; `tests/mirror.php`
 * closes that gap by diffing each copy against the real method body.
 *
 *   php tests/run.php            run everything
 *   php tests/run.php kb         run case files matching "kb"
 */

$filter = $argv[1] ?? '';

$GLOBALS['__tests'] = ['pass' => 0, 'fail' => 0, 'failures' => []];

function it(string $name, callable $fn): void {
    try {
        $fn();
        $GLOBALS['__tests']['pass']++;
        echo "  \033[32m✓\033[0m {$name}\n";
    } catch (Throwable $e) {
        $GLOBALS['__tests']['fail']++;
        $GLOBALS['__tests']['failures'][] = $name . ' — ' . $e->getMessage();
        echo "  \033[31m✗\033[0m {$name}\n      {$e->getMessage()}\n";
    }
}

function assertSame(mixed $expected, mixed $actual, string $what = ''): void {
    if ($expected !== $actual) {
        throw new RuntimeException(sprintf(
            '%sesperado %s, veio %s',
            $what !== '' ? "{$what}: " : '',
            var_export($expected, true),
            var_export($actual, true)
        ));
    }
}

function assertTrue(bool $cond, string $what = 'condição falsa'): void {
    if (!$cond) {
        throw new RuntimeException($what);
    }
}

$files = glob(__DIR__ . '/cases/*.php');
sort($files);
foreach ($files as $file) {
    if ($filter !== '' && !str_contains(basename($file), $filter)) {
        continue;
    }
    echo "\n\033[1m" . basename($file, '.php') . "\033[0m\n";
    require $file;
}

$r = $GLOBALS['__tests'];
echo "\n" . str_repeat('─', 60) . "\n";
printf("%d passaram · %d falharam\n", $r['pass'], $r['fail']);
foreach ($r['failures'] as $f) {
    echo "  FALHA: {$f}\n";
}

exit($r['fail'] === 0 ? 0 : 1);
