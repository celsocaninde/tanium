<?php

/**
 * Syntax-checks every PHP file in the plugin. The container has no composer
 * dev dependencies, so this stands in for a linter in the pre-commit loop.
 *
 *   php tools/lint.php
 */

$root = dirname(__DIR__);
$rii  = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));

$ok = $bad = 0;
foreach ($rii as $file) {
    if ($file->getExtension() !== 'php') {
        continue;
    }
    $path = $file->getPathname();
    exec(sprintf('php -l %s 2>&1', escapeshellarg($path)), $out, $code);
    if ($code === 0) {
        $ok++;
    } else {
        $bad++;
        echo str_replace($root . DIRECTORY_SEPARATOR, '', $path) . "\n";
        echo '    ' . implode("\n    ", $out) . "\n";
    }
    $out = [];
}

printf("%d arquivo(s) ok · %d com erro\n", $ok, $bad);
exit($bad === 0 ? 0 : 1);
