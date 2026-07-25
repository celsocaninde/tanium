<?php

/**
 * Verifies that every mirrored function in tests/cases/ is still byte-identical
 * (modulo whitespace and `self::`) to the method it copies in src/.
 *
 * The test suite cannot load the real classes — they extend GLPI base classes
 * and touch $DB — so each case file re-declares the function under test. That
 * copy is only trustworthy while it matches the original, which is what this
 * script enforces. Run it with the tests; a drift here means the suite is
 * green while testing dead code.
 *
 * Contract: a mirrored function carries `@mirror src/File.php::methodName`.
 *
 *   php tests/mirror.php
 */

$root  = dirname(__DIR__);
$files = glob("{$root}/tests/cases/*.php");

$checked = $drift = $broken = 0;

foreach ($files as $file) {
    $code = file_get_contents($file);
    if (!preg_match_all(
        '/@mirror\s+(?<src>[\w\/.]+)::(?<method>\w+)\s*\*\/\s*function\s+(?<fn>\w+)\s*\(/',
        $code,
        $matches,
        PREG_SET_ORDER
    )) {
        continue;
    }

    foreach ($matches as $m) {
        $checked++;
        $label = basename($file) . ': ' . $m['fn'] . '() ↔ ' . $m['src'] . '::' . $m['method'] . '()';

        $srcPath = "{$root}/{$m['src']}";
        if (!is_file($srcPath)) {
            echo "\033[31mFONTE AUSENTE\033[0m  {$label}\n";
            $broken++;
            continue;
        }

        $original = extractBody(file_get_contents($srcPath), $m['method']);
        $copy     = extractBody($code, $m['fn']);

        if ($original === null || $copy === null) {
            echo "\033[31mNÃO EXTRAÍDO\033[0m  {$label}\n";
            $broken++;
            continue;
        }

        if (normalize($original) !== normalize($copy)) {
            echo "\033[31mDIVERGIU\033[0m  {$label}\n";
            echo "    a cópia do teste não confere mais com o método real\n";
            $drift++;
            continue;
        }

        echo "\033[32mok\033[0m  {$label}\n";
    }
}

echo "\n" . str_repeat('─', 60) . "\n";
printf("%d espelho(s) · %d divergente(s) · %d quebrado(s)\n", $checked, $drift, $broken);
if ($checked === 0) {
    echo "AVISO: nenhum @mirror encontrado — os testes não estão ancorados no src/.\n";
    exit(1);
}

exit($drift + $broken === 0 ? 0 : 1);

/** Body of a function/method, by brace matching from its signature. */
function extractBody(string $code, string $name): ?string {
    if (!preg_match('/function\s+' . preg_quote($name, '/') . '\s*\(/', $code, $m, PREG_OFFSET_CAPTURE)) {
        return null;
    }
    $open = strpos($code, '{', $m[0][1]);
    if ($open === false) {
        return null;
    }

    $depth = 0;
    $len   = strlen($code);
    for ($i = $open; $i < $len; $i++) {
        $ch = $code[$i];
        // Skip over string literals so a brace inside one does not shift depth.
        if ($ch === "'" || $ch === '"') {
            $quote = $ch;
            for ($i++; $i < $len; $i++) {
                if ($code[$i] === '\\') {
                    $i++;
                    continue;
                }
                if ($code[$i] === $quote) {
                    break;
                }
            }
            continue;
        }
        if ($ch === '{') {
            $depth++;
        } elseif ($ch === '}') {
            $depth--;
            if ($depth === 0) {
                return substr($code, $open + 1, $i - $open - 1);
            }
        }
    }
    return null;
}

/**
 * Whitespace, comments and any `Scope::` prefix are noise for this comparison:
 * the copy lives at file scope, so it cannot keep `self::` — nor `Risk::` when
 * one plugin class calls another. Both sides are stripped the same way, so a
 * real difference in the logic still shows up.
 */
function normalize(string $body): string {
    $body = preg_replace('!/\*.*?\*/!s', '', $body);          // block comments
    $body = preg_replace('!//[^\n]*!', '', $body);            // line comments
    $body = preg_replace('/\b[A-Za-z_]\w*::/', '', $body);    // self:: / Risk:: / …
    $body = preg_replace('/\bself_/', '', $body);             // stand-in helpers
    return preg_replace('/\s+/', ' ', trim($body));
}
