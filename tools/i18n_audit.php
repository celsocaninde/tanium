<?php

/**
 * Lists every translatable string in the plugin that has no entry in a .po
 * catalogue — the source of "half the settings page is in English" bugs.
 *
 *   php tools/i18n_audit.php [locale]      (default: pt_BR)
 */

$root   = dirname(__DIR__);
$locale = $argv[1] ?? 'pt_BR';
$poFile = "{$root}/locales/{$locale}.po";

if (!is_file($poFile)) {
    fwrite(STDERR, "Catalogue not found: {$poFile}\n");
    exit(1);
}

// ── Known msgids from the catalogue ──────────────────────────────────────────
// Both halves of a plural entry count as known: the code calls _n('one',
// 'many', …) and either literal must resolve. Missing this is what makes an
// audit "find" strings that are in fact already translated.
$known      = [];
$translated = [];
$po         = file_get_contents($poFile);
$blockRe    = '(?:"(?:[^"\\\\]|\\\\.)*"\s*)+';
if (preg_match_all(
    "/^msgid\s+({$blockRe})(?:^msgid_plural\s+({$blockRe}))?^msgstr(?:\[0])?\s+({$blockRe})/ms",
    $po,
    $m,
    PREG_SET_ORDER
)) {
    foreach ($m as $entry) {
        $ids = [poDecode($entry[1])];
        if (($entry[2] ?? '') !== '') {
            $ids[] = poDecode($entry[2]);
        }
        $str = poDecode($entry[3]);
        foreach ($ids as $id) {
            if ($id === '') {
                continue; // header
            }
            $known[$id] = true;
            if ($str !== '') {
                $translated[$id] = true;
            }
        }
    }
}

// ── Strings the code actually asks for ───────────────────────────────────────
$missing = [];
$empty   = [];
$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($rii as $file) {
    if ($file->getExtension() !== 'php' || str_contains($file->getPathname(), DIRECTORY_SEPARATOR . 'tools' . DIRECTORY_SEPARATOR)) {
        continue;
    }
    $code = file_get_contents($file->getPathname());
    $rel  = str_replace($root . DIRECTORY_SEPARATOR, '', $file->getPathname());

    // __('…', 'tanium') and _n('one', 'many', $n, 'tanium'), single or double quoted.
    if (!preg_match_all('/\b_(?:_|n|x)\s*\(\s*(\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*")/', $code, $hits, PREG_OFFSET_CAPTURE)) {
        continue;
    }
    foreach ($hits[1] as $hit) {
        $literal = phpDecode($hit[0]);
        if ($literal === '' || !preg_match('/[a-zA-Z]/', $literal)) {
            continue;
        }
        $line = substr_count(substr($code, 0, $hit[1]), "\n") + 1;
        if (!isset($known[$literal])) {
            $missing[$literal][] = "{$rel}:{$line}";
        } elseif (!isset($translated[$literal])) {
            $empty[$literal][] = "{$rel}:{$line}";
        }
    }
}

report("NOT IN CATALOGUE", $missing);
report("PRESENT BUT UNTRANSLATED (empty msgstr)", $empty);

printf(
    "\n%d msgid(s) in %s · %d missing · %d empty\n",
    count($known),
    basename($poFile),
    count($missing),
    count($empty)
);

function report(string $title, array $items): void {
    if ($items === []) {
        echo "\n== {$title}: none ==\n";
        return;
    }
    echo "\n== {$title} (" . count($items) . ") ==\n";
    ksort($items);
    foreach ($items as $text => $where) {
        echo "\n  \"" . str_replace("\n", '\n', $text) . "\"\n";
        echo '      ' . implode(', ', array_slice($where, 0, 4)) . (count($where) > 4 ? ', …' : '') . "\n";
    }
}

/** Concatenate and unescape the quoted chunks of a po msgid/msgstr block. */
function poDecode(string $block): string {
    preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $block, $parts);
    $out = '';
    foreach ($parts[1] as $chunk) {
        $out .= stripcslashes($chunk);
    }
    return $out;
}

/** Unescape a PHP single- or double-quoted literal, quotes included. */
function phpDecode(string $literal): string {
    $body = substr($literal, 1, -1);
    return $literal[0] === "'"
        ? str_replace(["\\'", '\\\\'], ["'", '\\'], $body)
        : stripcslashes($body);
}
