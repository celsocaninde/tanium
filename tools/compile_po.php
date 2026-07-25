<?php

/**
 * Compiles locales/<locale>.po into the .mo GLPI actually loads, then reads the
 * result back and verifies a sample of entries. Exists because msgfmt is not
 * available in the GLPI container, and an out-of-date .mo silently leaves the
 * UI half-translated.
 *
 *   php tools/compile_po.php [locale]      (default: pt_BR)
 */

$root   = dirname(__DIR__);
$locale = $argv[1] ?? 'pt_BR';
$poFile = "{$root}/locales/{$locale}.po";
$moFile = "{$root}/locales/{$locale}.mo";

if (!is_file($poFile)) {
    fwrite(STDERR, "Catalogue not found: {$poFile}\n");
    exit(1);
}

$entries = parsePo($poFile);
if ($entries === []) {
    fwrite(STDERR, "No entries parsed from {$poFile}\n");
    exit(1);
}

file_put_contents($moFile, buildMo($entries));

// ── Verify: read the .mo back and resolve a sample ───────────────────────────
$readBack = readMo($moFile);
$failures = 0;
foreach ($entries as $key => $value) {
    if (!array_key_exists($key, $readBack) || $readBack[$key] !== $value) {
        $failures++;
        if ($failures <= 5) {
            fwrite(STDERR, 'Round-trip mismatch: ' . json_encode(substr($key, 0, 60)) . "\n");
        }
    }
}

printf(
    "%s → %s\n  %d entries (%d plural), %s\n  round-trip: %s\n",
    basename($poFile),
    basename($moFile),
    count($entries),
    count(array_filter(array_keys($entries), static fn(string $k): bool => str_contains($k, "\0"))),
    formatBytes(filesize($moFile)),
    $failures === 0 ? 'all entries match' : "{$failures} MISMATCH(ES)"
);

exit($failures === 0 ? 0 : 1);

/**
 * Parse a .po into [original => translation], where a plural entry keys on
 * "singular\0plural" and values join the forms with \0 — the layout the MO
 * format itself uses.
 *
 * @return array<string,string>
 */
function parsePo(string $file): array {
    $entries = [];
    $cur     = resetEntry();
    $field   = null; // which key the continuation lines append to

    foreach (file($file, FILE_IGNORE_NEW_LINES) as $line) {
        $trimmed = trim($line);

        if ($trimmed === '' || $trimmed[0] === '#') {
            // Blank line or comment closes the current entry.
            if ($trimmed === '') {
                flushEntry($entries, $cur);
                $cur   = resetEntry();
                $field = null;
            }
            continue;
        }

        if (preg_match('/^msgid\s+(.*)$/', $trimmed, $m)) {
            // A new msgid with an entry already buffered means no blank line
            // separated them — flush before starting the next.
            if ($cur['msgid'] !== null) {
                flushEntry($entries, $cur);
                $cur = resetEntry();
            }
            $field         = 'msgid';
            $cur['msgid']  = decodeChunks($m[1]);
        } elseif (preg_match('/^msgid_plural\s+(.*)$/', $trimmed, $m)) {
            $field                = 'plural';
            $cur['plural']        = decodeChunks($m[1]);
        } elseif (preg_match('/^msgstr\[(\d+)]\s+(.*)$/', $trimmed, $m)) {
            $field                    = 'msgstr' . $m[1];
            $cur['forms'][(int)$m[1]] = decodeChunks($m[2]);
        } elseif (preg_match('/^msgstr\s+(.*)$/', $trimmed, $m)) {
            $field           = 'msgstr0';
            $cur['forms'][0] = decodeChunks($m[1]);
        } elseif ($trimmed[0] === '"' && $field !== null) {
            $chunk = decodeChunks($trimmed);
            if ($field === 'msgid') {
                $cur['msgid'] .= $chunk;
            } elseif ($field === 'plural') {
                $cur['plural'] .= $chunk;
            } else {
                $idx                 = (int)substr($field, 6);
                $cur['forms'][$idx] .= $chunk;
            }
        }
    }
    flushEntry($entries, $cur);

    return $entries;
}

function resetEntry(): array {
    return ['msgid' => null, 'plural' => null, 'forms' => []];
}

/** @param array<string,string> $entries */
function flushEntry(array &$entries, array $cur): void {
    if ($cur['msgid'] === null || $cur['forms'] === []) {
        return;
    }
    ksort($cur['forms']);
    $translation = implode("\0", $cur['forms']);
    // An empty translation means "not translated" — leaving it out lets
    // gettext fall back to the source string instead of returning "".
    if ($translation === '' && $cur['msgid'] !== '') {
        return;
    }
    $key = $cur['plural'] !== null ? $cur['msgid'] . "\0" . $cur['plural'] : $cur['msgid'];
    $entries[$key] = $translation;
}

/** Concatenate every "…" chunk on a line and unescape it. */
function decodeChunks(string $text): string {
    preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $text, $m);
    $out = '';
    foreach ($m[1] as $chunk) {
        $out .= stripcslashes($chunk);
    }
    return $out;
}

/** @param array<string,string> $entries */
function buildMo(array $entries): string {
    // The format expects originals sorted bytewise so readers can binary-search.
    ksort($entries, SORT_STRING);

    $count       = count($entries);
    $originalsAt = 28;                    // right after the 7-word header
    $transAt     = $originalsAt + $count * 8;
    $dataAt      = $transAt + $count * 8; // no hash table: size 0, offset 0

    $origTable = '';
    $transTable = '';
    $data       = '';
    foreach ($entries as $original => $translation) {
        $origTable .= pack('VV', strlen($original), $dataAt + strlen($data));
        $data      .= $original . "\0";
    }
    foreach ($entries as $translation) {
        $transTable .= pack('VV', strlen($translation), $dataAt + strlen($data));
        $data       .= $translation . "\0";
    }

    return pack('VVVVVV', 0x950412de, 0, $count, $originalsAt, $transAt, 0)
        . pack('V', 0)
        . $origTable . $transTable . $data;
}

/** @return array<string,string> */
function readMo(string $file): array {
    $raw = file_get_contents($file);
    $hdr = unpack('Vmagic/Vrev/Vcount/Vorig/Vtrans', substr($raw, 0, 20));
    if ($hdr['magic'] !== 0x950412de) {
        throw new RuntimeException('Bad magic in generated .mo');
    }

    $out = [];
    for ($i = 0; $i < $hdr['count']; $i++) {
        $o = unpack('Vlen/Voff', substr($raw, $hdr['orig'] + $i * 8, 8));
        $t = unpack('Vlen/Voff', substr($raw, $hdr['trans'] + $i * 8, 8));
        $out[substr($raw, $o['off'], $o['len'])] = substr($raw, $t['off'], $t['len']);
    }
    return $out;
}

function formatBytes(int $bytes): string {
    return $bytes > 1024 ? round($bytes / 1024, 1) . ' KB' : $bytes . ' B';
}
