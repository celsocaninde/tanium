<?php

/** @mirror src/Sync.php::recordChanged */
function recordChanged(array $existing, array $record): bool {
    foreach ($record as $field => $value) {
        $old = $existing[$field] ?? null;
        if ($old === null && ($value === null || $value === '')) {
            continue;
        }
        // Numeric columns (cvss_score is decimal(4,1)) must compare by value:
        // "9.8" and 9.8 are equal, "9.80" and "9.8" too.
        if (is_numeric($old) && is_numeric($value)) {
            if ((float)$old !== (float)$value) {
                return true;
            }
            continue;
        }
        if ((string)$old !== (string)$value) {
            return true;
        }
    }
    return false;
}

// This gate decides whether the sync writes at all. A false positive means we
// are back to a full UPDATE per finding (the N+1 we removed); a false negative
// means real changes never reach the database.

it('linha idêntica não é escrita de novo', function () {
    $db  = ['cvss_score' => '9.8', 'severity' => 'critical', 'status' => 'open', 'computers_id' => '42'];
    $new = ['cvss_score' => 9.8,   'severity' => 'critical', 'status' => 'open', 'computers_id' => 42];
    assertSame(false, recordChanged($db, $new), 'string do banco vs tipo nativo');
});

it('decimal com zeros à direita é igual', function () {
    assertSame(false, recordChanged(['cvss_score' => '9.80'], ['cvss_score' => 9.8]));
    assertSame(false, recordChanged(['cvss_score' => '7.0'], ['cvss_score' => 7]));
});

it('mudança de status é detectada', function () {
    assertSame(true, recordChanged(['status' => 'open'], ['status' => 'remediated']));
});

it('mudança de CVSS é detectada', function () {
    assertSame(true, recordChanged(['cvss_score' => '7.5'], ['cvss_score' => 9.8]));
});

it('null no banco e null/vazio no payload são iguais', function () {
    assertSame(false, recordChanged(['kb_id' => null], ['kb_id' => null]));
    assertSame(false, recordChanged(['kb_id' => null], ['kb_id' => '']));
});

it('null virando valor é mudança', function () {
    assertSame(true, recordChanged(['kb_id' => null], ['kb_id' => 'KB5034441']));
});

it('valor virando null é mudança', function () {
    assertSame(true, recordChanged(['kb_id' => 'KB5034441'], ['kb_id' => null]));
});

it('campo ausente no banco conta como mudança', function () {
    assertSame(true, recordChanged([], ['severity' => 'high']));
});

it('só compara os campos que serão escritos', function () {
    // date_mod/id existem na linha mas não no record — não podem influenciar.
    $db = ['id' => '1', 'date_mod' => '2026-01-01 00:00:00', 'status' => 'open'];
    assertSame(false, recordChanged($db, ['status' => 'open']));
});

it('zero não é confundido com vazio', function () {
    assertSame(true, recordChanged(['computers_id' => '5'], ['computers_id' => 0]));
    assertSame(false, recordChanged(['computers_id' => '0'], ['computers_id' => 0]));
});
