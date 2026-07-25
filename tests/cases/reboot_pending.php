<?php

/** @mirror src/PatchDeploy.php::rebootValue */
function rebootValue(string $value): ?bool {
    $v = strtolower(trim($value));
    if ($v === '' || $v === '[no results]') {
        return null;
    }
    return (bool)preg_match('/^(1|true|yes|sim|required|pending|reboot)/i', $v);
}

/** @mirror src/PatchDeploy.php::rebootPending */
function rebootPending(?string $sensorDataJson, ?string $sensorName = null): ?bool {
    $sensors = json_decode((string)$sensorDataJson, true);
    if (!is_array($sensors)) {
        return null;
    }

    // An explicitly configured sensor wins: the guess below would also
    // match an unrelated sensor that merely has "restart" in its name.
    $configured = trim((string)$sensorName);
    if ($configured !== '' && array_key_exists($configured, $sensors)) {
        return self_rebootValue((string)$sensors[$configured]);
    }

    foreach ($sensors as $name => $value) {
        if (!preg_match('/reboot|restart|reinicial/i', (string)$name)) {
            continue;
        }
        $parsed = self_rebootValue((string)$value);
        if ($parsed !== null) {
            return $parsed;
        }
    }
    return null;
}

/** Stand-in for the `self::rebootValue()` call inside the mirrored method. */
function self_rebootValue(string $v): ?bool {
    return rebootValue($v);
}

it('reconhece afirmativos', function () {
    assertSame(true, rebootPending('{"Reboot Required":"Yes"}'));
    assertSame(true, rebootPending('{"Pending Restart":"True"}'));
    assertSame(true, rebootPending('{"Reboot Required":"Reboot Pending"}'));
    assertSame(true, rebootPending('{"Reboot Required":"1"}'));
});

it('reconhece negativos', function () {
    assertSame(false, rebootPending('{"Reboot Required":"No"}'));
    assertSame(false, rebootPending('{"Reboot Required":"false"}'));
});

it('desconhecido quando o sensor não respondeu', function () {
    assertSame(null, rebootPending('{"Reboot Required":"[no results]"}'));
    assertSame(null, rebootPending('{"Reboot Required":""}'));
});

it('desconhecido quando não há sensor de reboot', function () {
    assertSame(null, rebootPending('{"Computer Name":"srv01"}'));
    assertSame(null, rebootPending(''));
    assertSame(null, rebootPending(null));
    assertSame(null, rebootPending('lixo que não é json'));
});

it('o sensor configurado tem prioridade sobre o palpite', function () {
    // "Service Restart Count" casa com o regex e diria "true" por engano.
    $json = '{"Service Restart Count":"7","Needs Reboot":"No"}';
    assertSame(false, rebootPending($json, 'Needs Reboot'), 'deveria usar o configurado');
});

it('cai no palpite quando o configurado não foi coletado', function () {
    assertSame(true, rebootPending('{"Reboot Required":"Yes"}', 'Sensor Inexistente'));
});

it('pula sensor de reboot vazio e continua procurando', function () {
    $json = '{"Reboot Required":"[no results]","Pending Restart":"Yes"}';
    assertSame(true, rebootPending($json));
});
