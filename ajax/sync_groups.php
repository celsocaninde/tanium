<?php

include('../../../inc/includes.php');
Session::checkRight('config', READ);
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'POST required']); exit;
}

try {
    $config = \GlpiPlugin\Tanium\Config::getConfig();
    if (empty($config['api_url']) || empty($config['api_token'])) {
        echo json_encode(['success' => false, 'error' => 'API não configurada. Salve a URL e o token primeiro.']); exit;
    }

    $api   = new \GlpiPlugin\Tanium\Api($config['api_url'], $config['api_token']);
    $count = \GlpiPlugin\Tanium\ComputerGroup::syncFromApi($api);

    echo json_encode([
        'success' => true,
        'count'   => $count,
        'message' => $count > 0
            ? "{$count} grupo(s) sincronizado(s) com o Tanium."
            : 'Nenhum grupo retornado pela API. Verifique se o módulo Patch está ativo no Tanium.',
    ]);
} catch (\Throwable $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
