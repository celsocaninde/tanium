<?php

use GlpiPlugin\Tanium\Sync as TaniumSync;

include('../../../inc/includes.php');

Session::checkRight('config', UPDATE);

header('Content-Type: application/json');

$result = TaniumSync::run();
echo json_encode($result);
