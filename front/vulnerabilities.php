<?php

use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');

Session::checkRight('config', READ);

Html::header(__('Tanium — Vulnerabilities', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
Vulnerability::showPage();
Html::footer();
