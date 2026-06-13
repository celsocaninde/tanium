<?php

use GlpiPlugin\Tanium\Dashboard;

include('../../../inc/includes.php');

Session::checkRight('config', READ);

Html::header(__('Tanium — Dashboard', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
Dashboard::show();
Html::footer();
