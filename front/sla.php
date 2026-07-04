<?php

use GlpiPlugin\Tanium\Sla;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

Html::header(__('Tanium — SLA Compliance', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
Sla::showPage();
Html::footer();
