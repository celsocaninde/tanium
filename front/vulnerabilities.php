<?php

use GlpiPlugin\Tanium\Vulnerability;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

Html::header(__('Tanium — Vulnerabilities', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
Vulnerability::showPage();
Html::footer();
