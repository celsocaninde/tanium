<?php

use GlpiPlugin\Tanium\Remediation;

include('../../../inc/includes.php');

if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$days = (int)($_GET['days'] ?? 30);
if (!in_array($days, [7, 30, 90, 365], true)) {
    $days = 30;
}

// CSV/PDF exports stream before any HTML is emitted
if (($_GET['export'] ?? '') === 'events') {
    Remediation::exportEventsCsv($days);
}
if (($_GET['export'] ?? '') === 'endpoints') {
    Remediation::exportEndpointsCsv($days);
}
if (($_GET['export'] ?? '') === 'pdf') {
    $pdf = \GlpiPlugin\Tanium\PdfReport::remediationByEndpoint(
        Remediation::getByEndpoint($days, 10000),
        Remediation::getStats($days),
        $days
    );
    if ($pdf !== null) {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="tanium-remediacao-endpoints-' . date('Y-m-d') . '.pdf"');
        header('Content-Length: ' . strlen($pdf));
        echo $pdf;
        exit;
    }
    Session::addMessageAfterRedirect(__('PDF export unavailable (TCPDF not found) — check tanium.log.', 'tanium'), true, ERROR);
    Html::redirect('remediation.php?days=' . $days);
}

Html::header(__('Tanium — Remediation', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
echo "<style>.container-xl,.container-lg{max-width:100%!important}</style>";
Remediation::showPage();
Html::footer();
