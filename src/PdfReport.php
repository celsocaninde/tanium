<?php

namespace GlpiPlugin\Tanium;

use Toolbox;

/**
 * Builds PDF versions of the email notifications (critical-CVE alert and
 * weekly report) as attachments. Reuses TCPDF, bundled with GLPI core, so no
 * extra Composer dependency is needed. Returns null (and logs) when TCPDF
 * isn't available instead of breaking the email flow.
 */
class PdfReport {

    /**
     * @param array<int,array{cve_id:string,endpoint:string,cvss:mixed}> $cves
     */
    public static function critical(array $cves, int $count, string $glpiUrl): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', '[Tanium] TCPDF indisponivel -- PDF do alerta de CVE critico nao gerado.');
            return null;
        }

        $rows = '';
        foreach ($cves as $cve) {
            $endpoint = htmlspecialchars((string)($cve['endpoint'] ?? ''));
            $ip       = trim((string)($cve['ip'] ?? ''));
            $osName   = trim((string)($cve['os_name'] ?? ''));
            $meta     = trim($ip . ($ip !== '' && $osName !== '' ? ' - ' : '') . $osName);
            $title    = htmlspecialchars((string)($cve['title'] ?? ''));
            $affected = (int)($cve['affected_count'] ?? 0);

            $rows .= '<tr>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd"><b>' . htmlspecialchars((string)($cve['cve_id'] ?? '')) . '</b></td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . $title . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . $endpoint . ($meta !== '' ? '<br/><span style="color:#6b7280;font-size:7pt">' . htmlspecialchars($meta) . '</span>' : '') . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd;color:#d6336c"><b>' . htmlspecialchars((string)($cve['cvss'] ?? '-')) . '</b></td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . ($affected > 0 ? $affected : '-') . '</td>'
                . '</tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="5" style="padding:4px;color:#6b7280">Nenhum detalhe individual disponivel.</td></tr>';
        }

        $html = '<div style="font-size:9pt">'
            . '<h2 style="color:#e8212a;font-size:13pt;margin-bottom:2pt">Novos CVEs Criticos</h2>'
            . '<p style="color:#4a5568;font-size:9pt">' . $count . ' novo(s) CVE(s) critico(s) detectado(s) em ' . date('d/m/Y H:i') . '.</p>'
            . '<table cellpadding="3" style="width:100%;border-collapse:collapse;font-size:8pt">'
            . '<thead><tr style="background-color:#f1f3f7">'
            . '<th width="20%" style="padding:4px;text-align:left">CVE ID</th>'
            . '<th width="30%" style="padding:4px;text-align:left">Titulo</th>'
            . '<th width="28%" style="padding:4px;text-align:left">Endpoint</th>'
            . '<th width="11%" style="padding:4px;text-align:left">CVSS</th>'
            . '<th width="11%" style="padding:4px;text-align:left">Afetados</th>'
            . '</tr></thead>'
            . '<tbody>' . $rows . '</tbody>'
            . '</table>'
            . '<p style="color:#9ca3af;font-size:7pt;margin-top:10pt">Gerado automaticamente pelo plugin Tanium para GLPI. ' . htmlspecialchars($glpiUrl) . '</p>'
            . '</div>';

        return self::render('Tanium - CVEs Criticos', $html);
    }

    /**
     * @param array<string,mixed> $s stats produced by WeeklyReport::gatherStats()
     */
    public static function weekly(array $s, string $baseUrl): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', '[Tanium] TCPDF indisponivel -- PDF do relatorio semanal nao gerado.');
            return null;
        }

        $compliance = $s['patch_compliance'] !== null ? $s['patch_compliance'] . '%' : 'N/A';

        $topEpRows = '';
        foreach ($s['top_endpoints'] as $ep) {
            $topEpRows .= '<tr>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['tanium_name']) . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['ip_address']) . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd"><b>' . (int)$ep['risk_score'] . '</b></td>'
                . '</tr>';
        }

        $topCveRows = '';
        foreach ($s['top_cves'] as $cve) {
            $topCveRows .= '<tr>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$cve['cve_id']) . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)($cve['title'] ?? '')) . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars(ucfirst((string)$cve['severity'])) . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)($cve['cvss_score'] ?? '-')) . '</td>'
                . '<td style="padding:4px;border-bottom:1px solid #dddddd">' . (int)$cve['affected_count'] . '</td>'
                . '</tr>';
        }

        $html = '<div style="font-size:9pt">'
            . '<h2 style="color:#e8212a;font-size:13pt;margin-bottom:2pt">Relatorio Semanal de Seguranca</h2>'
            . '<p style="color:#4a5568;font-size:9pt">' . (int)$s['total_endpoints'] . ' endpoints monitorados &middot; Gerado em ' . date('d/m/Y H:i') . '</p>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse;margin-bottom:8pt">'
            . '<tr style="background-color:#f9fafb">'
            . '<td style="text-align:center"><b style="font-size:13pt;color:#d6336c">' . (int)$s['critical_endpoints'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">ENDPOINTS CRITICOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt;color:#d6336c">' . (int)$s['critical_cves'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">CVES CRITICOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt">' . htmlspecialchars($compliance) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">PATCH COMPLIANCE</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt">' . (int)$s['sla_breaches'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">SLA BREACHES</span></td>'
            . '</tr>'
            . '</table>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse;margin-bottom:10pt">'
            . '<tr style="background-color:#ffffff">'
            . '<td style="text-align:center"><b style="font-size:11pt;color:#e8590c">' . (int)$s['high_cves'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">CVES ALTOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:11pt;color:#c2860a">' . (int)$s['patches_missing'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">PATCHES AUSENTES</span></td>'
            . '<td style="text-align:center"><b style="font-size:11pt">' . (int)$s['total_cves'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">TOTAL DE CVES</span></td>'
            . '<td style="text-align:center"><b style="font-size:11pt">' . htmlspecialchars((string)$s['avg_risk']) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">RISCO MEDIO</span></td>'
            . '</tr>'
            . '</table>'
            . '<h3 style="color:#e8212a;font-size:10.5pt;margin-bottom:2pt">Top Endpoints de Risco</h3>'
            . '<table cellpadding="3" style="width:100%;border-collapse:collapse;margin-bottom:10pt;font-size:8pt">'
            . '<thead><tr style="background-color:#f1f3f7"><th width="45%" style="padding:4px;text-align:left">Nome</th><th width="30%" style="padding:4px;text-align:left">IP</th><th width="25%" style="padding:4px;text-align:left">Risco</th></tr></thead>'
            . '<tbody>' . ($topEpRows !== '' ? $topEpRows : '<tr><td colspan="3" style="padding:4px">Sem dados.</td></tr>') . '</tbody>'
            . '</table>'
            . '<h3 style="color:#e8212a;font-size:10.5pt;margin-bottom:2pt">Top CVEs por CVSS</h3>'
            . '<table cellpadding="3" style="width:100%;border-collapse:collapse;font-size:8pt">'
            . '<thead><tr style="background-color:#f1f3f7"><th width="17%" style="padding:4px;text-align:left">CVE ID</th><th width="38%" style="padding:4px;text-align:left">Titulo</th><th width="17%" style="padding:4px;text-align:left">Severidade</th><th width="14%" style="padding:4px;text-align:left">CVSS</th><th width="14%" style="padding:4px;text-align:left">Afetados</th></tr></thead>'
            . '<tbody>' . ($topCveRows !== '' ? $topCveRows : '<tr><td colspan="5" style="padding:4px">Sem dados.</td></tr>') . '</tbody>'
            . '</table>'
            . '<p style="color:#9ca3af;font-size:7pt;margin-top:10pt">Gerado automaticamente pelo plugin Tanium para GLPI. ' . htmlspecialchars($baseUrl) . '</p>'
            . '</div>';

        return self::render('Tanium - Relatorio Semanal', $html);
    }

    private static function render(string $title, string $html): ?string {
        try {
            $pdf = new \TCPDF('P', 'mm', 'A4', true, 'UTF-8', false);
            $pdf->SetCreator('GLPI Tanium Plugin');
            $pdf->SetTitle($title);
            $pdf->setPrintHeader(false);
            $pdf->setPrintFooter(false);
            $pdf->SetMargins(15, 15, 15);
            $pdf->SetAutoPageBreak(true, 15);
            $pdf->SetFont('helvetica', '', 9);
            $pdf->AddPage();

            self::drawBrandHeader($pdf);

            $pdf->writeHTML($html, true, false, true, false, '');

            return $pdf->Output('tanium-report.pdf', 'S');
        } catch (\Throwable $error) {
            Toolbox::logInFile('tanium', '[Tanium] Falha ao gerar PDF: ' . $error->getMessage());
            return null;
        }
    }

    /**
     * Draws the Tanium brand mark (red circle badge + wordmark) using native
     * TCPDF drawing calls -- more reliable across TCPDF versions than relying
     * on CSS border-radius support in writeHTML().
     */
    private static function drawBrandHeader(\TCPDF $pdf): void {
        $x = 15;
        $y = 15;
        $radius = 4;

        $pdf->SetFillColor(232, 33, 42);
        $pdf->Circle($x + $radius, $y + $radius, $radius, 0, 360, 'F');

        $pdf->SetFont('helvetica', 'B', 9);
        $pdf->SetTextColor(255, 255, 255);
        $pdf->SetXY($x, $y - 0.3);
        $pdf->Cell($radius * 2, $radius * 2, 'T', 0, 0, 'C');

        $pdf->SetFont('helvetica', 'B', 14);
        $pdf->SetTextColor(232, 33, 42);
        $pdf->SetXY($x + $radius * 2 + 3, $y - 1);
        $pdf->Cell(60, $radius * 2 + 2, 'TANIUM', 0, 0, 'L');

        $pdf->SetTextColor(0, 0, 0);
        $pdf->SetXY($x, $y + $radius * 2 + 4);
    }
}
