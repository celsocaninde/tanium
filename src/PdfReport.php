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
            $rows .= '<tr>'
                . '<td style="padding:6px;border-bottom:1px solid #dddddd"><b>' . htmlspecialchars((string)($cve['cve_id'] ?? '')) . '</b></td>'
                . '<td style="padding:6px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)($cve['endpoint'] ?? '')) . '</td>'
                . '<td style="padding:6px;border-bottom:1px solid #dddddd;color:#d6336c"><b>' . htmlspecialchars((string)($cve['cvss'] ?? '-')) . '</b></td>'
                . '</tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="3" style="padding:8px;color:#6b7280">Nenhum detalhe individual disponivel.</td></tr>';
        }

        $html = '<h2 style="color:#e8212a">Tanium - Novos CVEs Criticos</h2>'
            . '<p style="color:#4a5568">' . $count . ' novo(s) CVE(s) critico(s) detectado(s) em ' . date('d/m/Y H:i') . '.</p>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse">'
            . '<thead><tr style="background-color:#f1f3f7">'
            . '<th style="padding:6px;text-align:left">CVE ID</th>'
            . '<th style="padding:6px;text-align:left">Endpoint</th>'
            . '<th style="padding:6px;text-align:left">CVSS</th>'
            . '</tr></thead>'
            . '<tbody>' . $rows . '</tbody>'
            . '</table>'
            . '<p style="color:#9ca3af;font-size:9px;margin-top:16px">Gerado automaticamente pelo plugin Tanium para GLPI. ' . htmlspecialchars($glpiUrl) . '</p>';

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
                . '<td style="padding:5px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['tanium_name']) . '</td>'
                . '<td style="padding:5px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['ip_address']) . '</td>'
                . '<td style="padding:5px;border-bottom:1px solid #dddddd"><b>' . (int)$ep['risk_score'] . '</b></td>'
                . '</tr>';
        }

        $topCveRows = '';
        foreach ($s['top_cves'] as $cve) {
            $topCveRows .= '<tr>'
                . '<td style="padding:5px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$cve['cve_id']) . '</td>'
                . '<td style="padding:5px;border-bottom:1px solid #dddddd">' . htmlspecialchars(ucfirst((string)$cve['severity'])) . '</td>'
                . '<td style="padding:5px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)($cve['cvss_score'] ?? '-')) . '</td>'
                . '<td style="padding:5px;border-bottom:1px solid #dddddd">' . (int)$cve['affected_count'] . '</td>'
                . '</tr>';
        }

        $html = '<h2 style="color:#e8212a">Tanium - Relatorio Semanal de Seguranca</h2>'
            . '<p style="color:#4a5568">' . (int)$s['total_endpoints'] . ' endpoints monitorados &middot; Gerado em ' . date('d/m/Y H:i') . '</p>'
            . '<table cellpadding="6" style="width:100%;border-collapse:collapse;margin-bottom:14px">'
            . '<tr style="background-color:#f9fafb">'
            . '<td style="text-align:center"><b style="font-size:16px;color:#d6336c">' . (int)$s['critical_endpoints'] . '</b><br/><span style="font-size:8px;color:#6b7280">ENDPOINTS CRITICOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:16px;color:#d6336c">' . (int)$s['critical_cves'] . '</b><br/><span style="font-size:8px;color:#6b7280">CVES CRITICOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:16px">' . htmlspecialchars($compliance) . '</b><br/><span style="font-size:8px;color:#6b7280">PATCH COMPLIANCE</span></td>'
            . '<td style="text-align:center"><b style="font-size:16px">' . (int)$s['sla_breaches'] . '</b><br/><span style="font-size:8px;color:#6b7280">SLA BREACHES</span></td>'
            . '</tr>'
            . '</table>'
            . '<h3 style="color:#e8212a">Top Endpoints de Risco</h3>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse;margin-bottom:14px">'
            . '<thead><tr style="background-color:#f1f3f7"><th style="text-align:left">Nome</th><th style="text-align:left">IP</th><th style="text-align:left">Risco</th></tr></thead>'
            . '<tbody>' . ($topEpRows !== '' ? $topEpRows : '<tr><td colspan="3">Sem dados.</td></tr>') . '</tbody>'
            . '</table>'
            . '<h3 style="color:#e8212a">Top CVEs por CVSS</h3>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse">'
            . '<thead><tr style="background-color:#f1f3f7"><th style="text-align:left">CVE ID</th><th style="text-align:left">Severidade</th><th style="text-align:left">CVSS</th><th style="text-align:left">Afetados</th></tr></thead>'
            . '<tbody>' . ($topCveRows !== '' ? $topCveRows : '<tr><td colspan="4">Sem dados.</td></tr>') . '</tbody>'
            . '</table>'
            . '<p style="color:#9ca3af;font-size:9px;margin-top:16px">Gerado automaticamente pelo plugin Tanium para GLPI. ' . htmlspecialchars($baseUrl) . '</p>';

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
            $pdf->AddPage();
            $pdf->writeHTML($html, true, false, true, false, '');

            return $pdf->Output('tanium-report.pdf', 'S');
        } catch (\Throwable $error) {
            Toolbox::logInFile('tanium', '[Tanium] Falha ao gerar PDF: ' . $error->getMessage());
            return null;
        }
    }
}
