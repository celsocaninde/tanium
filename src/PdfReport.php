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
    public static function critical(array $cves, int $count, string $glpiUrl, string $groupLabel = ''): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', "[Tanium] TCPDF indisponivel -- PDF do alerta de CVE critico nao gerado.\n");
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

            // Column widths must match the <th> widths below on every single row --
            // TCPDF sizes each row's columns from its own cells, so a row without
            // explicit widths drifts out of alignment with the header (and with
            // other rows) instead of sharing one fixed grid.
            $rows .= '<tr>'
                . '<td width="20%" style="padding:4px;border-bottom:1px solid #dddddd"><b>' . htmlspecialchars((string)($cve['cve_id'] ?? '')) . '</b></td>'
                . '<td width="30%" style="padding:4px;border-bottom:1px solid #dddddd">' . $title . '</td>'
                . '<td width="28%" style="padding:4px;border-bottom:1px solid #dddddd">' . $endpoint . ($meta !== '' ? '<br/><span style="color:#6b7280;font-size:7pt">' . htmlspecialchars($meta) . '</span>' : '') . '</td>'
                . '<td width="11%" style="padding:4px;border-bottom:1px solid #dddddd;color:#d6336c"><b>' . htmlspecialchars((string)($cve['cvss'] ?? '-')) . '</b></td>'
                . '<td width="11%" style="padding:4px;border-bottom:1px solid #dddddd">' . ($affected > 0 ? $affected : '-') . '</td>'
                . '</tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="5" style="padding:4px;color:#6b7280">Nenhum detalhe individual disponivel.</td></tr>';
        }

        $titleSuffix = $groupLabel !== '' ? ' — ' . $groupLabel : '';

        $html = '<div style="font-size:9pt">'
            . '<h2 style="color:#e8212a;font-size:13pt;margin-bottom:2pt">Novos CVEs Criticos' . htmlspecialchars($titleSuffix) . '</h2>'
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

        return self::render('Tanium - CVEs Criticos' . $titleSuffix, $html);
    }

    /**
     * @param array<string,mixed> $s stats produced by WeeklyReport::gatherStats()
     */
    public static function weekly(array $s, string $baseUrl): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', "[Tanium] TCPDF indisponivel -- PDF do relatorio semanal nao gerado.\n");
            return null;
        }

        $compliance = $s['patch_compliance'] !== null ? $s['patch_compliance'] . '%' : 'N/A';

        // Widths repeated on every <td> so TCPDF keeps one fixed column grid instead
        // of resizing each row to its own content (see note in critical() above).
        $topEpRows = '';
        foreach ($s['top_endpoints'] as $ep) {
            $topEpRows .= '<tr>'
                . '<td width="45%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['tanium_name']) . '</td>'
                . '<td width="30%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['ip_address']) . '</td>'
                . '<td width="25%" style="padding:4px;border-bottom:1px solid #dddddd"><b>' . (int)$ep['risk_score'] . '</b></td>'
                . '</tr>';
        }

        $topCveRows = '';
        foreach ($s['top_cves'] as $cve) {
            $topCveRows .= '<tr>'
                . '<td width="17%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$cve['cve_id']) . '</td>'
                . '<td width="38%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)($cve['title'] ?? '')) . '</td>'
                . '<td width="17%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars(ucfirst((string)$cve['severity'])) . '</td>'
                . '<td width="14%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)($cve['cvss_score'] ?? '-')) . '</td>'
                . '<td width="14%" style="padding:4px;border-bottom:1px solid #dddddd">' . (int)$cve['affected_count'] . '</td>'
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
            . self::weeklyRemediationSection($s)
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

    /**
     * "Remediation of the period" block shared by the weekly and monthly PDFs.
     * Reads the remediated_cves_7d/patches_installed_7d (or *_30d) keys when
     * present; returns '' when the stats carry no remediation data.
     */
    private static function weeklyRemediationSection(array $s, string $suffix = '7d', string $periodLabel = 'ultimos 7 dias'): string {
        if (!isset($s["remediated_cves_{$suffix}"]) && !isset($s["patches_installed_{$suffix}"])) {
            return '';
        }

        $cves    = (int)($s["remediated_cves_{$suffix}"] ?? 0);
        $patches = (int)($s["patches_installed_{$suffix}"] ?? 0);
        if ($cves + $patches === 0) {
            return '<h3 style="color:#1a9c53;font-size:10.5pt;margin-bottom:2pt">Remediacao (' . $periodLabel . ')</h3>'
                . '<p style="color:#6b7280;font-size:8pt;margin-bottom:10pt">Nenhuma remediacao registrada no periodo.</p>';
        }

        $rows = '';
        foreach (($s['top_remediators'] ?? []) as $ep) {
            $rows .= '<tr>'
                . '<td width="46%" style="padding:4px;border-bottom:1px solid #dddddd">' . htmlspecialchars((string)$ep['name']) . '</td>'
                . '<td width="18%" style="padding:4px;border-bottom:1px solid #dddddd;color:#1a9c53"><b>' . (int)$ep['cves_fixed'] . '</b></td>'
                . '<td width="18%" style="padding:4px;border-bottom:1px solid #dddddd;color:#1a6dff"><b>' . (int)$ep['patches_fixed'] . '</b></td>'
                . '<td width="18%" style="padding:4px;border-bottom:1px solid #dddddd">' . ($ep['avg_days'] !== null ? number_format((float)$ep['avg_days'], 1) . ' d' : '-') . '</td>'
                . '</tr>';
        }

        $html = '<h3 style="color:#1a9c53;font-size:10.5pt;margin-bottom:2pt">Remediacao (' . $periodLabel . ')</h3>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse;margin-bottom:6pt">'
            . '<tr style="background-color:#f0faf4">'
            . '<td style="text-align:center"><b style="font-size:12pt;color:#1a9c53">' . $cves . '</b><br/><span style="font-size:6.5pt;color:#6b7280">CVES REMEDIADOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:12pt;color:#1a6dff">' . $patches . '</b><br/><span style="font-size:6.5pt;color:#6b7280">PATCHES INSTALADOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:12pt">' . (int)($s["endpoints_fixed_{$suffix}"] ?? 0) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">ENDPOINTS CORRIGIDOS</span></td>'
            . '</tr></table>';

        if ($rows !== '') {
            $html .= '<table cellpadding="3" style="width:100%;border-collapse:collapse;margin-bottom:10pt;font-size:8pt">'
                . '<thead><tr style="background-color:#f1f3f7">'
                . '<th width="46%" style="padding:4px;text-align:left">Endpoint</th>'
                . '<th width="18%" style="padding:4px;text-align:left">CVEs</th>'
                . '<th width="18%" style="padding:4px;text-align:left">Patches</th>'
                . '<th width="18%" style="padding:4px;text-align:left">Tempo medio</th>'
                . '</tr></thead><tbody>' . $rows . '</tbody></table>';
        }

        return $html;
    }

    /**
     * @param array<string,mixed> $s stats produced by MonthlyReport::gatherStats()
     */
    public static function monthly(array $s, string $baseUrl): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', "[Tanium] TCPDF indisponivel -- PDF do relatorio mensal nao gerado.\n");
            return null;
        }

        $compliance = $s['patch_compliance'] !== null ? $s['patch_compliance'] . '%' : 'N/A';
        $mttr30     = isset($s['mttr_30d']) && $s['mttr_30d'] !== null ? number_format((float)$s['mttr_30d'], 1) . ' dias' : '-';

        // Posture delta vs the ~30-day-old snapshot
        $deltaTable = '';
        $baseline   = $s['baseline'] ?? null;
        if ($baseline !== null) {
            $deltaRow = static function (string $label, int $now, int $then): string {
                $diff = $now - $then;
                $color = $diff > 0 ? '#d6336c' : ($diff < 0 ? '#1a9c53' : '#6b7280');
                $sign  = $diff > 0 ? '+' : '';
                return '<tr>'
                    . '<td width="40%" style="padding:4px;border-bottom:1px solid #dddddd">' . $label . '</td>'
                    . '<td width="20%" style="padding:4px;border-bottom:1px solid #dddddd">' . $then . '</td>'
                    . '<td width="20%" style="padding:4px;border-bottom:1px solid #dddddd"><b>' . $now . '</b></td>'
                    . '<td width="20%" style="padding:4px;border-bottom:1px solid #dddddd;color:' . $color . '"><b>' . $sign . $diff . '</b></td>'
                    . '</tr>';
            };
            $baselineDate = date('d/m/Y', strtotime((string)$baseline['recorded_at']));
            $deltaTable = '<h3 style="color:#e8212a;font-size:10.5pt;margin-bottom:2pt">Evolucao da postura (vs ' . $baselineDate . ')</h3>'
                . '<table cellpadding="3" style="width:100%;border-collapse:collapse;margin-bottom:10pt;font-size:8pt">'
                . '<thead><tr style="background-color:#f1f3f7">'
                . '<th width="40%" style="padding:4px;text-align:left">Indicador</th>'
                . '<th width="20%" style="padding:4px;text-align:left">Antes</th>'
                . '<th width="20%" style="padding:4px;text-align:left">Agora</th>'
                . '<th width="20%" style="padding:4px;text-align:left">Delta</th>'
                . '</tr></thead><tbody>'
                . $deltaRow('Total de CVEs', (int)$s['total_cves'], (int)$baseline['total_cves'])
                . $deltaRow('CVEs criticos', (int)$s['critical_cves'], (int)$baseline['critical_cves'])
                . $deltaRow('Patches ausentes', (int)$s['patches_missing'], (int)$baseline['patches_missing'])
                . $deltaRow('Risco medio', (int)round((float)$s['avg_risk']), (int)round((float)$baseline['avg_risk']))
                . '</tbody></table>';
        }

        $html = '<div style="font-size:9pt">'
            . '<h2 style="color:#e8212a;font-size:13pt;margin-bottom:2pt">Relatorio Mensal de Seguranca — ' . date('m/Y') . '</h2>'
            . '<p style="color:#4a5568;font-size:9pt">' . (int)$s['total_endpoints'] . ' endpoints monitorados &middot; Gerado em ' . date('d/m/Y H:i') . '</p>'
            . self::weeklyRemediationSection($s, '30d', 'ultimos 30 dias')
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse;margin-bottom:8pt">'
            . '<tr style="background-color:#f9fafb">'
            . '<td style="text-align:center"><b style="font-size:13pt;color:#d6336c">' . (int)$s['critical_cves'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">CVES CRITICOS ABERTOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt;color:#c2860a">' . (int)($s['new_findings_30d'] ?? 0) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">NOVOS FINDINGS (30D)</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt">' . htmlspecialchars($compliance) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">PATCH COMPLIANCE</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt">' . htmlspecialchars($mttr30) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">MTTR DO MES</span></td>'
            . '</tr></table>'
            . $deltaTable
            . '<p style="color:#9ca3af;font-size:7pt;margin-top:10pt">Gerado automaticamente pelo plugin Tanium para GLPI. ' . htmlspecialchars($baseUrl) . '</p>'
            . '</div>';

        return self::render('Tanium - Relatorio Mensal', $html);
    }

    /**
     * Per-endpoint remediation summary PDF — downloadable version of the
     * "Remediation by endpoint" table (front/remediation.php), for the
     * selected trailing window.
     *
     * @param array<int,array<string,mixed>> $rows  Remediation::getByEndpoint() rows
     * @param array<string,mixed>            $stats Remediation::getStats() result
     */
    public static function remediationByEndpoint(array $rows, array $stats, int $windowDays): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', "[Tanium] TCPDF indisponivel -- PDF de remediacao por endpoint nao gerado.\n");
            return null;
        }

        $esc  = static fn($v): string => htmlspecialchars((string)($v ?? ''), ENT_QUOTES, 'UTF-8');
        $mttr = $stats['mttr'] !== null ? number_format((float)$stats['mttr'], 1) . ' dias' : '-';

        // Widths repeated on every row -- see the note in critical().
        $body = '';
        foreach ($rows as $r) {
            $stillOpen = (int)$r['still_open'];
            $body .= '<tr>'
                . '<td width="30%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc($r['name'])
                    . ($r['os'] !== '' ? '<br/><span style="color:#6b7280;font-size:7pt">' . $esc($r['os']) . '</span>' : '') . '</td>'
                . '<td width="12%" style="padding:4px;border-bottom:1px solid #dddddd;color:#1a9c53"><b>' . (int)$r['cves_fixed'] . '</b></td>'
                . '<td width="12%" style="padding:4px;border-bottom:1px solid #dddddd;color:#1a6dff"><b>' . (int)$r['patches_fixed'] . '</b></td>'
                . '<td width="10%" style="padding:4px;border-bottom:1px solid #dddddd"><b>' . (int)$r['total'] . '</b></td>'
                . '<td width="12%" style="padding:4px;border-bottom:1px solid #dddddd">' . ($r['avg_days'] !== null ? number_format((float)$r['avg_days'], 1) . ' d' : '-') . '</td>'
                . '<td width="14%" style="padding:4px;border-bottom:1px solid #dddddd;font-size:7pt">' . ($r['last_fix'] !== null ? date('d/m/Y H:i', strtotime((string)$r['last_fix'])) : '-') . '</td>'
                . '<td width="10%" style="padding:4px;border-bottom:1px solid #dddddd;color:' . ($stillOpen > 0 ? '#d6336c' : '#1a9c53') . '"><b>' . $stillOpen . '</b></td>'
                . '</tr>';
        }
        if ($body === '') {
            $body = '<tr><td colspan="7" style="padding:4px;color:#6b7280">Nenhuma remediacao registrada no periodo.</td></tr>';
        }

        $html = '<div style="font-size:9pt">'
            . '<h2 style="color:#1a9c53;font-size:13pt;margin-bottom:2pt">Remediacao por Endpoint — ultimos ' . (int)$windowDays . ' dias</h2>'
            . '<p style="color:#4a5568;font-size:9pt">Gerado em ' . date('d/m/Y H:i') . '</p>'
            . '<table cellpadding="4" style="width:100%;border-collapse:collapse;margin-bottom:8pt">'
            . '<tr style="background-color:#f0faf4">'
            . '<td style="text-align:center"><b style="font-size:13pt;color:#1a9c53">' . (int)$stats['cves_remediated'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">CVES REMEDIADOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt;color:#1a6dff">' . (int)$stats['patches_installed'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">PATCHES INSTALADOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt">' . (int)$stats['endpoints_touched'] . '</b><br/><span style="font-size:6.5pt;color:#6b7280">ENDPOINTS CORRIGIDOS</span></td>'
            . '<td style="text-align:center"><b style="font-size:13pt">' . $esc($mttr) . '</b><br/><span style="font-size:6.5pt;color:#6b7280">MTTR</span></td>'
            . '</tr></table>'
            . '<table cellpadding="3" style="width:100%;border-collapse:collapse;font-size:7.5pt">'
            . '<thead><tr style="background-color:#f1f3f7">'
            . '<th width="30%" style="padding:4px;text-align:left">Endpoint</th>'
            . '<th width="12%" style="padding:4px;text-align:left">CVEs</th>'
            . '<th width="12%" style="padding:4px;text-align:left">Patches</th>'
            . '<th width="10%" style="padding:4px;text-align:left">Total</th>'
            . '<th width="12%" style="padding:4px;text-align:left">Tempo medio</th>'
            . '<th width="14%" style="padding:4px;text-align:left">Ultima correcao</th>'
            . '<th width="10%" style="padding:4px;text-align:left">Abertos</th>'
            . '</tr></thead><tbody>' . $body . '</tbody></table>'
            . '<p style="color:#9ca3af;font-size:7pt;margin-top:10pt">Gerado automaticamente pelo plugin Tanium para GLPI.</p>'
            . '</div>';

        return self::render('Tanium - Remediacao por Endpoint', $html);
    }

    /**
     * Remediation digest PDF, attached to the post-sync remediation email:
     * CVE findings closed and patches installed during one sync run.
     *
     * @param array<int,array{cve_id:string,endpoint:string,severity:string,cvss:mixed,detected_at:?string,days_open:?int}> $remediatedCves
     * @param array<int,array{patch_id:string,title:string,endpoint:string,severity:string}> $installedPatches
     */
    public static function remediation(array $remediatedCves, array $installedPatches, string $glpiUrl): ?string {
        if (!class_exists(\TCPDF::class)) {
            Toolbox::logInFile('tanium', "[Tanium] TCPDF indisponivel -- PDF de remediacao nao gerado.\n");
            return null;
        }

        $esc = static fn($v): string => htmlspecialchars((string)($v ?? ''), ENT_QUOTES, 'UTF-8');

        // Column widths repeated on every row -- see the note in critical().
        $cveRows = '';
        foreach ($remediatedCves as $ev) {
            $days = $ev['days_open'] !== null ? $ev['days_open'] . ' dia(s)' : '-';
            $cveRows .= '<tr>'
                . '<td width="22%" style="padding:4px;border-bottom:1px solid #dddddd"><b>' . $esc($ev['cve_id']) . '</b></td>'
                . '<td width="34%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc($ev['endpoint']) . '</td>'
                . '<td width="16%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc(ucfirst((string)$ev['severity'])) . '</td>'
                . '<td width="12%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc($ev['cvss'] ?? '-') . '</td>'
                . '<td width="16%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc($days) . '</td>'
                . '</tr>';
        }

        $patchRows = '';
        foreach ($installedPatches as $p) {
            $patchRows .= '<tr>'
                . '<td width="58%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc($p['title'] !== '' ? $p['title'] : $p['patch_id']) . '</td>'
                . '<td width="26%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc($p['endpoint']) . '</td>'
                . '<td width="16%" style="padding:4px;border-bottom:1px solid #dddddd">' . $esc(ucfirst((string)$p['severity'])) . '</td>'
                . '</tr>';
        }

        $daysOpen = array_values(array_filter(array_column($remediatedCves, 'days_open'), static fn($d) => $d !== null));
        $avgDays  = $daysOpen !== [] ? number_format(array_sum($daysOpen) / count($daysOpen), 1) : '-';

        $html = '<div style="font-size:9pt">'
            . '<h2 style="color:#1a9c53;font-size:13pt;margin-bottom:2pt">Relatorio de Remediacao</h2>'
            . '<p style="color:#4a5568;font-size:9pt">' . count($remediatedCves) . ' CVE(s) remediado(s) e '
            . count($installedPatches) . ' patch(es) instalado(s) registrados em ' . date('d/m/Y H:i')
            . ' &middot; tempo medio de correcao: ' . $avgDays . ' dia(s).</p>';

        if ($cveRows !== '') {
            $html .= '<h3 style="color:#1a9c53;font-size:10.5pt;margin-bottom:2pt">CVEs remediados</h3>'
                . '<table cellpadding="3" style="width:100%;border-collapse:collapse;margin-bottom:10pt;font-size:8pt">'
                . '<thead><tr style="background-color:#f1f3f7">'
                . '<th width="22%" style="padding:4px;text-align:left">CVE ID</th>'
                . '<th width="34%" style="padding:4px;text-align:left">Endpoint</th>'
                . '<th width="16%" style="padding:4px;text-align:left">Severidade</th>'
                . '<th width="12%" style="padding:4px;text-align:left">CVSS</th>'
                . '<th width="16%" style="padding:4px;text-align:left">Tempo aberto</th>'
                . '</tr></thead><tbody>' . $cveRows . '</tbody></table>';
        }

        if ($patchRows !== '') {
            $html .= '<h3 style="color:#1a9c53;font-size:10.5pt;margin-bottom:2pt">Patches instalados</h3>'
                . '<table cellpadding="3" style="width:100%;border-collapse:collapse;font-size:8pt">'
                . '<thead><tr style="background-color:#f1f3f7">'
                . '<th width="58%" style="padding:4px;text-align:left">Patch</th>'
                . '<th width="26%" style="padding:4px;text-align:left">Endpoint</th>'
                . '<th width="16%" style="padding:4px;text-align:left">Severidade</th>'
                . '</tr></thead><tbody>' . $patchRows . '</tbody></table>';
        }

        $html .= '<p style="color:#9ca3af;font-size:7pt;margin-top:10pt">Gerado automaticamente pelo plugin Tanium para GLPI. ' . $esc($glpiUrl) . '</p>'
            . '</div>';

        return self::render('Tanium - Relatorio de Remediacao', $html);
    }

    /**
     * Side-by-side endpoint comparison, mirroring front/compare.php.
     * $ep1/$ep2 are the arrays built by that page's endpoint loader
     * (keys: asset, cves, patches, sev, cve_ids).
     */
    public static function compare(array $ep1, array $ep2): ?string {
        $esc = static fn($v): string => htmlspecialchars((string)($v ?? ''), ENT_QUOTES, 'UTF-8');

        $sevColor = static fn(string $s): string => match (strtolower($s)) {
            'critical' => '#e8212a',
            'high'     => '#f97316',
            'medium'   => '#e8c42a',
            'low'      => '#1eb464',
            default    => '#7a8da8',
        };

        $sideHtml = static function (array $ep, array $other) use ($esc, $sevColor): string {
            $a  = $ep['asset'];
            $rs = (int)($a['risk_score'] ?? 0);
            $riskColor = $rs >= 70 ? '#e8212a' : ($rs >= 40 ? '#f97316' : ($rs >= 15 ? '#e8c42a' : '#1eb464'));

            $html = '<h3 style="color:#1c2330;margin:0 0 4px 0">' . $esc($a['tanium_name'] ?: $a['tanium_eid']) . '</h3>'
                  . '<p style="font-size:8pt;color:#5a6a85;margin:0 0 6px 0">'
                  . 'IP: ' . $esc($a['ip_address'] ?: '—')
                  . ' | OS: ' . $esc($a['os_name'] ?: '—') . ' ' . $esc($a['os_version'] ?? '')
                  . ' | Risco: <span style="color:' . $riskColor . ';font-weight:bold">' . $rs . '</span>'
                  . ' | Visto: ' . $esc($a['last_seen'] ?: '—')
                  . '</p>'
                  . '<p style="font-size:8pt;margin:0 0 6px 0">'
                  . '<span style="color:#e8212a;font-weight:bold">' . (int)$ep['sev']['critical'] . ' críticos</span> · '
                  . '<span style="color:#f97316;font-weight:bold">' . (int)$ep['sev']['high'] . ' altos</span> · '
                  . (int)$ep['sev']['medium'] . ' médios · '
                  . (int)$ep['sev']['low'] . ' baixos · '
                  . '<span style="font-weight:bold">' . count($ep['patches']) . ' patches ausentes</span>'
                  . '</p>';

            if (!empty($ep['cves'])) {
                $otherIds = $other['cve_ids'] ?? [];
                $html .= '<table border="0" cellpadding="3" style="font-size:8pt;width:100%">'
                       . '<tr style="background-color:#f0f2f6;color:#1c2330;font-weight:bold">'
                       . '<td width="42%">CVE</td><td width="22%">Severidade</td><td width="14%">CVSS</td><td width="22%">Presença</td></tr>';
                foreach (array_slice($ep['cves'], 0, 15) as $c) {
                    $shared = in_array($c['cve_id'], $otherIds, true);
                    // Widths mirror the header row's 42/22/14/22 split so TCPDF
                    // doesn't recompute a different column grid for these rows.
                    $html .= '<tr>'
                           . '<td width="42%">' . $esc($c['cve_id']) . '</td>'
                           . '<td width="22%" style="color:' . $sevColor((string)$c['severity']) . ';font-weight:bold">' . $esc(ucfirst((string)$c['severity'])) . '</td>'
                           . '<td width="14%">' . ($c['cvss_score'] !== null ? number_format((float)$c['cvss_score'], 1) : '—') . '</td>'
                           . '<td width="22%" style="color:' . ($shared ? '#1a6dff' : '#e8212a') . '">' . ($shared ? 'ambos' : 'exclusivo') . '</td>'
                           . '</tr>';
                }
                $html .= '</table>';
            } else {
                $html .= '<p style="font-size:8pt;color:#5a6a85">Sem CVEs registrados.</p>';
            }

            return $html;
        };

        $shared  = count(array_intersect($ep1['cve_ids'], $ep2['cve_ids']));
        $only1   = count($ep1['cve_ids']) - $shared;
        $only2   = count($ep2['cve_ids']) - $shared;

        $html = '<h1 style="color:#e8212a;font-size:14pt">Comparação de Endpoints</h1>'
              . '<p style="font-size:8pt;color:#5a6a85">Gerado em ' . date('d/m/Y H:i') . ' pelo plugin Tanium para GLPI</p>'
              . '<p style="font-size:9pt"><strong>' . $shared . '</strong> CVE(s) em comum · '
              . '<strong>' . $only1 . '</strong> exclusivo(s) de A · '
              . '<strong>' . $only2 . '</strong> exclusivo(s) de B</p>'
              . '<h2 style="color:#e8212a;font-size:11pt;border-bottom:1px solid #e8212a">Endpoint A</h2>'
              . $sideHtml($ep1, $ep2)
              . '<br/><h2 style="color:#1a6dff;font-size:11pt;border-bottom:1px solid #1a6dff">Endpoint B</h2>'
              . $sideHtml($ep2, $ep1);

        return self::render('Tanium - Comparacao de Endpoints', $html);
    }

    /**
     * Fleet health report ("boletim de saúde") — rows/summary from
     * HealthReport::getFleet()/summary(). Worst endpoints first.
     */
    public static function health(array $rows, array $summary): ?string {
        $esc = static fn($v): string => htmlspecialchars((string)($v ?? ''), ENT_QUOTES, 'UTF-8');

        $bandsLine = [];
        foreach ($summary['bands'] as $label => $n) {
            $bandsLine[] = "<strong>{$n}</strong> " . $esc($label);
        }

        $html = '<h1 style="color:#e8212a;font-size:14pt">Boletim de Saúde da Frota</h1>'
              . '<p style="font-size:8pt;color:#5a6a85">Gerado em ' . date('d/m/Y H:i') . ' pelo plugin Tanium para GLPI</p>'
              . '<p style="font-size:9pt">' . $summary['total'] . ' endpoints · nota média <strong>'
              . ($summary['avg'] !== null ? number_format($summary['avg'], 1) : '—') . '</strong> · '
              . implode(' · ', $bandsLine) . '</p>'
              . '<table border="0" cellpadding="3" style="font-size:7.5pt;width:100%">'
              . '<tr style="background-color:#f0f2f6;color:#1c2330;font-weight:bold">'
              . '<td width="26%">Endpoint</td><td width="7%">Nota</td><td width="10%">Veredito</td>'
              . '<td width="37%">Diagnóstico</td><td width="10%">CVEs C/A/M</td><td width="10%">Patches</td></tr>';

        // Widths mirror the header row's 26/7/10/37/10/10 split so TCPDF
        // doesn't recompute a different column grid for these rows.
        foreach ($rows as $r) {
            $html .= '<tr>'
                   . '<td width="26%">' . $esc($r['tanium_name'] ?: $r['tanium_eid']) . '</td>'
                   . '<td width="7%" style="color:' . $r['verdict_color'] . ';font-weight:bold">' . number_format($r['score'], 1) . '</td>'
                   . '<td width="10%" style="color:' . $r['verdict_color'] . ';font-weight:bold">' . $esc($r['verdict']) . '</td>'
                   . '<td width="37%">' . $esc($r['message']) . '</td>'
                   . '<td width="10%">' . (int)$r['cves_critical'] . ' / ' . (int)$r['cves_high'] . ' / ' . (int)$r['cves_medium'] . '</td>'
                   . '<td width="10%">' . (int)$r['missing_patches'] . '</td>'
                   . '</tr>';
        }
        $html .= '</table>';

        return self::render('Tanium - Boletim de Saude da Frota', $html);
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
            Toolbox::logInFile('tanium', '[Tanium] Falha ao gerar PDF: ' . $error->getMessage() . "\n");
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
