<?php

namespace GlpiPlugin\Tanium;

use CommonDBTM;
use CronTask;

class Cron extends CommonDBTM {

    public static $rightname = 'config';

    public static function getTypeName($nb = 0): string {
        return __('Tanium Cron', 'tanium');
    }

    public static function cronInfo(string $name): array {
        return match ($name) {
            'taniumsync' => [
                'description' => __('Tanium — synchronize endpoints, software and hardware into GLPI assets.', 'tanium'),
                'parameter'   => __('Hours between runs (overrides plugin setting)', 'tanium'),
            ],
            'epsskev' => [
                'description' => __('Tanium — refresh EPSS scores and CISA KEV flags for tracked CVEs.', 'tanium'),
            ],
            'agenthealth' => [
                'description' => __('Tanium — detect endpoints whose agent stopped reporting and open a consolidated ticket.', 'tanium'),
            ],
            'complysync' => [
                'description' => __('Tanium — import compliance benchmark results (CIS/DISA) from Tanium Comply.', 'tanium'),
            ],
            'threatsync' => [
                'description' => __('Tanium — import Threat Response alerts and open tickets for new high-severity ones.', 'tanium'),
            ],
            'slabreach' => [
                'description' => __('Tanium — daily webhook alert while remediation-SLA breaches exist.', 'tanium'),
            ],
            default => [],
        };
    }

    public static function cronSlabreach(CronTask $task): int {
        $config = Config::getConfig();

        if (empty($config['webhook_sla']) || empty($config['webhook_url'])) {
            $task->log(__('SLA breach webhook disabled in plugin settings. Skipping.', 'tanium'));
            return 0;
        }

        $stats = Sla::getStats();
        if ((int)$stats['breached'] === 0) {
            $task->log(__('No SLA-breached findings today. Nothing to notify.', 'tanium'));
            return 1;
        }

        $payload = Notification::buildSlaBreachPayload($stats, Sla::getTopBreachedEndpoints(5));
        $ok      = Notification::sendWebhook($config['webhook_url'], $payload);

        $task->log(sprintf(
            __('SLA breach webhook (%d findings overdue): %s', 'tanium'),
            (int)$stats['breached'],
            $ok ? 'OK' : 'FAIL'
        ));
        $task->setVolume((int)$stats['breached']);

        return $ok ? 1 : -1;
    }

    public static function cronThreatsync(CronTask $task): int {
        $config = Config::getConfig();

        if (empty($config['sync_threats'])) {
            $task->log(__('Threat Response sync disabled in plugin settings. Skipping.', 'tanium'));
            return 0;
        }
        if (empty($config['api_url']) || empty($config['api_token'])) {
            $task->log(__('Tanium plugin: API URL or token not configured. Skipping.', 'tanium'));
            return 0;
        }

        $api = new Api($config['api_url'], $config['api_token']);
        [$imported, $tickets] = ThreatResponse::syncFromApi($api);

        $task->log(sprintf(__('Threat sync finished — %d new alerts, %d tickets opened.', 'tanium'), $imported, $tickets));
        $task->setVolume($imported);

        return $imported > 0 ? 1 : 0;
    }

    public static function cronComplysync(CronTask $task): int {
        $config = Config::getConfig();

        if (empty($config['sync_compliance'])) {
            $task->log(__('Compliance sync disabled in plugin settings. Skipping.', 'tanium'));
            return 0;
        }
        if (empty($config['api_url']) || empty($config['api_token'])) {
            $task->log(__('Tanium plugin: API URL or token not configured. Skipping.', 'tanium'));
            return 0;
        }

        $api   = new Api($config['api_url'], $config['api_token']);
        $count = Compliance::syncFromApi($api);

        $task->log(sprintf(__('Compliance sync finished — %d findings imported.', 'tanium'), $count));
        $task->setVolume($count);

        return $count > 0 ? 1 : 0;
    }

    public static function cronAgenthealth(CronTask $task): int {
        $config = Config::getConfig();
        $days   = (int)($config['agent_stale_days'] ?? 7);
        $stale  = AgentHealth::countStale($days);

        $task->log(sprintf(__('%d endpoint(s) silent for more than %d days.', 'tanium'), $stale, $days));
        $task->setVolume($stale);

        $ticketId = AgentHealth::openTicketIfNeeded();
        if ($ticketId > 0) {
            $task->log(sprintf(__('Opened consolidated agent-health ticket #%d.', 'tanium'), $ticketId));
        }

        return 1;
    }

    public static function cronEpsskev(CronTask $task): int {
        $task->log(__('EPSS/KEV enrichment started…', 'tanium'));

        $result = Enrichment::refresh();

        $task->log(sprintf(
            __('EPSS/KEV enrichment finished — EPSS rows: %d | KEV matches: %d', 'tanium'),
            $result['epss'],
            $result['kev']
        ));
        $task->setVolume($result['epss'] + $result['kev']);

        return ($result['epss'] + $result['kev']) > 0 ? 1 : 0;
    }

    public static function crontaniumsync(CronTask $task): int {
        $config = Config::getConfig();

        if (empty($config['api_url']) || empty($config['api_token'])) {
            $task->log(__('Tanium plugin: API URL or token not configured. Skipping.', 'tanium'));
            return 0;
        }

        $task->log(__('Tanium sync started…', 'tanium'));

        $result = Sync::run();

        $msg = sprintf(
            __('Tanium sync finished — total: %d | created: %d | updated: %d | errors: %d', 'tanium'),
            $result['total'],
            $result['created'],
            $result['updated'],
            $result['errors']
        );
        $task->log($msg);
        $task->setVolume($result['total']);

        return $result['errors'] > 0 && $result['total'] === 0 ? -1 : 1;
    }
}
