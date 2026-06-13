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
            default => [],
        };
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
