<?php

use Glpi\Plugin\Hooks;
use GlpiPlugin\Tanium\ComputerTab;
use GlpiPlugin\Tanium\Config as TaniumConfig;
use GlpiPlugin\Tanium\Cron as TaniumCron;
use GlpiPlugin\Tanium\Profile as TaniumProfile;
use GlpiPlugin\Tanium\Sync as TaniumSync;
use GlpiPlugin\Tanium\WeeklyReport as TaniumWeeklyReport;
use GlpiPlugin\Tanium\CentralWidget as TaniumCentralWidget;
use GlpiPlugin\Tanium\PatchDeploy as TaniumPatchDeploy;
use GlpiPlugin\Tanium\Vulnerability;

define('PLUGIN_TANIUM_VERSION', '1.2.0');
define('PLUGIN_TANIUM_MIN_GLPI', '11.0.0');
define('PLUGIN_TANIUM_MAX_GLPI', '11.99.99');

function plugin_init_tanium(): void {
    global $PLUGIN_HOOKS;

    // Sync plugin rights into the active session (same pattern as SentinelOne)
    TaniumProfile::syncCurrentProfileRights();

    $PLUGIN_HOOKS['csrf_compliant']['tanium'] = true;

    if (!Plugin::isPluginActive('tanium')) {
        return;
    }

    // Config page link (shown on plugin list)
    $PLUGIN_HOOKS['config_page']['tanium'] = 'front/config.form.php';

    // CSS
    $PLUGIN_HOOKS[Hooks::ADD_CSS]['tanium'] = ['css/tanium.css'];

    // ── Menu under "Plug-ins" section (same as SentinelOne) ──────────────
    $PLUGIN_HOOKS[Hooks::MENU_TOADD]['tanium'] = [
        'plugins' => TaniumSync::class,
    ];

    // ── Profile tab (Configuração → Perfis → aba Tanium) ─────────────────
    Plugin::registerClass(TaniumProfile::class, [
        'addtabon' => [\Profile::class],
    ]);

    // ── Config tab on GLPI Config page ────────────────────────────────────
    Plugin::registerClass(TaniumConfig::class, [
        'addtabon' => [\Config::class],
    ]);

    // ── Tanium tab on Computer page ───────────────────────────────────────
    Plugin::registerClass(ComputerTab::class, [
        'addtabon' => [\Computer::class],
    ]);
    Plugin::registerClass(Vulnerability::class);

    // Other classes
    Plugin::registerClass(TaniumSync::class);
    Plugin::registerClass(TaniumCron::class);
    Plugin::registerClass(TaniumWeeklyReport::class);
    Plugin::registerClass(TaniumPatchDeploy::class);

    // Ticket update hook — triggers Tanium patch deployment on approval
    $PLUGIN_HOOKS[Hooks::ITEM_UPDATE]['tanium'] = [
        'Ticket' => 'plugin_tanium_ticket_update',
    ];

    // Central dashboard widget
    Plugin::registerClass(TaniumCentralWidget::class, [
        'addtabon' => [\Central::class],
    ]);

    // Cron task registration — sync
    CronTask::register(
        TaniumCron::class,
        'taniumsync',
        HOUR_TIMESTAMP,
        [
            'comment' => 'Tanium — automatic endpoint synchronization',
            'mode'    => CronTask::MODE_EXTERNAL,
        ]
    );

    // Cron task registration — weekly report
    CronTask::register(
        TaniumWeeklyReport::class,
        'weeklyreport',
        604800, // 7 days
        [
            'comment' => 'Tanium — weekly security report by email',
            'mode'    => CronTask::MODE_EXTERNAL,
        ]
    );

    // Cron task registration — check patch deployment status
    CronTask::register(
        TaniumPatchDeploy::class,
        'checkdeployments',
        300, // every 5 minutes
        [
            'comment' => 'Tanium — poll active patch deployments and auto-close tickets when complete',
            'mode'    => CronTask::MODE_EXTERNAL,
        ]
    );
}

// ── Hook callback — must be a named function, not a closure ──────────────────
function plugin_tanium_ticket_update(Ticket $ticket): void {
    \GlpiPlugin\Tanium\PatchDeploy::onTicketUpdate($ticket);
}

function plugin_version_tanium(): array {
    return [
        'name'         => 'Tanium',
        'version'      => PLUGIN_TANIUM_VERSION,
        'author'       => 'Celso Caninde / Claude',
        'license'      => 'GPLv2+',
        'homepage'     => 'https://developer.tanium.com',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_TANIUM_MIN_GLPI,
                'max' => PLUGIN_TANIUM_MAX_GLPI,
            ],
            'php'  => [
                'min'  => '8.2',
                'exts' => ['curl', 'json'],
            ],
        ],
    ];
}

function plugin_tanium_check_prerequisites(): bool {
    $ok = true;

    if (!extension_loaded('curl')) {
        echo "<div class='alert alert-danger'>" . __('The PHP cURL extension is required by the Tanium plugin.', 'tanium') . "</div>";
        $ok = false;
    }

    if (!extension_loaded('json')) {
        echo "<div class='alert alert-danger'>" . __('The PHP JSON extension is required by the Tanium plugin.', 'tanium') . "</div>";
        $ok = false;
    }

    return $ok;
}

function plugin_tanium_check_config(bool $verbose = false): bool {
    return true;
}
