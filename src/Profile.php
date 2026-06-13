<?php

namespace GlpiPlugin\Tanium;

use Html;
use Session;

class Profile extends \Profile {

    public const RIGHT_READ   = 'plugin_tanium_read';
    public const RIGHT_SYNC   = 'plugin_tanium_sync';
    public const RIGHT_CONFIG = 'plugin_tanium_config';

    public static function getAllRights(): array {
        return [
            [
                'label'  => 'Tanium - Visualização',
                'field'  => self::RIGHT_READ,
                'rights' => [READ],
            ],
            [
                'label'  => 'Tanium - Sincronização',
                'field'  => self::RIGHT_SYNC,
                'rights' => [READ, UPDATE],
            ],
            [
                'label'  => 'Tanium - Configuração',
                'field'  => self::RIGHT_CONFIG,
                'rights' => [READ, UPDATE],
            ],
        ];
    }

    // ── Rights checks ─────────────────────────────────────────────────────

    public static function hasReadRight(): bool {
        return Session::haveRight(self::RIGHT_READ, READ)
            || Session::haveRight(self::RIGHT_CONFIG, READ);
    }

    public static function hasSyncRight(): bool {
        return Session::haveRight(self::RIGHT_SYNC, UPDATE)
            || Session::haveRight(self::RIGHT_CONFIG, UPDATE);
    }

    public static function hasConfigReadRight(): bool {
        return Session::haveRight(self::RIGHT_CONFIG, READ);
    }

    public static function hasConfigUpdateRight(): bool {
        return Session::haveRight(self::RIGHT_CONFIG, UPDATE);
    }

    // ── Session sync ──────────────────────────────────────────────────────

    public static function syncCurrentProfileRights(): void {
        global $DB;

        if (
            !isset($DB)
            || !isset($_SESSION['glpiactiveprofile'])
            || !is_array($_SESSION['glpiactiveprofile'])
        ) {
            return;
        }

        $profileId = (int) ($_SESSION['glpiactiveprofile']['id'] ?? 0);
        if ($profileId <= 0 || !$DB->tableExists('glpi_profilerights')) {
            return;
        }

        foreach (self::getCurrentRightsForProfile($profileId) as $field => $rights) {
            $_SESSION['glpiactiveprofile'][$field] = $rights;
        }
    }

    public static function getCurrentRightsForProfile(int $profileId): array {
        global $DB;

        $result = [];
        $fields = array_column(self::getAllRights(), 'field');

        if ($profileId <= 0 || $fields === [] || !$DB->tableExists('glpi_profilerights')) {
            return $result;
        }

        foreach ($DB->request([
            'SELECT' => ['name', 'rights'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => [
                'profiles_id' => $profileId,
                'name'        => $fields,
            ],
        ]) as $row) {
            $result[(string) $row['name']] = (int) $row['rights'];
        }

        return $result;
    }

    // ── Ensure rights exist for all profiles ──────────────────────────────

    public static function ensureProfileRights(): void {
        global $DB;

        $rights = self::getAllRights();
        $fields = array_column($rights, 'field');

        if ($fields === [] || !$DB->tableExists('glpi_profilerights')) {
            return;
        }

        $profiles = [];
        foreach ($DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_profiles']) as $row) {
            $profiles[(int) $row['id']] = (string) $row['name'];
        }

        $existing = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'profiles_id', 'name', 'rights'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => ['name' => $fields],
        ]) as $row) {
            $existing[(int) $row['profiles_id'] . '|' . (string) $row['name']] = [
                'id'     => (int) $row['id'],
                'rights' => (int) $row['rights'],
            ];
        }

        foreach ($profiles as $profileId => $profileName) {
            foreach ($rights as $right) {
                $field         = (string) $right['field'];
                $defaultRights = self::getDefaultRightsForProfile($profileName, $right);
                $key           = $profileId . '|' . $field;

                if (isset($existing[$key])) {
                    if ($defaultRights > 0 && (int) $existing[$key]['rights'] === 0) {
                        $DB->update('glpi_profilerights', [
                            'rights' => $defaultRights,
                        ], ['id' => (int) $existing[$key]['id']]);
                    }
                    continue;
                }

                $DB->insert('glpi_profilerights', [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                    'rights'      => $defaultRights,
                ]);
            }
        }
    }

    public static function saveRightsForProfile(int $profileId, array $submittedRights): void {
        global $DB;

        if ($profileId <= 0 || !$DB->tableExists('glpi_profilerights')) {
            return;
        }

        foreach (self::getAllRights() as $right) {
            $field    = (string) $right['field'];
            $selected = isset($submittedRights[$field]) && is_array($submittedRights[$field])
                ? array_map('intval', $submittedRights[$field])
                : [];

            $mask = 0;
            foreach ($right['rights'] as $value) {
                if (in_array((int) $value, $selected, true)) {
                    $mask |= (int) $value;
                }
            }

            $existing = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_profilerights',
                'WHERE'  => ['profiles_id' => $profileId, 'name' => $field],
                'LIMIT'  => 1,
            ])->current();

            if ($existing) {
                $DB->update('glpi_profilerights', ['rights' => $mask], ['id' => (int) $existing['id']]);
            } else {
                $DB->insert('glpi_profilerights', [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                    'rights'      => $mask,
                ]);
            }
        }
    }

    // ── GLPI Profile tab ──────────────────────────────────────────────────

    public function getTabNameForItem(\CommonGLPI $item, $withtemplate = 0): string {
        if ($item instanceof \Profile) {
            return 'Tanium';
        }
        return '';
    }

    public static function displayTabContentForItem(\CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool {
        global $CFG_GLPI;

        if (!$item instanceof \Profile) {
            return true;
        }

        $profileId     = (int) $item->getID();
        $currentRights = self::getCurrentRightsForProfile($profileId);
        $canEdit       = Session::haveRight('profile', UPDATE);
        $formUrl       = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/tanium/front/profile.rights.php';

        $icons = [
            self::RIGHT_READ   => 'ti ti-eye',
            self::RIGHT_SYNC   => 'ti ti-refresh',
            self::RIGHT_CONFIG => 'ti ti-settings',
        ];

        echo "<div class='tanium-rights'>";

        // Header
        echo "<div class='tanium-rights-header'>";
        echo "<span class='tanium-rights-icon'><span class='ti ti-shield-lock'></span></span>";
        echo "<div><h3 class='tanium-rights-title'>" . __('Tanium — Permissions', 'tanium') . "</h3>";
        echo "<p class='tanium-rights-sub'>" . __('Define what this profile can see and manage in the Tanium plugin.', 'tanium') . "</p></div>";
        echo "</div>";

        echo "<form method='post' action='" . htmlspecialchars($formUrl) . "'>";
        Html::hidden('profiles_id', ['value' => $profileId]);

        echo "<div class='tanium-rights-list'>";
        foreach (self::getAllRights() as $right) {
            $field = (string) $right['field'];
            $mask  = (int) ($currentRights[$field] ?? 0);
            $icon  = $icons[$field] ?? 'ti ti-shield';

            echo "<div class='tanium-right-row'>";
            echo "<div class='tanium-right-info'>";
            echo "<span class='{$icon} tanium-right-ico'></span>";
            echo "<div>";
            echo "<strong class='tanium-right-label'>" . htmlspecialchars($right['label']) . "</strong>";
            echo "<code class='tanium-right-field'>" . htmlspecialchars($field) . "</code>";
            echo "</div>";
            echo "</div>";

            echo "<div class='tanium-right-perms'>";
            $permLabels = [READ => __('Read', 'tanium'), UPDATE => __('Update', 'tanium')];
            foreach ([READ, UPDATE] as $permission) {
                if (!in_array($permission, $right['rights'], true)) {
                    echo "<span class='tanium-right-na'>—</span>";
                    continue;
                }
                $checked  = ($mask & $permission) === $permission;
                $disabled = $canEdit ? '' : ' disabled';
                echo "<label class='tanium-right-toggle" . ($canEdit ? '' : ' tanium-right-disabled') . "'>";
                echo "<input type='checkbox' name='plugin_tanium_rights[" . htmlspecialchars($field) . "][]' value='{$permission}'"
                    . ($checked  ? ' checked'  : '')
                    . $disabled . ">";
                echo "<span class='tanium-toggle-track'></span>";
                echo "<span class='tanium-right-perm-label'>" . htmlspecialchars($permLabels[$permission]) . "</span>";
                echo "</label>";
            }
            echo "</div>";
            echo "</div>";
        }
        echo "</div>";

        if ($canEdit) {
            echo "<div class='tanium-rights-footer'>";
            echo "<button type='submit' name='save_tanium_rights' value='1' class='tanium-btn tanium-btn-primary'>";
            echo "<span class='ti ti-device-floppy'></span> " . __('Save permissions', 'tanium');
            echo "</button>";
            echo "</div>";
        }

        Html::closeForm();
        echo "</div>";

        return true;
    }

    private static function getDefaultRightsForProfile(string $profileName, array $right): int {
        if (
            strcasecmp($profileName, 'Super-Admin') !== 0
            && strcasecmp($profileName, 'Admin') !== 0
        ) {
            return 0;
        }

        $mask = 0;
        foreach ((array) $right['rights'] as $permission) {
            $mask |= (int) $permission;
        }
        return $mask;
    }
}
