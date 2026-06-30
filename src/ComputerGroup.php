<?php

namespace GlpiPlugin\Tanium;

use CommonGLPI;

class ComputerGroup extends CommonGLPI {

    public static $table = 'glpi_plugin_tanium_computer_groups';

    public static function ensureTable(): void {
        global $DB;

        if ($DB->tableExists(self::$table)) {
            // Fix signed → unsigned if table was created before this correction
            $col = $DB->doQuery("SHOW COLUMNS FROM `" . self::$table . "` LIKE 'tanium_group_id'");
            if ($col && ($def = $col->fetch_assoc())) {
                if (stripos((string)($def['Type'] ?? ''), 'unsigned') === false) {
                    $DB->doQuery("ALTER TABLE `" . self::$table . "` MODIFY `tanium_group_id` int unsigned NOT NULL DEFAULT 0");
                    $DB->doQuery("ALTER TABLE `" . self::$table . "` MODIFY `id` int unsigned NOT NULL AUTO_INCREMENT");
                }
            }
            return;
        }

        $DB->doQuery(
            "CREATE TABLE IF NOT EXISTS `" . self::$table . "` (
                `id`                int unsigned NOT NULL AUTO_INCREMENT,
                `tanium_group_id`   int unsigned NOT NULL DEFAULT 0,
                `tanium_group_name` varchar(255) NOT NULL DEFAULT '',
                `label`             varchar(255) NOT NULL DEFAULT '',
                `date_mod`          timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `tanium_group_id` (`tanium_group_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    /**
     * Fetch groups from Tanium API and upsert into local table.
     * Preserves any custom `label` the admin already set.
     * Returns number of groups synced.
     */
    public static function syncFromApi(Api $api): int {
        global $DB;
        self::ensureTable();

        $apiGroups = $api->getComputerGroups();
        if (empty($apiGroups)) {
            return 0;
        }

        $count = 0;
        foreach ($apiGroups as $g) {
            $gid   = (int)($g['id'] ?? 0);
            $gname = trim((string)($g['name'] ?? ''));
            if ($gid <= 0 || $gname === '') continue;

            $exists = $DB->doQuery(
                "SELECT id, label FROM `glpi_plugin_tanium_computer_groups` WHERE tanium_group_id = {$gid} LIMIT 1"
            );

            if ($exists && ($row = $exists->fetch_assoc())) {
                $DB->doQuery(
                    "UPDATE `glpi_plugin_tanium_computer_groups`
                     SET tanium_group_name = '" . $DB->escape($gname) . "', date_mod = NOW()
                     WHERE tanium_group_id = {$gid}"
                );
            } else {
                $DB->doQuery(
                    "INSERT INTO `glpi_plugin_tanium_computer_groups`
                     (tanium_group_id, tanium_group_name, label, date_mod)
                     VALUES ({$gid}, '" . $DB->escape($gname) . "', '', NOW())"
                );
            }
            $count++;
        }

        return $count;
    }

    /** Returns all local groups, sorted by label (fallback to Tanium name). */
    public static function getAll(): array {
        global $DB;

        self::ensureTable();

        $rows = [];
        $res  = $DB->doQuery(
            "SELECT * FROM `glpi_plugin_tanium_computer_groups`
             ORDER BY IF(label != '', label, tanium_group_name) ASC"
        );
        if (!$res) return [];
        while ($row = $res->fetch_assoc()) {
            $rows[] = $row;
        }
        return $rows;
    }

    /** Save a custom label for a group. */
    public static function saveLabel(int $taniumGroupId, string $label): void {
        global $DB;
        self::ensureTable();
        $DB->doQuery(
            "UPDATE `glpi_plugin_tanium_computer_groups`
             SET label = '" . $DB->escape(trim($label)) . "', date_mod = NOW()
             WHERE tanium_group_id = {$taniumGroupId}"
        );
    }

    /** Returns display name: custom label if set, otherwise Tanium group name. */
    public static function displayName(array $group): string {
        $label = trim((string)($group['label'] ?? ''));
        return $label !== '' ? $label : (string)($group['tanium_group_name'] ?? '#' . $group['tanium_group_id']);
    }

    /**
     * Derives the "Content Set" (organizational prefix) from a Tanium group name.
     *
     * Tanium groups follow the convention "<Org> - <Role> [Env]" — e.g.
     * "Sebrae - MS - Linux Server [HML]" → Content Set "Sebrae - MS".
     * The rule is generic: everything before the final " - " segment. Groups
     * without that separator are their own Content Set.
     */
    public static function contentSet(array $group): string {
        $name = trim((string)($group['tanium_group_name'] ?? ''));
        $pos  = mb_strrpos($name, ' - ');
        return $pos !== false ? trim(mb_substr($name, 0, $pos)) : $name;
    }
}
