<?php
/**
 * v2.23.0 verification harness — ticket defaults (category, assignee, source,
 * type) applied to every ticket the plugin opens.
 * Run inside the GLPI container:
 *   docker exec glpi-glpi-1 php /var/www/glpi/plugins/tanium/tools/verify_v223.php
 *
 * Creates throwaway dropdowns (category, group, request source), points the
 * plugin settings at them, exercises Config::applyTicketDefaults() and one real
 * Ticket::add(), then restores the previous settings and deletes everything it
 * created.
 */

use Glpi\Kernel\Kernel;
use GlpiPlugin\Tanium\Config as TaniumConfig;

require '/var/www/glpi/vendor/autoload.php';
$kernel = new Kernel();
$kernel->boot();

Plugin::load('tanium');

// Cron-like session: no logged-in user, root entity active.
$_SESSION['glpiactive_entity']          = 0;
$_SESSION['glpiactiveentities']         = [0];
$_SESSION['glpiactiveentities_string']  = "'0'";
$_SESSION['glpiactiveprofile']['plugin_tanium_read'] = READ;

global $DB;

$pass = 0;
$fail = 0;
function check(string $name, bool $ok, string $extra = ''): void {
    global $pass, $fail;
    echo ($ok ? 'PASS' : 'FAIL') . " — {$name}" . ($extra !== '' ? " ({$extra})" : '') . "\n";
    $ok ? $pass++ : $fail++;
}

// ── Snapshot the live settings so the run is non-destructive ──────────────
$before = TaniumConfig::getConfig();
$keys   = ['ticket_category_id', 'ticket_tech_id', 'ticket_group_id', 'ticket_requesttype_id', 'ticket_type'];
foreach (array_keys(TaniumConfig::TICKET_KINDS) as $kind) {
    $keys[] = 'ticket_category_' . $kind . '_id';
}
$snapshot = [];
foreach ($keys as $k) {
    $snapshot[$k] = (int)($before[$k] ?? 0);
}

// ── Throwaway dropdown values ─────────────────────────────────────────────
$catDefault = new ITILCategory();
$catId      = (int)$catDefault->add(['name' => 'TANIUM-VERIFY-DEFAULT', 'entities_id' => 0, 'is_recursive' => 1]);

$catPatch   = new ITILCategory();
$catPatchId = (int)$catPatch->add(['name' => 'TANIUM-VERIFY-PATCH', 'entities_id' => 0, 'is_recursive' => 1]);

$group   = new Group();
$groupId = (int)$group->add(['name' => 'TANIUM-VERIFY-GROUP', 'entities_id' => 0, 'is_recursive' => 1, 'is_assign' => 1]);

$source   = new RequestType();
$sourceId = (int)$source->add(['name' => 'TANIUM-VERIFY-SOURCE']);

$user   = $DB->request(['SELECT' => ['id'], 'FROM' => 'glpi_users', 'WHERE' => ['is_deleted' => 0, 'is_active' => 1], 'ORDER' => 'id ASC', 'LIMIT' => 1])->current();
$techId = (int)($user['id'] ?? 0);

check('test fixtures created', $catId > 0 && $catPatchId > 0 && $groupId > 0 && $sourceId > 0 && $techId > 0,
    "cat={$catId} patch={$catPatchId} group={$groupId} source={$sourceId} tech={$techId}");

function restore(array $snapshot): void {
    TaniumConfig::saveConfig($snapshot);
}

try {
    TaniumConfig::saveConfig([
        'ticket_category_id'       => $catId,
        'ticket_category_patch_id' => $catPatchId,
        'ticket_tech_id'           => $techId,
        'ticket_group_id'          => $groupId,
        'ticket_requesttype_id'    => $sourceId,
        'ticket_type'              => Ticket::DEMAND_TYPE,
    ]);
    $config = TaniumConfig::getConfig();

    // ── 1. Global default applies to a kind with no override ──────────────
    $out = TaniumConfig::applyTicketDefaults(['name' => 'x'], 'cve', $config);
    check('kind without override falls back to the default category',
        (int)($out['itilcategories_id'] ?? 0) === $catId, 'got=' . ($out['itilcategories_id'] ?? 'unset'));

    // ── 2. Per-kind override wins over the default ────────────────────────
    $out = TaniumConfig::applyTicketDefaults(['name' => 'x'], 'patch', $config);
    check('per-kind override wins over the default category',
        (int)($out['itilcategories_id'] ?? 0) === $catPatchId, 'got=' . ($out['itilcategories_id'] ?? 'unset'));

    // ── 3. A category chosen by a human is never overwritten ──────────────
    $out = TaniumConfig::applyTicketDefaults(['name' => 'x', 'itilcategories_id' => 999999], 'patch', $config);
    check('caller category is preserved', (int)$out['itilcategories_id'] === 999999);

    // ── 4. Assignee, source and type ──────────────────────────────────────
    $out = TaniumConfig::applyTicketDefaults(['name' => 'x', 'type' => Ticket::INCIDENT_TYPE], 'threat', $config);
    check('assigned technician set',   (int)($out['_users_id_assign'] ?? 0) === $techId);
    check('assigned group set',        (int)($out['_groups_id_assign'] ?? 0) === $groupId);
    check('request source set',        (int)($out['requesttypes_id'] ?? 0) === $sourceId);
    check('configured type overrides the hardcoded one',
        (int)($out['type'] ?? 0) === Ticket::DEMAND_TYPE, 'got=' . ($out['type'] ?? 'unset'));

    // ── 5. Dangling ids are dropped, not written ──────────────────────────
    $ghost = $config;
    $ghost['ticket_category_id']       = 987654;
    $ghost['ticket_category_patch_id'] = 0;
    $ghost['ticket_group_id']          = 987654;
    $out = TaniumConfig::applyTicketDefaults(['name' => 'x'], 'patch', $ghost);
    check('deleted category id is ignored', !isset($out['itilcategories_id']));
    check('deleted group id is ignored',    !isset($out['_groups_id_assign']));

    // ── 6. "Keep each ticket default" leaves the type alone ───────────────
    $keep = $config;
    $keep['ticket_type'] = 0;
    $out  = TaniumConfig::applyTicketDefaults(['name' => 'x', 'type' => Ticket::INCIDENT_TYPE], 'cve', $keep);
    check('type 0 keeps the ticket own type', (int)$out['type'] === Ticket::INCIDENT_TYPE);

    // ── 7. The settings widgets render (wrong class or option = fatal page)
    // Only the new dropdowns: rendering the whole form would call the Tanium
    // API for the sensor/package datalists.
    $ref    = new ReflectionMethod(TaniumConfig::class, 'categoryDropdown');
    $ref->setAccessible(true);
    $catHtml = (string)$ref->invoke(new TaniumConfig(), 'ticket_category_id', $catId, $config);
    check('category dropdown renders', str_contains($catHtml, 'ticket_category_id'), strlen($catHtml) . ' bytes');

    ob_start();
    Group::dropdown(['name' => 'ticket_group_id', 'value' => $groupId, 'condition' => ['is_assign' => 1], 'entity' => [0], 'display_emptychoice' => true, 'width' => '100%']);
    RequestType::dropdown(['name' => 'ticket_requesttype_id', 'value' => $sourceId, 'display_emptychoice' => true, 'width' => '100%']);
    User::dropdown(['name' => 'ticket_tech_id', 'value' => $techId, 'right' => 'own_ticket', 'entity' => [0], 'display_emptychoice' => true, 'width' => '100%']);
    $widgets = (string)ob_get_clean();
    check('group/source/technician dropdowns render',
        str_contains($widgets, 'ticket_group_id')
        && str_contains($widgets, 'ticket_requesttype_id')
        && str_contains($widgets, 'ticket_tech_id'));

    // ── 8. End to end: a real ticket comes out pre-filled ─────────────────
    $ticket   = new Ticket();
    $ticketId = (int)$ticket->add(TaniumConfig::applyTicketDefaults([
        'name'        => '[Tanium] VERIFY v2.23 — apagar',
        'content'     => 'Chamado de verificacao criado por tools/verify_v223.php',
        'entities_id' => 0,
        'type'        => Ticket::INCIDENT_TYPE,
        'urgency'     => 2,
        'impact'      => 2,
        'priority'    => 2,
    ], 'patch', $config));

    check('ticket created', $ticketId > 0, "id={$ticketId}");

    if ($ticketId > 0) {
        $row = $DB->request(['FROM' => 'glpi_tickets', 'WHERE' => ['id' => $ticketId]])->current();
        check('ticket stored with the override category',
            (int)$row['itilcategories_id'] === $catPatchId, 'got=' . $row['itilcategories_id']);
        check('ticket stored with the request source',
            (int)$row['requesttypes_id'] === $sourceId, 'got=' . $row['requesttypes_id']);
        check('ticket stored with the configured type',
            (int)$row['type'] === Ticket::DEMAND_TYPE, 'got=' . $row['type']);

        $assignUser = $DB->request([
            'FROM'  => 'glpi_tickets_users',
            'WHERE' => ['tickets_id' => $ticketId, 'type' => CommonITILActor::ASSIGN, 'users_id' => $techId],
        ])->current();
        check('technician recorded as assignee', $assignUser !== null);

        $assignGroup = $DB->request([
            'FROM'  => 'glpi_groups_tickets',
            'WHERE' => ['tickets_id' => $ticketId, 'type' => CommonITILActor::ASSIGN, 'groups_id' => $groupId],
        ])->current();
        check('group recorded as assignee', $assignGroup !== null);

        $ticket->delete(['id' => $ticketId], true);
    }
} finally {
    restore($snapshot);

    if (!empty($ticketId)) {
        $DB->doQuery("DELETE FROM glpi_tickets WHERE id = " . (int)$ticketId);
    }
    foreach ([[new ITILCategory(), $catId], [new ITILCategory(), $catPatchId], [new Group(), $groupId], [new RequestType(), $sourceId]] as [$item, $id]) {
        if ($id > 0) {
            $item->delete(['id' => $id], true);
        }
    }
}

$after = TaniumConfig::getConfig();
$restored = true;
foreach ($snapshot as $k => $v) {
    if ((int)($after[$k] ?? 0) !== $v) {
        $restored = false;
    }
}
check('previous settings restored', $restored);

echo "\n{$pass} passed, {$fail} failed\n";
exit($fail > 0 ? 1 : 0);
