<?php

include('../../../inc/includes.php');
if (!\GlpiPlugin\Tanium\Profile::hasReadRight()) { Html::displayRightError(); }

$webDir = \Plugin::getWebDir('tanium');
$groups = \GlpiPlugin\Tanium\ComputerGroup::getAll();

Html::header(__('Tanium — Grupos de Computadores', 'tanium'), $_SERVER['PHP_SELF'], 'tools', 'plugins');
?>
<style>
.container-xl,.container-lg{max-width:100%!important}
.tg-on td:first-child{box-shadow:inset 3px 0 0 #22c55e}
.tg-badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;padding:3px 10px;border-radius:99px;white-space:nowrap}
.tg-badge.on{background:rgba(34,197,94,.14);color:#16a34a}
.tg-badge.off{background:rgba(148,163,184,.16);color:#94a3b8}
.tg-dot{width:7px;height:7px;border-radius:50%;background:currentColor;flex-shrink:0}
.tg-flash{animation:tgflash 1.1s ease-out}
@keyframes tgflash{0%{background:rgba(34,197,94,.28)}100%{background:transparent}}
.tanium-btn.tg-saved{background:#22c55e!important;border-color:#22c55e!important;color:#fff!important}
.tanium-btn.tg-saved:hover{background:#16a34a!important;border-color:#16a34a!important;color:#fff!important}
</style>
<div class="tanium-page-wrap">

<div class="tanium-card" style="margin-bottom:20px">
    <div class="tanium-card-header">
        <span class="ti ti-users-group"></span>
        <span style="margin-left:8px;font-weight:700">Grupos de Computadores do Tanium</span>
        <div style="margin-left:auto;display:flex;gap:10px;align-items:center">
            <span id="sync-status" class="tanium-small tanium-muted"></span>
            <button class="tanium-btn tanium-btn-primary tanium-btn-sm" onclick="syncGroups(this)">
                <span class="ti ti-refresh"></span> Sincronizar com Tanium
            </button>
            <a href="<?= $webDir ?>/front/config.form.php" class="tanium-btn tanium-btn-secondary tanium-btn-sm">
                <span class="ti ti-arrow-left"></span> Configurações
            </a>
        </div>
    </div>

    <div class="tanium-card-body" style="padding:16px 24px">
        <p class="tanium-small tanium-muted" style="margin:0 0 4px">
            Clique em <strong>Sincronizar</strong> para importar os grupos do Tanium.<br>
            O campo <strong>Rótulo</strong> é um nome personalizado exibido no seletor de deploy — útil para identificar o ambiente
            (ex.: "Produção Windows", "Estações TI"). Se vazio, usa o nome original do Tanium.
        </p>
    </div>

    <?php if (empty($groups)): ?>
    <div class="tanium-card-body">
        <p class="tanium-empty" style="margin:0">
            <span class="ti ti-cloud-off" style="font-size:28px;display:block;margin-bottom:8px"></span>
            Nenhum grupo importado ainda. Clique em <strong>Sincronizar com Tanium</strong> para carregar os grupos.
        </p>
    </div>
    <?php else: ?>
    <div class="tanium-card-body tanium-p0">
    <table class="tanium-table">
        <thead>
            <tr>
                <th style="width:90px">Status</th>
                <th style="width:80px">ID Tanium</th>
                <th>Nome no Tanium</th>
                <th>Rótulo personalizado</th>
                <th style="width:220px"><?= __('GLPI Entity', 'tanium') ?></th>
                <th style="width:100px"></th>
            </tr>
        </thead>
        <tbody>
        <?php foreach ($groups as $g):
            $gid    = (int)$g['tanium_group_id'];
            $gname  = htmlspecialchars($g['tanium_group_name']);
            $label  = htmlspecialchars($g['label'] ?? '');
            $hasLbl = trim($g['label'] ?? '') !== '';
        ?>
        <tr id="row-<?= $gid ?>" class="<?= $hasLbl ? 'tg-on' : '' ?>">
            <td>
                <span id="status-<?= $gid ?>" class="tg-badge <?= $hasLbl ? 'on' : 'off' ?>">
                    <span class="tg-dot"></span><?= $hasLbl ? 'Ativo' : 'Padrão' ?>
                </span>
            </td>
            <td class="tanium-mono tanium-small" style="color:var(--tanium-muted)"><?= $gid ?></td>
            <td class="tanium-small"><?= $gname ?></td>
            <td>
                <input
                    type="text"
                    class="tanium-input tanium-input-sm"
                    style="width:100%;max-width:320px"
                    placeholder="<?= $gname ?>"
                    value="<?= $label ?>"
                    data-gid="<?= $gid ?>"
                    oninput="markChosen(<?= $gid ?>, this)"
                    onkeydown="if(event.key==='Enter'){saveLabel(<?= $gid ?>,this)}"
                />
            </td>
            <td>
                <?php
                $entSel = array_key_exists('entities_id', $g) && $g['entities_id'] !== null ? (int)$g['entities_id'] : null;
                echo str_replace(
                    "name='group_entity'",
                    "name='group_entity' data-gid='{$gid}' onchange='saveEntity({$gid}, this)'",
                    \GlpiPlugin\Tanium\Config::entitySelect('group_entity', $entSel, true)
                );
                ?>
            </td>
            <td>
                <button
                    class="tanium-btn tanium-btn-xs <?= $hasLbl ? 'tg-saved' : 'tanium-btn-primary' ?>"
                    onclick="saveLabel(<?= $gid ?>, this.closest('tr').querySelector('input'))">
                    <span class="ti ti-check"></span> Salvar
                </button>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

</div><!-- .tanium-page-wrap -->

<script>
const _webDir = <?= json_encode($webDir) ?>;
const _csrf   = <?= json_encode(Session::getNewCSRFToken()) ?>;

async function syncGroups(btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="ti ti-loader-2"></span> Sincronizando…';
    const st = document.getElementById('sync-status');
    st.textContent = '';

    try {
        const r = await fetch(_webDir + '/ajax/sync_groups.php', {
            method: 'POST',
            headers: {'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf}
        });
        const d = await r.json();
        if (d.success) {
            st.style.color = '#68d391';
            st.textContent = '✓ ' + d.message;
            setTimeout(() => location.reload(), 1200);
        } else {
            st.style.color = '#fc8181';
            st.textContent = '✗ ' + (d.error || 'Erro desconhecido');
        }
    } catch(e) {
        st.style.color = '#fc8181';
        st.textContent = '✗ Erro de rede: ' + e.message;
    }
    btn.disabled = false;
    btn.innerHTML = '<span class="ti ti-refresh"></span> Sincronizar com Tanium';
}

// Feedback imediato: ao escolher/editar o rótulo, o botão Salvar fica verde.
async function saveEntity(gid, select) {
    const entityId = parseInt(select.value, 10);
    select.disabled = true;
    try {
        const r = await fetch(_webDir + '/ajax/save_group_label.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
            body: JSON.stringify({tanium_group_id: gid, entities_id: entityId})
        });
        const d = await r.json();
        if (!d.success) { alert('Erro ao salvar entidade: ' + (d.error || 'Desconhecido')); }
        const row = document.getElementById('row-' + gid);
        row.classList.remove('tg-flash'); void row.offsetWidth; row.classList.add('tg-flash');
    } catch(e) {
        alert('Erro de rede: ' + e.message);
    } finally {
        select.disabled = false;
    }
}

function markChosen(gid, input) {
    const row = document.getElementById('row-' + gid);
    const btn = row.querySelector('button');
    const has = input.value.trim() !== '';
    btn.classList.toggle('tg-saved', has);
    btn.classList.toggle('tanium-btn-primary', !has);
}

async function saveLabel(gid, input) {
    const label  = input.value.trim();
    const row    = document.getElementById('row-' + gid);
    const status = document.getElementById('status-' + gid);
    const btn    = row.querySelector('button');
    const btnHtml = btn.innerHTML;

    btn.disabled = true;
    btn.innerHTML = '<span class="ti ti-loader-2"></span>';

    try {
        const r = await fetch(_webDir + '/ajax/save_group_label.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': _csrf},
            body: JSON.stringify({tanium_group_id: gid, label})
        });
        const d = await r.json();
        if (d.success) {
            // Persistent "active" indicator based on whether a label is set
            const hasLabel = label !== '';
            row.classList.toggle('tg-on', hasLabel);
            status.className = 'tg-badge ' + (hasLabel ? 'on' : 'off');
            status.innerHTML = '<span class="tg-dot"></span>' + (hasLabel ? 'Ativo' : 'Padrão');

            // Botão fica verde quando o grupo está escolhido (rótulo definido)
            btn.classList.toggle('tg-saved', hasLabel);
            btn.classList.toggle('tanium-btn-primary', !hasLabel);

            // Quick flash + button confirmation
            row.classList.remove('tg-flash'); void row.offsetWidth; row.classList.add('tg-flash');
            btn.innerHTML = '<span class="ti ti-check"></span> Salvo';
            setTimeout(() => { btn.innerHTML = btnHtml; btn.disabled = false; }, 1100);
        } else {
            alert('Erro ao salvar: ' + (d.error || 'Desconhecido'));
            btn.innerHTML = btnHtml; btn.disabled = false;
        }
    } catch(e) {
        alert('Erro de rede: ' + e.message);
        btn.innerHTML = btnHtml; btn.disabled = false;
    }
}
</script>

<?php Html::footer();
