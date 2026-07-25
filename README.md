<div align="center">
  <img src="public/img/tanium-logo.svg" alt="Tanium" width="200" />
  <br/><br/>
  <img src="https://img.shields.io/badge/GLPI-11.x-0078D7?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0xIDE1aC0ydi02aDJ2NnptMC04aC0yVjdoMnYyeiIvPjwvc3ZnPg==" />
  <img src="https://img.shields.io/badge/PHP-8.2%2B-777BB4?style=flat-square&logo=php&logoColor=white" />
  <img src="https://img.shields.io/badge/License-GPL--2.0-green?style=flat-square" />
  <img src="https://img.shields.io/badge/Tanium-API%20REST-E8212A?style=flat-square" />
  <br/><br/>
  <strong>Plugin de integração Tanium ↔ GLPI 11</strong>
  <br/>
  <em>See Everything. Do Anything.</em>
</div>

---

> 🇧🇷 [Português](#-português) | 🇺🇸 [English](#-english)

---

## 🇧🇷 Português

### 📋 Sobre

Plugin que conecta a plataforma **Tanium** ao **GLPI 11**, trazendo visibilidade total dos endpoints para dentro do seu CMDB: vulnerabilidades CVE com score CVSS, patches ausentes, histórico de implantações e um dashboard de risco em tempo real.

> **Tanium** é a plataforma de gerenciamento e segurança de endpoints em tempo real usada por grandes corporações para ter visibilidade e controle de toda a infraestrutura de TI — *See Everything. Do Anything.*

### ✨ Funcionalidades

| Recurso | Descrição |
|---|---|
| 🖥️ **Endpoints** | Sincroniza computadores do Tanium como ativos GLPI |
| 🔍 **Vulnerabilidades CVE** | Importa CVEs com severidade, score CVSS e status de remediação |
| 🩹 **Patch Remediation** | Rastreia patches ausentes e histórico de implantação |
| 📊 **Dashboard** | Painel com KPIs de risco, compliance e cobertura — todos os cards com drill-down para a lista filtrada |
| 🗓️ **Relatório Semanal** | Envio automático de relatório de segurança por e-mail, com seção de remediação da semana |
| 📆 **Relatório Mensal** | Relatório mensal com remediação de 30 dias, MTTR e evolução da postura vs mês anterior |
| ✅ **Tendência de Remediação** | Página dedicada: CVEs remediados e patches instalados por endpoint, gráfico semanal, MTTR e exportação CSV |
| 📬 **Digest de Correções** | E-mail automático (com PDF) ao fim de cada sync que registrar CVEs remediados / patches instalados |
| 🔁 **Auto-close de findings** | CVEs/patches que somem do feed do Tanium são marcados como remediados (alimenta MTTR e relatórios) |
| 🎫 **Chamado de remediação** | Chamado por endpoint que concluiu correções, já solucionado, com o histórico completo de transições (registro de auditoria) |
| ♻️ **Aviso de reboot pendente** | Endpoint aguardando reinício é sinalizado na lista de patches — patch instalado continua reportado como ausente até o reboot |
| ♻️ **Auto-resolução de chamados** | Chamados automáticos (CVEs críticos, agentes silenciosos, Threat Response) são solucionados sozinhos quando a condição desaparece |
| 📺 **Modo TV/Kiosk** | Painel de segurança em tela cheia com auto-refresh e acesso por link com token (sem login) para TVs de NOC/SOC |
| ⚙️ **Sincronização** | Agendamento via Cron com suporte a sync incremental |
| 🛟 **Sync resiliente** | O cursor incremental só avança quando o ciclo termina sem erro — endpoints que falharam voltam na execução seguinte em vez de serem pulados |
| 🗑️ **Endpoints retirados** | Máquinas que somem da frota do Tanium são marcadas com data de retirada e, opcionalmente, expurgadas após carência configurável |
| 💻 **Aba no Computador** | Dados Tanium diretamente na ficha do ativo no GLPI |
| 🎯 **Widget Central** | Resumo de risco no painel inicial do GLPI |
| 🔒 **Perfis** | Controle de acesso granular por perfil GLPI |
| 🔥 **EPSS / CISA KEV** | Enriquecimento diário de CVEs com probabilidade de exploração e catálogo KEV; filtros "somente KEV" / "somente ransomware" com priorização por EPSS |
| ⏱️ **SLA + MTTR** | Prazos de remediação por severidade, compliance, MTTR 90d e webhook diário de violação |
| 🛰️ **Saúde do agente** | Detecção de agentes silenciosos com chamado consolidado automático |
| 📐 **Comply / Threat Response** | Benchmarks CIS/DISA por endpoint e alertas de ameaça → chamados, com página dedicada de alertas |
| 🩺 **Boletim de Saúde** | Nota 0–10 e veredito por endpoint, com exportação em PDF |
| 🔐 **Hardening** | Token da API armazenado cifrado (GLPIKey) e monitoramento de expiração |
| 🛡️ **Ações remotas** | Quarentena / reinício do client condicionados à aprovação do chamado |
| 🧩 **Dashboard cards nativos** | 7 cards no dashboard nativo do GLPI (grupo "Tanium") |
| 🔗 **Correlação cross-plugin** | Badges quando o CVE também é visto pelo Nessus/SentinelOne |
| 📄 **Exportações** | PDF do comparativo de endpoints e busca nativa GLPI com CSV |
| 🌐 **i18n completa** | 670 strings traduzidas para pt_BR (.mo compilado, sem dependência de `msgfmt`) |

### 🚀 Requisitos

- **GLPI** ≥ 11.0.0
- **PHP** ≥ 8.2 com extensões `curl` e `json`
- **Tanium** com API REST habilitada e token de acesso

### 📦 Instalação

1. Copie a pasta `tanium` para `glpi/plugins/`
2. Acesse **Configuração → Plugins** no GLPI
3. Clique em **Instalar** e depois em **Ativar**
4. Vá em **Plug-ins → Tanium → Configuração** e informe a URL da API e o token

```
glpi/plugins/
└── tanium/
    ├── setup.php       ← registro do plugin
    ├── hook.php        ← install / uninstall
    ├── src/            ← lógica principal (PSR-4)
    ├── front/          ← páginas
    ├── ajax/           ← endpoints AJAX
    └── public/         ← assets (CSS, imagens)
```

### ⚙️ Configuração

| Campo | Descrição |
|---|---|
| 🌐 **API URL** | Endereço da API REST do Tanium (ex: `https://tanium.empresa.com.br`) |
| 🔑 **API Token** | Token de autenticação gerado no console Tanium |
| 🔄 **Frequência** | Intervalo de sincronização (horas) |
| 📥 **Limite** | Máximo de endpoints por execução do cron |
| 📧 **E-mail** | Destinatário do relatório semanal de segurança |
| 🔁 **Auto-close de findings** | Marca como remediado o que sumiu do feed do Tanium (ligado por padrão) |
| 🎫 **Chamado de remediação** | Abre um chamado por endpoint que concluiu correções, já solucionado, com o histórico completo |
| ♻️ **Sensor de reboot pendente** | Nome do sensor do Tanium que indica reinício pendente (coletado automaticamente; vazio desativa o aviso) |
| 🗑️ **Remover endpoints retirados** | Dias de carência antes de apagar os dados Tanium de uma máquina que sumiu da frota (0 = só marcar) |

### 🧪 Testes

```
php tests/run.php      # lógica pura (43 casos)
php tests/mirror.php   # garante que as cópias dos testes conferem com src/
php tools/lint.php     # php -l em todo o plugin
php tools/i18n_audit.php pt_BR
```

As classes do plugin estendem base do GLPI e usam `$DB`, então não são carregáveis fora do container. Cada caso de teste **re-declara** a função testada como função livre, e o `mirror.php` compara essa cópia com o corpo do método real em `src/` (ignorando espaços, comentários e `self::`) — sem ele, a suíte ficaria verde testando código morto.

### ✅ Ciclo de vida de uma correção

O que acontece quando alguém atualiza a máquina (`apt upgrade`, Windows Update, deploy pelo Tanium) e reinicia:

1. **O plugin não olha o servidor** — ele só espelha o que o Tanium reporta. Nada muda no GLPI até o Tanium reavaliar o endpoint.
2. **Duas fontes, velocidades diferentes:** patches vêm do sensor *Applicable Patches* (ao vivo, reflete rápido); CVEs vêm do módulo *Comply*, que só muda quando o **scan agendado dele** roda. É normal o patch fechar antes do CVE.
3. **No Windows, o reboot é o gatilho:** até reiniciar, o KB instalado continua sendo reportado como aplicável — a lista mostra `missing` mesmo já tendo sido aplicado. Se o tenant coletar um sensor de reboot (ver *Sensores customizados*), a tela avisa em vez de parecer falha.
4. **No próximo `taniumsync`**, o item ausente do payload muda de status — **nenhuma linha é apagada**:
   - CVE → `remediated`, com a transição gravada em `cve_history`
   - Patch → `installed`, com a transição gravada em `patch_history`
5. **Em cascata:** risk score recalculado, chamado de CVE crítico auto-solucionado, digest de correções por e-mail (com PDF) e — se habilitado — o **chamado de remediação** por endpoint.

**Por que às vezes não fecha:**

| Situação | Comportamento |
|---|---|
| Sensor deu erro/timeout, ou a máquina estava desligada durante o sync | Nada é fechado (proteção contra fechar tudo em massa por soluço) |
| `Auto-close de findings` desligado | Só fecha se o próprio Tanium reportar o status `remediated` |
| Finding abaixo do `Severidade mínima` configurada | Nunca entra no payload, então a ausência não prova nada — fica aberto até o filtro baixar |
| Windows aguardando reboot | Continua `missing` até reiniciar |

> A tela de patches abre filtrada em `missing` — o que foi corrigido está no filtro **Installed / Remediated**, não foi apagado. As tabelas de estado atual nunca são expurgadas; só as de histórico, pela retenção configurada.

### 🕐 Tarefas Agendadas (Cron)

| Tarefa | Intervalo | Descrição |
|---|---|---|
| `taniumsync` | 1 hora | Sincroniza endpoints e vulnerabilidades |
| `weeklyreport` | 7 dias | Envia relatório semanal por e-mail |
| `checkdeployments` | 5 minutos | Monitora e fecha tickets de patches concluídos |
| `epsskev` | 1 dia | Atualiza scores EPSS e flags do catálogo CISA KEV |
| `agenthealth` | 1 dia | Detecta agentes silenciosos e abre chamado consolidado |
| `complysync` | 1 dia | Importa resultados de benchmark (CIS/DISA) do Tanium Comply |
| `threatsync` | 15 minutos | Importa alertas do Threat Response e abre chamados |
| `slabreach` | 1 dia | Webhook diário enquanto houver violações de SLA |
| `purgehistory` | 1 dia | Expurga histórico além da retenção configurada |
| `purgeretired` | 1 dia | Remove endpoints que o Tanium parou de reportar, após a carência configurada (0 = desativado) |
| `apihealth` | 1 dia | Verifica saúde da API e avisa antes do token expirar |

### 🗂️ Estrutura do Código

```
src/
├── Api.php            — Comunicação com a API REST/GraphQL Tanium
├── Sync.php           — Sincronização de endpoints (incremental server-side)
├── Dashboard.php      — Dashboard e KPIs de risco
├── DashboardCards.php — Cards no dashboard nativo do GLPI
├── Vulnerability.php  — Gestão de CVEs e remediação
├── Enrichment.php     — EPSS / CISA KEV
├── Sla.php            — SLA de remediação e MTTR
├── AgentHealth.php    — Agentes silenciosos
├── Compliance.php     — Benchmarks Comply (CIS/DISA)
├── ThreatResponse.php — Alertas de ameaça → chamados
├── HealthReport.php   — Boletim de Saúde da frota (nota por endpoint)
├── RemoteAction.php   — Ações remotas condicionadas a aprovação
├── PatchDeploy.php    — Implantação e monitoramento de patches
├── CrossPlugin.php    — Correlação com Nessus/SentinelOne
├── PdfReport.php      — Exportações em PDF
├── Config.php         — Configurações do plugin
├── Profile.php        — Controle de acesso por perfil
├── Cron.php           — Tarefas agendadas
├── WeeklyReport.php   — Relatório semanal de segurança
├── ComputerTab.php    — Aba Tanium na ficha do computador
├── ComputerGroup.php  — Grupos de computadores Tanium
├── CentralWidget.php  — Widget no painel central do GLPI
└── Notification.php   — Notificações GLPI

tests/
├── run.php            — Executor da suíte (43 casos, sem dependências)
├── mirror.php         — Verifica se as cópias dos testes batem com src/
└── cases/             — Casos por função (os_type, kb_parts, reboot_pending, …)

tools/
├── lint.php           — php -l recursivo no plugin
├── i18n_audit.php     — Strings do código ausentes no .po
└── compile_po.php     — Compila .po → .mo em PHP puro (sem msgfmt)
```

---

## 🇺🇸 English

### 📋 About

Plugin that connects the **Tanium** platform to **GLPI 11**, bringing full endpoint visibility into your CMDB: CVE vulnerabilities with CVSS scores, missing patches, deployment history, and a real-time risk dashboard.

> **Tanium** is the real-time endpoint management and security platform used by large enterprises to gain visibility and control over their entire IT infrastructure — *See Everything. Do Anything.*

### ✨ Features

| Feature | Description |
|---|---|
| 🖥️ **Endpoints** | Syncs Tanium computers as GLPI assets |
| 🔍 **CVE Vulnerabilities** | Imports CVEs with severity, CVSS score and remediation status |
| 🩹 **Patch Remediation** | Tracks missing patches and deployment history |
| 📊 **Dashboard** | KPI panel with risk, compliance and coverage metrics — every card drills down to the filtered list |
| 🗓️ **Weekly Report** | Automated security report delivery by e-mail, with a weekly remediation section |
| 📆 **Monthly Report** | Monthly report with 30-day remediation, MTTR and posture evolution vs the previous month |
| ✅ **Remediation Trend** | Dedicated page: remediated CVEs and installed patches per endpoint, weekly chart, MTTR and CSV export |
| 📬 **Fix Digest** | Automatic email (with PDF) after every sync that records remediated CVEs / installed patches |
| 🔁 **Findings auto-close** | CVEs/patches that vanish from the Tanium feed are marked as remediated (feeds MTTR and reports) |
| 🎫 **Remediation ticket** | One ticket per endpoint that finished remediating, opened already solved, carrying the full transition history (audit trail) |
| ♻️ **Pending reboot warning** | Endpoints awaiting a restart are flagged on the patch list — an installed patch keeps reporting as missing until the reboot |
| ♻️ **Ticket auto-resolution** | Auto-opened tickets (critical CVEs, silent agents, Threat Response) are solved automatically once the condition clears |
| 📺 **TV/Kiosk mode** | Full-screen auto-refreshing security panel with token-link access (no login) for NOC/SOC wall TVs |
| ⚙️ **Synchronization** | Cron scheduling with incremental sync support |
| 🛟 **Resilient sync** | The incremental cursor only advances when the cycle ends without errors — failed endpoints come back on the next run instead of being skipped |
| 🗑️ **Retired endpoints** | Machines that disappear from the Tanium fleet are stamped with a retirement date and, optionally, purged after a configurable grace period |
| 💻 **Computer Tab** | Tanium data directly on the asset record in GLPI |
| 🎯 **Central Widget** | Risk summary on the GLPI home panel |
| 🔒 **Profiles** | Granular access control per GLPI profile |
| 🔥 **EPSS / CISA KEV** | Daily CVE enrichment with exploitation probability and the KEV catalog; KEV-only / ransomware-only filters ranked by EPSS |
| ⏱️ **SLA + MTTR** | Per-severity remediation deadlines, compliance, 90-day MTTR and daily breach webhook |
| 🛰️ **Agent health** | Silent-agent detection with automatic consolidated ticket |
| 📐 **Comply / Threat Response** | CIS/DISA benchmarks per endpoint and threat alerts → tickets, with a dedicated alert list page |
| 🩺 **Fleet Health Report** | 0–10 score and verdict per endpoint, with PDF export |
| 🔐 **Hardening** | API token stored encrypted (GLPIKey) with expiry monitoring |
| 🛡️ **Remote actions** | Quarantine / client restart gated by ticket approval |
| 🧩 **Native dashboard cards** | 7 cards in the native GLPI dashboard ("Tanium" group) |
| 🔗 **Cross-plugin correlation** | Badges when a CVE is also seen by Nessus/SentinelOne |
| 📄 **Exports** | Endpoint comparison PDF and native GLPI search with CSV |
| 🌐 **Full i18n** | 670 strings translated to pt_BR (compiled .mo, no `msgfmt` dependency) |

### 🚀 Requirements

- **GLPI** ≥ 11.0.0
- **PHP** ≥ 8.2 with `curl` and `json` extensions
- **Tanium** with REST API enabled and access token

### 📦 Installation

1. Copy the `tanium` folder to `glpi/plugins/`
2. Go to **Setup → Plugins** in GLPI
3. Click **Install** then **Enable**
4. Navigate to **Plugins → Tanium → Configuration** and enter the API URL and token

### ⚙️ Configuration

| Field | Description |
|---|---|
| 🌐 **API URL** | Tanium REST API endpoint (e.g. `https://tanium.company.com`) |
| 🔑 **API Token** | Authentication token generated in the Tanium console |
| 🔄 **Frequency** | Sync interval (hours) |
| 📥 **Limit** | Max endpoints per cron run |
| 📧 **E-mail** | Weekly security report recipient |
| 🔁 **Findings auto-close** | Marks whatever vanished from the Tanium feed as remediated (on by default) |
| 🎫 **Remediation ticket** | Opens one already-solved ticket per endpoint that finished remediating, with the full history |
| ♻️ **Pending reboot sensor** | Name of the Tanium sensor reporting a pending restart (collected automatically; empty disables the warning) |
| 🗑️ **Purge retired endpoints** | Grace period, in days, before deleting the Tanium data of a machine that left the fleet (0 = flag only) |

### 🧪 Tests

```
php tests/run.php      # pure logic (43 cases)
php tests/mirror.php   # asserts the test copies still match src/
php tools/lint.php     # php -l across the whole plugin
php tools/i18n_audit.php pt_BR
```

The plugin classes extend GLPI base classes and rely on `$DB`, so they cannot be loaded outside the container. Each test case **re-declares** the function under test as a free function, and `mirror.php` compares that copy against the real method body in `src/` (ignoring whitespace, comments and `self::`) — without it the suite would stay green while testing dead code.

### ✅ Life cycle of a fix

What happens when someone patches a machine (`apt upgrade`, Windows Update, a Tanium deployment) and reboots:

1. **The plugin never looks at the server** — it only mirrors what Tanium reports. Nothing changes in GLPI until Tanium re-evaluates the endpoint.
2. **Two sources, different speeds:** patches come from the *Applicable Patches* sensor (live, reflects quickly); CVEs come from the *Comply* module, which only changes when **its own scheduled scan** runs. A patch closing before its CVE is normal.
3. **On Windows the reboot is the gate:** until the restart, the installed KB keeps being reported as applicable — the list shows `missing` even though it was already applied. If the tenant collects a reboot sensor (see *Custom sensors*), the screen warns instead of looking broken.
4. **On the next `taniumsync`**, the item missing from the payload changes status — **no row is ever deleted**:
   - CVE → `remediated`, transition written to `cve_history`
   - Patch → `installed`, transition written to `patch_history`
5. **Cascading:** risk score recomputed, critical-CVE ticket auto-solved, fix digest e-mailed (with PDF) and — if enabled — the per-endpoint **remediation ticket**.

**Why it sometimes does not close:**

| Situation | Behaviour |
|---|---|
| Sensor errored/timed out, or the machine was off during the sync | Nothing is closed (guards against mass-closing everything on a hiccup) |
| `Findings auto-close` disabled | Only closes when Tanium itself reports the `remediated` status |
| Finding below the configured `Minimum severity` | Never enters the payload, so its absence proves nothing — stays open until the filter is lowered |
| Windows awaiting reboot | Stays `missing` until the restart |

> The patch screen opens filtered on `missing` — what was fixed lives under the **Installed / Remediated** filter, it was not deleted. Current-state tables are never purged; only history tables are, per the configured retention.

### 🕐 Scheduled Tasks (Cron)

| Task | Interval | Description |
|---|---|---|
| `taniumsync` | 1 hour | Syncs endpoints and vulnerabilities |
| `weeklyreport` | 7 days | Sends weekly security report by e-mail |
| `checkdeployments` | 5 minutes | Monitors and closes completed patch tickets |
| `epsskev` | 1 day | Refreshes EPSS scores and CISA KEV flags |
| `agenthealth` | 1 day | Flags silent agents and opens a consolidated ticket |
| `complysync` | 1 day | Imports Comply benchmark results (CIS/DISA) |
| `threatsync` | 15 minutes | Imports Threat Response alerts and opens tickets |
| `slabreach` | 1 day | Webhook alert while SLA breaches exist |
| `purgehistory` | 1 day | Purges history rows past the configured retention |
| `purgeretired` | 1 day | Removes endpoints Tanium stopped reporting, after the configured grace period (0 = disabled) |
| `apihealth` | 1 day | Checks API health and warns before the token expires |

### 🗂️ Code Structure

```
src/
├── Api.php            — Tanium REST/GraphQL API communication
├── Sync.php           — Endpoint synchronization (server-side incremental)
├── Dashboard.php      — Dashboard & risk KPIs
├── DashboardCards.php — Cards for the native GLPI dashboard
├── Vulnerability.php  — CVE management & remediation
├── Enrichment.php     — EPSS / CISA KEV
├── Sla.php            — Remediation SLA & MTTR
├── AgentHealth.php    — Silent agents
├── Compliance.php     — Comply benchmarks (CIS/DISA)
├── ThreatResponse.php — Threat alerts → tickets
├── HealthReport.php   — Fleet health report (per-endpoint score)
├── RemoteAction.php   — Approval-gated remote actions
├── PatchDeploy.php    — Patch deployment & monitoring
├── CrossPlugin.php    — Nessus/SentinelOne correlation
├── PdfReport.php      — PDF exports
├── Config.php         — Plugin settings
├── Profile.php        — Profile-based access control
├── Cron.php           — Scheduled tasks
├── WeeklyReport.php   — Weekly security report
├── ComputerTab.php    — Tanium tab on Computer record
├── ComputerGroup.php  — Tanium computer groups
├── CentralWidget.php  — GLPI central panel widget
└── Notification.php   — GLPI notifications

tests/
├── run.php            — Suite runner (43 cases, zero dependencies)
├── mirror.php         — Checks the test copies still match src/
└── cases/             — One file per function (os_type, kb_parts, reboot_pending, …)

tools/
├── lint.php           — Recursive php -l over the plugin
├── i18n_audit.php     — Code strings missing from the .po
└── compile_po.php     — Compiles .po → .mo in pure PHP (no msgfmt)
```

### 📄 License

GPL-2.0-or-later — see [LICENSE](LICENSE) file.

---

<div align="center">
  <img src="public/img/tanium-logo.svg" alt="Tanium" width="100" />
  <br/><br/>
  <sub>GLPI 11 · Tanium · PHP 8.2+</sub>
</div>
