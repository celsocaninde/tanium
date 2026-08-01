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
| 🎯 **Plano de ação** | Fila do que fazer primeiro, ordenada pelo risco que cada ação realmente remove da frota — um patch em 99 máquinas fica acima de um CVE isolado |
| ⏳ **Fim de suporte (EOL)** | Detecta SO sem suporte do fabricante, marca o endpoint e aplica piso de risco: o conserto ali é migração, não patch |
| 📉 **Nota que reage à correção** | Modelo de risco sem saturação: cada lote de CVEs corrigido move o número e a faixa, em vez de deixar o endpoint travado em "100 Crítico" |
| 🔎 **Cálculo aberto** | O endpoint mostra a conta que gerou a nota — piso da severidade, volume e amplitude, com os achados que entraram |
| 📈 **Antes → depois** | Histórico de risco por endpoint com variação do período, gráfico e quantos CVEs/patches foram corrigidos |
| 🛟 **Sync resiliente** | O cursor incremental só avança quando o ciclo termina sem erro — endpoints que falharam voltam na execução seguinte em vez de serem pulados |
| 🗑️ **Endpoints retirados** | Máquinas que somem da frota do Tanium são marcadas com data de retirada e, opcionalmente, expurgadas após carência configurável. Detectado por varredura diária de IDs, que funciona **também** com sync incremental |
| 🔐 **Escopo por entidade** | Listas, dashboard, boletim, plano de ação e páginas por endpoint respeitam as entidades do perfil — inclusive a ficha individual, que recusa um `eid` fora do escopo |
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
| 🩺 **Diagnóstico do plugin** | Tela que responde "isto está funcionando?": estado de cada cron, capacidades que o Gateway recusou, tamanho das tabelas, últimas execuções e log — tudo lido ao vivo |
| 📉 **Burn-down** | Vazão em vez de estoque: abertos vs fechados por semana, saldo e projeção — incluindo "nunca neste ritmo" quando a fila cresce |
| ♻️ **Reincidência** | Patch que foi instalado e voltou a faltar, com os endpoints que mais revertem — aponta imagem base, GPO ou repositório, não a equipe |
| 🎯 **Campanhas** | Erradicação de um alvo acompanhada até o fim: linha de base no dia da decisão, prazo, progresso e quem ainda falta |
| 🧭 **Fora do padrão** | Endpoint comparado com máquinas do mesmo SO **e mesma geração** — desvio ali é configuração divergente, não falta de patch |
| 🏷️ **Severidade unificada** | Windows, RHEL, Ubuntu e SUSE falam escalas diferentes; tudo é normalizado na entrada e o que não tem nota vira `unknown` explícito |
| 🔎 **Campos nativos** | Nota de risco, último contato e criptografia expostos como critérios de busca do Computer — usáveis em listas salvas, dashboards e **regras de negócio** do GLPI |
| 📺 **Kiosk com alerta** | A TV rompe o carrossel quando há o que dizer (exposição KEV nova, sync parado, agentes em silêncio) |
| 🎫 **Chamado já triado** | Categoria, técnico, grupo, origem e tipo definidos nas configurações e aplicados a **todo** chamado do plugin — inclusive os que o cron abre de madrugada, que antes chegavam sem categoria |
| 🌐 **i18n completa** | 924 strings traduzidas para pt_BR (.mo compilado, sem dependência de `msgfmt`) |

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
| 🔄 **Frequência** | Intervalo entre sincronizações (horas). A tarefa roda de hora em hora e ela mesma decide se está na hora; o botão "Executar agora" ignora o intervalo |
| 📥 **Limite** | Máximo de endpoints por execução do cron |
| 📧 **E-mail** | Destinatário do relatório semanal de segurança |
| 🔁 **Auto-close de findings** | Marca como remediado o que sumiu do feed do Tanium (ligado por padrão) |
| 🎚️ **Severidade mínima de CVE** | Corta achados abaixo do nível escolhido já na importação. Cuidado: o que é cortado nunca entra no payload, logo nunca é fechado automaticamente |
| 🎫 **Chamado de remediação** | Abre um chamado por endpoint que concluiu correções, já solucionado, com o histórico completo |
| ♻️ **Sensor de reboot pendente** | Nome do sensor do Tanium que indica reinício pendente (coletado automaticamente; vazio desativa o aviso) |
| 🗑️ **Remover endpoints retirados** | Dias de carência antes de apagar os dados Tanium de uma máquina que sumiu da frota (0 = só marcar) |
| 🧹 **Retenção de achados fechados** | Por quanto tempo CVEs remediados e patches instalados são guardados. Achados **abertos** nunca são expurgados (0 = guardar para sempre) |
| 📺 **Alertas no Kiosk** | A TV interrompe o carrossel em eventos urgentes: nova exposição KEV, sincronização parada, agentes em silêncio |
| 🗂️ **Categoria padrão** | Categoria ITIL aplicada a todo chamado do Tanium, com **override opcional por tipo** (CVE, patch/remediação, agente, ameaça, ação remota) |
| 👷 **Técnico / grupo atribuído** | Preenche o campo "Atribuído a". Vazio mantém o comportamento antigo: o chamado fica atribuído à conta requerente (o usuário de automação) |
| 🛎️ **Origem da requisição** | Preenche "Origem da requisição" — crie uma origem "Tanium" para separar esses chamados nos relatórios |
| 🏷️ **Tipo do chamado** | Incidente ou Requisição para todos, ou "manter o padrão de cada chamado" (segurança = incidente, instalação de agente = requisição) |

### 🧪 Testes

```
php tests/run.php      # lógica pura (142 casos)
php tests/mirror.php   # garante que as cópias dos testes conferem com src/
php tools/lint.php     # php -l em todo o plugin
php tools/i18n_audit.php pt_BR
```

As classes do plugin estendem base do GLPI e usam `$DB`, então não são carregáveis fora do container. Cada caso de teste **re-declara** a função testada como função livre, e o `mirror.php` compara essa cópia com o corpo do método real em `src/` (ignorando espaços, comentários e `self::`) — sem ele, a suíte ficaria verde testando código morto.

### 🎯 Plano de ação

A tela de vulnerabilidades responde *"quão ruim está"*. Esta responde *"o que eu faço primeiro"*.

Cada ação candidata é **simulada contra o modelo de risco real**: o score de cada endpoint afetado é recalculado como se a ação já tivesse sido concluída, e os pontos liberados são somados na frota inteira. Três tipos entram na mesma fila e ficam comparáveis:

| Tipo | O que é | Como pontua |
|---|---|---|
| **Patch** | implantar um patch em todas as máquinas onde falta | soma da queda de risco em cada uma |
| **CVE** | remediar um CVE em todas as máquinas onde está aberto | idem, com o KEV descontando nos dois níveis |
| **Migração** | trocar um SO fora de suporte | **todo** o risco atual daqueles endpoints |

Migração carrega o risco inteiro porque nesses hosts as outras duas ações **não existem** — nenhuma correção vai chegar. Deixar isso fora da fila é o que faz um time trabalhar a lista de patches enquanto um servidor sem suporte acumula CVEs críticos.

Duas consequências que aparecem na prática:
- Uma atualização cumulativa faltando em **99 máquinas** rende mais que um CVE crítico isolado, e sobe na fila.
- O *Malicious Software Removal Tool*, faltando em **160 máquinas**, fica lá embaixo: fechá-lo quase não move score nenhum. Abrangência sozinha não é prioridade.

O empate no risco é desempatado pela abrangência — duas ações que liberam os mesmos pontos não são iguais se uma é uma implantação e a outra são 15 investigações separadas.

### ⏳ Fim de suporte

O plugin reportava "patch ausente" para sempre em máquinas cujo fabricante parou de publicar patches. **O achado não é remediável**, então ele nunca fechava, o score nunca melhorava, e o time gastava esforço numa fila que não anda. Na frota de referência isso era **15% dos endpoints**.

`src/Lifecycle.php` traz um catálogo estático de datas de fim de suporte (Windows cliente e Server, Ubuntu LTS, CentOS, RHEL, AlmaLinux/Rocky, Debian, Oracle Linux, SLES) casado contra `os_name` + `os_version`. Três estados: `supported`, `ending_soon` (dentro de 180 dias) e `eol`.

O catálogo é uma tabela estática de propósito — precisa funcionar em GLPI sem internet, e corrigir uma data é mudar uma linha. Ele **nunca chuta**: SO não reconhecido vira `unknown`, nunca `supported`, porque presumir suporte esconderia justamente o host exótico e abandonado. A constante `REVIEWED_ON` registra a última revisão humana das datas e aparece na interface.

### 📉 Como a nota é calculada

O plugin tem **duas notas**, e elas são a mesma coisa vista de dois ângulos:

| | Onde aparece | Escala | Conta |
|---|---|---|---|
| **Nota de risco** | ficha do endpoint | 0–100, **maior pior** | CVEs abertos + patches ausentes |
| **Nota de saúde** | boletim da frota | 0–10, **maior melhor** | a nota de risco (7 pontos) + higiene (3 pontos) |

**Nota de risco.** A pior severidade presente define o **piso**; o **volume** dentro dessa severidade move a nota dentro da faixa, em escala logarítmica; os achados de severidade menor somam uma **amplitude** limitada a 10 pontos.

| Severidade dominante | Faixa possível |
|---|---|
| Crítica | 60 – 100 |
| Alta | 35 – 69 |
| Média | 15 – 39 |
| Baixa | 5 – 10 |

Faixas exibidas: **0–14 Baixo · 15–39 Médio · 40–69 Alto · 70–100 Crítico**. Disso saem dois invariantes úteis: um endpoint **sem nenhum CVE crítico nunca chega à faixa crítica**, por mais volume que acumule; e **limpar uma severidade inteira sempre derruba a nota para uma faixa abaixo**, porque o piso desce.

Composição das contagens:
- CVEs no **catálogo KEV** somam também no nível crítico — exploração confirmada pesa mais que a severidade teórica.
- **Patches ausentes** entram **um nível abaixo** da própria severidade (patch crítico conta como alto), porque um patch é exposição ainda não confirmada como explorável naquele host — sozinho, não pode tornar um endpoint crítico.
- Só **achados abertos** contam. O que foi remediado sai inteiramente da conta.

**Nota de saúde.** `10 − 7 × (risco/100) − higiene`, com higiene valendo agente em silêncio (1,0), SO fora de suporte (0,8), disco sem criptografia (0,6) e Defender com problema (0,6) — 3,0 no total. Dado desconhecido (`NULL`) nunca penaliza. Defender só é avaliado em Windows. Nota **0,0 só existe** com risco 100 **e** as quatro falhas de higiene juntas.

**Piso de fim de suporte.** Endpoint cujo SO não recebe mais correções tem o risco elevado a **no mínimo 40 (Alto)**, mesmo com zero achados abertos: máquina sem suporte não é máquina segura, é máquina onde ninguém mais procura vulnerabilidade e para a qual nenhuma correção virá. O piso entra como linha própria no detalhamento, para ficar claro que veio do sistema operacional e não de um achado.

A ficha do endpoint traz o botão **"De onde vem esse número?"**, que abre a conta linha a linha — piso, volume, amplitude e os achados que entraram — somando exatamente o valor exibido ao lado.

> **Por que o modelo mudou (v2.15.0):** antes era soma de peso fixo por achado, com corte em `min(100, …)`. Um endpoint real somava ~4.400 contra um teto de 100, então corrigir *todos* os críticos **e** *todos* os altos deixava o badge parado em "100 Crítico"; no boletim, dezenas de máquinas muito diferentes entre si empatavam em 0,0. A escala saturava exatamente onde a triagem acontece. Na frota de referência, a troca levou os endpoints cravados em 100 de **63 para 4** e as notas zeradas do boletim de **30 para 0**.

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
├── Risk.php           — Modelo de risco 0–100 e nota 0–10 (aritmética pura)
├── Lifecycle.php      — Fim de suporte do SO (catálogo estático)
├── ActionPlan.php     — Ranking de ações por risco removido
├── RiskHistory.php    — Histórico de risco por endpoint (antes → depois)
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
├── Analytics.php      — Burn-down, projeção, reincidência e outliers
├── Campaign.php       — Campanhas de erradicação (progresso derivado, nunca gravado)
├── Diagnostics.php    — Autodiagnóstico do plugin (crons, capacidades, dados)
├── Severity.php       — Vocabulário único de severidade entre plataformas
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
├── run.php            — Executor da suíte (142 casos, sem dependências)
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
| 🎯 **Action plan** | A queue of what to do first, ranked by the risk each action actually removes from the fleet — one patch on 99 machines outranks a lone CVE |
| ⏳ **End of support (EOL)** | Detects operating systems the vendor no longer fixes, flags the endpoint and applies a risk floor: the fix there is migration, not patching |
| 📉 **A score that reacts to remediation** | Non-saturating risk model: every batch of fixed CVEs moves the number and the band, instead of leaving the endpoint frozen at "100 Critical" |
| 🔎 **Open arithmetic** | The endpoint page shows the calculation behind its score — severity floor, volume and breadth, with the findings that went in |
| 📈 **Before → after** | Per-endpoint risk history with the period's movement, a chart, and how many CVEs/patches were fixed |
| 🛟 **Resilient sync** | The incremental cursor only advances when the cycle ends without errors — failed endpoints come back on the next run instead of being skipped |
| 🗑️ **Retired endpoints** | Machines that disappear from the Tanium fleet are stamped with a retirement date and, optionally, purged after a configurable grace period. Detected by a daily id sweep, so it works **with** incremental sync too |
| 🔐 **Entity scoping** | Lists, dashboard, health report, action plan and per-endpoint pages honour the profile's entities — including the detail page, which refuses an out-of-scope `eid` |
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
| 🩺 **Plugin diagnostics** | A screen that answers "is this working?": every cron's state, the capabilities the Gateway refused, table sizes, recent runs and the log — all read live |
| 📉 **Burn-down** | Flow instead of stock: opened vs closed per week, net movement and a forecast — including "never at this rate" when the queue is growing |
| ♻️ **Reincidence** | Patches installed that came back, with the endpoints that revert most — points at the base image, a policy or a repository, not at the team |
| 🎯 **Campaigns** | One target tracked to eradication: baseline taken the day it was decided, due date, progress and who is left |
| 🧭 **Outliers** | Endpoints compared against machines on the same OS **and the same major version** — deviation there is configuration drift, not a missing patch |
| 🏷️ **Unified severity** | Windows, RHEL, Ubuntu and SUSE speak different scales; everything is normalised at ingest and anything unrated becomes an explicit `unknown` |
| 🔎 **Native search fields** | Risk score, last seen and encryption exposed as Computer search options — usable in saved searches, dashboards and GLPI **business rules** |
| 📺 **Kiosk alert mode** | The wall TV breaks out of the carousel when it has something to say (new KEV exposure, sync stopped, agents going silent) |
| 🎫 **Pre-triaged tickets** | Category, technician, group, source and type set in the settings and applied to **every** ticket the plugin opens — including the ones the cron raises overnight, which used to arrive with no category |
| 🌐 **Full i18n** | 924 strings translated to pt_BR (compiled .mo, no `msgfmt` dependency) |

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
| 🔄 **Frequency** | Interval between syncs (hours). The task runs hourly and decides for itself whether it is due; "Run now" bypasses the interval |
| 📥 **Limit** | Max endpoints per cron run |
| 📧 **E-mail** | Weekly security report recipient |
| 🔁 **Findings auto-close** | Marks whatever vanished from the Tanium feed as remediated (on by default) |
| 🎚️ **Minimum CVE severity** | Drops findings below the chosen level at import. Careful: what is filtered out never enters the payload, so it can never be auto-closed |
| 🎫 **Remediation ticket** | Opens one already-solved ticket per endpoint that finished remediating, with the full history |
| ♻️ **Pending reboot sensor** | Name of the Tanium sensor reporting a pending restart (collected automatically; empty disables the warning) |
| 🗑️ **Purge retired endpoints** | Grace period, in days, before deleting the Tanium data of a machine that left the fleet (0 = flag only) |
| 🧹 **Closed-findings retention** | How long remediated CVEs and installed patches are kept. **Open** findings are never purged (0 = keep forever) |
| 📺 **Kiosk alerts** | The wall TV breaks out of the carousel on urgent events: new KEV exposure, sync stopped, agents going silent |
| 🗂️ **Default category** | ITIL category applied to every Tanium ticket, with an **optional override per kind** (CVE, patch/remediation, agent, threat, remote action) |
| 👷 **Assigned technician / group** | Fills the "Assigned to" field. Left empty it keeps the old behaviour: the ticket stays assigned to the requester account (the automation user) |
| 🛎️ **Request source** | Fills "Request source" — create a "Tanium" source to tell these tickets apart in reports |
| 🏷️ **Ticket type** | Incident or Request for all of them, or "keep each ticket default" (security = incident, agent installation = request) |

### 🧪 Tests

```
php tests/run.php      # pure logic (142 cases)
php tests/mirror.php   # asserts the test copies still match src/
php tools/lint.php     # php -l across the whole plugin
php tools/i18n_audit.php pt_BR
```

The plugin classes extend GLPI base classes and rely on `$DB`, so they cannot be loaded outside the container. Each test case **re-declares** the function under test as a free function, and `mirror.php` compares that copy against the real method body in `src/` (ignoring whitespace, comments and `self::`) — without it the suite would stay green while testing dead code.

### 🎯 Action plan

The vulnerability screen answers *"how bad is it"*. This one answers *"what do I do first"*.

Every candidate action is **simulated against the real risk model**: the score of each affected endpoint is recomputed as if the action were already done, and the points freed are summed across the fleet. Three kinds share one queue and become comparable:

| Kind | What it is | How it scores |
|---|---|---|
| **Patch** | deploy one patch everywhere it is missing | sum of the risk drop on each machine |
| **CVE** | remediate one CVE everywhere it is open | same, with KEV discounting at both levels |
| **Migration** | replace an operating system past end of support | the **whole** current risk of those endpoints |

Migration carries the full risk because on those hosts the other two actions **do not exist** — no fix is coming. Leaving it out of the queue is what has a team working the patch list while an unsupported server piles up critical CVEs.

Two consequences that show up in practice:
- One cumulative update missing on **99 machines** outranks a lone critical CVE and rises in the queue.
- The *Malicious Software Removal Tool*, missing on **160 machines**, sits near the bottom: closing it barely moves any score. Reach alone is not priority.

Ties on risk are broken by reach — two actions freeing the same points are not equal when one is a single deployment and the other is 15 separate investigations.

### ⏳ End of support

The plugin reported "missing patch" forever on machines whose vendor had stopped shipping patches. **The finding is not remediable**, so it never closed, the score never improved, and the team spent effort on a line that cannot move. On the reference fleet that was **15% of the endpoints**.

`src/Lifecycle.php` carries a static catalogue of end-of-support dates (Windows client and Server, Ubuntu LTS, CentOS, RHEL, AlmaLinux/Rocky, Debian, Oracle Linux, SLES) matched against `os_name` + `os_version`. Three states: `supported`, `ending_soon` (within 180 days) and `eol`.

The catalogue is deliberately a static table — it has to work on a GLPI with no internet, and fixing a date is a one-line change. It **never guesses**: an unrecognised OS becomes `unknown`, never `supported`, because assuming support would hide exactly the exotic, abandoned host. The `REVIEWED_ON` constant records the last human review of the dates and is surfaced in the UI.

### 📉 How the score is calculated

The plugin has **two scores**, and they are the same thing from two angles:

| | Where | Scale | Built from |
|---|---|---|---|
| **Risk score** | endpoint page | 0–100, **higher is worse** | open CVEs + missing patches |
| **Health grade** | fleet report | 0–10, **higher is better** | the risk score (7 points) + hygiene (3 points) |

**Risk score.** The worst severity present sets a **floor**; the **volume** inside that severity moves the score within its band, logarithmically; lower-severity findings add a **breadth** term capped at 10 points.

| Dominant severity | Possible range |
|---|---|
| Critical | 60 – 100 |
| High | 35 – 69 |
| Medium | 15 – 39 |
| Low | 5 – 10 |

Displayed bands: **0–14 Low · 15–39 Medium · 40–69 High · 70–100 Critical**. Two useful invariants follow: an endpoint with **no critical finding can never reach the critical band**, however much volume it piles up; and **clearing a whole severity always drops the score one band**, because the floor moves down.

How the counts are composed:
- CVEs in the **KEV catalogue** also count at the critical level — confirmed exploitation outweighs the theoretical severity band.
- **Missing patches** enter **one level below** their own severity (a critical patch counts as high), because a patch is exposure not yet confirmed exploitable on that host — on its own it must not make an endpoint critical.
- Only **open findings** count. Anything remediated leaves the calculation entirely.

**Health grade.** `10 − 7 × (risk/100) − hygiene`, where hygiene is agent silent (1.0), OS past end of support (0.8), disk not encrypted (0.6) and Defender unhealthy (0.6) — 3.0 in total. Unknown data (`NULL`) never penalises. Defender is only judged on Windows. A **0.0 is only reachable** with risk 100 **and** all four hygiene checks failing.

**End-of-support floor.** An endpoint whose OS no longer receives fixes is raised to **at least 40 (High)** even with zero open findings: an unsupported machine is not a safe machine, it is one nobody is looking for vulnerabilities in any more and for which no fix will ever arrive. The floor appears as its own line in the breakdown, so it is clear the lift came from the operating system and not from a finding.

The endpoint page carries a **"Where does this number come from?"** button that opens the arithmetic line by line — floor, volume, breadth and the findings that went in — adding up to exactly the number displayed beside it.

> **Why the model changed (v2.15.0):** it used to sum a fixed weight per finding and clamp with `min(100, …)`. A real endpoint summed ~4,400 against a ceiling of 100, so remediating *every* critical **and** *every* high CVE left the badge reading "100 Critical"; in the fleet report, dozens of very different machines tied at 0.0. The scale saturated exactly where triage happens. On the reference fleet the change took endpoints pinned at 100 from **63 to 4**, and zeroed health grades from **30 to 0**.

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
├── Risk.php           — 0–100 risk model and 0–10 grade (pure arithmetic)
├── Lifecycle.php      — OS end-of-support detection (static catalogue)
├── ActionPlan.php     — Ranking of actions by risk removed
├── RiskHistory.php    — Per-endpoint risk history (before → after)
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
├── Analytics.php      — Burn-down, forecast, reincidence and outliers
├── Campaign.php       — Eradication campaigns (progress derived, never stored)
├── Diagnostics.php    — Plugin self-diagnostics (crons, capabilities, data)
├── Severity.php       — One severity vocabulary across platforms
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
├── run.php            — Suite runner (142 cases, zero dependencies)
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
