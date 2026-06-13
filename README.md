<div align="center">
  <img src="public/img/tanium-logo.svg" alt="Tanium" width="200" />
  <br/><br/>
  <img src="https://img.shields.io/badge/GLPI-11.x-0078D7?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0xIDE1aC0ydi02aDJ2NnptMC04aC0yVjdoMnYyeiIvPjwvc3ZnPg==" />
  <img src="https://img.shields.io/badge/PHP-8.1%2B-777BB4?style=flat-square&logo=php&logoColor=white" />
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
| 📊 **Dashboard** | Painel com KPIs de risco, compliance e cobertura |
| 🗓️ **Relatório Semanal** | Envio automático de relatório de segurança por e-mail |
| ⚙️ **Sincronização** | Agendamento via Cron com suporte a sync incremental |
| 💻 **Aba no Computador** | Dados Tanium diretamente na ficha do ativo no GLPI |
| 🎯 **Widget Central** | Resumo de risco no painel inicial do GLPI |
| 🔒 **Perfis** | Controle de acesso granular por perfil GLPI |

### 🚀 Requisitos

- **GLPI** ≥ 11.0.0
- **PHP** ≥ 8.1 com extensões `curl` e `json`
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

### 🕐 Tarefas Agendadas (Cron)

| Tarefa | Intervalo | Descrição |
|---|---|---|
| `taniumsync` | 1 hora | Sincroniza endpoints e vulnerabilidades |
| `weeklyreport` | 7 dias | Envia relatório semanal por e-mail |
| `checkdeployments` | 5 minutos | Monitora e fecha tickets de patches concluídos |

### 🗂️ Estrutura do Código

```
src/
├── Api.php           — Comunicação com a API REST Tanium
├── Sync.php          — Lógica de sincronização de endpoints
├── Dashboard.php     — Dashboard e KPIs de risco
├── Vulnerability.php — Gestão de CVEs e remediação
├── PatchDeploy.php   — Implantação e monitoramento de patches
├── Config.php        — Configurações do plugin
├── Profile.php       — Controle de acesso por perfil
├── Cron.php          — Tarefas agendadas
├── WeeklyReport.php  — Relatório semanal de segurança
├── ComputerTab.php   — Aba Tanium na ficha do computador
├── CentralWidget.php — Widget no painel central do GLPI
└── Notification.php  — Notificações GLPI
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
| 📊 **Dashboard** | KPI panel with risk, compliance and coverage metrics |
| 🗓️ **Weekly Report** | Automated security report delivery by e-mail |
| ⚙️ **Synchronization** | Cron scheduling with incremental sync support |
| 💻 **Computer Tab** | Tanium data directly on the asset record in GLPI |
| 🎯 **Central Widget** | Risk summary on the GLPI home panel |
| 🔒 **Profiles** | Granular access control per GLPI profile |

### 🚀 Requirements

- **GLPI** ≥ 11.0.0
- **PHP** ≥ 8.1 with `curl` and `json` extensions
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

### 🕐 Scheduled Tasks (Cron)

| Task | Interval | Description |
|---|---|---|
| `taniumsync` | 1 hour | Syncs endpoints and vulnerabilities |
| `weeklyreport` | 7 days | Sends weekly security report by e-mail |
| `checkdeployments` | 5 minutes | Monitors and closes completed patch tickets |

### 🗂️ Code Structure

```
src/
├── Api.php           — Tanium REST API communication
├── Sync.php          — Endpoint synchronization logic
├── Dashboard.php     — Dashboard & risk KPIs
├── Vulnerability.php — CVE management & remediation
├── PatchDeploy.php   — Patch deployment & monitoring
├── Config.php        — Plugin settings
├── Profile.php       — Profile-based access control
├── Cron.php          — Scheduled tasks
├── WeeklyReport.php  — Weekly security report
├── ComputerTab.php   — Tanium tab on Computer record
├── CentralWidget.php — GLPI central panel widget
└── Notification.php  — GLPI notifications
```

### 📄 License

GPL-2.0-or-later — see [LICENSE](LICENSE) file.

---

<div align="center">
  <img src="public/img/tanium-logo.svg" alt="Tanium" width="100" />
  <br/><br/>
  Made with ❤️ for <strong>SEBRAE/MS</strong>
  <br/>
  <sub>GLPI 11 · Tanium · PHP 8.1+</sub>
</div>
