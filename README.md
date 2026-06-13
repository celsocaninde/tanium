# 🛡️ Tanium Plugin for GLPI 11

> 🇧🇷 [Português](#-português) | 🇺🇸 [English](#-english)

---

## 🇧🇷 Português

### 📋 Sobre

Plugin de integração entre **Tanium** e **GLPI 11**, desenvolvido para sincronizar endpoints, vulnerabilidades CVE, patches e dados de hardware/software diretamente no inventário do GLPI.

### ✨ Funcionalidades

| Recurso | Descrição |
|---|---|
| 🖥️ **Endpoints** | Sincroniza computadores do Tanium com ativos do GLPI |
| 🔍 **Vulnerabilidades** | Importa CVEs com severidade, score CVSS e status |
| 🩹 **Patch Remediation** | Rastreia patches ausentes e histórico de implantação |
| 📊 **Dashboard** | Painel com KPIs de risco, compliance e cobertura |
| 🗓️ **Relatório Semanal** | Envio automático de relatório por e-mail |
| ⚙️ **Sincronização** | Agendamento via Cron com suporte a incremental |
| 🔒 **Perfis** | Controle de acesso por perfil GLPI |

### 🚀 Requisitos

- **GLPI** ≥ 11.0.0
- **PHP** ≥ 8.1
- **Tanium** com API REST habilitada

### 📦 Instalação

1. Copie a pasta `tanium` para `glpi/plugins/`
2. Acesse **Configuração → Plugins** no GLPI
3. Clique em **Instalar** e depois em **Ativar**
4. Vá em **Plug-ins → Tanium** e configure a URL da API e o token

```
glpi/plugins/
└── tanium/
    ├── setup.php
    ├── hook.php
    ├── src/
    ├── front/
    └── ...
```

### ⚙️ Configuração

| Campo | Descrição |
|---|---|
| 🌐 API URL | Endereço da API REST do Tanium |
| 🔑 API Token | Token de autenticação |
| 🔄 Frequência | Intervalo de sincronização (horas) |
| 📥 Limite | Máximo de endpoints por sincronização |
| 📧 E-mail | Destinatário do relatório semanal |

### 🗂️ Estrutura

```
src/
├── Api.php           — Comunicação com a API Tanium
├── Sync.php          — Lógica de sincronização
├── Dashboard.php     — Dashboard e KPIs
├── Vulnerability.php — Gerenciamento de CVEs
├── PatchDeploy.php   — Implantação de patches
├── Config.php        — Configurações do plugin
├── Profile.php       — Controle de acesso
├── Cron.php          — Tarefas agendadas
└── WeeklyReport.php  — Relatório semanal
```

### 📸 Screenshots

> Dashboard com KPIs de risco, mapa de calor de vulnerabilidades e histórico de sincronização.

---

## 🇺🇸 English

### 📋 About

Integration plugin between **Tanium** and **GLPI 11**, designed to synchronize endpoints, CVE vulnerabilities, patches, and hardware/software data directly into the GLPI inventory.

### ✨ Features

| Feature | Description |
|---|---|
| 🖥️ **Endpoints** | Syncs Tanium computers with GLPI assets |
| 🔍 **Vulnerabilities** | Imports CVEs with severity, CVSS score and status |
| 🩹 **Patch Remediation** | Tracks missing patches and deployment history |
| 📊 **Dashboard** | KPI panel with risk, compliance and coverage metrics |
| 🗓️ **Weekly Report** | Automated e-mail report delivery |
| ⚙️ **Synchronization** | Cron scheduling with incremental sync support |
| 🔒 **Profiles** | Access control per GLPI profile |

### 🚀 Requirements

- **GLPI** ≥ 11.0.0
- **PHP** ≥ 8.1
- **Tanium** with REST API enabled

### 📦 Installation

1. Copy the `tanium` folder to `glpi/plugins/`
2. Go to **Setup → Plugins** in GLPI
3. Click **Install** then **Enable**
4. Navigate to **Plugins → Tanium** and configure the API URL and token

### ⚙️ Configuration

| Field | Description |
|---|---|
| 🌐 API URL | Tanium REST API endpoint |
| 🔑 API Token | Authentication token |
| 🔄 Frequency | Sync interval (hours) |
| 📥 Limit | Max endpoints per sync |
| 📧 E-mail | Weekly report recipient |

### 🗂️ Structure

```
src/
├── Api.php           — Tanium API communication
├── Sync.php          — Synchronization logic
├── Dashboard.php     — Dashboard & KPIs
├── Vulnerability.php — CVE management
├── PatchDeploy.php   — Patch deployment
├── Config.php        — Plugin settings
├── Profile.php       — Access control
├── Cron.php          — Scheduled tasks
└── WeeklyReport.php  — Weekly report
```

### 📄 License

GPL-2.0-or-later — see [LICENSE](LICENSE) file.

---

<div align="center">
  Made with ❤️ for <strong>SEBRAE/MS</strong> · GLPI 11 · Tanium
</div>
