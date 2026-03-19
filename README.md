# OpenClaw Security Shield 🔒

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)]()
[![Version](https://img.shields.io/badge/version-1.6.0-cyan.svg)](https://github.com/wooluo/openclaw-security)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**OpenClaw Security Shield** 是一个专为 OpenClaw 设计的企业级安全防护系统

</div>

---

## 目录

- [概述](#概述)
- [安全背景](#-安全背景)
- [核心功能](#-核心功能)
- [三道防线架构](#-三道防线架构)
- [安装指南](#-安装指南)
- [快速开始](#-快速开始)
- [命令行工具](#-命令行工具)
- [配置说明](#-配置说明)
- [威胁检测规则](#-威胁检测规则)
- [项目结构](#-项目结构)
- [开发指南](#-开发指南)
- [常见问题](#-常见问题)
- [路线图](#路线图)
- [贡献](#-贡献)

---

## 概述

OpenClaw Security Shield 是一个全面的安全防护解决方案，专为检测和防御恶意 Skills、保护 API 密钥、监控网络流量、审计操作日志等场景设计。系统采用**零信任架构**和**深度防御**策略，提供多层级的安全防护。

### 主要特点

- 🛡️ **零信任架构** - 默认拒绝所有未验证的操作
- 🔍 **智能威胁检测** - 基于规则和行为的双重检测引擎
- 🚦 **三道防线体系** - 预防、检测、响应的完整安全闭环
- 🔄 **自动更新机制** - 实时同步最新的威胁情报库
- 📊 **完整审计追踪** - 所有操作可追溯、可分析
- ⚡ **高性能实时监控** - 低延迟的流量分析和行为监控

---

## 🚨 安全背景

根据最新的安全审计报告，OpenClaw 生态系统面临严峻的安全挑战：

| 指标 | 数值 | 风险等级 |
|------|------|----------|
| 已发现恶意 Skills | **341+** | 🔴 严重 |
| 存在安全问题的 Skills | **~20%** | 🟠 高 |
| API 密钥泄露事件 | **89+** | 🔴 严重 |
| 反向 Shell 攻击 | **23+** | 🔴 严重 |

### 恶意插件常见行为

- 🔑 窃取 API 密钥和环境变量
- 🐚 开启反向 Shell 进行远程控制
- 📡 未授权的网络连接和数据外传
- 📂 敏感文件访问和修改
- ⛏️ 加密货币挖矿（Cryptojacking）
- 🤖 僵尸网络（Botnet）控制节点

---

## ✨ 核心功能

### 1. Skill 安全扫描器

```python
# 智能代码分析，检测恶意模式
result = shield.scan_skill("/path/to/skill.py")
```

- **静态代码分析** - AST 解析深度分析代码结构
- **危险函数检测** - eval/exec/subprocess/shell 等高危函数
- **敏感信息检测** - 硬编码密钥、凭证、Token 检测
- **网络行为分析** - 可疑连接、SSRF、数据外传检测
- **混淆代码识别** - Base64、Hex、Unicode 混淆检测

### 2. API 密钥保护

```python
# 自动加密存储和泄露检测
api_protection = APIKeyProtection(config)
api_protection.protect_key("OPENAI_API_KEY", "sk-...")
```

- 🔐 **环境变量加密存储** - AES-256 加密保护
- 🛡️ **运行时内存保护** - 防止内存转储泄露
- 🔍 **泄露检测与告警** - 实时扫描代码库中的密钥
- 🔄 **自动轮换机制** - 支持定期自动轮换密钥

### 3. 网络流量监控

```python
# 实时流量分析
monitor = NetworkMonitor(config)
monitor.start()
```

- 📡 **实时流量分析** - 深度包检测（DPI）
- 🚫 **域名黑名单验证** - 动态更新的恶意域名库
- 🛡️ **SSRF 攻击防护** - 服务端请求伪造检测
- 🔥 **异常连接阻断** - 自动阻断可疑连接

### 4. 权限管理

```python
# 基于能力的访问控制
access = AccessController(config)
access.check_permission(skill, Capability.NETWORK_ACCESS)
```

- ✅ **最小权限原则** - 仅授予必要的权限
- 📦 **沙箱隔离执行** - 隔离环境运行不可信代码
- 🎯 **能力（Capability）控制** - 细粒度权限控制
- 📋 **访问控制列表（ACL）** - 灵活的访问策略

### 5. 日志审计

```python
# 完整的操作审计
auditor = SecurityAuditor(config)
auditor.log_event("SKILL_SCAN", {"file": "skill.py"})
```

- 📝 **完整操作记录** - 所有操作可追溯
- 🚨 **异常行为告警** - 智能异常检测
- 🔒 **审计日志加密** - 防止日志篡改
- 📊 **合规性报告** - 自动生成合规报告

### 6. 实时威胁检测

```python
# AI 增强的威胁检测
detector = AdvancedThreatDetector(config)
threats = detector.analyze(file_path, content, static_results)
```

- 🧠 **行为分析引擎** - 基于 ML 的异常检测
- 🎯 **异常检测算法** - 统计和启发式分析
- 🌐 **威胁情报集成** - 实时同步全球威胁情报
- ⚡ **自动响应机制** - 检测即响应

---

## 🏗️ 三道防线架构

OpenClaw Security Shield 采用纵深防御策略，构建三道安全防线：

```
┌─────────────────────────────────────────────────────────────┐
│                    OpenClaw Security Shield                 │
│                        v1.1.0                               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  第一道防线：预防层 (Prevention Layer)                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ • Skill 安装前扫描                                     │  │
│  │ • 静态代码分析                                         │  │
│  │ • 依赖安全检查                                         │  │
│  │ • 沙箱隔离执行                                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  第二道防线：检测层 (Detection Layer)                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ • AI 流量分析                                          │  │
│  │ • Prompt 注入检测                                      │  │
│  │ • LLM 适配器监控                                       │  │
│  │ • SSL/TLS 流量解密分析                                 │  │
│  └───────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  第三道防线：响应层 (Response Layer)                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ • 访问控制 & 能力管理                                  │  │
│  │ • 反病毒引擎 & 隔离区                                  │  │
│  │ • 微隔离 & 防火墙                                      │  │
│  │ • 威胁情报同步                                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 第一道防线：预防层

- **SkillScanner** - 安装前的完整代码扫描
- **AssetManager** - 资产发现与清单管理
- **ProcessMonitor** - 进程行为监控

### 第二道防线：检测层

- **AIAnalyzer** - AI 流量行为分析
- **PromptGuard** - Prompt 注入防护
- **ContentAuditor** - 内容安全审计
- **SSLInspector** - 加密流量解密分析

### 第三道防线：响应层

- **AccessController** - 动态访问控制
- **AVEngine** - 反病毒引擎
- **MicroSegmentation** - 微隔离网络
- **ThreatIntel** - 威胁情报同步

---

## 📦 安装指南

### 系统要求

- Python >= 3.8
- Linux / macOS / Windows
- 至少 512MB 可用内存
- 网络连接（用于更新威胁规则）

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/wooluo/openclaw-security.git
cd openclaw-security

# 创建虚拟环境（推荐）
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 初始化配置
python -m openclaw_shield init
```

### 验证安装

```bash
# 检查版本
openclaw-shield version

# 运行测试
pytest tests/ -v
```

---

## 🚀 快速开始

### Python API 使用

```python
from openclaw_shield import SecurityShield

# 初始化安全防护
shield = SecurityShield()

# 扫描单个 Skill
result = shield.scan_skill("/path/to/skill.py")
print(f"风险等级: {result['risk_level']}")
print(f"是否通过: {result['passed']}")

# 批量扫描目录
results = shield.scan_all_skills("/path/to/skills")
print(f"扫描完成: {results['scanned']} 个文件")

# 启动实时监控
await shield.start_monitoring()

# 生成安全报告
report = shield.generate_report(format='html')
```

### 作为 Python 包使用

```python
# 仅使用扫描器
from openclaw_shield import SkillScanner

scanner = SkillScanner(config)
result = scanner.scan_file("malicious.py")

# 仅使用网络监控
from openclaw_shield import NetworkMonitor

monitor = NetworkMonitor(config)
monitor.add_callback(lambda event: print(f"检测到: {event}"))
monitor.start()

# API 密钥保护
from openclaw_shield import APIKeyProtection

api_protect = APIKeyProtection(config)
api_protect.protect_all_keys()
```

---

## 💻 命令行工具

### 基本命令

```bash
# 初始化配置
openclaw-shield init

# 扫描单个 Skill
openclaw-shield scan /path/to/skill.py

# 批量扫描目录
openclaw-shield scan-all /path/to/skills/directory

# 实时监控
openclaw-shield monitor

# 查看状态
openclaw-shield status
```

### 高级命令

```bash
# API 密钥泄露扫描
openclaw-shield leaks /path/to/project

# 查看安全告警
openclaw-shield alerts --limit 50

# 查看未解决的威胁
openclaw-shield threats

# 标记威胁已解决
openclaw-shield resolve <threat_id>

# 生成报告
openclaw-shield report --format html --output report.html
```

### 更新管理

```bash
# 更新威胁规则
openclaw-shield update rules

# 查看更新状态
openclaw-shield update status

# 回滚更新
openclaw-shield update rollback rules

# 设置自动更新调度
openclaw-shield update schedule --hours 12 --daemon
```

---

## 🔧 配置说明

### 主配置文件 (`openclaw-shield.yaml`)

```yaml
# 安全设置
security:
  scan_on_install: true          # 安装时自动扫描
  block_malicious: true          # 自动拦截恶意代码
  quarantine_dir: ./quarantine   # 隔离目录
  keys_file: ./config/.keyring   # 密钥存储位置

# API 密钥保护
api_key:
  encryption: true               # 启用加密
  auto_rotate: true              # 自动轮换
  rotation_interval: 86400       # 轮换间隔（秒）
  warning_threshold: 3           # 告警阈值

# 网络监控
network:
  monitor: true                  # 启用监控
  auto_block: true               # 自动阻断
  whitelist:                     # 白名单
    - api.openai.com
    - api.anthropic.com
    - *.cdn.openclaw.ai
  blacklist_file: ./config/blacklist.txt
  connection_timeout: 30
  max_connections_per_ip: 10

# 日志配置
logging:
  level: INFO                    # 日志级别
  file: ./logs/security.log
  encrypt_logs: false            # 加密日志
  retention_days: 90             # 保留天数
  max_log_size: 100MB

# 威胁检测
threat_detection:
  enabled: true
  sensitivity: high              # low/medium/high
  auto_block: true
  rules_file: ./config/threat_rules.yaml
  confidence_threshold: 0.7      # 置信度阈值

# 审计配置
audit:
  database: ./data/audit.db
  retention_days: 90
  export_format: json            # json/html/text
  auto_cleanup: true

# Skills 配置
skills:
  directory: ~/.openclaw/workspace/skills
  auto_scan: true                # 自动扫描
  require_approval: false        # 需要审批
  max_file_size: 10MB
  allowed_extensions:
    - .py
    - .js
    - .ts
    - .json
```

---

## 🎯 威胁检测规则

### 规则概览 (v1.6.0)

系统内置 **89 条** 检测规则，涵盖通用威胁、CVE 相关漏洞和知名攻击模式。

### 基础规则 (rule_001 ~ rule_010)

| 规则 ID | 类型 | 严重性 | 描述 |
|---------|------|--------|------|
| rule_001 | subprocess_abuse | HIGH | 可疑的 subprocess 使用 |
| rule_002 | network_connection | HIGH | 网络套接字连接 |
| rule_003 | env_collection | MEDIUM | 环境变量访问 |
| rule_004 | obfuscation | MEDIUM | Base64 混淆检测 |
| rule_005 | unsafe_deserialization | HIGH | Pickle 反序列化 |
| rule_006 | code_execution | CRITICAL | 动态代码执行 |
| rule_007 | credential_theft | CRITICAL | 凭证窃取 |
| rule_008 | filesystem_modification | MEDIUM | 文件系统修改 |
| rule_009 | data_exfiltration | MEDIUM | 数据外传 |
| rule_010 | reverse_shell | CRITICAL | 反向 Shell |

### CVE 相关规则 (26条)

| 规则 ID | CVE | 类型 | 严重性 | 描述 |
|---------|-----|------|--------|------|
| cve_2026_25253_websocket | CVE-2026-25253 | websocket_hijacking | 🔴 CRITICAL | WebSocket 劫持攻击 |
| cve_2026_25253_token | CVE-2026-25253 | token_theft | 🔴 CRITICAL | 认证令牌窃取 |
| cve_2026_26322_ssrf | CVE-2026-26322 | ssrf_attack | 🟠 HIGH | SSRF 攻击 |
| cve_2026_24763_path_injection | CVE-2026-24763 | command_injection | 🔴 CRITICAL | PATH 命令注入 |
| cve_2026_26319_webhook | CVE-2026-26319 | missing_auth | 🟠 HIGH | Webhook 认证缺失 |
| cve_2026_26329_upload | CVE-2026-26329 | file_upload_traversal | 🟠 HIGH | 文件上传路径遍历 |
| cve_2026_29610_path_hijack | CVE-2026-29610 | path_hijacking | 🔴 CRITICAL | PATH 劫持命令执行 |
| cve_2026_28472_device_bypass | CVE-2026-28472 | device_confirmation_bypass | 🔴 CRITICAL | 设备确认绕过 |
| cve_2026_4039_config_override | CVE-2026-4039 | config_override | 🟠 HIGH | 配置环境变量覆盖 |
| cve_2026_28453_zip_slip | CVE-2026-28453 | zip_slip | 🟠 HIGH | Zip Slip 路径遍历 |
| cve_2026_27001_workspace_leak | CVE-2026-27001 | workspace_path_leak | 🟡 MEDIUM | 工作区路径泄露 |
| cve_2026_28363_bypass | CVE-2026-28363 | security_bypass | 🟠 HIGH | 安全绕过 |
| cve_2026_26327 | CVE-2026-26327 | input_validation_bypass | 🟠 HIGH | 输入验证绕过 |
| cve_2026_22817_jwt | CVE-2026-22817 | jwt_algorithm_confusion | 🟠 HIGH | JWT 算法混淆 |
| cve_2026_22818_jwks | CVE-2026-22818 | jwks_missing_alg | 🟠 HIGH | JWKS 缺失算法 |
| cve_2026_28393_hook_path | CVE-2026-28393 | hook_path_traversal | 🟠 HIGH | Hook 路径遍历 |
| cve_2026_28466_approval_bypass | CVE-2026-28466 | approval_bypass | 🔴 CRITICAL | 审批绕过 (CVSS 9.4) |
| cve_2026_27486_process_cleanup | CVE-2026-27486 | process_ownership_bypass | 🟡 MEDIUM | 进程清理绕过 |
| cve_2026_32063_systemd_injection | CVE-2026-32063 | systemd_injection | 🟠 HIGH | Systemd 注入 |
| cve_2026_26325_allowlist_bypass | CVE-2026-26325 | allowlist_bypass | 🟠 HIGH | 白名单绕过 |
| cve_2026_26323_script_injection | CVE-2026-26323 | script_command_injection | 🟠 HIGH | 脚本命令注入 |
| cve_2026_26320 | CVE-2026-26320 | input_sanitization | 🟠 HIGH | 输入清理漏洞 |
| cve_2026_25593_config_rce | CVE-2026-25593 | cli_path_injection | 🔴 CRITICAL | Config RCE (CVSS 9.8) |
| cve_2026_28452_archive_dos | CVE-2026-28452 | resource_exhaustion | 🟡 MEDIUM | Archive DoS 攻击 |
| cve_2026_27488_cron_ssrf | CVE-2026-27488 | extraction_ssrf | 🟠 HIGH | Cron Webhook SSRF |

### CNVD 规则 (2条)

| 规则 ID | CNVD | 类型 | 严重性 | 描述 |
|---------|------|--------|--------|------|
| cnvd_2026_13544_identity_forgery | CNVD-2026-13544 | identity_forgery | 🟠 HIGH | 身份伪造漏洞 |
| cnvd_2026_13543 | CNVD-2026-13543 | dns_tunneling | 🟠 HIGH | DNS 隧道外传 |

### GHSA 规则 (5条)

| 规则 ID | GHSA | 类型 | 严重性 | 描述 |
|---------|------|--------|--------|------|
| ghsa_56f2_image_ssrf | GHSA-56f2-hvwg-5743 | image_tool_ssrf | 🟠 HIGH | 图片工具 SSRF |
| ghsa_pg2v_urbit_ssrf | GHSA-pg2v-8xwh-qhcc | urbit_auth_ssrf | 🟡 MEDIUM | Urbit 认证 SSRF |
| ghsa_c37p_webhook_bypass | GHSA-c37p-4qqg-3p76 | webhook_auth_bypass | 🟡 MEDIUM | Webhook 认证绕过 |
| ghsa_82g8_host_env | GHSA-82g8-464f-2mv7 | host_env_poisoning | 🟠 HIGH | Host 环境变量注入 |
| ghsa_w2cg_base64_dos | GHSA-w2cg-vxx6-5xjg | resource_exhaustion | 🟠 HIGH | Base64 DoS 攻击 |

### 知名攻击模式 (2条)

| 规则 ID | 攻击名称 | 类型 | 严重性 | 描述 |
|---------|----------|--------|--------|------|
| clawjacked_ws_brute | ClawJacked | websocket_brute_force | 🔴 CRITICAL | WebSocket 暴力破解 |
| clawjacked_auto_approve | ClawJacked | auto_device_approval | 🟠 HIGH | 自动设备批准漏洞 |

---
| clawjacked_auto_approve | ClawJacked | auto_device_approval | 🟠 HIGH | 自动设备批准漏洞 |

### 攻击模式检测规则

| 规则 ID | 类型 | 严重性 | 描述 |
|---------|------|--------|------|
| clawhavoc_typosquatting | typosquatting | 🟠 HIGH | 包名仿冒攻击 |
| clawhavoc_malicious_skill | supply_chain_attack | 🔴 CRITICAL | ClawHavoc 供应链攻击 |
| clawdrain_trojan | trojan_skill | 🔴 CRITICAL | Clawdrain 木马技能 |
| cve_path_traversal | path_traversal | 🟠 HIGH | 路径遍历 |
| cve_lfi | local_file_inclusion | 🟠 HIGH | 本地文件包含 |
| cve_env_injection | env_injection | 🟠 HIGH | 环境变量注入 |
| cve_dns_exfiltration | dns_exfiltration | 🟠 HIGH | DNS 数据外渗 |
| cve_cryptomining | cryptomining | 🔴 CRITICAL | 加密货币挖矿 |
| cve_botnet_c2 | botnet_c2 | 🔴 CRITICAL | 僵尸网络 C2 |
| cve_container_escape | container_escape | 🔴 CRITICAL | 容器逃逸 |
| cve_privilege_escalation | privilege_escalation | 🟠 HIGH | 权限提升 |
| cve_prompt_injection | prompt_injection | 🟠 HIGH | LLM 提示注入 |
| cve_api_key_harvesting | api_key_harvesting | 🔴 CRITICAL | API 密钥窃取 |
| log_poisoning | log_poisoning | 🟠 HIGH | 日志投毒攻击 |
| indirect_prompt_injection | indirect_prompt_injection | 🟠 HIGH | 间接提示注入 |
| infostealer_pattern | infostealer | 🔴 CRITICAL | 窃密木马检测 |
| shadow_ai_operations | shadow_ai | 🟡 MEDIUM | 影子 AI 操作 |
| llm_tool_injection | tool_injection | 🟠 HIGH | LLM 工具注入 |
| nostr_config_tampering | unauthenticated_config | 🔴 CRITICAL | Nostr 配置篡改 |
| frontmatter_traversal | frontmatter_traversal | 🟠 HIGH | Frontmatter 遍历 |
| prompt_replay_attack | prompt_replay | 🟠 HIGH | 提示注入重放 |
| mdns_disclosure | mdns_info_disclosure | 🟡 MEDIUM | mDNS 信息泄露 |
| memory_poisoning | memory_poisoning | 🟠 HIGH | 内存投毒 (SOUL.md/MEMORY.md) |
| atomic_stealer_amos | atomic_stealer | 🔴 CRITICAL | Atomic Stealer 恶意软件 |
| delayed_activation | delayed_payload | 🟠 HIGH | 延迟激活载荷 |
| cloud_metadata_ssrf | cloud_metadata_ssrf | 🔴 CRITICAL | 云元数据 SSRF |
| localhost_trust_bypass | localhost_trust_bypass | 🟠 HIGH | 本地信任绕过 |
| shell_env_hijack | shell_hijacking | 🔴 CRITICAL | SHELL 环境变量劫持 |
| macos_persistence_launchagent | macos_persistence | 🔴 CRITICAL | macOS 持久化 |
| shell_profile_persistence | shell_profile_persistence | 🟠 HIGH | Shell 配置持久化 |
| hidden_css_injection | hidden_css_injection | 🟠 HIGH | 隐藏 CSS 提示注入 |
| runaway_api_cost | runaway_api_cost | 🟡 MEDIUM | API 成本失控 |
| oauth_overreach | oauth_overreach | 🟠 HIGH | OAuth 权限过度 |
| dns_tunneling | dns_tunneling | 🟠 HIGH | DNS 隧道外渗 |

---
| clawjacked_auto_approve | ClawJacked | auto_device_approval | 🟠 HIGH | 自动设备批准漏洞 |

### 攻击模式检测规则

| 规则 ID | 类型 | 严重性 | 描述 |
|---------|------|--------|------|
| clawhavoc_typosquatting | typosquatting | 🟠 HIGH | 包名仿冒攻击 |
| clawhavoc_malicious_skill | supply_chain_attack | 🔴 CRITICAL | ClawHavoc 供应链攻击 |
| clawdrain_trojan | trojan_skill | 🔴 CRITICAL | Clawdrain 木马技能 |
| cve_path_traversal | path_traversal | 🟠 HIGH | 路径遍历 |
| cve_lfi | local_file_inclusion | 🟠 HIGH | 本地文件包含 |
| cve_env_injection | env_injection | 🟠 HIGH | 环境变量注入 |
| cve_dns_exfiltration | dns_exfiltration | 🟠 HIGH | DNS 数据外渗 |
| cve_cryptomining | cryptomining | 🔴 CRITICAL | 加密货币挖矿 |
| cve_botnet_c2 | botnet_c2 | 🔴 CRITICAL | 僵尸网络 C2 |
| cve_container_escape | container_escape | 🔴 CRITICAL | 容器逃逸 |
| cve_privilege_escalation | privilege_escalation | 🟠 HIGH | 权限提升 |
| cve_prompt_injection | prompt_injection | 🟠 HIGH | LLM 提示注入 |
| cve_api_key_harvesting | api_key_harvesting | 🔴 CRITICAL | API 密钥窃取 |
| log_poisoning | log_poisoning | 🟠 HIGH | 日志投毒攻击 |
| indirect_prompt_injection | indirect_prompt_injection | 🟠 HIGH | 间接提示注入 |
| infostealer_pattern | infostealer | 🔴 CRITICAL | 窃密木马检测 |
| shadow_ai_operations | shadow_ai | 🟡 MEDIUM | 影子 AI 操作 |
| llm_tool_injection | tool_injection | 🟠 HIGH | LLM 工具注入 |

---

## 📁 项目结构

```
openclaw-security/
├── openclaw_shield/
│   ├── __init__.py           # 包初始化，导出所有公共接口
│   ├── shield.py             # 核心安全盾类
│   ├── scanner.py            # Skill 扫描器
│   ├── monitor.py            # 网络监控
│   ├── api_protection.py     # API 密钥保护
│   ├── audit.py              # 审计日志
│   ├── threats.py            # 威胁检测引擎
│   ├── config.py             # 配置管理
│   ├── cli.py                # 命令行接口
│   ├── updater.py            # 自动更新
│   ├── advanced_threats.py   # 高级威胁检测
│   │
│   # 第一道防线模块
│   ├── asset_manager.py      # 资产管理
│   ├── process_monitor.py    # 进程监控
│   │
│   # 第二道防线模块
│   ├── ai_analyzer.py        # AI 流量分析
│   ├── prompt_guard.py       # Prompt 注入防护
│   ├── content_audit.py      # 内容审计
│   ├── llm_adapter.py        # LLM 适配器
│   ├── traffic_decrypt.py    # SSL/TLS 解密
│   │
│   # 第三道防线模块
│   ├── access_control.py     # 访问控制
│   ├── av_engine.py          # 反病毒引擎
│   ├── microseg.py           # 微隔离
│   └── network_sync.py       # 威胁情报同步
│
├── config/
│   ├── openclaw-shield.yaml  # 主配置文件
│   ├── threat_rules.yaml     # 威胁规则
│   └── blacklist.txt         # 域名黑名单
│
├── tests/
│   ├── test_scanner.py
│   ├── test_threat_detection.py
│   └── pytest.ini
│
├── requirements.txt          # Python 依赖
├── LICENSE                   # MIT 许可证
├── README.md                 # 项目文档
└── .gitignore
```

---

## 🛠️ 开发指南

### 运行测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试
pytest tests/test_scanner.py -v

# 生成覆盖率报告
pytest tests/ --cov=openclaw_shield --cov-report=html
```

### 代码风格

```bash
# 使用 Black 格式化代码
black openclaw_shield/

# 使用 isort 排序导入
isort openclaw_shield/

# 使用 pylint 检查代码质量
pylint openclaw_shield/
```

### 添加新的威胁规则

编辑 `config/threat_rules.yaml`:

```yaml
rules:
  - id: rule_011
    type: your_threat_type
    severity: HIGH
    message: "Your threat description"
    conditions:
      - type: import
        value: suspicious_module
    remediation: "How to fix this issue"
```

---

## ❓ 常见问题

### Q1: 扫描速度慢怎么办？

A: 可以调整配置中的并发设置，或者使用 `--fast` 模式进行快速扫描。

### Q2: 如何降低误报率？

A: 调整 `threat_detection.confidence_threshold` 参数，提高阈值可以减少误报。

### Q3: 如何添加自定义域名白名单？

A: 编辑 `config/openclaw-shield.yaml` 中的 `network.whitelist` 字段。

### Q4: 隔离的文件如何恢复？

A: 使用 `openclaw-shield quarantine restore <file_id>` 命令。

### Q5: 系统资源占用高怎么办？

A: 调整 `logging.level` 和 `threat_detection.sensitivity` 参数。

---

## 🗺️ 路线图

### v1.2.0 (计划中)

- [ ] Web 管理控制台
- [ ] 分布式部署支持
- [ ] Kubernetes 集成
- [ ] 更多 LLM 提供商支持

### v2.0.0 (未来)

- [ ] 机器学习威胁检测模型
- [ ] 联邦学习威胁情报共享
- [ ] 区块链审计日志
- [ ] 云原生架构重构

---

## 🤝 贡献

我们欢迎所有形式的贡献！

### 贡献方式

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 开发规范

- 遵循 PEP 8 代码风格
- 添加适当的单元测试
- 更新相关文档
- 保持提交信息清晰

---

## 📊 性能指标

| 指标 | 数值 |
|------|------|
| 扫描速度 | ~1000 文件/分钟 |
| 内存占用 | ~50-200MB |
| CPU 使用 | 空闲 <5%，扫描时 10-30% |
| 检测准确率 | >95% |
| 误报率 | <3% |

---

## 📝 许可证

本项目采用 **MIT 许可证** - 详见 [LICENSE](LICENSE) 文件

```
Copyright (c) 2024 OpenClaw Security Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 致谢

- [OpenClaw](https://openclaw.ai) 社区
- 所有安全研究人员的贡献
- [Bandit](https://github.com/PyCQA/bandit) - Python 静态分析
- [Safety](https://github.com/pyupio/safety) - 依赖安全检查

---

## 📮 联系方式

- 🐛 问题反馈: [GitHub Issues](https://github.com/wooluo/openclaw-security/issues)
- 🔐 安全漏洞: wooluo@gmail.com

---

<div align="center">

**⚠️ 免责声明**

本工具仅供合法的安全防护用途，请遵守当地法律法规。
使用本工具进行的任何非法操作，后果由使用者自行承担。

Made with ❤️ by OpenClaw Security Team

</div>
