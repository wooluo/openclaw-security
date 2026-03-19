# OpenClaw Security Shield 🔒

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)]()

**OpenClaw Security Shield** 是一个专为 OpenClaw 设计的全面安全防护系统，用于检测和防御恶意 Skills、保护 API Key、监控网络流量、审计操作日志等。

## 🚨 安全背景

根据安全审计报告：
- 已发现 **341+ 恶意 Skills**
- 近 **20%** 的 Skills 存在安全问题
- 恶意插件可能：窃取 API Key、开启反向 Shell、远程控制设备

## ✨ 核心功能

### 1. Skill 安全扫描器
- 静态代码分析，检测恶意模式
- 危险函数调用检测（eval、exec、subprocess 等）
- 敏感信息泄露检测
- 网络连接可疑行为分析

### 2. API Key 保护
- 环境变量加密存储
- 运行时内存保护
- 泄露检测与告警
- 自动轮换机制

### 3. 网络流量监控
- 实时流量分析
- 可疑连接检测
- 域名黑名单验证
- SSRF 攻击防护

### 4. 权限管理
- 最小权限原则
- 沙箱隔离执行
- 能力（Capability）控制
- 访问控制列表（ACL）

### 5. 日志审计
- 完整操作记录
- 异常行为告警
- 审计日志加密
- 合规性报告生成

### 6. 实时威胁检测
- 行为分析引擎
- 异常检测算法
- 威胁情报集成
- 自动响应机制

## 📦 安装

```bash
# 克隆仓库
git clone https://github.com/wooluo/openclaw-SEC.git
cd openclaw-SEC

# 安装依赖
pip install -r requirements.txt

# 初始化配置
python -m openclaw_shield --init
```

## 🚀 快速开始

### 基本使用

```python
from openclaw_shield import SecurityShield

# 初始化安全防护
shield = SecurityShield()

# 扫描 Skill
result = shield.scan_skill("/path/to/skill.py")
print(result)

# 启动实时监控
shield.start_monitoring()
```

### 命令行工具

```bash
# 扫描单个 Skill
openclaw-shield scan /path/to/skill.py

# 扫描所有 Skills
openclaw-shield scan-all /path/to/skills/directory

# 启动守护进程
openclaw-shield daemon start

# 查看安全报告
openclaw-shield report

# 实时监控
openclaw-shield monitor
```

## 📖 详细文档

- [安装指南](docs/installation.md)
- [配置说明](docs/configuration.md)
- [API 文档](docs/api.md)
- [安全最佳实践](docs/best-practices.md)
- [威胁检测规则](docs/threat-rules.md)

## 🔧 配置示例

```yaml
# openclaw-shield.yaml
security:
  scan_on_install: true
  block_malicious: true
  quarantine_dir: ./quarantine

api_key:
  encryption: true
  auto_rotate: true
  rotation_interval: 86400  # 24小时

network:
  monitor: true
  whitelist:
    - api.openclaw.ai
    - *.cdn.openclaw.ai
  blacklist_file: ./config/blacklist.txt

logging:
  level: INFO
  file: ./logs/security.log
  encrypt_logs: true
  retention_days: 90

threat_detection:
  enabled: true
  sensitivity: high
  auto_block: true
```

## 🛡️ 安全特性

- **零信任架构**：默认拒绝所有未验证的操作
- **深度防御**：多层安全机制
- **最小权限**：Skills 只能访问必要资源
- **审计追踪**：完整的操作记录
- **自动响应**：检测到威胁自动处理

## 📊 安全报告示例

```
═══════════════════════════════════════════════════════
         OpenClaw Security Shield - 扫描报告
═══════════════════════════════════════════════════════

文件: malicious_skill.py
风险等级: 🔴 高危 (CRITICAL)

检测到的问题:
  ✗ 发现代码执行函数: eval()
  ✗ 检测到反向 Shell: socket.connect()
  ✗ 发现敏感信息收集: os.environ
  ✗ 可疑网络连接: 185.xxx.xxx.xxx

建议操作:
  → 立即隔离此 Skill
  → 检查其他相关 Skills
  → 审查系统访问日志

═══════════════════════════════════════════════════════
```

## 🤝 贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📝 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 🙏 致谢

- OpenClaw 社区
- 所有安全研究人员
- 贡献者列表

## 📮 联系方式

- 问题反馈: [GitHub Issues](https://github.com/wooluo/openclaw-SEC/issues)
- 安全漏洞: wooluo@gmail.com

---

**⚠️ 免责声明**: 本工具仅供合法的安全防护用途，请遵守当地法律法规。
