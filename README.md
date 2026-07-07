# x-cfui — Xray 中继管理面板

> 一款轻量级、全功能、单文件的 Xray 中继管理面板。  
> 一通操作即可完成部署，开箱即用。

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![Xray](https://img.shields.io/badge/Xray-v26.3.27-green)](https://github.com/XTLS/Xray-core)

---

## 📸 截图

> TODO: 请在此处添加面板截图

| 主界面 | 节点管理 | 客户端设置 |
|-------|---------|-----------|
| ![screenshot](docs/screenshots/main.png) | ![screenshot](docs/screenshots/nodes.png) | ![screenshot](docs/screenshots/clients.png) |

---

## ✨ 特色

### 全功能面板
- **单文件架构** — 整个面板只有一个 `app.py`（Python Flask），后端 + 前端 + HTML/CSS/JS + 国际化全部内聚
- **轻量极速** — 源文件仅 217KB，零外部前端依赖
- **一键部署** — 一条命令完成面板 + Xray + 防火墙 + BBR + fail2ban 全套部署
- **离线可用** — 所有依赖（Xray 二进制、Python 库）打包内嵌，无需网络下载

### 多节点中继管理
- 管理 **CN 入口 / SG 出口 / RU 出口** 三台服务器
- 支持 **VMess / VLESS / Shadowsocks / Trojan / Hysteria2 / WireGuard** 等多种协议
- 自动生成 **Reality** 配置（TLS 指纹伪装）
- 出口节点 BBR 状态一键验证
- 节点名称可编辑

### 安全防护
- **面板登录暴力破解防护** — 60 秒内 17 次失败自动封禁 17200 秒（参数可配）
- **SSH 防暴（fail2ban）** — 三台服务器统一配置，参数与面板同步
- **UFW 防火墙** — 端口规则自动管理
- **SSH 安全加固** — 一键启用仅密钥登录、修改端口

### 系统运维
- **整机配置备份/恢复** — 一键备份面板 + 系统全部配置（455 项），支持离线搬家
- **官方出厂模板** — 可移植的分流/站点配置模板，不含服务器身份凭据
- **开机自启核验** — 一键检查三台服务器服务状态
- **端口占用检测** — 实时查看端口使用情况
- **GeoIP 数据库管理** — 在线更新 geoip.dat / geosite.dat

### 客户端连接
- 支持多域名/多地址管理（增删）
- 自动生成各协议连接串 + QR 码
- 支持 PC / 安卓 / iOS 客户端订阅
- 中英文界面一键切换

---

## 🚀 快速开始

### 方式一：从源码直接部署（推荐，全离线）

```bash
git clone https://github.com/你的用户名/x-cfui.git
cd x-cfui/xray_admin
sudo bash deploy_xcfui.sh
```

> `deploy_xcfui.sh` 已内嵌 Xray 二进制 + segno 库，全程离线可用，无需任何网络下载。

### 方式二：下载烘焙成品

从 [GitHub Releases](https://github.com/你的用户名/x-cfui/releases) 下载 `xcfui-deploy.sh`：

```bash
sudo bash xcfui-deploy.sh
```

两者完全相同，只是烘焙成品是 base64 封装的单文件。

### 方式三：搬家恢复

```bash
# 从 Release 下载 xcfui-restore.sh（备份包已内嵌）
sudo bash xcfui-restore.sh
```

脚本自动完成：
- ✅ 安装 Xray + nginx + ufw + fail2ban
- ✅ 随机生成面板入口、管理员账号/密码、客户端 UUID
- ✅ 配置 BBR TCP 加速
- ✅ 配置防火墙放行端口
- ✅ 配置 fail2ban 暴力破解防护
- ✅ 注册 systemd 服务，开机自启
- ✅ 启动面板（默认端口 5000）

部署完成后访问：`http://服务器IP:5000/随机入口Token`

### 搬家恢复（从旧机迁移到新机）

```bash
# 单文件，备份包已内嵌
sudo bash xcfui-restore.sh
```

---

## 🏗 架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  客户端     │────▶│  CN 入口    │────▶│  SG 出口    │
│ (v2rayNG)   │     │  (面板)     │     │  (中继)     │
│ (Shadowrocket) │   │  xray      │     │  xray       │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  RU 出口    │
                    │  (中继)     │
                    └─────────────┘
```

- **CN 入口**：面板所在服务器，客户端直接连接，负责流量分发
- **SG / RU 出口**：中继节点，处理实际代理请求

---

## 🧩 技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | Python Flask（内嵌于 app.py） |
| 前端 | 原生 HTML + CSS + JavaScript（无框架） |
| 二维码 | segno (Python) |
| 国际化 | 内建中/英双语言（i18n） |
| 代理核心 | Xray-core v26.3.27 |
| 防火墙 | ufw + nftables |
| 防护 | fail2ban |
| TCP 加速 | BBR |

---

## 📦 项目结构

```
xray_admin/
├── app.py                  ← 面板核心源码（单文件全栈）
├── deploy_xcfui.sh         ← 部署脚本源码
├── restore_xcfui.sh        ← 恢复脚本源码
├── backup_xcfui.sh         ← 备份脚本源码
├── make_xcfui.py           ← 单文件脚本烘焙工具
├── audit_panel.py          ← 面板静态审计工具
├── smoke_live.py           ← 真机运行时冒烟测试
├── deploy_panel.py         ← 面板推送部署工具
├── xcfui-deploy.sh         ← 烘焙产物：一键部署（24MB，含 Xray 内嵌）
├── xcfui-restore.sh        ← 烘焙产物：一键搬家（25MB，含备份包内嵌）
├── pack_xcfui.py           ← 备份包重打包工具
└── ssh_keys_backup/        ← 服务器管理密钥（请勿公开）
```

---

## 🔧 开发

```bash
# 1. 修改 app.py
vim app.py

# 2. 语法检查
python3 -m py_compile app.py

# 3. 静态审计
python3 audit_panel.py

# 4. 烘焙单文件脚本（可选）
python3 make_xcfui.py

# 5. 推送到服务器测试
python3 deploy_panel.py
```

---

## 📋 To-do / Roadmap

- [x] 面板基础框架（节点管理、客户端链接、QR 码）
- [x] 多节点管理与状态监测
- [x] 暴力破解防护 + fail2ban 集成
- [x] 整机配置备份/恢复/搬家
- [x] SSH 安全加固
- [x] 开机自启核验
- [x] 导航分类 UI 重构
- [x] 客户端多地址支持
- [x] 离线部署（内嵌 Xray + segno）
- [x] 服务状态同步搬家
- [ ] ……

---

## ⚖️ License

[MIT](LICENSE)

Copyright (c) 2026

---

## 🙏 致谢

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- [segno](https://github.com/heuer/segno)
