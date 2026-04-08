# Product Security Lab Review

## 简介

`product-security-lab-review` 是一套面向防御场景的 Codex skill，用来做三类事情：

- 收集厂商官方发布页、安全公告页和 Feed 中的新内容
- 拉取最新 CVE、NVD、CISA KEV 信息并做关联
- 在本地授权实验室里生成日报或安全摘要

这套 skill 不用于攻击自动化，不提供 exploit、payload、认证绕过、持久化或公网上目标测试能力。

## 目录结构

- [SKILL.md](C:/Users/linu/.codex/skills/product-security-lab-review/SKILL.md)
  机器可读的 skill 说明和触发规则
- [README.md](C:/Users/linu/.codex/skills/product-security-lab-review/README.md)
  用户可读说明
- [scripts/common.py](C:/Users/linu/.codex/skills/product-security-lab-review/scripts/common.py)
  通用 HTTP、时间和输出辅助函数
- [scripts/fetch_vendor_releases.py](C:/Users/linu/.codex/skills/product-security-lab-review/scripts/fetch_vendor_releases.py)
  厂商发布页、公告页、RSS/Atom 采集
- [scripts/fetch_latest_cves.py](C:/Users/linu/.codex/skills/product-security-lab-review/scripts/fetch_latest_cves.py)
  NVD CVE 拉取并合并 CISA KEV
- [scripts/build_security_digest.py](C:/Users/linu/.codex/skills/product-security-lab-review/scripts/build_security_digest.py)
  批量采集、状态对比、日报生成
- [scripts/run_security_digest.ps1](C:/Users/linu/.codex/skills/product-security-lab-review/scripts/run_security_digest.ps1)
  PowerShell 包装器，负责执行并落日志
- [scripts/register_daily_digest_task.ps1](C:/Users/linu/.codex/skills/product-security-lab-review/scripts/register_daily_digest_task.ps1)
  Windows 每日计划任务注册脚本
- [references/vendor-source-config.md](C:/Users/linu/.codex/skills/product-security-lab-review/references/vendor-source-config.md)
  厂商信息源配置格式
- [references/digest-config.md](C:/Users/linu/.codex/skills/product-security-lab-review/references/digest-config.md)
  日报配置格式
- [references/scheduler.md](C:/Users/linu/.codex/skills/product-security-lab-review/references/scheduler.md)
  Windows 调度说明

## 核心能力

### 1. 厂商发布页采集

支持：

- 官方发布页
- 官方安全公告页
- RSS / Atom Feed
- HTML 页面链接回退提取

适合收集：

- 新版本发布
- 安全修复发布
- 安全公告
- 官方 CVE 公告页

### 2. 最新漏洞关联

当前实现使用：

- NVD CVE 2.0 API
- CISA KEV JSON

输出字段包括：

- `cve_id`
- `published`
- `severity`
- `score`
- `summary`
- `affected_versions`
- `mechanism_summary`
- `advisory_urls`
- `public_poc_urls`

### 3. 日报生成

支持：

- 多个发布源批量采集
- 多个 CVE 查询批量执行
- 与上次状态自动对比，只突出新增项
- 生成 Markdown 日报

默认输出结构只保留两个业务目录：

- `日报内容`
- `运行日志`

`日报内容` 下会写入：

- 按日期归档的历史日报 `YYYY-MM-DD\安全日报-YYYY-MM-DD-HH-MM-SS.md`
- 最新日报 `latest.md`
- 隐藏状态文件 `.digest-state.json`

`运行日志` 下会写入：

- 按日期归档的运行日志 `YYYY-MM-DD\运行日志-YYYY-MM-DD-HH-MM-SS.log`

### 4. 每日定时执行

支持：

- PowerShell 手动执行
- Windows Task Scheduler 定时执行
- 当前登录用户的交互式计划任务模式

## 常用命令

### 单独采集厂商发布

```powershell
python C:\Users\linu\.codex\skills\product-security-lab-review\scripts\fetch_vendor_releases.py `
  --url "https://blog.python.org/" `
  --vendor "Python" `
  --product "Python Blog" `
  --keyword release `
  --limit 5 `
  --format markdown
```

### 单独拉取最新 CVE

```powershell
python C:\Users\linu\.codex\skills\product-security-lab-review\scripts\fetch_latest_cves.py `
  --days 1 `
  --kev-only `
  --limit 20 `
  --format markdown
```

### 生成日报

```powershell
python C:\Users\linu\.codex\skills\product-security-lab-review\scripts\build_security_digest.py `
  --config C:\path\to\digest-config.json `
  --output-root C:\path\to\security-output `
  --format markdown
```

### PowerShell 包装运行

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\linu\.codex\skills\product-security-lab-review\scripts\run_security_digest.ps1" `
  -ConfigPath C:\path\to\digest-config.json `
  -OutputRoot C:\path\to\security-output
```

### 注册每日任务

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\linu\.codex\skills\product-security-lab-review\scripts\register_daily_digest_task.ps1" `
  -ConfigPath C:\path\to\digest-config.json `
  -OutputRoot C:\path\to\security-output `
  -ScheduleTime 22:00 `
  -TaskName "Daily Security Digest" `
  -Force
```

## 日报字段

每条漏洞默认包含：

- 漏洞详情链接
- 漏洞介绍
- 目标版本
- 利用原理的高层摘要
- 厂商/官方参考链接
- 已公开 PoC 的公开参考链接
- 其他参考链接

说明：

- `利用原理` 只保留防御向高层描述，不输出攻击步骤
- `已公开 PoC` 只给公开参考链接，不复制代码

## 安全边界

禁止内容：

- exploit 开发
- payload 生成
- 认证绕过
- 暴力破解
- 持久化
- 横向移动
- 对公网或第三方目标扫描

允许内容：

- 官方信息收集
- CVE 关联和版本比对
- 配置审计
- 依赖分析
- 本地实验室中的非破坏性验证
- 修复建议和摘要报告

## 维护建议

- 优先使用厂商官方站点，不要默认接入镜像站或转载站
- 新增信息源前，先单独测试页面稳定性和响应速度
- 如某个源经常超时，单独降频或从配置中移除
- 定期检查 NVD API 和 CISA KEV 源地址是否变化
