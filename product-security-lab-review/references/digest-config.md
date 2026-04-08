# Digest Config

使用方式：

```powershell
python scripts/build_security_digest.py --config <file> --output-root <dir> --format markdown
```

这个配置文件用于批量执行两类采集任务：

- `release_targets`：厂商发布页 / 公告页 / Feed
- `cve_queries`：NVD + CISA KEV 漏洞查询

## 顶层字段

- `profile_name`
  可选，当前配置名称
- `release_targets`
  可选，厂商发布源数组，格式见 [vendor-source-config.md](vendor-source-config.md)
- `cve_queries`
  可选，漏洞查询数组
- `report`
  可选，日报展示设置

## cve_queries 字段

每个条目支持：

- `name`
  必填，查询名称
- `days`
  可选，最近 N 天窗口
- `start_date`
  可选，起始时间
- `end_date`
  可选，结束时间
- `keywords`
  可选，关键字数组，对应 NVD `keywordSearch`
- `cpe_name`
  可选，NVD `cpeName`
- `severity`
  可选，`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`
- `kev_only`
  可选，只保留 KEV 条目
- `limit`
  可选，过滤后的最大返回数量
- `results_per_page`
  可选，NVD 单页大小
- `max_pages`
  可选，分页上限
- `sleep_seconds`
  可选，请求分页之间的等待时间
- `api_key_env`
  可选，NVD API Key 的环境变量名
- `timeout`
  可选，单查询超时秒数

## report 字段

- `title`
  日报标题
- `max_release_items`
  日报中展示的新增发布条目数量
- `max_cve_items`
  每个 CVE 查询展示的新增漏洞数量

## 输出结构

`--output-root` 下只保留两个业务目录：

- `日报内容`
  保存按日期归档的历史日报、`latest.md` 和 `.digest-state.json`
- `运行日志`
  由 `run_security_digest.ps1` 按日期写入运行日志

说明：

- `.digest-state.json` 是隐藏状态文件，用来和上次结果比较
- 日报只突出本次新发现的发布项和漏洞项
- 不再依赖旧版 `snapshots/`、`reports/`、`latest/` 目录结构
- 历史日报文件命名为 `YYYY-MM-DD\安全日报-YYYY-MM-DD-HH-MM-SS.md`
- 历史日志文件命名为 `YYYY-MM-DD\运行日志-YYYY-MM-DD-HH-MM-SS.log`

## 示例

```json
{
  "profile_name": "daily-security-digest",
  "release_targets": [
    {
      "vendor": "Python",
      "product": "Python Blog",
      "url": "https://blog.python.org/",
      "mode": "auto",
      "keywords": ["release", "security"],
      "limit": 5
    }
  ],
  "cve_queries": [
    {
      "name": "kev-last-1-day",
      "days": 1,
      "kev_only": true,
      "limit": 50
    },
    {
      "name": "high-last-1-day",
      "days": 1,
      "severity": "HIGH",
      "limit": 50
    }
  ],
  "report": {
    "title": "Daily Security Digest",
    "max_release_items": 20,
    "max_cve_items": 20
  }
}
```
