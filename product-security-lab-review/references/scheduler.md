# Daily Scheduling

使用 `scripts/run_security_digest.ps1` 和 `scripts/register_daily_digest_task.ps1` 可以把日报任务挂到 Windows 计划任务。

## 相关脚本

- `scripts/run_security_digest.ps1`
  执行 `build_security_digest.py`，并把运行日志写到 `<output-root>\运行日志`
- `scripts/register_daily_digest_task.ps1`
  为当前登录用户注册一个每日任务

## 注册任务

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\register_daily_digest_task.ps1 `
  -ConfigPath C:\path\to\digest-config.json `
  -OutputRoot C:\path\to\security-output `
  -ScheduleTime 22:00 `
  -TaskName "Daily Security Digest" `
  -Force
```

默认行为：

- 任务路径：`\Codex\`
- 运行模式：当前用户，交互式登录令牌

这种模式的优点是：

- 不需要额外保存密码
- 配置简单

需要注意的是：

- 只有当前用户会话可用时才会执行
- 它不是后台服务
- 如果机器关机、睡眠或者没有可用会话，任务可能错过触发时间

## 手动执行一次

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_security_digest.ps1 `
  -ConfigPath C:\path\to\digest-config.json `
  -OutputRoot C:\path\to\security-output
```

## 直接触发已注册任务

```powershell
Start-ScheduledTask -TaskPath "\Codex\" -TaskName "Daily Security Digest"
```

## 输出位置

- 日报：`<output-root>\日报内容`
- 日志：`<output-root>\运行日志`

`日报内容` 下会保留：

- 历史日报 `YYYY-MM-DD\安全日报-YYYY-MM-DD-HH-MM-SS.md`
- 最新日报 `latest.md`
- 隐藏状态文件 `.digest-state.json`

`运行日志` 下会保留：

- 运行日志 `YYYY-MM-DD\运行日志-YYYY-MM-DD-HH-MM-SS.log`
