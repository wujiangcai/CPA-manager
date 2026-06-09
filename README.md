# zny CPA Monitor

新手请先看：[使用教程.md](使用教程.md)

CPA 本地监测面板，用来查看 CPA 总请求、总 token、等效金额，以及本地 auth 号池状态、Plan、额度、失效账号和自动清理日志。

交流群：QQ 454765232

## 功能

- CPA 总消耗监控：请求数、token、模型、耗时、首字时间、按时间范围统计金额。
- 账号池监测：读取 CPA auth JSON，显示 Plus / Pro / Team、额度状态、过期状态。
- 额度查询：支持 direct auth 方式直接查 ChatGPT 额度。
- 清理失效号：支持 401 / 402 / 403 / 404 / 503、无额度、过期、缺 token 等账号清理。
- 低于 5% 删除可单独开关，关闭后只提示不删除。
- 合并 dashboard：默认 `http://127.0.0.1:18321/`。

## 目录

```text
.
├─ RUN_ON_YOUR_PC/                 # CPA 总消耗监控
├─ account_pool_monitor/           # CPA auth 号池监控
├─ cpa_detection_dashboard.py      # 合并入口
├─ start_all.ps1                   # 启动全部
├─ stop_all.ps1                    # 关闭全部
├─ start_all.cmd                   # Windows 双击启动全部
└─ stop_all.cmd                    # Windows 双击关闭全部
```

## 快速开始

1. 安装 Python 3.10+。
2. 复制配置文件：

```powershell
copy RUN_ON_YOUR_PC\monitor_config.example.json RUN_ON_YOUR_PC\monitor_config.json
copy account_pool_monitor\monitor_config.example.json account_pool_monitor\monitor_config.json
```

3. 修改 `RUN_ON_YOUR_PC\monitor_config.json`：

```json
{
  "upstream_base_url": "http://127.0.0.1:8317/v1",
  "upstream_api_key": "",
  "upstream_api_key_env": "CPA_MONITOR_UPSTREAM_API_KEY"
}
```

如果你的 CPA 需要本地 key，推荐用环境变量：

```powershell
$env:CPA_MONITOR_UPSTREAM_API_KEY="your-cpa-local-key"
```

4. 修改 `account_pool_monitor\monitor_config.json`：

```json
{
  "auth_dir": "D:/YOUR_CPA/auth",
  "cpa_base_url": "http://127.0.0.1:8317"
}
```

5. 启动：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\start_all.ps1
```

或双击 `start_all.cmd`。

打开：

- 合并面板：`http://127.0.0.1:18321/`
- 总消耗监控：`http://127.0.0.1:18319/`
- 号池监控：`http://127.0.0.1:18320/`

关闭：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\stop_all.ps1
```

或双击 `stop_all.cmd`。

## 安全提醒

不要把下面这些文件提交或发给别人：

- `monitor_config.json`
- `monitor_data/`
- `*.log`
- 你的 CPA `auth` 目录
- 任何带 `access_token` / `refresh_token` / `id_token` / API key 的文件

开源包里只应该包含 `*.example.json`，不要包含真实配置。

## 价格表

`RUN_ON_YOUR_PC/model_prices.json` 可自行修改。不同 CPA 模型名可能和官方模型名不完全一致，金额仅按价格表重算。
