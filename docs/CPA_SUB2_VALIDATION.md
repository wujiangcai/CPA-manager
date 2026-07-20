# CPA / Sub2 JSON 导入验活说明

本文说明号池监控如何识别 CPA 与 sub2api JSON、如何执行验活，以及结果文件的含义。

格式兼容参考：[GPTSession2CPAandSub2API](https://github.com/yynxxxxx/GPTSession2CPAandSub2API)。

## 1. 使用入口

1. 启动项目后打开 `http://127.0.0.1:18320/`。
2. 找到“CPA / Sub2 JSON 一键验活”。
3. 选择 `.json`、`.jsonl` 或 `.ndjson` 文件。
4. 点击“选择文件并开始检测”。

页面会显示识别数量、CPA/Sub2 格式统计、上传数量、存活数量、死亡数量以及归档下载地址。

## 2. 支持的 CPA 格式

CPA auth 的 token 和账号信息位于顶层：

```json
{
  "type": "codex",
  "account_id": "00000000-0000-4000-9000-000000000000",
  "chatgpt_account_id": "00000000-0000-4000-9000-000000000000",
  "email": "example@example.com",
  "plan_type": "plus",
  "access_token": "example-access-token",
  "refresh_token": "",
  "session_token": "example-session-token",
  "expired": "2099-01-01T00:00:00Z"
}
```

支持单个对象、对象数组、`auths` / `data` / `items` 等容器以及 NDJSON。

## 3. 支持的 Sub2 格式

sub2api 导出文件使用 `exported_at` / `proxies` / `accounts` 结构，账号凭证位于 `credentials`：

```json
{
  "exported_at": "2026-07-20T00:00:00Z",
  "proxies": [],
  "accounts": [
    {
      "name": "Example Account",
      "platform": "openai",
      "type": "oauth",
      "concurrency": 10,
      "priority": 1,
      "credentials": {
        "access_token": "example-access-token",
        "chatgpt_account_id": "00000000-0000-4000-9000-000000000000",
        "chatgpt_user_id": "user-example",
        "email": "example@example.com",
        "expires_at": "2099-01-01T00:00:00Z",
        "expires_in": 3600,
        "plan_type": "plus"
      },
      "extra": {
        "source": "chatgpt_web_session",
        "last_refresh": "2026-07-20T00:00:00Z"
      }
    }
  ]
}
```

每个 Sub2 账号会被规范化为 CPA `type: "codex"` auth。程序会从顶层字段、`credentials`、`token` 和 JWT claims 中补充：

- `access_token`、`refresh_token`、`id_token`、`session_token`
- `account_id` / `chatgpt_account_id`
- 邮箱、Plan、过期时间

Sub2 的代理列表不会写入 CPA auth；验活使用 `monitor_config.json` 中统一配置的 `proxy_url`。

## 4. 验活流程

每个账号依次经过以下步骤：

1. 识别输入结构并拆成单账号记录。
2. 将 Sub2 或 camelCase OAuth 字段规范化为 CPA auth 字段。
3. 写入 CPA auth 目录或通过 CPA 管理接口上传。
4. 使用 `access_token` 和 `Chatgpt-Account-Id` 请求 ChatGPT WHAM usage 接口。
5. 解析 5 小时、7 天及附加额度窗口。
6. 根据本地状态、接口响应和剩余额度分类并归档。

判定为可用需要同时满足：

- 账号未禁用、未过期，Access Token 未过期；
- 必要字段完整；
- WHAM usage 请求成功；
- 额度状态为 `ok`；
- 最低剩余额度高于 `quota_low_threshold_percent`。

低额度、额度耗尽、401/402/403/404/503、缺少账号 ID、缺少 Access Token 或已过期的账号会进入 `dead`。代理预检或整个检测过程异常时会停止归档和删除，避免把网络问题误判成死亡账号。

## 5. refresh_token 规则

以下账号允许 `refresh_token` 为空，并继续使用 Access Token 做真实验活：

- K12 auth；
- 带 `session_token` 的 CPA session auth；
- 带 `id_token_synthetic: true` 的 session 转换 auth；
- Sub2 auth。

普通 CPA OAuth 如果既没有 refresh token，也没有上述 session/Sub2 标记，仍会显示“缺 Token”。

## 6. 输出目录

每次导入生成独立批次：

```text
account_pool_monitor/monitor_data/import_batches/<批次>/
├── split/       # 规范化后的单账号 CPA JSON
├── alive/       # 验活且额度高于阈值
├── dead/        # 无效、过期、低额度或额度耗尽
└── manifest.json
```

同时生成 `<批次>.zip`，其中包含 `alive`、`dead` 和脱敏后的 `manifest.json`。

默认行为：

- `alive` 账号保留在 CPA auth 目录；
- `dead` 账号从 CPA auth 目录移除并归档；
- 可通过配置调整保留和移动行为。

## 7. 相关配置

编辑 `account_pool_monitor/monitor_config.json`：

```json
{
  "auth_dir": "D:/YOUR_CPA/auth",
  "cpa_base_url": "http://127.0.0.1:8317",
  "quota_low_threshold_percent": 5,
  "quota_query_concurrency": 32,
  "import_upload_concurrency": 32,
  "proxy_url": "",
  "proxy_check_enabled": true,
  "proxy_check_url": "https://chatgpt.com/cdn-cgi/trace",
  "proxy_check_timeout_seconds": 8,
  "import_keep_alive_in_auth_dir": true,
  "import_move_dead_from_auth_dir": true
}
```

如果设置了 `proxy_url`，程序会先使用该代理访问 `proxy_check_url`。预检失败时不会继续验活。

## 8. 自动化测试

在项目根目录执行：

```powershell
python -m unittest discover -s tests -v
```

测试覆盖 CPA session、Sub2 导出、NDJSON、Sub2 完整批次导入与存活归档、非 Codex 类型回归以及敏感 token 脱敏。

## 9. 凭证保护

输入文件、`auth_dir`、`monitor_data` 和日志都可能包含登录凭证。不要提交以下内容：

- `monitor_config.json`
- `monitor_data/`
- 真实 CPA/Sub2 导出 JSON
- `access_token`、`refresh_token`、`id_token`、`session_token`

示例和问题日志中应只使用虚构或已脱敏数据。
