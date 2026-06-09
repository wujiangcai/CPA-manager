# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import hashlib
import html
import json
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_NAME = "zny CPA Account Pool Monitor"
APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "monitor_data"
EXPORT_DIR = DATA_DIR / "available_exports"
CONFIG_PATH = APP_DIR / "monitor_config.json"
QUOTA_CACHE_PATH = DATA_DIR / "quota_cache.json"
EVENT_LOG_PATH = DATA_DIR / "events.jsonl"
CLEANUP_MANIFEST_PATH = DATA_DIR / "cleanup_manifest.jsonl"
CLEANUP_DISPLAY_HOURS = 12

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 18320,
    "cpa_config_path": "",
    "auth_dir": "",
    "cpa_base_url": "http://127.0.0.1:8317",
    "management_key": "",
    "quota_query_mode": "direct_auth",
    "proxy_url": "",
    "quota_low_threshold_percent": 5,
    "quota_query_timeout_seconds": 25,
    "quota_query_concurrency": 8,
    "quota_query_retries": 3,
    "quota_delete_cache_max_age_seconds": 600,
    "auto_cleanup_enabled": False,
    "auto_cleanup_interval_seconds": 3600,
    "cleanup_delete_quota_low": False,
    "cleanup_quarantine_dir": "",
    "cleanup_skip_disabled": True,
    "cleanup_move_expired": True,
    "cleanup_move_missing_tokens": True,
    "cleanup_move_read_errors": True,
    "cleanup_move_access_expired": False,
}

WHAM_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
WHAM_HEADERS = {
    "Authorization": "Bearer $TOKEN$",
    "Content-Type": "application/json",
    "User-Agent": "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal",
}
SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "authorization_code",
    "rt",
    "secret",
    "password",
    "management_key",
}

LOG_LOCK = threading.Lock()
QUOTA_LOCK = threading.Lock()
CLEANUP_LOCK = threading.Lock()
CLEANUP_STATE = {"last_run": 0.0, "last_result": None}


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def isoformat_local(value: dt.datetime | None = None) -> str:
    if value is None:
        value = now_local()
    return value.isoformat(timespec="seconds")


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return default
    except Exception as exc:
        log_event("error", f"读取 JSON 失败: {path}", {"error": str(exc)})
        return default


def write_json(path: Path, payload: Any) -> None:
    ensure_data_dir()
    raw = json.dumps(payload, ensure_ascii=False, indent=2)
    last_error: Exception | None = None
    for attempt in range(10):
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.{attempt}.tmp")
        try:
            tmp.write_text(raw, encoding="utf-8")
            os.replace(str(tmp), str(path))
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.15)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
    if last_error:
        raise last_error


def log_event(level: str, message: str, extra: dict[str, Any] | None = None) -> None:
    ensure_data_dir()
    row = {
        "time": isoformat_local(),
        "level": level,
        "message": message,
        "extra": sanitize_for_output(extra or {}),
    }
    line = json.dumps(row, ensure_ascii=False)
    with LOG_LOCK:
        with EVENT_LOG_PATH.open("a", encoding="utf-8") as fp:
            fp.write(line + "\n")


def read_recent_events(limit: int = 200) -> list[dict[str, Any]]:
    if not EVENT_LOG_PATH.exists():
        return []
    items: deque[dict[str, Any]] = deque(maxlen=max(1, min(limit, 1000)))
    try:
        with EVENT_LOG_PATH.open("r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []
    return list(items)


def clean_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def normalize_base_url(value: str) -> str:
    value = clean_string(value) or "http://127.0.0.1:8317"
    return value.rstrip("/")


def parse_scalar_from_yaml(text: str, key: str) -> str:
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$")
    match = pattern.search(text)
    if not match:
        return ""
    value = match.group(1).split("#", 1)[0].strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    return value.strip()


def load_config() -> dict[str, Any]:
    raw = load_json(CONFIG_PATH, {})
    cfg = DEFAULT_CONFIG.copy()
    if isinstance(raw, dict):
        cfg.update(raw)

    env_key = os.environ.get("CPA_MANAGEMENT_KEY") or os.environ.get("MANAGEMENT_PASSWORD")
    if env_key and not clean_string(cfg.get("management_key")):
        cfg["management_key"] = env_key.strip()

    cpa_config_path = Path(clean_string(cfg.get("cpa_config_path")) or DEFAULT_CONFIG["cpa_config_path"])
    if cpa_config_path.exists():
        try:
            text = cpa_config_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            text = cpa_config_path.read_text(encoding="gbk", errors="ignore")
        except Exception:
            text = ""
        if text:
            auth_dir = parse_scalar_from_yaml(text, "auth-dir")
            if auth_dir and not clean_string(cfg.get("auth_dir")):
                cfg["auth_dir"] = auth_dir
            host = parse_scalar_from_yaml(text, "host") or "127.0.0.1"
            port = parse_scalar_from_yaml(text, "port") or "8317"
            if not clean_string(cfg.get("cpa_base_url")):
                cfg["cpa_base_url"] = f"http://{host}:{port}"
            proxy_url = parse_scalar_from_yaml(text, "proxy-url")
            if proxy_url and not clean_string(cfg.get("proxy_url")):
                cfg["proxy_url"] = proxy_url

    if not clean_string(cfg.get("auth_dir")):
        cfg["auth_dir"] = ""
    cfg["auth_dir"] = clean_string(cfg["auth_dir"]).replace("\\", "/")
    cfg["cpa_base_url"] = normalize_base_url(clean_string(cfg.get("cpa_base_url")))
    cfg["proxy_url"] = clean_string(cfg.get("proxy_url"))
    cfg["quota_query_mode"] = clean_string(cfg.get("quota_query_mode") or "direct_auth").lower()
    cfg["port"] = int(cfg.get("port") or 18320)
    cfg["quota_low_threshold_percent"] = float(cfg.get("quota_low_threshold_percent") or 5)
    cfg["quota_query_timeout_seconds"] = int(cfg.get("quota_query_timeout_seconds") or 25)
    cfg["quota_query_concurrency"] = max(1, min(int(cfg.get("quota_query_concurrency") or 8), 64))
    cfg["quota_query_retries"] = max(1, min(int(cfg.get("quota_query_retries") or 3), 6))
    cfg["quota_delete_cache_max_age_seconds"] = max(30, int(cfg.get("quota_delete_cache_max_age_seconds") or 600))
    cfg["auto_cleanup_enabled"] = bool(cfg.get("auto_cleanup_enabled", True))
    cfg["auto_cleanup_interval_seconds"] = max(3600, int(cfg.get("auto_cleanup_interval_seconds") or 3600))
    cfg["cleanup_delete_quota_low"] = bool(cfg.get("cleanup_delete_quota_low", True))
    cfg["cleanup_quarantine_dir"] = clean_string(cfg.get("cleanup_quarantine_dir"))
    cfg["cleanup_move_expired"] = bool(cfg.get("cleanup_move_expired", True))
    cfg["cleanup_move_missing_tokens"] = bool(cfg.get("cleanup_move_missing_tokens", True))
    cfg["cleanup_move_read_errors"] = bool(cfg.get("cleanup_move_read_errors", True))
    cfg["cleanup_move_access_expired"] = bool(cfg.get("cleanup_move_access_expired", False))
    cfg["cleanup_skip_disabled"] = bool(cfg.get("cleanup_skip_disabled", True))
    return cfg


def save_runtime_config(updates: dict[str, Any]) -> dict[str, Any]:
    current = load_json(CONFIG_PATH, {})
    if not isinstance(current, dict):
        current = {}
    current.update(updates)
    write_json(CONFIG_PATH, current)
    return load_config()


def parse_datetime(value: Any) -> dt.datetime | None:
    if value is None or value is False:
        return None
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc).astimezone()
        except Exception:
            return None
    raw = clean_string(value)
    if not raw:
        return None
    if raw.isdigit():
        return parse_datetime(int(raw))
    raw = raw.replace("Z", "+00:00")
    for candidate in (raw, raw.replace(" ", "T", 1)):
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=now_local().tzinfo)
            return parsed.astimezone()
        except ValueError:
            continue
    return None


def decode_jwt_payload(token: Any) -> dict[str, Any] | None:
    raw = clean_string(token)
    if not raw or "." not in raw:
        return None
    parts = raw.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        data = base64.urlsafe_b64decode(payload.encode("ascii"))
        parsed = json.loads(data.decode("utf-8", errors="ignore"))
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


def short_hash(value: Any) -> str:
    raw = clean_string(value)
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]


def mask_tail(value: Any, size: int = 6) -> str:
    raw = clean_string(value)
    if not raw:
        return ""
    if len(raw) <= size:
        return "*" * len(raw)
    return "..." + raw[-size:]


def first_non_empty(*values: Any) -> str:
    for value in values:
        raw = clean_string(value)
        if raw:
            return raw
    return ""


def first_value(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


PLAN_ALIASES = {
    "plus": "plus",
    "chatgptplus": "plus",
    "chatgpt_plus": "plus",
    "plususer": "plus",
    "pro": "pro",
    "chatgptpro": "pro",
    "chatgpt_pro": "pro",
    "team": "team",
    "business": "team",
    "chatgptteam": "team",
    "chatgpt_team": "team",
    "enterprise": "enterprise",
    "free": "free",
}


def normalize_plan(value: Any) -> str:
    raw = clean_string(value).strip().lower()
    if not raw or raw in {"unknown", "none", "null", "-", "false"}:
        return ""
    compact = re.sub(r"[^a-z0-9]+", "", raw)
    if raw in PLAN_ALIASES:
        return PLAN_ALIASES[raw]
    if compact in PLAN_ALIASES:
        return PLAN_ALIASES[compact]
    for marker, plan in (
        ("team", "team"),
        ("business", "team"),
        ("pro", "pro"),
        ("plus", "plus"),
        ("enterprise", "enterprise"),
        ("free", "free"),
    ):
        if re.search(rf"(^|[^a-z0-9]){re.escape(marker)}([^a-z0-9]|$)", raw):
            return plan
    return raw


def plan_from_text(value: Any) -> str:
    raw = clean_string(value).lower()
    if not raw:
        return ""
    for marker, plan in (
        ("team", "team"),
        ("business", "team"),
        ("pro", "pro"),
        ("plus", "plus"),
        ("enterprise", "enterprise"),
        ("free", "free"),
    ):
        if re.search(rf"(^|[^a-z0-9]){marker}([^a-z0-9]|$)", raw):
            return plan
    return ""


def extract_plan_from_mapping(mapping: dict[str, Any], *fallback_texts: Any) -> tuple[str, str]:
    field_names = (
        "plan_type",
        "chatgpt_plan_type",
        "planType",
        "plan",
        "account_plan",
        "accountPlan",
        "subscription_plan",
        "subscriptionPlan",
        "tier",
        "sku",
    )
    for field_name in field_names:
        plan = normalize_plan(mapping.get(field_name))
        if plan:
            return plan, "auth"
    for text in fallback_texts:
        plan = plan_from_text(text)
        if plan:
            return plan, "file"
    return "unknown", "auth"


def parse_account_id(raw: dict[str, Any]) -> str:
    direct = first_non_empty(
        raw.get("chatgpt_account_id"),
        raw.get("chatgptAccountId"),
        raw.get("account_id"),
        raw.get("accountID"),
    )
    if direct:
        return direct
    payload = decode_jwt_payload(raw.get("id_token"))
    if isinstance(payload, dict):
        nested = payload.get("https://api.openai.com/auth")
        if isinstance(nested, dict):
            return first_non_empty(nested.get("chatgpt_account_id"), nested.get("account_id"))
        return first_non_empty(payload.get("chatgpt_account_id"), payload.get("account_id"))
    return ""


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    raw = clean_string(value).lower()
    return raw in {"1", "true", "yes", "y", "on"}


def scan_auth_accounts(cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    auth_dir = Path(clean_string(cfg.get("auth_dir")))
    warnings: list[str] = []
    if not auth_dir.exists():
        return [], [f"号池目录不存在: {auth_dir}"]
    files = sorted(auth_dir.glob("*.json"), key=lambda p: p.name.lower())
    accounts: list[dict[str, Any]] = []
    for file_path in files:
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8-sig"))
            if not isinstance(raw, dict):
                raise ValueError("JSON 顶层不是对象")
        except Exception as exc:
            accounts.append(
                {
                    "file": file_path.name,
                    "email": "",
                    "name": "",
                    "type": "",
                    "plan": "",
                    "status": "read_error",
                    "issues": ["read_error"],
                    "read_error": str(exc),
                    "disabled": False,
                    "expired": False,
                    "has_access": False,
                    "has_refresh": False,
                    "account_id_tail": "",
                    "account_id_hash": "",
                    "_account_id": "",
                    "_file_path": str(file_path),
                }
            )
            continue

        disabled = boolish(raw.get("disabled"))
        expired_at = parse_datetime(raw.get("expired"))
        expired = boolish(raw.get("expired")) or bool(expired_at and expired_at <= now_local())
        last_refresh_at = parse_datetime(raw.get("last_refresh"))
        access_payload = decode_jwt_payload(raw.get("access_token"))
        access_exp_at = parse_datetime(access_payload.get("exp")) if access_payload else None
        access_expired = bool(access_exp_at and access_exp_at <= now_local())
        has_access = bool(clean_string(raw.get("access_token")))
        has_refresh = bool(clean_string(raw.get("refresh_token")))
        account_id = parse_account_id(raw)
        plan, plan_source = extract_plan_from_mapping(raw, file_path.name, raw.get("email"), raw.get("name"))
        if plan == "unknown" and isinstance(access_payload, dict):
            plan, plan_source = extract_plan_from_mapping(access_payload, file_path.name, raw.get("email"), raw.get("name"))

        issues: list[str] = []
        if disabled:
            issues.append("disabled")
        if expired:
            issues.append("expired")
        if not has_access:
            issues.append("missing_access")
        if not has_refresh:
            issues.append("missing_refresh")
        if access_expired:
            issues.append("access_expired")

        if disabled:
            status = "disabled"
        elif expired:
            status = "expired"
        elif not has_access or not has_refresh:
            status = "missing_token"
        elif access_expired:
            status = "token_expired"
        else:
            status = "ok"

        accounts.append(
            {
                "file": file_path.name,
                "email": clean_string(raw.get("email")),
                "name": clean_string(raw.get("name")),
                "type": clean_string(raw.get("type")),
                "plan": plan or "unknown",
                "plan_source": plan_source,
                "status": status,
                "issues": issues,
                "disabled": disabled,
                "expired": expired,
                "expired_at": iso_or_empty(expired_at),
                "expired_raw": safe_short(raw.get("expired")),
                "last_refresh_at": iso_or_empty(last_refresh_at),
                "access_expires_at": iso_or_empty(access_exp_at),
                "access_seconds_left": seconds_left(access_exp_at),
                "has_access": has_access,
                "has_refresh": has_refresh,
                "account_id_tail": mask_tail(account_id),
                "account_id_hash": short_hash(account_id),
                "_account_id": account_id,
                "_match_names": build_match_names(file_path.name, raw),
                "_file_path": str(file_path),
            }
        )
    return accounts, warnings


def quota_cache_is_fresh(cache: dict[str, Any] | None, cfg: dict[str, Any]) -> bool:
    if not isinstance(cache, dict):
        return False
    created_at = parse_datetime(cache.get("created_at"))
    if created_at is None:
        return False
    max_age = max(30, int(cfg.get("quota_delete_cache_max_age_seconds") or 600))
    return (now_local() - created_at).total_seconds() <= max_age


def quota_cache_covers_accounts(cache: dict[str, Any] | None, accounts: list[dict[str, Any]]) -> bool:
    if not isinstance(cache, dict) or not isinstance(cache.get("reports"), list):
        return False
    codex_accounts = [item for item in accounts if clean_string(item.get("type")).lower() == "codex"]
    if not codex_accounts:
        return True
    merged_accounts = []
    for account in codex_accounts:
        item = dict(account)
        item["issues"] = list(account.get("issues") or [])
        merged_accounts.append(item)
    merge_quota(merged_accounts, cache)
    matched = sum(1 for item in merged_accounts if isinstance(item.get("quota"), dict))
    if matched < len(codex_accounts):
        log_event(
            "warn",
            "额度缓存未覆盖当前号池",
            {"accounts": len(codex_accounts), "matched": matched, "reports": len(cache.get("reports") or [])},
        )
        return False
    return True


def quota_cache_is_usable(cache: dict[str, Any] | None, cfg: dict[str, Any], accounts: list[dict[str, Any]]) -> bool:
    return quota_cache_is_fresh(cache, cfg) and quota_cache_covers_accounts(cache, accounts)


def quota_error_is_invalid(error: Any) -> bool:
    text = clean_string(error).lower()
    return any(
        marker in text
        for marker in (
            "http 401",
            "unauthorized",
            "invalid",
            "invalid_api_key",
            "invalid token",
            "expired token",
            "access token",
            "forbidden",
            "http 403",
            "http 402",
            "http 404",
            "http 503",
            "503 service unavailable",
            "not_found",
            "not found",
            "deactivated_workspace",
            "workspace deactivated",
            "deactivated workspace",
        )
    )


def cleanup_reason_for_account(account: dict[str, Any], cfg: dict[str, Any]) -> str:
    if cfg.get("cleanup_skip_disabled", True) and account.get("disabled"):
        return ""
    quota = account.get("quota")
    if isinstance(quota, dict) and quota_cache_is_fresh(account.get("_quota_cache"), cfg):
        quota_status = clean_string(quota.get("status"))
        if quota_status == "low":
            return "quota_low" if cfg.get("cleanup_delete_quota_low", True) else ""
        if quota_status == "exhausted":
            return "quota_exhausted"
        if quota_status == "missing":
            return "quota_missing"
        if quota_status == "error" and quota_error_is_invalid(quota.get("error")):
            return "quota_invalid"
    status = clean_string(account.get("status"))
    if status == "read_error" and cfg.get("cleanup_move_read_errors", True):
        return "read_error"
    if status == "expired" and cfg.get("cleanup_move_expired", True):
        return "expired"
    if status == "missing_token" and cfg.get("cleanup_move_missing_tokens", True):
        return "missing_token"
    if status == "token_expired" and cfg.get("cleanup_move_access_expired", False):
        return "access_expired"
    return ""


def append_cleanup_manifest(row: dict[str, Any]) -> None:
    ensure_data_dir()
    line = json.dumps(sanitize_for_output(row), ensure_ascii=False)
    with LOG_LOCK:
        with CLEANUP_MANIFEST_PATH.open("a", encoding="utf-8") as fp:
            fp.write(line + "\n")


def parse_iso_time(value: Any) -> dt.datetime | None:
    text = clean_string(value)
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed
    except Exception:
        return None


def read_recent_cleanup_items(hours: int = CLEANUP_DISPLAY_HOURS) -> list[dict[str, Any]]:
    ensure_data_dir()
    cutoff = now_local() - dt.timedelta(hours=max(1, int(hours or CLEANUP_DISPLAY_HOURS)))
    rows: list[dict[str, Any]] = []
    try:
        with CLEANUP_MANIFEST_PATH.open("r", encoding="utf-8-sig") as fp:
            lines = fp.readlines()
    except FileNotFoundError:
        return []
    except Exception as exc:
        log_event("error", "读取自动删除日志失败", {"error": str(exc)})
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        when = parse_iso_time(item.get("time"))
        if when is not None and when < cutoff:
            continue
        rows.append(sanitize_for_output(item))
    rows.sort(key=lambda item: clean_string(item.get("time")), reverse=True)
    return rows


def cleanup_stats(hours: int = CLEANUP_DISPLAY_HOURS) -> dict[str, Any]:
    ensure_data_dir()
    cutoff = now_local() - dt.timedelta(hours=max(1, int(hours or CLEANUP_DISPLAY_HOURS)))
    total = 0
    recent = 0
    last_time = ""
    by_reason: dict[str, int] = {}
    try:
        with CLEANUP_MANIFEST_PATH.open("r", encoding="utf-8-sig") as fp:
            lines = fp.readlines()
    except FileNotFoundError:
        return {"total": 0, "recent": 0, "hours": hours, "last_time": "", "by_reason": {}}
    except Exception as exc:
        log_event("error", "读取自动删除统计失败", {"error": str(exc)})
        return {"total": 0, "recent": 0, "hours": hours, "last_time": "", "by_reason": {}}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        total += 1
        reason = clean_string(item.get("reason")) or "unknown"
        by_reason[reason] = by_reason.get(reason, 0) + 1
        when_text = clean_string(item.get("time"))
        if when_text and (not last_time or when_text > last_time):
            last_time = when_text
        when = parse_iso_time(when_text)
        if when is not None and when >= cutoff:
            recent += 1
    return {"total": total, "recent": recent, "hours": hours, "last_time": last_time, "by_reason": by_reason}


def cleanup_auth_pool(cfg: dict[str, Any], force: bool = False, quota_cache: dict[str, Any] | None = None) -> dict[str, Any]:
    if not force and not cfg.get("auto_cleanup_enabled", True):
        return {"enabled": False, "deleted": 0, "moved": 0, "skipped": 0, "errors": 0, "items": [], "ran_at": ""}
    now_ts = time.time()
    interval = max(3600, int(cfg.get("auto_cleanup_interval_seconds") or 3600))
    with CLEANUP_LOCK:
        if not force and CLEANUP_STATE.get("last_run") and now_ts - float(CLEANUP_STATE["last_run"]) < interval:
            result = CLEANUP_STATE.get("last_result")
            if isinstance(result, dict):
                return result
        accounts, warnings = scan_auth_accounts(cfg)
        if quota_cache:
            accounts = merge_quota(accounts, quota_cache)
            for account in accounts:
                account["_quota_cache"] = quota_cache
        result = {
            "enabled": True,
            "ran_at": isoformat_local(),
            "deleted": 0,
            "moved": 0,
            "skipped": 0,
            "errors": 0,
            "warnings": warnings,
            "items": [],
        }
        for account in accounts:
            reason = cleanup_reason_for_account(account, cfg)
            if not reason:
                result["skipped"] += 1
                continue
            file_text = clean_string(account.get("_file_path"))
            if not file_text:
                result["errors"] += 1
                continue
            file_path = Path(file_text)
            try:
                if not file_path.exists():
                    result["skipped"] += 1
                    continue
                file_path.unlink()
                row = {
                    "time": isoformat_local(),
                    "reason": reason,
                    "file": file_path.name,
                    "from": str(file_path),
                    "action": "deleted",
                    "email": account.get("email"),
                    "status": account.get("status"),
                    "quota_status": account.get("quota", {}).get("status") if isinstance(account.get("quota"), dict) else "",
                    "quota_error": account.get("quota", {}).get("error") if isinstance(account.get("quota"), dict) else "",
                    "disabled": account.get("disabled"),
                }
                append_cleanup_manifest(row)
                log_event("warn", "已自动删除失效 CPA 账号", row)
                result["items"].append(row)
                result["deleted"] += 1
            except Exception as exc:
                result["errors"] += 1
                row = {"file": file_path.name, "reason": reason, "error": str(exc)}
                result["items"].append(row)
                log_event("error", "自动删除 CPA 账号失败", row)
        CLEANUP_STATE["last_run"] = now_ts
        CLEANUP_STATE["last_result"] = result
        return result


def delete_accounts_by_plan(cfg: dict[str, Any], plan: str, refresh_quota: bool = True) -> dict[str, Any]:
    target_plan = normalize_plan(plan)
    allowed_plans = {"plus", "pro", "team", "enterprise", "free"}
    if target_plan not in allowed_plans:
        raise ValueError("unsupported plan")

    cache = load_quota_cache()
    warnings: list[str] = []
    if refresh_quota:
        try:
            with QUOTA_LOCK:
                cache = query_quota_reports(cfg)
        except Exception as exc:
            warnings.append("quota refresh failed, using current cache: " + safe_short(str(exc), 180))
            log_event("error", "鎵嬪姩鎵归噺鍒犻櫎鍓嶆煡璇㈤搴﹀け璐?", {"plan": target_plan, "error": str(exc)})

    accounts, scan_warnings = scan_auth_accounts(cfg)
    warnings.extend(scan_warnings)
    if cache:
        accounts = merge_quota(accounts, cache)

    result = {
        "ok": True,
        "plan": target_plan,
        "ran_at": isoformat_local(),
        "matched": 0,
        "deleted": 0,
        "skipped": 0,
        "errors": 0,
        "warnings": warnings,
        "items": [],
    }

    with CLEANUP_LOCK:
        for account in accounts:
            if normalize_plan(account.get("plan")) != target_plan:
                continue
            result["matched"] += 1
            file_text = clean_string(account.get("_file_path"))
            if not file_text:
                result["errors"] += 1
                continue
            file_path = Path(file_text)
            try:
                if not file_path.exists():
                    result["skipped"] += 1
                    continue
                file_path.unlink()
                row = {
                    "time": isoformat_local(),
                    "reason": "manual_plan_" + target_plan,
                    "plan": target_plan,
                    "file": file_path.name,
                    "from": str(file_path),
                    "action": "deleted",
                    "email": account.get("email"),
                    "status": account.get("status"),
                    "quota_status": account.get("quota", {}).get("status") if isinstance(account.get("quota"), dict) else "",
                    "quota_error": account.get("quota", {}).get("error") if isinstance(account.get("quota"), dict) else "",
                    "disabled": account.get("disabled"),
                }
                append_cleanup_manifest(row)
                log_event("warn", "鎵嬪姩鎵归噺鍒犻櫎 CPA 璐﹀彿", row)
                result["items"].append(row)
                result["deleted"] += 1
            except Exception as exc:
                result["errors"] += 1
                row = {"file": file_path.name, "plan": target_plan, "reason": "manual_plan_" + target_plan, "error": str(exc)}
                result["items"].append(row)
                log_event("error", "鎵嬪姩鎵归噺鍒犻櫎 CPA 璐﹀彿澶辫触", row)
    return result


def cleanup_worker() -> None:
    while True:
        try:
            cfg = load_config()
            interval = max(3600, int(cfg.get("auto_cleanup_interval_seconds") or 3600))
            if not cfg.get("auto_cleanup_enabled", True):
                time.sleep(60)
                continue
            cache = None
            try:
                with QUOTA_LOCK:
                    cache = query_quota_reports(cfg)
            except Exception as exc:
                log_event("error", "自动额度查询失败，已跳过额度删除", {"error": str(exc)})
            cleanup_auth_pool(cfg, force=True, quota_cache=cache)
            interval = max(3600, int(cfg.get("auto_cleanup_interval_seconds") or 3600))
        except Exception as exc:
            log_event("error", "自动清理线程异常", {"error": str(exc)})
            interval = 3600
        time.sleep(interval)


def build_match_names(file_name: str, raw: dict[str, Any]) -> list[str]:
    values = {
        Path(file_name).stem.lower(),
        file_name.lower(),
        clean_string(raw.get("email")).lower(),
        clean_string(raw.get("name")).lower(),
    }
    return [v for v in values if v]


def iso_or_empty(value: dt.datetime | None) -> str:
    if value is None:
        return ""
    return value.astimezone().isoformat(timespec="seconds")


def seconds_left(value: dt.datetime | None) -> int | None:
    if value is None:
        return None
    return int((value - now_local()).total_seconds())


def safe_short(value: Any, max_len: int = 80) -> str:
    raw = clean_string(value)
    if len(raw) > max_len:
        return raw[: max_len - 3] + "..."
    return raw


def sanitize_for_output(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_s = str(key)
            key_l = key_s.lower()
            if key_l.endswith("_configured") or key_l.startswith("has_"):
                out[key_s] = sanitize_for_output(item)
            elif key_l in SENSITIVE_KEYS or key_l.endswith("_secret") or key_l.endswith("_password"):
                out[key_s] = "[hidden]"
            elif key_s.startswith("_"):
                continue
            else:
                out[key_s] = sanitize_for_output(item)
        return out
    if isinstance(value, list):
        return [sanitize_for_output(item) for item in value]
    if isinstance(value, str) and len(value) > 240:
        return value[:237] + "..."
    return value


def request_json(method: str, url: str, payload: dict[str, Any] | None, cfg: dict[str, Any]) -> dict[str, Any]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    key = clean_string(cfg.get("management_key"))
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=int(cfg.get("quota_query_timeout_seconds") or 25)) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {safe_short(body, 220)}") from exc
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise RuntimeError("返回不是 JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("返回 JSON 顶层不是对象")
    return parsed


def request_json_direct(method: str, url: str, payload: dict[str, Any] | None, headers: dict[str, str], cfg: dict[str, Any]) -> dict[str, Any]:
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    proxy_url = clean_string(cfg.get("proxy_url"))
    opener = None
    if proxy_url and proxy_url.lower() not in {"direct", "none", "false"}:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    try:
        if opener:
            with opener.open(req, timeout=int(cfg.get("quota_query_timeout_seconds") or 25)) as resp:
                raw = resp.read()
        else:
            with urllib.request.urlopen(req, timeout=int(cfg.get("quota_query_timeout_seconds") or 25)) as resp:
                raw = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {safe_short(body, 220)}") from exc
    except Exception as exc:
        raise RuntimeError(str(exc)) from exc
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        raise RuntimeError("返回不是 JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("返回 JSON 顶层不是对象")
    return parsed


def fetch_management_auth_files(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    url = normalize_base_url(cfg["cpa_base_url"]) + "/v0/management/auth-files"
    payload = request_json("GET", url, None, cfg)
    files = payload.get("files")
    if not isinstance(files, list):
        raise RuntimeError("CPA 管理接口 auth-files 返回异常")
    return [item for item in files if isinstance(item, dict)]


def parse_body(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("empty or invalid quota payload")


def number(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    raw = clean_string(value)
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def parse_reset_label(window: dict[str, Any]) -> str:
    reset_at = number(first_value(window, "reset_at", "resetAt"))
    if reset_at and reset_at > 0:
        return dt.datetime.fromtimestamp(reset_at, tz=dt.timezone.utc).astimezone().strftime("%m-%d %H:%M")
    reset_after = number(first_value(window, "reset_after_seconds", "resetAfterSeconds"))
    if reset_after and reset_after > 0:
        return (now_local() + dt.timedelta(seconds=reset_after)).strftime("%m-%d %H:%M")
    return "-"


def deduce_used_percent(window: dict[str, Any], limit_reached: Any, allowed: Any) -> float | None:
    used = number(first_value(window, "used_percent", "usedPercent"))
    if used is not None:
        return clamp(used, 0, 100)
    if boolish(limit_reached) or clean_string(allowed).lower() == "false":
        if parse_reset_label(window) != "-":
            return 100.0
    return None


def build_quota_window(id_value: str, label: str, window: dict[str, Any] | None, limit_reached: Any, allowed: Any) -> dict[str, Any] | None:
    if not isinstance(window, dict):
        return None
    used = deduce_used_percent(window, limit_reached, allowed)
    remaining = None if used is None else clamp(100.0 - used, 0, 100)
    return {
        "id": id_value,
        "label": label,
        "used_percent": used,
        "remaining_percent": remaining,
        "reset_label": parse_reset_label(window),
        "exhausted": bool(used is not None and used >= 100),
    }


def parse_codex_windows(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rate_limit = first_value(payload, "rate_limit", "rateLimit")
    windows: list[dict[str, Any]] = []
    if isinstance(rate_limit, dict):
        primary = first_value(rate_limit, "primary_window", "primaryWindow")
        secondary = first_value(rate_limit, "secondary_window", "secondaryWindow")
        candidates = [item for item in (primary, secondary) if isinstance(item, dict)]
        five_hour = None
        weekly = None
        for item in candidates:
            duration = number(first_value(item, "limit_window_seconds", "limitWindowSeconds"))
            if duration == 5 * 60 * 60 and five_hour is None:
                five_hour = item
            if duration == 7 * 24 * 60 * 60 and weekly is None:
                weekly = item
        if five_hour is None and isinstance(primary, dict):
            five_hour = primary
        if weekly is None and isinstance(secondary, dict):
            weekly = secondary
        limit_reached = first_value(rate_limit, "limit_reached", "limitReached")
        allowed = first_value(rate_limit, "allowed")
        for item in (
            build_quota_window("code-5h", "5h", five_hour, limit_reached, allowed),
            build_quota_window("code-7d", "7d", weekly, limit_reached, allowed),
        ):
            if item:
                windows.append(item)

    additional: list[dict[str, Any]] = []
    raw_additional = first_value(payload, "additional_rate_limits", "additionalRateLimits")
    if isinstance(raw_additional, list):
        for index, item in enumerate(raw_additional, 1):
            if not isinstance(item, dict):
                continue
            nested = first_value(item, "rate_limit", "rateLimit")
            if not isinstance(nested, dict):
                continue
            name = first_non_empty(
                item.get("limit_name"),
                item.get("limitName"),
                item.get("metered_feature"),
                item.get("meteredFeature"),
                f"additional-{index}",
            )
            primary = first_value(nested, "primary_window", "primaryWindow")
            secondary = first_value(nested, "secondary_window", "secondaryWindow")
            limit_reached = first_value(nested, "limit_reached", "limitReached")
            allowed = first_value(nested, "allowed")
            for extra in (
                build_quota_window(f"{name}-primary", f"{name} 5h", primary if isinstance(primary, dict) else None, limit_reached, allowed),
                build_quota_window(f"{name}-secondary", f"{name} 7d", secondary if isinstance(secondary, dict) else None, limit_reached, allowed),
            ):
                if extra:
                    additional.append(extra)
    return windows, additional


def min_remaining(windows: list[dict[str, Any]]) -> float | None:
    values = [item.get("remaining_percent") for item in windows if isinstance(item.get("remaining_percent"), (int, float))]
    if not values:
        return None
    return float(min(values))


def derive_quota_status(windows: list[dict[str, Any]], additional: list[dict[str, Any]], error: str, threshold: float) -> str:
    if error:
        if "missing" in error.lower():
            return "missing"
        return "error"
    all_windows = windows + additional
    if not all_windows:
        return "unknown"
    if any(item.get("exhausted") for item in all_windows):
        return "exhausted"
    remaining = min_remaining(all_windows)
    if remaining is not None and remaining <= threshold:
        return "low"
    return "ok"


def quota_error_is_transient(error: Any) -> bool:
    text = clean_string(error).lower()
    return any(
        marker in text
        for marker in (
            "http 429",
            "http 500",
            "http 502",
            "http 504",
            "timed out",
            "timeout",
            "temporarily",
            "try again later",
            "unable to check usage",
            "connection reset",
            "remote end closed",
        )
    )


def quota_report_has_value(report: dict[str, Any]) -> bool:
    if clean_string(report.get("status")) not in {"ok", "low", "exhausted"}:
        return False
    windows = report.get("windows")
    additional = report.get("additional_windows")
    return bool(windows or additional)


def query_one_codex_quota(entry: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    auth_index = first_non_empty(entry.get("auth_index"), entry.get("authIndex"))
    account_id = parse_account_id(entry)
    name = first_non_empty(entry.get("name"), entry.get("id"), entry.get("email"), "unknown")
    email = clean_string(entry.get("email"))
    plan, _plan_source = extract_plan_from_mapping(entry, entry.get("file"), name, email)
    report = {
        "provider": "codex",
        "name": name,
        "email": email,
        "auth_index": auth_index,
        "account_id_tail": mask_tail(account_id),
        "account_id_hash": short_hash(account_id),
        "plan": plan or "unknown",
        "status": "unknown",
        "error": "",
        "windows": [],
        "additional_windows": [],
        "min_remaining_percent": None,
        "queried_at": isoformat_local(),
    }
    if not auth_index:
        report["error"] = "missing auth_index"
        report["status"] = "missing"
        return report
    if not account_id:
        report["error"] = "missing chatgpt_account_id"
        report["status"] = "missing"
        return report

    headers = dict(WHAM_HEADERS)
    headers["Chatgpt-Account-Id"] = account_id
    payload = {
        "auth_index": auth_index,
        "method": "GET",
        "url": WHAM_USAGE_URL,
        "header": headers,
    }
    try:
        response = request_json("POST", normalize_base_url(cfg["cpa_base_url"]) + "/v0/management/api-call", payload, cfg)
        status_code = int(response.get("status_code") or response.get("statusCode") or 0)
        body = response.get("body")
        if status_code < 200 or status_code >= 300:
            report["error"] = safe_short(body if isinstance(body, str) else json.dumps(body, ensure_ascii=False), 220) or f"HTTP {status_code}"
            report["status"] = "error"
            return report
        parsed = parse_body(body)
        plan_from_body = normalize_plan(first_non_empty(parsed.get("plan_type"), parsed.get("planType"), parsed.get("plan")))
        if plan_from_body:
            report["plan"] = plan_from_body
        windows, additional = parse_codex_windows(parsed)
        report["windows"] = windows
        report["additional_windows"] = additional
        report["min_remaining_percent"] = min_remaining(windows + additional)
        report["status"] = derive_quota_status(windows, additional, "", float(cfg.get("quota_low_threshold_percent") or 5))
        return report
    except Exception as exc:
        report["error"] = safe_short(str(exc), 220)
        report["status"] = derive_quota_status([], [], report["error"], float(cfg.get("quota_low_threshold_percent") or 5))
        return report


def quota_report_base(entry: dict[str, Any], account_id: str) -> dict[str, Any]:
    name = first_non_empty(entry.get("name"), entry.get("id"), entry.get("email"), entry.get("file"), "unknown")
    plan, _plan_source = extract_plan_from_mapping(entry, entry.get("file"), name, entry.get("email"))
    return {
        "provider": "codex",
        "name": name,
        "email": clean_string(entry.get("email")),
        "file": clean_string(entry.get("file")),
        "auth_index": clean_string(entry.get("auth_index") or entry.get("authIndex")),
        "account_id_tail": mask_tail(account_id),
        "account_id_hash": short_hash(account_id),
        "plan": plan or "unknown",
        "status": "unknown",
        "error": "",
        "windows": [],
        "additional_windows": [],
        "min_remaining_percent": None,
        "queried_at": isoformat_local(),
        "source": "direct_auth",
    }


def load_raw_auth_for_account(account: dict[str, Any]) -> dict[str, Any]:
    path_text = clean_string(account.get("_file_path"))
    if not path_text:
        raise RuntimeError("missing auth file path")
    with Path(path_text).open("r", encoding="utf-8-sig") as fp:
        raw = json.load(fp)
    if not isinstance(raw, dict):
        raise RuntimeError("auth JSON 顶层不是对象")
    raw.setdefault("file", account.get("file"))
    return raw


def query_one_codex_quota_direct(account: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    try:
        entry = load_raw_auth_for_account(account)
    except Exception as exc:
        report = quota_report_base(account, "")
        report["error"] = safe_short(str(exc), 220)
        report["status"] = "error"
        return report

    account_id = parse_account_id(entry)
    report = quota_report_base({**entry, "file": account.get("file")}, account_id)
    if boolish(entry.get("disabled")):
        report["status"] = "disabled"
        report["error"] = "手动禁用，已跳过额度查询"
        return report
    token = clean_string(entry.get("access_token"))
    if not token:
        report["error"] = "missing access token"
        report["status"] = "missing"
        return report
    if not account_id:
        report["error"] = "missing chatgpt_account_id"
        report["status"] = "missing"
        return report

    headers = dict(WHAM_HEADERS)
    headers["Authorization"] = "Bearer " + token
    headers["Chatgpt-Account-Id"] = account_id
    attempts = max(1, int(cfg.get("quota_query_retries") or 3))
    last_error = ""
    for attempt in range(attempts):
        try:
            parsed = request_json_direct("GET", WHAM_USAGE_URL, None, headers, cfg)
            plan_from_body = normalize_plan(first_non_empty(parsed.get("plan_type"), parsed.get("planType"), parsed.get("plan")))
            if plan_from_body:
                report["plan"] = plan_from_body
            windows, additional = parse_codex_windows(parsed)
            report["windows"] = windows
            report["additional_windows"] = additional
            report["min_remaining_percent"] = min_remaining(windows + additional)
            report["status"] = derive_quota_status(windows, additional, "", float(cfg.get("quota_low_threshold_percent") or 5))
            if attempt:
                report["retry_count"] = attempt
            return report
        except Exception as exc:
            last_error = safe_short(str(exc), 220)
            if not quota_error_is_transient(last_error) or attempt >= attempts - 1:
                break
            time.sleep(min(3.0, 0.7 * (attempt + 1)))
    report["error"] = last_error
    report["status"] = derive_quota_status([], [], report["error"], float(cfg.get("quota_low_threshold_percent") or 5))
    return report


def quota_cache_lookup(cache: dict[str, Any] | None) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_file: dict[str, dict[str, Any]] = {}
    by_email: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    if not isinstance(cache, dict) or not isinstance(cache.get("reports"), list):
        return by_file, by_email, by_name
    for report in cache.get("reports") or []:
        if not isinstance(report, dict):
            continue
        file_name = clean_string(report.get("file")).lower()
        if file_name:
            by_file[file_name] = report
        email = clean_string(report.get("email")).lower()
        if email:
            by_email[email] = report
        name = clean_string(report.get("name")).lower()
        if name:
            by_name[name] = report
    return by_file, by_email, by_name


def find_cached_report(report: dict[str, Any], cache: dict[str, Any] | None) -> dict[str, Any] | None:
    by_file, by_email, by_name = quota_cache_lookup(cache)
    file_name = clean_string(report.get("file")).lower()
    if file_name and file_name in by_file:
        return by_file[file_name]
    email = clean_string(report.get("email")).lower()
    if email and email in by_email:
        return by_email[email]
    name = clean_string(report.get("name")).lower()
    if name and name in by_name:
        return by_name[name]
    return None


def preserve_cached_quota_on_transient_errors(reports: list[dict[str, Any]], previous_cache: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(previous_cache, dict):
        return reports
    preserved: list[dict[str, Any]] = []
    for report in reports:
        if clean_string(report.get("status")) == "error" and quota_error_is_transient(report.get("error")):
            previous = find_cached_report(report, previous_cache)
            if isinstance(previous, dict) and quota_report_has_value(previous):
                item = dict(previous)
                item["stale_from_cache"] = True
                item["last_refresh_error"] = clean_string(report.get("error"))
                item["last_refresh_attempt_at"] = clean_string(report.get("queried_at"))
                preserved.append(item)
                log_event(
                    "warn",
                    "额度临时查询失败，保留上次正常结果",
                    {
                        "file": report.get("file"),
                        "email": report.get("email"),
                        "error": report.get("error"),
                        "cached_queried_at": previous.get("queried_at"),
                    },
                )
                continue
        preserved.append(report)
    return preserved


def query_quota_reports_direct(cfg: dict[str, Any]) -> dict[str, Any]:
    started = time.time()
    previous_cache = load_quota_cache()
    accounts, warnings = scan_auth_accounts(cfg)
    codex_accounts = [item for item in accounts if clean_string(item.get("type")).lower() == "codex"]
    reports: list[dict[str, Any]] = []
    workers = max(1, min(int(cfg.get("quota_query_concurrency") or 8), 64))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(query_one_codex_quota_direct, account, cfg) for account in codex_accounts]
        for future in concurrent.futures.as_completed(futures):
            reports.append(future.result())
    reports = preserve_cached_quota_on_transient_errors(reports, previous_cache)
    reports.sort(key=lambda item: (clean_string(item.get("status")), clean_string(item.get("name")).lower()))
    payload = {
        "created_at": isoformat_local(),
        "elapsed_seconds": round(time.time() - started, 3),
        "auth_file_count": len(accounts),
        "codex_count": len(codex_accounts),
        "source": "direct_auth",
        "warnings": warnings,
        "reports": reports,
    }
    write_json(QUOTA_CACHE_PATH, payload)
    log_event("info", "CPA 额度查询完成", {"source": "direct_auth", "codex_count": len(codex_accounts), "elapsed_seconds": payload["elapsed_seconds"]})
    return payload


def query_quota_reports(cfg: dict[str, Any]) -> dict[str, Any]:
    mode = clean_string(cfg.get("quota_query_mode") or "direct_auth").lower()
    if mode in {"direct", "direct_auth", "auth", "local"}:
        return query_quota_reports_direct(cfg)
    key = clean_string(cfg.get("management_key"))
    if not key:
        return query_quota_reports_direct(cfg)
    started = time.time()
    auth_files = fetch_management_auth_files(cfg)
    codex_entries = []
    for entry in auth_files:
        provider = first_non_empty(entry.get("provider"), entry.get("type")).lower()
        if provider == "codex":
            codex_entries.append(entry)
    reports: list[dict[str, Any]] = []
    workers = max(1, min(int(cfg.get("quota_query_concurrency") or 8), 64))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(query_one_codex_quota, entry, cfg) for entry in codex_entries]
        for future in concurrent.futures.as_completed(futures):
            reports.append(future.result())
    reports.sort(key=lambda item: (clean_string(item.get("status")), clean_string(item.get("name")).lower()))
    payload = {
        "created_at": isoformat_local(),
        "elapsed_seconds": round(time.time() - started, 3),
        "auth_file_count": len(auth_files),
        "codex_count": len(codex_entries),
        "reports": reports,
    }
    write_json(QUOTA_CACHE_PATH, payload)
    log_event("info", "CPA 额度查询完成", {"codex_count": len(codex_entries), "elapsed_seconds": payload["elapsed_seconds"]})
    return payload


def load_quota_cache() -> dict[str, Any] | None:
    payload = load_json(QUOTA_CACHE_PATH, None)
    return payload if isinstance(payload, dict) else None


def merge_quota(accounts: list[dict[str, Any]], cache: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not cache or not isinstance(cache.get("reports"), list):
        for account in accounts:
            account["quota"] = None
        return accounts
    hash_buckets: dict[str, list[dict[str, Any]]] = {}
    by_file: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    by_email: dict[str, dict[str, Any]] = {}
    for report in cache.get("reports") or []:
        if not isinstance(report, dict):
            continue
        file_name = clean_string(report.get("file")).lower()
        if file_name:
            by_file[file_name] = report
        account_hash = clean_string(report.get("account_id_hash"))
        if account_hash:
            hash_buckets.setdefault(account_hash, []).append(report)
        email = clean_string(report.get("email")).lower()
        if email:
            by_email[email] = report
        name = clean_string(report.get("name")).lower()
        if name:
            by_name[name] = report
    by_unique_hash = {key: value[0] for key, value in hash_buckets.items() if len(value) == 1}

    for account in accounts:
        report = None
        file_name = clean_string(account.get("file")).lower()
        if file_name:
            report = by_file.get(file_name)
        if report is None and account.get("email"):
            report = by_email.get(account["email"].lower())
        if report is None:
            for name in account.get("_match_names") or []:
                report = by_name.get(name)
                if report is not None:
                    break
        if report is None and account.get("account_id_hash"):
            report = by_unique_hash.get(account["account_id_hash"])
        if report:
            report_plan = normalize_plan(report.get("plan"))
            output_report = dict(report)
            output_report["plan"] = report_plan or normalize_plan(account.get("plan")) or "unknown"
            account["quota"] = sanitize_for_output(output_report)
            if report_plan:
                account["plan"] = report_plan
                account["plan_source"] = "quota"
            else:
                account["plan"] = normalize_plan(account.get("plan")) or "unknown"
                account["plan_source"] = account.get("plan_source") or "auth"
        else:
            account["plan"] = normalize_plan(account.get("plan")) or "unknown"
            account["plan_source"] = account.get("plan_source") or "auth"
            account["quota"] = None
        if report and report.get("status") in {"low", "exhausted"}:
            if "quota_" + clean_string(report.get("status")) not in account["issues"]:
                account["issues"].append("quota_" + clean_string(report.get("status")))
    return accounts


def account_is_exportable(account: dict[str, Any], require_quota: bool = True, threshold: float = 5.0) -> tuple[bool, str]:
    if account.get("disabled"):
        return False, "disabled"
    status = clean_string(account.get("status"))
    if status != "ok":
        return False, status or "not_ok"
    file_text = clean_string(account.get("_file_path"))
    if not file_text:
        return False, "missing_file_path"
    if not Path(file_text).exists():
        return False, "file_not_found"
    if require_quota:
        quota = account.get("quota")
        if not isinstance(quota, dict):
            return False, "quota_missing"
        quota_status = clean_string(quota.get("status"))
        if quota_status != "ok":
            return False, "quota_" + (quota_status or "unknown")
        remaining = quota.get("min_remaining_percent")
        if isinstance(remaining, (int, float)) and float(remaining) <= float(threshold):
            return False, "quota_low"
    return True, "ok"


def export_available_accounts(cfg: dict[str, Any], refresh_quota: bool = True) -> dict[str, Any]:
    warnings: list[str] = []
    cache = None
    if refresh_quota:
        try:
            with QUOTA_LOCK:
                cache = query_quota_reports(cfg)
        except Exception as exc:
            warning = "额度刷新失败，改用当前缓存筛选: " + safe_short(str(exc), 180)
            warnings.append(warning)
            log_event("error", "导出可用账号前刷新额度失败", {"error": str(exc)})
            cache = load_quota_cache()
    else:
        cache = load_quota_cache()

    accounts, scan_warnings = scan_auth_accounts(cfg)
    warnings.extend(scan_warnings)
    accounts = merge_quota(accounts, cache)
    threshold = float(cfg.get("quota_low_threshold_percent") or 5)
    export_name = "available_" + now_local().strftime("%Y%m%d_%H%M%S")
    export_folder = EXPORT_DIR / export_name
    export_zip = EXPORT_DIR / f"{export_name}.zip"
    export_folder.mkdir(parents=True, exist_ok=True)

    result = {
        "ok": True,
        "ran_at": isoformat_local(),
        "source_auth_dir": clean_string(cfg.get("auth_dir")),
        "folder": str(export_folder),
        "zip": str(export_zip),
        "download_url": f"/api/download-export?name={urllib.parse.quote(export_zip.name)}",
        "total": len(accounts),
        "exported": 0,
        "skipped": 0,
        "errors": 0,
        "warnings": warnings,
        "items": [],
        "skipped_items": [],
    }

    for account in accounts:
        ok, reason = account_is_exportable(account, require_quota=True, threshold=threshold)
        quota = account.get("quota") if isinstance(account.get("quota"), dict) else {}
        row = {
            "file": account.get("file"),
            "email": account.get("email"),
            "name": account.get("name"),
            "plan": account.get("plan"),
            "status": account.get("status"),
            "quota_status": quota.get("status") if isinstance(quota, dict) else "",
            "min_remaining_percent": quota.get("min_remaining_percent") if isinstance(quota, dict) else None,
            "reason": reason,
        }
        if not ok:
            result["skipped"] += 1
            result["skipped_items"].append(row)
            continue
        file_path = Path(clean_string(account.get("_file_path")))
        target_path = export_folder / file_path.name
        try:
            shutil.copy2(file_path, target_path)
            row["action"] = "copied"
            row["to"] = str(target_path)
            result["items"].append(row)
            result["exported"] += 1
        except Exception as exc:
            row["error"] = str(exc)
            result["errors"] += 1
            result["items"].append(row)
            log_event("error", "导出可用账号失败", row)

    manifest = dict(result)
    manifest["items"] = sanitize_for_output(result["items"])
    manifest["skipped_items"] = sanitize_for_output(result["skipped_items"])
    manifest_path = export_folder / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    with zipfile.ZipFile(export_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(export_folder.iterdir(), key=lambda item: item.name.lower()):
            if path.is_file():
                zf.write(path, arcname=path.name)

    log_event(
        "info",
        "已导出可用 CPA 账号",
        {"exported": result["exported"], "skipped": result["skipped"], "errors": result["errors"], "zip": str(export_zip)},
    )
    return result


def build_summary(accounts: list[dict[str, Any]], cache: dict[str, Any] | None) -> dict[str, Any]:
    total = len(accounts)
    disabled = sum(1 for item in accounts if item.get("disabled"))
    expired = sum(1 for item in accounts if item.get("expired"))
    missing = sum(1 for item in accounts if item.get("status") == "missing_token")
    token_expired = sum(1 for item in accounts if item.get("status") == "token_expired")
    read_error = sum(1 for item in accounts if item.get("status") == "read_error")
    local_ok = sum(1 for item in accounts if item.get("status") == "ok")
    quota_low = 0
    quota_exhausted = 0
    quota_error = 0
    quota_known = 0
    for item in accounts:
        quota = item.get("quota")
        if not isinstance(quota, dict):
            continue
        quota_known += 1
        if quota.get("status") == "low":
            quota_low += 1
        elif quota.get("status") == "exhausted":
            quota_exhausted += 1
        elif quota.get("status") == "error":
            quota_error += 1
    return {
        "total": total,
        "local_ok": local_ok,
        "disabled": disabled,
        "expired": expired,
        "missing_token": missing,
        "token_expired": token_expired,
        "read_error": read_error,
        "problem_accounts": total - local_ok,
        "quota_known": quota_known,
        "quota_unknown": max(0, total - quota_known),
        "quota_low": quota_low,
        "quota_exhausted": quota_exhausted,
        "quota_error": quota_error,
        "quota_cache_created_at": cache.get("created_at") if isinstance(cache, dict) else "",
    }


def public_config(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "auth_dir": cfg.get("auth_dir"),
        "cpa_config_path": cfg.get("cpa_config_path"),
        "cpa_base_url": cfg.get("cpa_base_url"),
        "host": cfg.get("host"),
        "port": cfg.get("port"),
        "management_key_configured": bool(clean_string(cfg.get("management_key"))),
        "quota_query_mode": cfg.get("quota_query_mode"),
        "proxy_url_configured": bool(clean_string(cfg.get("proxy_url"))),
        "quota_low_threshold_percent": cfg.get("quota_low_threshold_percent"),
        "quota_query_concurrency": cfg.get("quota_query_concurrency"),
        "auto_cleanup_enabled": bool(cfg.get("auto_cleanup_enabled")),
        "auto_cleanup_interval_seconds": cfg.get("auto_cleanup_interval_seconds"),
        "cleanup_delete_quota_low": bool(cfg.get("cleanup_delete_quota_low", True)),
        "cleanup_quarantine_dir": cfg.get("cleanup_quarantine_dir"),
    }


def build_status_payload() -> dict[str, Any]:
    cfg = load_config()
    cache = load_quota_cache()
    accounts, warnings = scan_auth_accounts(cfg)
    quota_cache = cache if quota_cache_is_usable(cache, cfg, accounts) else None
    cleanup_result = cleanup_auth_pool(cfg, quota_cache=quota_cache)
    cleanup_recent = read_recent_cleanup_items(CLEANUP_DISPLAY_HOURS)
    cleanup_count_stats = cleanup_stats(CLEANUP_DISPLAY_HOURS)
    cache = load_quota_cache()
    accounts = merge_quota(accounts, cache)
    public_accounts = sanitize_for_output(accounts)
    return {
        "ok": True,
        "name": APP_NAME,
        "generated_at": isoformat_local(),
        "config": public_config(cfg),
        "warnings": warnings,
        "summary": build_summary(accounts, cache),
        "accounts": public_accounts,
        "quota_cache": sanitize_for_output(cache) if cache else None,
        "cleanup": sanitize_for_output(cleanup_result),
        "cleanup_stats": sanitize_for_output(cleanup_count_stats),
        "cleanup_recent": cleanup_recent,
        "cleanup_recent_hours": CLEANUP_DISPLAY_HOURS,
        "events": read_recent_events(80),
    }


def render_index() -> str:
    return r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CPA 号池监测</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f7f4;
      --ink: #202124;
      --muted: #626a73;
      --line: #dcdeda;
      --panel: #ffffff;
      --good: #16834a;
      --warn: #a86400;
      --bad: #b3261e;
      --blue: #1f5fbf;
      --soft-blue: #eaf1ff;
      --soft-red: #fff0ef;
      --soft-green: #eaf7ef;
      --soft-yellow: #fff7e0;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    header {
      position: sticky;
      top: 0;
      z-index: 5;
      background: rgba(247, 247, 244, .96);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(10px);
    }
    .topbar {
      max-width: 1500px;
      margin: 0 auto;
      padding: 14px 18px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    h1 {
      font-size: 20px;
      line-height: 1.2;
      margin: 0;
      white-space: nowrap;
    }
    .sub {
      color: var(--muted);
      font-size: 12px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      min-width: 0;
      flex: 1;
    }
    button, input {
      font: inherit;
    }
    button {
      border: 1px solid #b9c1cc;
      background: #fff;
      color: var(--ink);
      border-radius: 6px;
      padding: 8px 11px;
      cursor: pointer;
      white-space: nowrap;
    }
    button.primary {
      background: #1f5fbf;
      color: #fff;
      border-color: #1f5fbf;
    }
    button.danger {
      background: #b3261e;
      color: #fff;
      border-color: #b3261e;
    }
    button:disabled {
      cursor: wait;
      opacity: .65;
    }
    main {
      max-width: 1500px;
      margin: 0 auto;
      padding: 16px 18px 28px;
    }
    .status-line {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 12px;
      color: var(--muted);
      font-size: 13px;
    }
    .pill {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 9px;
      background: #fff;
    }
    .pill.good { color: var(--good); background: var(--soft-green); border-color: #c8e8d4; }
    .pill.warn { color: var(--warn); background: var(--soft-yellow); border-color: #f0d99d; }
    .pill.bad { color: var(--bad); background: var(--soft-red); border-color: #f1c5c1; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
      gap: 8px;
      margin-bottom: 14px;
    }
    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      min-height: 72px;
    }
    .metric .label {
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 5px;
    }
    .metric .value {
      font-size: 24px;
      font-weight: 700;
      line-height: 1.1;
    }
    section {
      margin-top: 16px;
      min-width: 0;
    }
    .section-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
    }
    h2 {
      font-size: 16px;
      margin: 0;
    }
    .tools {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .search {
      width: 260px;
      max-width: 100%;
      border: 1px solid #c6ccd2;
      border-radius: 6px;
      padding: 8px 10px;
      background: #fff;
    }
    .table-wrap {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: auto;
      width: 100%;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 1040px;
    }
    th, td {
      padding: 9px 10px;
      border-bottom: 1px solid #ecefeb;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }
    th {
      position: sticky;
      top: 0;
      background: #fbfbf9;
      z-index: 1;
      color: #434a52;
      font-weight: 700;
    }
    tr:last-child td { border-bottom: none; }
    .mono {
      font-family: Consolas, "Courier New", monospace;
      word-break: break-all;
    }
    .muted { color: var(--muted); }
    .status {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      border: 1px solid var(--line);
      background: #fff;
      white-space: nowrap;
    }
    .status.ok { color: var(--good); background: var(--soft-green); border-color: #c8e8d4; }
    .status.disabled, .status.expired, .status.read_error, .status.error, .status.exhausted { color: var(--bad); background: var(--soft-red); border-color: #f1c5c1; }
    .status.token_expired, .status.missing_token, .status.missing, .status.low, .status.unknown { color: var(--warn); background: var(--soft-yellow); border-color: #f0d99d; }
    .bar {
      width: 96px;
      height: 8px;
      border-radius: 999px;
      background: #e1e5e9;
      overflow: hidden;
      margin-top: 4px;
    }
    .bar > i {
      display: block;
      height: 100%;
      background: var(--good);
    }
    .bar.low > i { background: var(--bad); }
    .bar.warn > i { background: var(--warn); }
    .notice {
      border: 1px solid #d8c68b;
      background: #fff9e6;
      color: #5c4815;
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 12px;
      font-size: 13px;
    }
    .cleanup-log {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 14px;
    }
    .cleanup-log table {
      min-width: 760px;
    }
    .cleanup-log .empty {
      padding: 18px;
      color: var(--muted);
      font-size: 13px;
    }
    .cleanup-details {
      margin-bottom: 14px;
    }
    .cleanup-details summary {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      cursor: pointer;
      list-style: none;
    }
    .cleanup-details summary::-webkit-details-marker {
      display: none;
    }
    .cleanup-details[open] summary {
      border-bottom-left-radius: 0;
      border-bottom-right-radius: 0;
    }
    .cleanup-summary-main {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px 12px;
      min-width: 0;
    }
    .cleanup-summary-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--ink);
    }
    .cleanup-summary-action {
      border: 1px solid #b9c1cc;
      border-radius: 6px;
      padding: 6px 10px;
      background: #fff;
      color: var(--ink);
      white-space: nowrap;
      font-size: 13px;
    }
    .cleanup-details .cleanup-log {
      border-top: 0;
      border-top-left-radius: 0;
      border-top-right-radius: 0;
    }
    .reason {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 3px 8px;
      background: var(--soft-red);
      color: var(--bad);
      border: 1px solid #f1c5c1;
      font-size: 12px;
      white-space: nowrap;
    }
    .split {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(360px, .8fr);
      gap: 14px;
    }
    .log-list {
      background: #111827;
      color: #e5e7eb;
      border-radius: 8px;
      padding: 10px;
      min-height: 220px;
      max-height: 360px;
      overflow: auto;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
      line-height: 1.45;
    }
    @media (max-width: 1100px) {
      .metrics { grid-template-columns: repeat(4, minmax(118px, 1fr)); }
      .split { grid-template-columns: 1fr; }
    }
    @media (max-width: 720px) {
      .topbar {
        align-items: stretch;
        flex-wrap: wrap;
      }
      h1 { width: 100%; }
      .sub { width: 100%; flex-basis: 100%; white-space: normal; }
      .topbar button { flex: 1; min-width: 120px; }
      main { padding: 12px 10px 22px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric { min-height: 66px; }
      .metric .value { font-size: 22px; }
      .section-head { align-items: stretch; flex-direction: column; }
      .tools { width: 100%; }
      .search { width: 100%; }
      th, td { padding: 8px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <h1>CPA 号池监测</h1>
      <div class="sub" id="sourceLine">读取中...</div>
      <button id="cleanupBtn">立即清理</button>
      <button id="autoCleanupBtn"></button>
      <button id="lowQuotaDeleteBtn"></button>
      <button class="primary" id="quotaBtn">查询额度</button>
      <button class="primary" id="exportAvailableBtn">导出可用账号</button>
      <button class="danger" id="deleteTeamBtn"></button>
    </div>
  </header>
  <main>
    <div id="notice"></div>
    <div class="status-line" id="statusLine"></div>
    <div class="metrics" id="metrics"></div>
    <section id="cleanupLogSection"></section>
    <div class="split">
      <section>
        <div class="section-head">
          <h2>需要处理</h2>
          <div class="muted" id="problemCount"></div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>账号</th><th>状态</th><th>额度</th><th>文件</th><th>到期/刷新</th></tr></thead>
            <tbody id="problemRows"></tbody>
          </table>
        </div>
      </section>
      <section>
        <div class="section-head">
          <h2>运行日志</h2>
          <div class="muted" id="logCount"></div>
        </div>
        <div class="log-list" id="logs"></div>
      </section>
    </div>
    <section>
      <div class="section-head">
        <h2>账号列表</h2>
        <div class="tools">
          <input class="search" id="search" placeholder="搜索邮箱 / 文件 / 状态">
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>邮箱</th>
              <th>Plan</th>
              <th>本地状态</th>
              <th>额度状态</th>
              <th>5h</th>
              <th>7d</th>
              <th>Access Token</th>
              <th>账号ID</th>
              <th>JSON 文件</th>
            </tr>
          </thead>
          <tbody id="accountRows"></tbody>
        </table>
      </div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    let state = null;
    let cleanupLogExpanded = false;

    function h(value) {
      return String(value ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
    }
    function statusLabel(status) {
      const labels = {
        ok: '正常', disabled: '已禁用', expired: '已过期', missing_token: '缺 Token',
        token_expired: 'Access 过期', read_error: '读取失败', low: '低于阈值',
        exhausted: '已耗尽', error: '错误', missing: '缺字段', unknown: '未知'
      };
      return labels[status] || status || '未知';
    }
    function statusPill(status) {
      return `<span class="status ${h(status || 'unknown')}">${h(statusLabel(status))}</span>`;
    }
    function metric(label, value, cls='') {
      return `<div class="metric ${cls}"><div class="label">${h(label)}</div><div class="value">${h(value)}</div></div>`;
    }
    function fmtDate(value) {
      if (!value) return '-';
      return String(value).replace('T', ' ').replace(/\+\d\d:\d\d$/, '');
    }
    function fmtInterval(seconds) {
      const value = Number(seconds || 0);
      if (!value) return '-';
      if (value % 3600 === 0) return `${value / 3600}\u5c0f\u65f6`;
      if (value % 60 === 0) return `${value / 60}\u5206\u949f`;
      return `${value}\u79d2`;
    }
    function quotaFor(account) {
      return account.quota || null;
    }
    function windowById(quota, id) {
      if (!quota || !Array.isArray(quota.windows)) return null;
      return quota.windows.find(w => w.id === id) || null;
    }
    function windowCell(win) {
      if (!win || typeof win.remaining_percent !== 'number') return '<span class="muted">-</span>';
      const pct = Math.max(0, Math.min(100, win.remaining_percent));
      const cls = pct <= 5 ? 'low' : pct <= 15 ? 'warn' : '';
      return `<div>${pct.toFixed(1)}% <span class="muted">${h(win.reset_label || '-')}</span></div><div class="bar ${cls}"><i style="width:${pct}%"></i></div>`;
    }
    function quotaCell(account) {
      const q = quotaFor(account);
      if (!q) return '<span class="status unknown">未查询</span>';
      return `${statusPill(q.status)}${q.error ? `<div class="muted">${h(q.error)}</div>` : ''}`;
    }
    function planCell(account) {
      const q = quotaFor(account);
      const bad = new Set(['', 'unknown', 'none', 'null', '-']);
      const quotaPlan = q && q.plan ? String(q.plan).trim() : '';
      const authPlan = account.plan ? String(account.plan).trim() : '';
      const plan = !bad.has(quotaPlan.toLowerCase()) ? quotaPlan : (!bad.has(authPlan.toLowerCase()) ? authPlan : 'unknown');
      return h(plan);
    }
    function cleanupReasonLabel(reason) {
      const labels = {
        quota_low: '额度低于阈值',
        quota_exhausted: '额度耗尽',
        quota_missing: '额度缺失',
        quota_invalid: '额度/账号失效',
        token_expired: 'Token 过期',
        missing_token: '缺 Token',
        read_error: '读取失败',
        expired: '账号过期',
        manual_plan_team: '手动删除 Team'
      };
      return labels[reason] || reason || '自动删除';
    }
    function accountTitle(account) {
      const email = account.email || account.name || '(无邮箱)';
      return `<div>${h(email)}</div><div class="muted mono">${h(account.type || 'codex')}</div>`;
    }
    function render(data) {
      state = data;
      const cfg = data.config || {};
      const s = data.summary || {};
      const cleanupStats = data.cleanup_stats || {};
      const cleanupRecent = Array.isArray(data.cleanup_recent) ? data.cleanup_recent : [];
      $('sourceLine').textContent = `${cfg.auth_dir || '-'}  ·  CPA ${cfg.cpa_base_url || '-'}`;
      $('metrics').innerHTML = [
        metric('总账号', s.total ?? 0),
        metric('本地正常', s.local_ok ?? 0),
        metric('禁用', s.disabled ?? 0),
        metric('过期', s.expired ?? 0),
        metric('Token 过期', s.token_expired ?? 0),
        metric('额度低', (s.quota_low ?? 0) + (s.quota_exhausted ? ` / 耗尽 ${s.quota_exhausted}` : '')),
        metric('额度已查', s.quota_known ?? 0),
        metric('额度未知', s.quota_unknown ?? 0)
      ].join('');
      $('metrics').innerHTML += metric('自动删除', cleanupStats.total ?? 0);
      const notice = [];
      if (data.quota_error) {
        notice.push('额度查询失败：' + data.quota_error);
      }
      for (const w of (data.warnings || [])) notice.push(w);
      $('notice').innerHTML = notice.length ? `<div class="notice">${notice.map(h).join('<br>')}</div>` : '';
      const cleanupTotal = cleanupStats.total ?? 0;
      const cleanupRecentText = cleanupStats.recent ? ' / \u8fd1' + h(cleanupStats.hours || 12) + '\u5c0f\u65f6 ' + h(cleanupStats.recent) : '';
      const cleanupIntervalText = cfg.auto_cleanup_interval_seconds ? ' \u00b7 \u6bcf' + h(fmtInterval(cfg.auto_cleanup_interval_seconds)) + '\u81ea\u52a8\u67e5\u4e00\u6b21' : '';
      const cleanupStatusText = '\u81ea\u52a8\u6e05\u7406 ' + (cfg.auto_cleanup_enabled ? '\u5df2\u542f\u7528' : '\u672a\u542f\u7528') + cleanupIntervalText + ' \u00b7 \u81ea\u52a8\u5220\u9664 ' + h(cleanupTotal) + ' \u4e2a' + cleanupRecentText;
      $('autoCleanupBtn').textContent = cfg.auto_cleanup_enabled ? '\u5173\u95ed\u81ea\u52a8\u5220\u9664' : '\u5f00\u542f\u81ea\u52a8\u5220\u9664\u4e00\u5c0f\u65f6';
      $('lowQuotaDeleteBtn').textContent = cfg.cleanup_delete_quota_low ? '\u5173\u95ed\u4f4e\u4e8e5%\u5220\u9664' : '\u5f00\u542f\u4f4e\u4e8e5%\u5220\u9664';
      $('statusLine').innerHTML = [
        `<span class="pill good">页面 ${h(data.generated_at || '-')}</span>`,
        `<span class="pill good">额度模式 ${h(cfg.quota_query_mode || 'direct_auth')}</span>`,
        `<span class="pill ${cfg.proxy_url_configured ? 'good' : 'warn'}">代理 ${cfg.proxy_url_configured ? '已配置' : '未配置'}</span>`,
        `<span class="pill">低额度阈值 ${h(cfg.quota_low_threshold_percent)}%</span>`,
        `<span class="pill ${cfg.auto_cleanup_enabled ? 'good' : 'warn'}">${cleanupStatusText}</span>`,
        `<span class="pill ${cfg.cleanup_delete_quota_low ? 'good' : 'warn'}">\u4f4e\u4e8e5%\u5220\u9664 ${cfg.cleanup_delete_quota_low ? '\u5df2\u542f\u7528' : '\u5df2\u5173\u95ed'}</span>`,
        s.quota_cache_created_at ? `<span class="pill">额度缓存 ${h(fmtDate(s.quota_cache_created_at))}</span>` : ''
      ].filter(Boolean).join('');
      renderProblems(data.accounts || []);
      renderCleanupLog(cleanupRecent, data.cleanup_recent_hours || 12);
      renderAccounts(data.accounts || []);
      renderLogs(data.events || []);
    }
    function renderCleanupLog(items, hours) {
      const target = $('cleanupLogSection');
      if (!items.length) {
        target.innerHTML = '';
        return;
      }
      const latest = items[0] || {};
      const actionText = cleanupLogExpanded ? '\u6536\u8d77\u660e\u7ec6' : '\u5c55\u5f00\u660e\u7ec6';
      const detailAttr = cleanupLogExpanded ? ' open' : '';
      target.innerHTML = `
        <details class="cleanup-details"${detailAttr} id="cleanupDetails">
          <summary>
            <span class="cleanup-summary-main">
              <span class="cleanup-summary-title">\u81ea\u52a8\u5220\u9664\u65e5\u5fd7</span>
              <span class="muted">\u6700\u8fd1 ${h(hours)} \u5c0f\u65f6 ${h(items.length)} \u6761</span>
              <span class="muted">\u6700\u65b0 ${h(fmtDate(latest.time))} ${h(latest.email || latest.name || latest.file || '-')}</span>
            </span>
            <span class="cleanup-summary-action" id="cleanupToggleText">${h(actionText)}</span>
          </summary>
          <div class="cleanup-log table-wrap">
            <table>
              <thead><tr><th>\u5220\u9664\u65f6\u95f4</th><th>\u8d26\u53f7</th><th>\u539f\u56e0</th><th>\u989d\u5ea6\u72b6\u6001</th><th>JSON \u6587\u4ef6</th></tr></thead>
              <tbody>${items.map(item => `
                <tr>
                  <td>${h(fmtDate(item.time))}</td>
                  <td>${h(item.email || item.name || '-')}</td>
                  <td><span class="reason">${h(cleanupReasonLabel(item.reason))}</span></td>
                  <td>${h(statusLabel(item.quota_status || item.status || 'unknown'))}${item.quota_error ? `<div class="muted">${h(item.quota_error)}</div>` : ''}</td>
                  <td class="mono">${h(item.file || item.from || '-')}</td>
                </tr>
              `).join('')}</tbody>
            </table>
          </div>
        </details>`;
      const details = $('cleanupDetails');
      if (details) {
        details.addEventListener('toggle', () => {
          cleanupLogExpanded = details.open;
          const toggleText = $('cleanupToggleText');
          if (toggleText) toggleText.textContent = details.open ? '\u6536\u8d77\u660e\u7ec6' : '\u5c55\u5f00\u660e\u7ec6';
        });
      }
      return;
      target.innerHTML = `
        <div class="section-head">
          <h2>自动删除日志</h2>
          <div class="muted">显示最近 ${h(hours)} 小时，之后自动隐藏</div>
        </div>
        <div class="cleanup-log table-wrap">
          <table>
            <thead><tr><th>删除时间</th><th>账号</th><th>原因</th><th>额度状态</th><th>JSON 文件</th></tr></thead>
            <tbody>${items.map(item => `
              <tr>
                <td>${h(fmtDate(item.time))}</td>
                <td>${h(item.email || item.name || '-')}</td>
                <td><span class="reason">${h(cleanupReasonLabel(item.reason))}</span></td>
                <td>${h(statusLabel(item.quota_status || item.status || 'unknown'))}${item.quota_error ? `<div class="muted">${h(item.quota_error)}</div>` : ''}</td>
                <td class="mono">${h(item.file || item.from || '-')}</td>
              </tr>
            `).join('')}</tbody>
          </table>
        </div>`;
    }
    function renderProblems(accounts) {
      const rows = accounts.filter(a => a.status !== 'ok' || (a.quota && ['low','exhausted','error','missing'].includes(a.quota.status)));
      $('problemCount').textContent = `${rows.length} 个`;
      $('problemRows').innerHTML = rows.length ? rows.map(a => {
        const q = quotaFor(a);
        const q5 = windowById(q, 'code-5h');
        const q7 = windowById(q, 'code-7d');
        return `<tr>
          <td>${accountTitle(a)}</td>
          <td>${statusPill(a.status)}<div class="muted">${h((a.issues || []).join(', ') || '-')}</div></td>
          <td>${quotaCell(a)}<div>${windowCell(q5)}</div><div>${windowCell(q7)}</div></td>
          <td class="mono">${h(a.file)}</td>
          <td><div>exp: ${h(fmtDate(a.expired_at))}</div><div class="muted">refresh: ${h(fmtDate(a.last_refresh_at))}</div></td>
        </tr>`;
      }).join('') : '<tr><td colspan="5" class="muted">暂无需要处理的账号</td></tr>';
    }
    function renderAccounts(accounts) {
      const query = $('search').value.trim().toLowerCase();
      const filtered = !query ? accounts : accounts.filter(a => JSON.stringify(a).toLowerCase().includes(query));
      $('accountRows').innerHTML = filtered.map(a => {
        const q = quotaFor(a);
        return `<tr>
          <td>${accountTitle(a)}</td>
          <td>${planCell(a)}</td>
          <td>${statusPill(a.status)}<div class="muted">${h((a.issues || []).join(', ') || '-')}</div></td>
          <td>${quotaCell(a)}</td>
          <td>${windowCell(windowById(q, 'code-5h'))}</td>
          <td>${windowCell(windowById(q, 'code-7d'))}</td>
          <td><div>${h(fmtDate(a.access_expires_at))}</div><div class="muted">${a.access_seconds_left == null ? '-' : h(Math.round(a.access_seconds_left / 60)) + ' 分钟'}</div></td>
          <td class="mono">${h(a.account_id_tail || '-')}</td>
          <td class="mono">${h(a.file)}</td>
        </tr>`;
      }).join('') || '<tr><td colspan="9" class="muted">没有匹配账号</td></tr>';
    }
    function renderLogs(events) {
      $('logCount').textContent = `${events.length} 条`;
      $('logs').innerHTML = events.length ? events.slice().reverse().map(e => {
        const extra = e.extra && Object.keys(e.extra).length ? ' ' + JSON.stringify(e.extra) : '';
        return `<div>[${h(fmtDate(e.time))}] ${h(e.level)} ${h(e.message)}${h(extra)}</div>`;
      }).join('') : '<div class="muted">暂无日志</div>';
    }
    async function loadStatus() {
      try {
        const res = await fetch('/api/status', {cache:'no-store'});
        render(await res.json());
      } catch (err) {}
    }
    async function queryQuota() {
      $('quotaBtn').disabled = true;
      $('quotaBtn').textContent = '查询中...';
      try {
        const res = await fetch('/api/quota?refresh=1', {cache:'no-store'});
        const data = await res.json();
        render(data);
      } finally {
        $('quotaBtn').disabled = false;
        $('quotaBtn').textContent = '查询额度';
      }
    }
    async function cleanupNow() {
      $('cleanupBtn').disabled = true;
      $('cleanupBtn').textContent = '清理中...';
      try {
        const res = await fetch('/api/cleanup?force=1', {cache:'no-store'});
        const data = await res.json();
        render(data);
      } finally {
        $('cleanupBtn').disabled = false;
        $('cleanupBtn').textContent = '立即清理';
      }
    }
    async function exportAvailableAccounts() {
      if (!confirm('导出可用账号？系统会先刷新额度，只复制本地正常且额度正常的账号 JSON，不会删除原号池文件。')) return;
      const btn = $('exportAvailableBtn');
      btn.disabled = true;
      btn.textContent = '导出中...';
      try {
        const res = await fetch('/api/export-available?refresh=1', {method:'POST', cache:'no-store'});
        const data = await res.json();
        render(data);
        const result = data.export || {};
        if (result.download_url) {
          window.location.href = result.download_url;
        }
        alert(`导出完成：可用 ${result.exported ?? 0} 个，跳过 ${result.skipped ?? 0} 个，失败 ${result.errors ?? 0} 个。\n\n本地目录：${result.folder || '-'}`);
      } catch (err) {
        alert('导出失败：' + err);
      } finally {
        btn.disabled = false;
        btn.textContent = '导出可用账号';
      }
    }
    async function toggleAutoCleanup() {
      const cfg = state && state.config ? state.config : {};
      const nextEnabled = !cfg.auto_cleanup_enabled;
      const message = nextEnabled
        ? '\u5f00\u542f\u81ea\u52a8\u5220\u9664\uff1f\u5f00\u542f\u540e\u6bcf1\u5c0f\u65f6\u81ea\u52a8\u67e5\u989d\u5ea6\uff0c\u5e76\u5220\u9664 401\u3001\u6ca1\u989d\u5ea6\u3001\u4f4e\u4e8e5% \u7684\u8d26\u53f7\u3002'
        : '\u5173\u95ed\u81ea\u52a8\u5220\u9664\uff1f\u5173\u95ed\u540e\u4e0d\u4f1a\u81ea\u52a8\u5220\u53f7\uff0c\u4f46\u624b\u52a8\u201c\u7acb\u5373\u6e05\u7406\u201d\u8fd8\u80fd\u7528\u3002';
      if (!confirm(message)) return;
      const btn = $('autoCleanupBtn');
      btn.disabled = true;
      btn.textContent = nextEnabled ? '\u5f00\u542f\u4e2d...' : '\u5173\u95ed\u4e2d...';
      try {
        const enabled = nextEnabled ? '1' : '0';
        const res = await fetch(`/api/auto-cleanup?enabled=${enabled}&interval=3600`, {method:'POST', cache:'no-store'});
        const data = await res.json();
        render(data);
      } finally {
        btn.disabled = false;
      }
    }
    async function toggleLowQuotaDelete() {
      const cfg = state && state.config ? state.config : {};
      const nextEnabled = !cfg.cleanup_delete_quota_low;
      const message = nextEnabled
        ? '\u5f00\u542f\u4f4e\u989d\u5220\u9664\uff1f\u5f00\u542f\u540e\uff0c\u4f4e\u4e8e5% \u7684\u8d26\u53f7\u4f1a\u5728\u81ea\u52a8\u6e05\u7406\u548c\u7acb\u5373\u6e05\u7406\u65f6\u88ab\u5220\u9664\u3002'
        : '\u5173\u95ed\u4f4e\u989d\u5220\u9664\uff1f\u5173\u95ed\u540e\uff0c\u4f4e\u4e8e5% \u7684\u8d26\u53f7\u53ea\u4f1a\u663e\u793a\u4e3a\u4f4e\u989d\u5ea6\uff0c\u4e0d\u4f1a\u88ab\u81ea\u52a8\u6216\u7acb\u5373\u6e05\u7406\u5220\u9664\u3002';
      if (!confirm(message)) return;
      const btn = $('lowQuotaDeleteBtn');
      btn.disabled = true;
      btn.textContent = nextEnabled ? '\u5f00\u542f\u4e2d...' : '\u5173\u95ed\u4e2d...';
      try {
        const enabled = nextEnabled ? '1' : '0';
        const res = await fetch(`/api/low-quota-delete?enabled=${enabled}`, {method:'POST', cache:'no-store'});
        const data = await res.json();
        render(data);
      } finally {
        btn.disabled = false;
      }
    }
    function accountPlanValue(account) {
      const q = quotaFor(account);
      return String((q && q.plan) || account.plan || '').trim().toLowerCase();
    }
    async function deleteTeamAccounts() {
      const btn = $('deleteTeamBtn');
      btn.disabled = true;
      btn.textContent = '\u7edf\u8ba1\u4e2d...';
      try {
        const statusRes = await fetch('/api/status', {cache:'no-store'});
        const latestData = await statusRes.json();
        const accounts = Array.isArray(latestData.accounts) ? latestData.accounts : [];
        const teamCount = accounts.filter(a => accountPlanValue(a) === 'team').length;
        state = latestData;
        render(latestData);
        if (!confirm(`\u5f53\u524d\u8bc6\u522b\u5230 Team \u8d26\u53f7 ${teamCount} \u4e2a\u3002\u786e\u5b9a\u5168\u90e8\u5220\u9664\u5417\uff1f\n\n\u5220\u9664\u540e JSON \u4f1a\u76f4\u63a5\u4ece\u672c\u673a\u53f7\u6c60\u5220\u9664\uff0c\u4e0d\u80fd\u6062\u590d\u3002`)) return;
        const liveBtn = $('deleteTeamBtn');
        if (liveBtn) {
          liveBtn.disabled = true;
          liveBtn.textContent = '\u5220\u9664\u4e2d...';
        }
        const res = await fetch('/api/delete-plan?plan=team&confirm=DELETE_TEAM&refresh=1', {method:'POST', cache:'no-store'});
        const data = await res.json();
        render(data);
        const result = data.delete_plan || {};
        alert(`Team \u5220\u9664\u5b8c\u6210\uff1a\u5339\u914d ${result.matched ?? 0} \u4e2a\uff0c\u5df2\u5220\u9664 ${result.deleted ?? 0} \u4e2a\uff0c\u5931\u8d25 ${result.errors ?? 0} \u4e2a\u3002`);
      } finally {
        const resetBtn = $('deleteTeamBtn');
        if (resetBtn) {
          resetBtn.disabled = false;
          resetBtn.textContent = '\u5220\u9664\u5168\u90e8 Team';
        }
      }
    }
    $('deleteTeamBtn').textContent = '\u5220\u9664\u5168\u90e8 Team';
    $('cleanupBtn').addEventListener('click', cleanupNow);
    $('autoCleanupBtn').addEventListener('click', toggleAutoCleanup);
    $('lowQuotaDeleteBtn').addEventListener('click', toggleLowQuotaDelete);
    $('quotaBtn').addEventListener('click', queryQuota);
    $('exportAvailableBtn').addEventListener('click', exportAvailableAccounts);
    $('deleteTeamBtn').addEventListener('click', deleteTeamAccounts);
    $('search').addEventListener('input', () => state && renderAccounts(state.accounts || []));
    loadStatus();
    setInterval(loadStatus, 30000);
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "zny-cpa-account-pool-monitor/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(sanitize_for_output(payload), ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, raw, "application/json; charset=utf-8")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/":
            self.send_bytes(200, render_index().encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/ping":
            self.send_json({"ok": True, "name": APP_NAME, "time": isoformat_local()})
            return
        if path == "/api/logs":
            self.send_json({"ok": True, "events": read_recent_events(300)})
            return
        if path == "/api/status":
            query = urllib.parse.parse_qs(parsed.query)
            if (query.get("refresh") or [""])[-1] in {"1", "true", "yes", "on"}:
                self.handle_quota()
            else:
                self.send_json(build_status_payload())
            return
        if path == "/api/quota":
            self.handle_quota()
            return
        if path == "/api/cleanup":
            self.handle_cleanup()
            return
        if path == "/api/download-export":
            self.handle_download_export(parsed)
            return
        if path == "/favicon.ico":
            self.send_bytes(404, b"", "text/plain")
            return
        self.send_json({"ok": False, "error": "not found"}, 404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/quota":
            self.handle_quota()
            return
        if parsed.path == "/api/cleanup":
            self.handle_cleanup()
            return
        if parsed.path == "/api/auto-cleanup":
            self.handle_auto_cleanup(parsed)
            return
        if parsed.path == "/api/low-quota-delete":
            self.handle_low_quota_delete(parsed)
            return
        if parsed.path == "/api/delete-plan":
            self.handle_delete_plan(parsed)
            return
        if parsed.path == "/api/export-available":
            self.handle_export_available(parsed)
            return
        self.send_json({"ok": False, "error": "not found"}, 404)

    def handle_export_available(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        refresh = (query.get("refresh") or ["1"])[-1] not in {"0", "false", "no", "off"}
        cfg = load_config()
        try:
            result = export_available_accounts(cfg, refresh_quota=refresh)
        except Exception as exc:
            log_event("error", "导出可用账号失败", {"error": str(exc)})
            payload = build_status_payload()
            payload["ok"] = False
            payload["export_error"] = str(exc)
            self.send_json(payload, 200)
            return
        payload = build_status_payload()
        payload["export"] = sanitize_for_output(result)
        self.send_json(payload)

    def handle_download_export(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        name = clean_string((query.get("name") or [""])[-1])
        if not name or name != Path(name).name or not name.lower().endswith(".zip"):
            self.send_json({"ok": False, "error": "invalid export name"}, 400)
            return
        path = EXPORT_DIR / name
        try:
            resolved_export_dir = EXPORT_DIR.resolve()
            resolved_path = path.resolve()
        except Exception:
            self.send_json({"ok": False, "error": "invalid export path"}, 400)
            return
        if resolved_export_dir not in resolved_path.parents or not resolved_path.exists() or not resolved_path.is_file():
            self.send_json({"ok": False, "error": "export not found"}, 404)
            return
        try:
            body = resolved_path.read_bytes()
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, 500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", f'attachment; filename="{resolved_path.name}"')
        self.end_headers()
        self.wfile.write(body)

    def handle_quota(self) -> None:
        cfg = load_config()
        try:
            with QUOTA_LOCK:
                cache = query_quota_reports(cfg)
                cleanup_result = cleanup_auth_pool(cfg, force=True, quota_cache=cache)
        except Exception as exc:
            log_event("error", "CPA 额度查询失败", {"error": str(exc)})
            payload = build_status_payload()
            payload["ok"] = False
            payload["quota_error"] = str(exc)
            self.send_json(payload, 200)
            return
        payload = build_status_payload()
        payload["quota"] = sanitize_for_output(cache)
        payload["cleanup"] = sanitize_for_output(cleanup_result)
        self.send_json(payload)

    def handle_cleanup(self) -> None:
        cfg = load_config()
        accounts, _warnings = scan_auth_accounts(cfg)
        cache = load_quota_cache()
        quota_cache = cache if quota_cache_is_usable(cache, cfg, accounts) else None
        if quota_cache is None:
            try:
                with QUOTA_LOCK:
                    quota_cache = query_quota_reports(cfg)
            except Exception as exc:
                log_event("error", "手动清理前刷新额度失败，已跳过额度删除", {"error": str(exc)})
                quota_cache = None
        try:
            result = cleanup_auth_pool(cfg, force=True, quota_cache=quota_cache)
        except Exception as exc:
            log_event("error", "手动清理失败", {"error": str(exc)})
            payload = build_status_payload()
            payload["ok"] = False
            payload["cleanup_error"] = str(exc)
            self.send_json(payload, 200)
            return
        payload = build_status_payload()
        payload["cleanup"] = sanitize_for_output(result)
        self.send_json(payload)

    def handle_auto_cleanup(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        enabled_raw = clean_string((query.get("enabled") or [""])[-1]).lower()
        interval_raw = clean_string((query.get("interval") or ["3600"])[-1])
        enabled = enabled_raw in {"1", "true", "yes", "on", "enable", "enabled"}
        try:
            interval = max(3600, int(interval_raw or "3600"))
        except ValueError:
            interval = 3600
        cfg = save_runtime_config(
            {
                "auto_cleanup_enabled": enabled,
                "auto_cleanup_interval_seconds": interval,
            }
        )
        CLEANUP_STATE["last_run"] = time.time() if enabled else 0.0
        CLEANUP_STATE["last_result"] = None
        log_event("info", "更新自动删除配置", {"enabled": enabled, "interval": interval})
        payload = build_status_payload()
        payload["auto_cleanup_updated"] = {
            "enabled": cfg.get("auto_cleanup_enabled"),
            "interval": cfg.get("auto_cleanup_interval_seconds"),
        }
        self.send_json(payload)

    def handle_low_quota_delete(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        enabled_raw = clean_string((query.get("enabled") or [""])[-1]).lower()
        enabled = enabled_raw in {"1", "true", "yes", "on", "enable", "enabled"}
        cfg = save_runtime_config({"cleanup_delete_quota_low": enabled})
        log_event("info", "更新低额度删除配置", {"enabled": enabled})
        payload = build_status_payload()
        payload["low_quota_delete_updated"] = {"enabled": cfg.get("cleanup_delete_quota_low")}
        self.send_json(payload)

    def handle_delete_plan(self, parsed: urllib.parse.ParseResult) -> None:
        query = urllib.parse.parse_qs(parsed.query)
        plan = clean_string((query.get("plan") or [""])[-1]).lower()
        confirm = clean_string((query.get("confirm") or [""])[-1])
        refresh = (query.get("refresh") or ["1"])[-1] not in {"0", "false", "no", "off"}
        if plan != "team" or confirm != "DELETE_TEAM":
            self.send_json({"ok": False, "error": "confirmation required"}, 400)
            return
        cfg = load_config()
        try:
            result = delete_accounts_by_plan(cfg, plan, refresh_quota=refresh)
        except Exception as exc:
            log_event("error", "鎵嬪姩鎵归噺鍒犻櫎 Team 澶辫触", {"error": str(exc)})
            payload = build_status_payload()
            payload["ok"] = False
            payload["delete_plan_error"] = str(exc)
            self.send_json(payload, 200)
            return
        payload = build_status_payload()
        payload["delete_plan"] = sanitize_for_output(result)
        self.send_json(payload)


def main() -> None:
    ensure_data_dir()
    cfg = load_config()
    host = clean_string(cfg.get("host")) or "127.0.0.1"
    port = int(cfg.get("port") or 18320)
    log_event("info", "CPA 号池监测启动", {"listen": f"{host}:{port}", "auth_dir": cfg.get("auth_dir")})
    threading.Thread(target=cleanup_worker, name="cpa-auth-cleanup", daemon=True).start()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"{APP_NAME} listening on http://{host}:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log_event("info", "CPA 号池监测停止")
        server.server_close()


if __name__ == "__main__":
    main()
