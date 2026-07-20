import http.client
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
from html import escape as html_escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("CPA_USAGE_MONITOR_CONFIG", APP_DIR / "monitor_config.json"))

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 18319,
    "upstream_base_url": "http://127.0.0.1:8317/v1",
    "upstream_api_key": "",
    "upstream_api_key_env": "CPA_MONITOR_UPSTREAM_API_KEY",
    "preserve_client_authorization": True,
    "data_dir": "monitor_data",
    "price_file": "model_prices.json",
    "connect_timeout_seconds": 15,
    "read_timeout_seconds": 900,
    "max_body_bytes": 104857600,
}

DEFAULT_PRICES = {
    "currency": "USD",
    "currency_symbol": "$",
    "updated": "2026-06-08",
    "source": "https://platform.openai.com/docs/pricing/",
    "note": "OpenAI official API pricing copied from https://platform.openai.com/docs/pricing/ on 2026-06-08. Prices are editable.",
    "default": {
        "input_per_1m": 0,
        "cached_input_per_1m": 0,
        "output_per_1m": 0,
        "total_blended_per_1m": 6.0,
    },
    "models": {
        "gpt-5.5": {
            "input_per_1m": 5.0,
            "cached_input_per_1m": 0.5,
            "output_per_1m": 30.0,
            "long_context_min_input_tokens": 272000,
            "long_input_per_1m": 10.0,
            "long_cached_input_per_1m": 1.0,
            "long_output_per_1m": 45.0,
        },
        "gpt-5.5-pro": {
            "input_per_1m": 30.0,
            "cached_input_per_1m": 0.0,
            "output_per_1m": 180.0,
            "long_context_min_input_tokens": 272000,
            "long_input_per_1m": 60.0,
            "long_cached_input_per_1m": 0.0,
            "long_output_per_1m": 270.0,
        },
        "gpt-5.4": {
            "input_per_1m": 2.5,
            "cached_input_per_1m": 0.25,
            "output_per_1m": 15.0,
        },
        "gpt-5.4-pro": {
            "input_per_1m": 30.0,
            "cached_input_per_1m": 0.0,
            "output_per_1m": 180.0,
            "long_context_min_input_tokens": 272000,
            "long_input_per_1m": 60.0,
            "long_cached_input_per_1m": 0.0,
            "long_output_per_1m": 270.0,
        },
        "gpt-5.4-mini": {
            "input_per_1m": 0.75,
            "cached_input_per_1m": 0.075,
            "output_per_1m": 4.5,
        },
        "gpt-5.4-nano": {
            "input_per_1m": 0.2,
            "cached_input_per_1m": 0.02,
            "output_per_1m": 1.25,
        },
        "gpt-5.3-codex": {
            "input_per_1m": 1.75,
            "cached_input_per_1m": 0.175,
            "output_per_1m": 14.0,
        },
    },
}

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

DB_LOCK = threading.Lock()


class MonitorError(Exception):
    def __init__(self, status, message, error_type="monitor_error"):
        super().__init__(message)
        self.status = int(status)
        self.message = str(message)
        self.error_type = str(error_type)


def read_json(path, default):
    try:
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return default


def write_json_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def resolve_app_path(value, default_name):
    text = str(value or default_name)
    path = Path(text)
    if not path.is_absolute():
        path = APP_DIR / path
    return path


def load_config():
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        loaded = read_json(CONFIG_PATH, {})
        if isinstance(loaded, dict):
            config.update(loaded)
    return config


def config_bool(value, default):
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return bool(default)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enable", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disable", "disabled"}:
        return False
    return bool(default)


def config_int(value, default, minimum, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    parsed = max(int(minimum), parsed)
    if maximum is not None:
        parsed = min(int(maximum), parsed)
    return parsed


CONFIG = load_config()
HOST = str(os.environ.get("CPA_USAGE_MONITOR_HOST") or CONFIG.get("host") or "127.0.0.1")
PORT = config_int(os.environ.get("CPA_USAGE_MONITOR_PORT") or CONFIG.get("port"), 18319, 1, 65535)
UPSTREAM_BASE_URL = str(CONFIG.get("upstream_base_url") or "").rstrip("/")
UPSTREAM_API_KEY = str(
    os.environ.get(str(CONFIG.get("upstream_api_key_env") or "CPA_MONITOR_UPSTREAM_API_KEY"))
    or CONFIG.get("upstream_api_key")
    or ""
)
PRESERVE_CLIENT_AUTHORIZATION = config_bool(CONFIG.get("preserve_client_authorization"), True)
DATA_DIR = resolve_app_path(CONFIG.get("data_dir"), "monitor_data")
PRICE_FILE = resolve_app_path(CONFIG.get("price_file"), "model_prices.json")
USAGE_DB = DATA_DIR / "usage.sqlite3"
CONNECT_TIMEOUT = config_int(CONFIG.get("connect_timeout_seconds"), 15, 1, 300)
READ_TIMEOUT = config_int(CONFIG.get("read_timeout_seconds"), 900, 1, 86400)
MAX_BODY_BYTES = config_int(CONFIG.get("max_body_bytes"), 104857600, 1024, 2147483648)


def ensure_price_file():
    if not PRICE_FILE.exists():
        write_json_atomic(PRICE_FILE, DEFAULT_PRICES)


def load_prices():
    ensure_price_file()
    loaded = read_json(PRICE_FILE, DEFAULT_PRICES)
    if not isinstance(loaded, dict):
        return DEFAULT_PRICES
    if not isinstance(loaded.get("models"), dict):
        loaded["models"] = {}
    if not isinstance(loaded.get("default"), dict):
        loaded["default"] = DEFAULT_PRICES["default"]
    return loaded


def db_connect():
    conn = sqlite3.connect(USAGE_DB, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db_connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                day TEXT NOT NULL,
                request_id TEXT NOT NULL,
                account TEXT,
                ip TEXT,
                method TEXT,
                path TEXT,
                model TEXT,
                status INTEGER,
                elapsed_ms INTEGER,
                ttft_ms INTEGER,
                estimated_tokens INTEGER,
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                cached_tokens INTEGER,
                total_tokens INTEGER,
                bytes_in INTEGER,
                bytes_out INTEGER,
                error_type TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_day ON usage(day)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_model ON usage(model)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_account ON usage(account)")


def safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def safe_float(value, default=0.0):
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def today_text():
    return time.strftime("%Y-%m-%d", time.localtime())


def normalize_date_text(value, default):
    text = str(value or "").strip()[:10]
    try:
        time.strptime(text, "%Y-%m-%d")
        return text
    except Exception:
        return default


def parse_json_body(headers, body):
    content_type = str(headers.get("Content-Type") or "").lower()
    if not body or "json" not in content_type:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def extract_model(payload):
    if isinstance(payload, dict):
        model = payload.get("model")
        if isinstance(model, str):
            return model[:200]
        if isinstance(payload.get("body"), dict):
            return extract_model(payload["body"])
    return ""


def estimate_tokens(value):
    total = 0
    if value is None:
        return 0
    if isinstance(value, str):
        return max(1, (len(value) + 3) // 4)
    if isinstance(value, (int, float, bool)):
        return 1
    if isinstance(value, list):
        for item in value:
            total += estimate_tokens(item)
        return total
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) in {"max_tokens", "max_completion_tokens"}:
                total += max(0, safe_int(item, 0))
            else:
                total += estimate_tokens(item)
        return total
    return 0


def first_present_int(*values):
    for value in values:
        if value is not None:
            return safe_int(value, 0)
    return 0


def normalize_usage(usage):
    if not isinstance(usage, dict):
        return {}
    prompt_tokens = first_present_int(usage.get("prompt_tokens"), usage.get("input_tokens"))
    completion_tokens = first_present_int(usage.get("completion_tokens"), usage.get("output_tokens"))
    total_tokens = first_present_int(usage.get("total_tokens"))
    if total_tokens <= 0 and prompt_tokens + completion_tokens > 0:
        total_tokens = prompt_tokens + completion_tokens

    cached_tokens = 0
    for details_key in ("prompt_tokens_details", "input_tokens_details"):
        details = usage.get(details_key)
        if isinstance(details, dict):
            cached_tokens = max(
                cached_tokens,
                first_present_int(details.get("cached_tokens"), details.get("cache_read_input_tokens")),
            )
    cached_tokens = min(max(0, cached_tokens), max(0, prompt_tokens))

    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cached_tokens": cached_tokens,
        "total_tokens": total_tokens,
    }


def find_usage_in_obj(obj):
    if isinstance(obj, dict):
        if isinstance(obj.get("usage"), dict):
            return normalize_usage(obj["usage"])
        for value in obj.values():
            usage = find_usage_in_obj(value)
            if usage:
                return usage
    elif isinstance(obj, list):
        for value in obj:
            usage = find_usage_in_obj(value)
            if usage:
                return usage
    return {}


def update_usage_from_sse(data_bytes, pending_text, current_usage):
    text = pending_text + data_bytes.decode("utf-8", errors="ignore")
    lines = text.splitlines(keepends=True)
    if lines and not (lines[-1].endswith("\n") or lines[-1].endswith("\r")):
        pending_text = lines.pop()
    else:
        pending_text = ""
    usage = current_usage
    for line in lines:
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]" or '"usage"' not in payload:
            continue
        try:
            parsed = json.loads(payload)
        except Exception:
            continue
        found = find_usage_in_obj(parsed)
        if found:
            usage = found
    return pending_text[-20000:], usage


def update_usage_from_json_buffer(buffer_bytes, content_type, current_usage):
    if current_usage or b'"usage"' not in buffer_bytes:
        return current_usage
    if "json" not in str(content_type or "").lower() and not buffer_bytes.lstrip().startswith((b"{", b"[")):
        return current_usage
    try:
        parsed = json.loads(buffer_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        return current_usage
    return find_usage_in_obj(parsed) or current_usage


def token_speed(completion_tokens, elapsed_ms, ttft_ms):
    completion_tokens = safe_int(completion_tokens, 0)
    elapsed_ms = safe_int(elapsed_ms, 0)
    ttft_ms = safe_int(ttft_ms, 0)
    active_ms = max(1, elapsed_ms - ttft_ms)
    if completion_tokens <= 0:
        return 0.0
    return round(completion_tokens / (active_ms / 1000.0), 2)


def parse_bearer(value):
    text = str(value or "").strip()
    if text.lower().startswith("bearer "):
        return text[7:].strip()
    return ""


def account_from_headers(headers):
    gateway_user = str(headers.get("X-Gateway-User") or "").strip()
    if gateway_user:
        return gateway_user[:120]
    explicit = str(headers.get("X-CPA-Monitor-Account") or headers.get("X-User") or "").strip()
    if explicit:
        return explicit[:120]
    token = parse_bearer(headers.get("Authorization"))
    if token:
        digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:12]
        return "self:" + digest
    return "self/local"


def client_ip(headers, client_address):
    forwarded = str(headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if forwarded:
        return forwarded[:80]
    real_ip = str(headers.get("X-Real-IP") or "").strip()
    if real_ip:
        return real_ip[:80]
    try:
        return str(client_address[0])[:80]
    except Exception:
        return ""


def read_body(handler):
    length_text = handler.headers.get("Content-Length")
    if not length_text:
        return b""
    length = safe_int(length_text, -1)
    if length < 0:
        raise MonitorError(400, "Invalid Content-Length", "bad_request")
    if length > MAX_BODY_BYTES:
        raise MonitorError(413, "Request body is too large", "request_too_large")
    body = handler.rfile.read(length) if length else b""
    if len(body) != length:
        raise MonitorError(400, "Incomplete request body", "bad_request")
    return body


def target_url(incoming_path):
    parsed = urllib.parse.urlsplit(incoming_path)
    request_path = parsed.path or ""
    if request_path == "/v1":
        suffix = ""
    elif request_path.startswith("/v1/"):
        suffix = request_path[len("/v1") :]
    else:
        raise MonitorError(404, "Only /v1 is served by this monitor", "not_found")
    target = UPSTREAM_BASE_URL + suffix
    if parsed.query:
        target += "?" + parsed.query
    return target


def send_cors(handler):
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, OpenAI-Beta, X-Gateway-User, X-CPA-Monitor-Account",
    )
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")


def write_usage_record(record):
    init_db()
    row = {
        "ts": str(record.get("ts") or now_text()),
        "day": str(record.get("ts") or now_text())[:10],
        "request_id": str(record.get("request_id") or ""),
        "account": str(record.get("account") or ""),
        "ip": str(record.get("ip") or ""),
        "method": str(record.get("method") or ""),
        "path": str(record.get("path") or ""),
        "model": str(record.get("model") or ""),
        "status": safe_int(record.get("status"), 0),
        "elapsed_ms": safe_int(record.get("elapsed_ms"), 0),
        "ttft_ms": safe_int(record.get("ttft_ms"), 0),
        "estimated_tokens": safe_int(record.get("estimated_tokens"), 0),
        "prompt_tokens": safe_int(record.get("prompt_tokens"), 0),
        "completion_tokens": safe_int(record.get("completion_tokens"), 0),
        "cached_tokens": safe_int(record.get("cached_tokens"), 0),
        "total_tokens": safe_int(record.get("total_tokens"), 0),
        "bytes_in": safe_int(record.get("bytes_in"), 0),
        "bytes_out": safe_int(record.get("bytes_out"), 0),
        "error_type": str(record.get("error_type") or ""),
    }
    with DB_LOCK:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO usage (
                    ts, day, request_id, account, ip, method, path, model, status,
                    elapsed_ms, ttft_ms, estimated_tokens, prompt_tokens, completion_tokens,
                    cached_tokens, total_tokens, bytes_in, bytes_out, error_type
                )
                VALUES (
                    :ts, :day, :request_id, :account, :ip, :method, :path, :model, :status,
                    :elapsed_ms, :ttft_ms, :estimated_tokens, :prompt_tokens, :completion_tokens,
                    :cached_tokens, :total_tokens, :bytes_in, :bytes_out, :error_type
                )
                """,
                row,
            )


def price_for_model(model, prices):
    models = prices.get("models") if isinstance(prices, dict) else {}
    if not isinstance(models, dict):
        models = {}
    model_text = str(model or "").strip()
    if model_text in models and isinstance(models[model_text], dict):
        return models[model_text], model_text
    for key in sorted(models.keys(), key=lambda item: len(str(item)), reverse=True):
        key_text = str(key)
        if model_text == key_text or model_text.startswith(key_text + "-"):
            entry = models.get(key)
            if isinstance(entry, dict):
                return entry, key_text
    default = prices.get("default") if isinstance(prices, dict) else {}
    if not isinstance(default, dict):
        default = DEFAULT_PRICES["default"]
    return default, ""


def blended_total_rate(entry, prices, fallback_rate):
    if isinstance(entry, dict) and "total_blended_per_1m" in entry:
        return safe_float(entry.get("total_blended_per_1m"), fallback_rate)
    default = prices.get("default") if isinstance(prices, dict) else {}
    if isinstance(default, dict) and "total_blended_per_1m" in default:
        return safe_float(default.get("total_blended_per_1m"), fallback_rate)
    return fallback_rate


def record_cost_usd(model, prompt_tokens, completion_tokens, cached_tokens, fallback_tokens, prices, total_tokens=None):
    entry, matched = price_for_model(model, prices)
    input_rate = safe_float(entry.get("input_per_1m"), 0.0)
    cached_rate = safe_float(entry.get("cached_input_per_1m"), input_rate)
    output_rate = safe_float(entry.get("output_per_1m"), 0.0)
    prompt_tokens = max(0, safe_int(prompt_tokens, 0))
    completion_tokens = max(0, safe_int(completion_tokens, 0))
    cached_tokens = min(max(0, safe_int(cached_tokens, 0)), prompt_tokens)
    fallback_tokens = max(0, safe_int(fallback_tokens, 0))
    total_tokens = max(0, safe_int(total_tokens, 0))

    long_min = safe_int(entry.get("long_context_min_input_tokens"), 0)
    if long_min > 0 and prompt_tokens > long_min:
        input_rate = safe_float(entry.get("long_input_per_1m"), input_rate)
        cached_rate = safe_float(entry.get("long_cached_input_per_1m"), cached_rate)
        output_rate = safe_float(entry.get("long_output_per_1m"), output_rate)

    if prompt_tokens <= 0 and completion_tokens <= 0:
        blended_tokens = total_tokens if total_tokens > 0 else fallback_tokens
        if blended_tokens > 0:
            blended_rate = blended_total_rate(entry, prices, input_rate)
            return (blended_tokens * blended_rate) / 1_000_000, total_tokens <= 0, matched or "total_blended"

    uncached_input = max(0, prompt_tokens - cached_tokens)
    cost = (
        (uncached_input * input_rate)
        + (cached_tokens * cached_rate)
        + (completion_tokens * output_rate)
    ) / 1_000_000
    if fallback_tokens > 0:
        blended_rate = blended_total_rate(entry, prices, input_rate)
        cost += (fallback_tokens * blended_rate) / 1_000_000
        return cost, True, matched
    return cost, False, matched


def sql_group_by(start_date, end_date, group_cols):
    allowed = {"model", "account"}
    cols = [col for col in group_cols if col in allowed]
    select_cols = ", ".join(cols) + (", " if cols else "")
    group_clause = " GROUP BY " + ", ".join(cols) if cols else ""
    sql = f"""
        SELECT
            {select_cols}
            COUNT(*) AS requests,
            SUM(CASE WHEN status >= 200 AND status < 400 THEN 1 ELSE 0 END) AS success,
            SUM(CASE WHEN status < 200 OR status >= 400 THEN 1 ELSE 0 END) AS errors,
            SUM(CASE WHEN total_tokens > 0 THEN 1 ELSE 0 END) AS usage_requests,
            SUM(CASE WHEN total_tokens <= 0 THEN 1 ELSE 0 END) AS estimated_requests,
            SUM(CASE WHEN total_tokens > 0 THEN total_tokens ELSE 0 END) AS actual_tokens,
            SUM(CASE WHEN total_tokens <= 0 THEN estimated_tokens ELSE 0 END) AS estimated_fallback_tokens,
            SUM(prompt_tokens) AS prompt_tokens,
            SUM(completion_tokens) AS completion_tokens,
            SUM(cached_tokens) AS cached_tokens,
            SUM(bytes_in) AS bytes_in,
            SUM(bytes_out) AS bytes_out,
            SUM(elapsed_ms) AS elapsed_ms,
            SUM(CASE WHEN ttft_ms > 0 THEN ttft_ms ELSE 0 END) AS ttft_ms_total,
            SUM(CASE WHEN ttft_ms > 0 THEN 1 ELSE 0 END) AS ttft_count
        FROM usage
        WHERE day >= ? AND day <= ?
        {group_clause}
    """
    with db_connect() as conn:
        rows = [dict(row) for row in conn.execute(sql, (start_date, end_date)).fetchall()]
    return rows


def add_costs(rows, prices):
    for row in rows:
        cost, estimated_cost, matched = record_cost_usd(
            row.get("model") or "",
            row.get("prompt_tokens"),
            row.get("completion_tokens"),
            row.get("cached_tokens"),
            row.get("estimated_fallback_tokens"),
            prices,
            row.get("actual_tokens"),
        )
        row["cost_usd"] = cost
        row["estimated_cost"] = estimated_cost
        row["matched_price_model"] = matched
        row["total_display_tokens"] = safe_int(row.get("actual_tokens"), 0) + safe_int(
            row.get("estimated_fallback_tokens"), 0
        )
        price_entry, _ = price_for_model(row.get("model") or "", prices)
        equivalent_rate = blended_total_rate(
            price_entry,
            prices,
            safe_float(price_entry.get("input_per_1m"), 0.0) if isinstance(price_entry, dict) else 0.0,
        )
        row["equivalent_cost_usd"] = (
            safe_int(row.get("total_display_tokens"), 0) * equivalent_rate
        ) / 1_000_000
        row["avg_elapsed_ms"] = (
            safe_int(row.get("elapsed_ms"), 0) / max(1, safe_int(row.get("requests"), 0))
        )
        row["avg_ttft_ms"] = (
            safe_int(row.get("ttft_ms_total"), 0) / max(1, safe_int(row.get("ttft_count"), 0))
            if safe_int(row.get("ttft_count"), 0) > 0
            else 0
        )
        row["tokens_per_second"] = token_speed(
            row.get("completion_tokens"), row.get("elapsed_ms"), row.get("ttft_ms_total")
        )
    rows.sort(key=lambda item: (safe_int(item.get("total_display_tokens"), 0), safe_int(item.get("requests"), 0)), reverse=True)
    return rows


def combine_totals(model_rows):
    total = {
        "requests": 0,
        "success": 0,
        "errors": 0,
        "usage_requests": 0,
        "estimated_requests": 0,
        "actual_tokens": 0,
        "estimated_fallback_tokens": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cached_tokens": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "cost_usd": 0.0,
        "equivalent_cost_usd": 0.0,
    }
    for row in model_rows:
        for key in total:
            if key in {"cost_usd", "equivalent_cost_usd"}:
                total[key] += safe_float(row.get(key), 0.0)
            else:
                total[key] += safe_int(row.get(key), 0)
    total["total_display_tokens"] = total["actual_tokens"] + total["estimated_fallback_tokens"]
    return total


def combine_rows(rows, key_fields):
    numeric_keys = {
        "requests",
        "success",
        "errors",
        "usage_requests",
        "estimated_requests",
        "actual_tokens",
        "estimated_fallback_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cached_tokens",
        "bytes_in",
        "bytes_out",
        "elapsed_ms",
        "ttft_ms_total",
        "ttft_count",
        "cost_usd",
        "equivalent_cost_usd",
    }
    grouped = {}
    for row in rows:
        key = tuple(str(row.get(field) or "") for field in key_fields)
        item = grouped.setdefault(key, {field: str(row.get(field) or "") for field in key_fields})
        for numeric_key in numeric_keys:
            if numeric_key in {"cost_usd", "equivalent_cost_usd"}:
                item[numeric_key] = safe_float(item.get(numeric_key), 0.0) + safe_float(row.get(numeric_key), 0.0)
            else:
                item[numeric_key] = safe_int(item.get(numeric_key), 0) + safe_int(row.get(numeric_key), 0)
    combined = list(grouped.values())
    for item in combined:
        item["total_display_tokens"] = safe_int(item.get("actual_tokens"), 0) + safe_int(
            item.get("estimated_fallback_tokens"), 0
        )
        item["avg_elapsed_ms"] = safe_int(item.get("elapsed_ms"), 0) / max(1, safe_int(item.get("requests"), 0))
        item["avg_ttft_ms"] = (
            safe_int(item.get("ttft_ms_total"), 0) / max(1, safe_int(item.get("ttft_count"), 0))
            if safe_int(item.get("ttft_count"), 0) > 0
            else 0
        )
        item["tokens_per_second"] = token_speed(
            item.get("completion_tokens"), item.get("elapsed_ms"), item.get("ttft_ms_total")
        )
    combined.sort(
        key=lambda item: (safe_int(item.get("total_display_tokens"), 0), safe_int(item.get("requests"), 0)),
        reverse=True,
    )
    return combined


def stats_for_range(start_date, end_date):
    prices = load_prices()
    model_rows = add_costs(sql_group_by(start_date, end_date, ["model"]), prices)
    account_model_rows = add_costs(sql_group_by(start_date, end_date, ["account", "model"]), prices)
    account_rows = combine_rows(account_model_rows, ["account"])
    return {
        "start": start_date,
        "end": end_date,
        "currency": str(prices.get("currency") or "USD"),
        "currency_symbol": str(prices.get("currency_symbol") or "$"),
        "price_updated": str(prices.get("updated") or ""),
        "price_source": str(prices.get("source") or ""),
        "total": combine_totals(model_rows),
        "models": model_rows,
        "accounts": account_rows,
        "account_models": account_model_rows,
    }


def recent_records(limit=100):
    prices = load_prices()
    with db_connect() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM usage ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
    for row in rows:
        fallback = safe_int(row.get("estimated_tokens"), 0) if safe_int(row.get("total_tokens"), 0) <= 0 else 0
        cost, estimated_cost, matched = record_cost_usd(
            row.get("model") or "",
            row.get("prompt_tokens"),
            row.get("completion_tokens"),
            row.get("cached_tokens"),
            fallback,
            prices,
            row.get("total_tokens"),
        )
        row["cost_usd"] = cost
        row["estimated_cost"] = estimated_cost
        row["matched_price_model"] = matched
        row["display_tokens"] = safe_int(row.get("total_tokens"), 0) or fallback
        row["tokens_per_second"] = token_speed(row.get("completion_tokens"), row.get("elapsed_ms"), row.get("ttft_ms"))
    return rows


def format_int(value):
    return f"{safe_int(value, 0):,}"


def format_money(value, symbol="$"):
    return symbol + f"{safe_float(value, 0.0):,.4f}"


def format_bytes(value):
    size = safe_float(value, 0.0)
    units = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024.0
        index += 1
    if index == 0:
        return f"{int(size)} {units[index]}"
    return f"{size:.1f} {units[index]}"


def format_ms(value):
    value = safe_float(value, 0.0)
    if value <= 0:
        return "-"
    if value >= 1000:
        return f"{value / 1000:.2f}s"
    return f"{value:.0f}ms"


def model_name(row):
    model = str(row.get("model") or "").strip()
    if model:
        return model
    path = str(row.get("path") or "").strip()
    return path or "unknown"


def render_model_table(rows, symbol):
    if not rows:
        return '<div class="empty">这个时间范围还没有记录</div>'
    body = []
    for row in rows[:200]:
        cost_mark = " *" if row.get("estimated_cost") else ""
        body.append(
            f"""
            <tr>
              <td title="{html_escape(model_name(row))}">{html_escape(model_name(row))}</td>
              <td class="num">{format_int(row.get("requests"))}</td>
              <td class="num">{format_int(row.get("success"))}</td>
              <td class="num">{format_int(row.get("errors"))}</td>
              <td class="num strong">{format_int(row.get("actual_tokens"))}</td>
              <td class="num">{format_int(row.get("estimated_fallback_tokens"))}</td>
              <td class="num">{format_int(row.get("prompt_tokens"))}</td>
              <td class="num">{format_int(row.get("completion_tokens"))}</td>
              <td class="num">{format_money(row.get("cost_usd"), symbol)}{cost_mark}</td>
              <td class="num">{format_ms(row.get("avg_ttft_ms"))}</td>
              <td class="num">{format_ms(row.get("avg_elapsed_ms"))}</td>
            </tr>
            """
        )
    return f"""
      <table>
        <thead>
          <tr>
            <th>模型/接口</th><th class="num">请求</th><th class="num">成功</th><th class="num">失败</th>
            <th class="num">实际 token</th><th class="num">估算 token</th><th class="num">输入</th>
            <th class="num">输出</th><th class="num">金额</th><th class="num">平均首字</th><th class="num">平均耗时</th>
          </tr>
        </thead>
        <tbody>{"".join(body)}</tbody>
      </table>
    """


def render_account_table(rows, symbol):
    if not rows:
        return '<div class="empty">这个时间范围还没有账号记录</div>'
    body = []
    for row in rows[:300]:
        body.append(
            f"""
            <tr>
              <td title="{html_escape(str(row.get("account") or ""))}">{html_escape(str(row.get("account") or "unknown"))}</td>
              <td>{html_escape(model_name(row))}</td>
              <td class="num">{format_int(row.get("requests"))}</td>
              <td class="num">{format_int(row.get("actual_tokens"))}</td>
              <td class="num">{format_int(row.get("estimated_fallback_tokens"))}</td>
              <td class="num">{format_money(row.get("cost_usd"), symbol)}</td>
              <td class="num">{format_ms(row.get("avg_ttft_ms"))}</td>
              <td class="num">{format_ms(row.get("avg_elapsed_ms"))}</td>
            </tr>
            """
        )
    return f"""
      <table>
        <thead>
          <tr><th>账号</th><th>模型/接口</th><th class="num">请求</th><th class="num">实际 token</th><th class="num">估算 token</th><th class="num">金额</th><th class="num">平均首字</th><th class="num">平均耗时</th></tr>
        </thead>
        <tbody>{"".join(body)}</tbody>
      </table>
    """


def render_recent_table(rows, symbol):
    if not rows:
        return '<div class="empty">还没有请求记录</div>'
    body = []
    for row in rows:
        cost_mark = " *" if row.get("estimated_cost") else ""
        body.append(
            f"""
            <tr>
              <td>{html_escape(str(row.get("ts") or ""))}</td>
              <td title="{html_escape(str(row.get("account") or ""))}">{html_escape(str(row.get("account") or ""))}</td>
              <td title="{html_escape(str(row.get("ip") or ""))}">{html_escape(str(row.get("ip") or ""))}</td>
              <td title="{html_escape(model_name(row))}">{html_escape(model_name(row))}</td>
              <td class="num">{safe_int(row.get("status"), 0)}</td>
              <td class="num">{format_int(row.get("display_tokens"))}</td>
              <td class="num">{format_int(row.get("prompt_tokens"))}</td>
              <td class="num">{format_int(row.get("completion_tokens"))}</td>
              <td class="num">{format_money(row.get("cost_usd"), symbol)}{cost_mark}</td>
              <td class="num">{format_ms(row.get("ttft_ms"))}</td>
              <td class="num">{format_ms(row.get("elapsed_ms"))}</td>
              <td class="path" title="{html_escape(str(row.get("path") or ""))}">{html_escape(str(row.get("path") or ""))}</td>
            </tr>
            """
        )
    return f"""
      <table>
        <thead>
          <tr><th>时间</th><th>账号</th><th>原请求 IP</th><th>模型/接口</th><th class="num">状态</th><th class="num">token</th><th class="num">输入</th><th class="num">输出</th><th class="num">金额</th><th class="num">首字</th><th class="num">耗时</th><th>路径</th></tr>
        </thead>
        <tbody>{"".join(body)}</tbody>
      </table>
    """


def card(title, value, note=""):
    return f"""
      <div class="card">
        <span>{html_escape(title)}</span>
        <strong>{html_escape(str(value))}</strong>
        <small>{html_escape(note)}</small>
      </div>
    """


def render_dashboard(query):
    init_db()
    params = urllib.parse.parse_qs(query)
    today = today_text()
    start_date = normalize_date_text((params.get("start") or [""])[0], today)
    end_date = normalize_date_text((params.get("end") or [""])[0], today)
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    today_stats = stats_for_range(today, today)
    range_stats = stats_for_range(start_date, end_date)
    recent = recent_records(100)
    symbol = today_stats.get("currency_symbol") or "$"
    base_url = f"http://{HOST}:{PORT}/v1"
    dashboard_url = f"http://{HOST}:{PORT}/"
    today_total = today_stats["total"]
    range_total = range_stats["total"]
    price_source = range_stats.get("price_source") or ""

    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CPA 总消耗监控</title>
  <style>
    :root {{
      color-scheme: light;
      --bg:#f6f7f9; --panel:#ffffff; --text:#17202a; --muted:#687386; --line:#dfe4ea;
      --accent:#0f766e; --accent-weak:#d9f2ee; --bad:#b42318;
    }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Segoe UI, Microsoft YaHei, Arial, sans-serif; background:var(--bg); color:var(--text); }}
    header {{ background:#101820; color:#fff; padding:18px 22px; }}
    header h1 {{ margin:0 0 10px; font-size:22px; font-weight:700; letter-spacing:0; }}
    .topline {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; }}
    .pill {{ background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.22); border-radius:6px; padding:8px 10px; font-size:13px; }}
    .wrap {{ max-width:1500px; margin:0 auto; padding:18px; }}
    section {{ margin:0 0 18px; background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; }}
    h2 {{ margin:0 0 12px; font-size:17px; }}
    .subtle {{ color:var(--muted); font-size:13px; line-height:1.5; }}
    .grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
    .card {{ border:1px solid var(--line); border-radius:8px; padding:14px; min-width:0; background:#fff; }}
    .card span {{ display:block; color:var(--muted); font-size:13px; margin-bottom:8px; }}
    .card strong {{ display:block; font-size:24px; line-height:1.1; word-break:break-all; }}
    .card small {{ display:block; margin-top:8px; color:var(--muted); min-height:18px; }}
    form.range {{ display:flex; flex-wrap:wrap; gap:10px; align-items:end; margin-bottom:14px; }}
    label {{ display:grid; gap:5px; color:var(--muted); font-size:13px; }}
    input {{ height:36px; border:1px solid var(--line); border-radius:6px; padding:0 10px; font:inherit; min-width:160px; }}
    button, .button {{ height:36px; border:0; border-radius:6px; padding:0 14px; background:var(--accent); color:#fff; font:inherit; cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; }}
    .table-scroll {{ overflow:auto; border:1px solid var(--line); border-radius:8px; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; min-width:960px; background:#fff; }}
    th, td {{ padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; text-align:left; white-space:nowrap; }}
    th {{ background:#f1f4f7; color:#344054; font-weight:700; position:sticky; top:0; z-index:1; }}
    td {{ max-width:260px; overflow:hidden; text-overflow:ellipsis; }}
    .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
    .strong {{ font-weight:700; }}
    .path {{ max-width:360px; }}
    .empty {{ color:var(--muted); padding:14px; border:1px dashed var(--line); border-radius:8px; }}
    .note {{ margin-top:10px; color:var(--muted); font-size:13px; line-height:1.6; }}
    @media (max-width: 760px) {{
      header {{ padding:15px; }}
      .wrap {{ padding:12px; }}
      section {{ padding:12px; border-radius:6px; }}
      .grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
      .card strong {{ font-size:20px; }}
      input {{ min-width:130px; width:100%; }}
      form.range label {{ flex:1 1 140px; }}
      button, .button {{ width:100%; justify-content:center; }}
    }}
    @media (max-width: 420px) {{
      .grid {{ grid-template-columns:1fr; }}
      header h1 {{ font-size:19px; }}
      .pill {{ width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>CPA 总消耗监控</h1>
    <div class="topline">
      <div class="pill">监控接入地址 / Base URL: {html_escape(base_url)}</div>
      <div class="pill">监控后台: {html_escape(dashboard_url)}</div>
      <div class="pill">真实 CPA: {html_escape(UPSTREAM_BASE_URL)}</div>
    </div>
  </header>
  <main class="wrap">
    <section>
      <h2>今日总览</h2>
      <div class="grid">
        {card("今日请求数", format_int(today_total.get("requests")), f"成功 {format_int(today_total.get("success"))} / 失败 {format_int(today_total.get("errors"))}")}
        {card("今日总消耗 token", format_int(today_total.get("total_display_tokens")), "实际 token + 估算 token")}
        {card("今日实际 token", format_int(today_total.get("actual_tokens")), "上游 response.usage 返回")}
        {card("今日估算 token", format_int(today_total.get("estimated_fallback_tokens")), "未返回 usage 的请求")}
        {card("今日输出流量", format_bytes(today_total.get("bytes_out")), "上游返回 body")}
        {card("今日花费", format_money(today_total.get("cost_usd"), symbol), "按当前价格表计算")}
      </div>
      <div class="note">金额后面带 * 的记录，表示那条请求没有返回 usage，只能用请求体粗略估算。真正计费最可靠的是上游返回的 prompt/completion/total token。只有经过 {html_escape(base_url)} 的请求会被统计；直接打到真实 CPA 8317 的请求看不到。</div>
    </section>

    <section>
      <h2>区间查询</h2>
      <form class="range" method="get" action="/">
        <label>开始日期 <input type="date" name="start" value="{html_escape(start_date)}"></label>
        <label>结束日期 <input type="date" name="end" value="{html_escape(end_date)}"></label>
        <button type="submit">查询</button>
        <a class="button" href="/">今天</a>
      </form>
      <div class="grid">
        {card("区间请求数", format_int(range_total.get("requests")), f"{html_escape(start_date)} 至 {html_escape(end_date)}")}
        {card("区间总消耗 token", format_int(range_total.get("total_display_tokens")), "实际 token + 估算 token，用于金额口径")}
        {card("区间实际 token", format_int(range_total.get("actual_tokens")), "上游 response.usage 返回")}
        {card("区间估算 token", format_int(range_total.get("estimated_fallback_tokens")), "未返回 usage 的补充参考")}
        {card("区间输出流量", format_bytes(range_total.get("bytes_out")), "上游返回 body")}
        {card("区间花费", format_money(range_total.get("cost_usd"), symbol), "按当前价格表计算")}
      </div>
    </section>

    <section>
      <h2>区间模型统计</h2>
      <div class="table-scroll">{render_model_table(range_stats["models"], symbol)}</div>
    </section>

    <section>
      <h2>区间账号模型统计</h2>
      <div class="table-scroll">{render_account_table(range_stats["account_models"], symbol)}</div>
    </section>

    <section>
      <h2>最近请求</h2>
      <div class="table-scroll">{render_recent_table(recent, symbol)}</div>
    </section>

    <section>
      <h2>价格表</h2>
      <div class="note">
        当前价格文件：{html_escape(str(PRICE_FILE))}<br>
        更新时间：{html_escape(str(range_stats.get("price_updated") or ""))}<br>
        来源：{html_escape(price_source)}<br>
        页面只显示一个花费金额，按当前 model_prices.json 价格表计算。未匹配模型或只有 total_tokens、没有输入/输出拆分的数据，按 default.total_blended_per_1m 计算；你有 CPA 特殊模型价格时，直接改 model_prices.json。
      </div>
    </section>
  </main>
</body>
</html>"""
    return html


class Handler(BaseHTTPRequestHandler):
    server_version = "znyengine-cpa-usage-monitor/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("[%s] %s\n" % (now_text(), fmt % args))
        sys.stdout.flush()

    def send_json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        send_cors(self)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def send_html(self, status, html):
        raw = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def send_error_json(self, exc):
        self.send_json(
            exc.status,
            {"error": {"message": exc.message, "type": exc.error_type, "code": exc.error_type}},
        )

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        send_cors(self)
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        self.handle_any()

    def do_POST(self):
        self.handle_any()

    def do_PUT(self):
        self.handle_any()

    def do_PATCH(self):
        self.handle_any()

    def do_DELETE(self):
        self.handle_any()

    def handle_any(self):
        started = time.perf_counter()
        request_id = uuid.uuid4().hex[:12]
        path = urllib.parse.urlsplit(self.path).path
        should_log = path == "/v1" or path.startswith("/v1/")
        account = account_from_headers(self.headers)
        ip = client_ip(self.headers, self.client_address)
        model = ""
        estimated_tokens = 0
        bytes_in = 0
        bytes_out = 0
        ttft_ms = 0
        prompt_tokens = 0
        completion_tokens = 0
        cached_tokens = 0
        total_tokens = 0
        status = 500
        error_type = ""
        self._response_started = False

        try:
            if path in {"/ping", "/health"}:
                status = 200
                self.send_json(
                    200,
                    {
                        "ok": True,
                        "name": "znyengine CPA usage monitor",
                        "time": now_text(),
                        "base_url": f"http://{HOST}:{PORT}/v1",
                        "upstream_base_url": UPSTREAM_BASE_URL,
                    },
                )
                return

            if path in {"/", "/dashboard"}:
                status = 200
                query = urllib.parse.urlsplit(self.path).query
                self.send_html(200, render_dashboard(query))
                return

            if path == "/api/summary":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                today = today_text()
                start_date = normalize_date_text((query.get("start") or [""])[0], today)
                end_date = normalize_date_text((query.get("end") or [""])[0], today)
                if start_date > end_date:
                    start_date, end_date = end_date, start_date
                status = 200
                self.send_json(200, stats_for_range(start_date, end_date))
                return

            if not should_log:
                raise MonitorError(404, "Only /v1 and dashboard are served by this monitor", "not_found")

            body = read_body(self)
            bytes_in = len(body)
            payload = parse_json_body(self.headers, body)
            model = extract_model(payload)
            estimated_tokens = estimate_tokens(payload)
            proxy_result = self.proxy_to_upstream(body, request_id)
            status = proxy_result["status"]
            bytes_out = proxy_result["bytes_out"]
            ttft_ms = proxy_result.get("ttft_ms", 0)
            usage_info = proxy_result.get("usage") or {}
            prompt_tokens = safe_int(usage_info.get("prompt_tokens"), 0)
            completion_tokens = safe_int(usage_info.get("completion_tokens"), 0)
            cached_tokens = safe_int(usage_info.get("cached_tokens"), 0)
            total_tokens = safe_int(usage_info.get("total_tokens"), 0)

        except MonitorError as exc:
            status = exc.status
            error_type = exc.error_type
            if self._response_started:
                self.close_connection = True
            else:
                self.send_error_json(exc)
        except BrokenPipeError:
            status = 499
            error_type = "client_disconnected"
        except Exception:
            status = 502
            error_type = "monitor_exception"
            traceback.print_exc()
            if self._response_started:
                self.close_connection = True
            else:
                try:
                    self.send_error_json(MonitorError(502, "Monitor failed to proxy the request", "monitor_exception"))
                except Exception:
                    pass
        finally:
            if should_log:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                if not model:
                    model = path
                record = {
                    "ts": now_text(),
                    "request_id": request_id,
                    "account": account,
                    "ip": ip,
                    "method": self.command,
                    "path": path,
                    "model": model,
                    "status": status,
                    "elapsed_ms": elapsed_ms,
                    "ttft_ms": ttft_ms,
                    "estimated_tokens": estimated_tokens,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "cached_tokens": cached_tokens,
                    "total_tokens": total_tokens,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "error_type": error_type,
                }
                try:
                    write_usage_record(record)
                except Exception:
                    traceback.print_exc()

    def proxy_to_upstream(self, body, request_id):
        proxy_started = time.perf_counter()
        target = target_url(self.path)
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in {"http", "https"}:
            raise MonitorError(500, "Unsupported upstream URL scheme", "monitor_config_error")
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        host = parsed.hostname
        if not host:
            raise MonitorError(500, "Invalid upstream URL", "monitor_config_error")
        request_path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in HOP_BY_HOP_HEADERS or lower in {"host", "content-length", "authorization"}:
                continue
            headers[key] = value
        headers["Host"] = parsed.netloc
        headers["X-CPA-Monitor-Request-ID"] = request_id
        if UPSTREAM_API_KEY:
            headers["Authorization"] = "Bearer " + UPSTREAM_API_KEY
        elif PRESERVE_CLIENT_AUTHORIZATION:
            auth = self.headers.get("Authorization")
            if auth:
                headers["Authorization"] = auth
        if body or self.command in {"POST", "PUT", "PATCH"}:
            headers["Content-Length"] = str(len(body))

        conn = conn_cls(host, port=parsed.port, timeout=CONNECT_TIMEOUT)
        bytes_out = 0
        ttft_ms = 0
        usage_info = {}
        sse_pending = ""
        json_buffer = bytearray()
        json_buffer_limit = 2 * 1024 * 1024
        response_content_type = ""
        try:
            conn.request(self.command, request_path, body=body if body else None, headers=headers)
            conn.sock.settimeout(READ_TIMEOUT)
            resp = conn.getresponse()
            ttft_ms = int((time.perf_counter() - proxy_started) * 1000)
            self.send_response(resp.status, resp.reason)
            self._response_started = True
            for key, value in resp.getheaders():
                lower = key.lower()
                if lower == "content-type":
                    response_content_type = value
                if lower in HOP_BY_HOP_HEADERS or lower in {"content-length", "connection"}:
                    continue
                self.send_header(key, value)
            self.send_header("Connection", "close")
            send_cors(self)
            self.end_headers()
            self.close_connection = True
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                if bytes_out == 0:
                    ttft_ms = int((time.perf_counter() - proxy_started) * 1000)
                bytes_out += len(chunk)
                content_type_lower = response_content_type.lower()
                if "event-stream" in content_type_lower or chunk.startswith(b"data:") or b"\ndata:" in chunk:
                    sse_pending, usage_info = update_usage_from_sse(chunk, sse_pending, usage_info)
                elif len(json_buffer) < json_buffer_limit:
                    remaining = json_buffer_limit - len(json_buffer)
                    json_buffer.extend(chunk[:remaining])
                self.wfile.write(chunk)
                self.wfile.flush()
            usage_info = update_usage_from_json_buffer(bytes(json_buffer), response_content_type, usage_info)
            return {"status": resp.status, "bytes_out": bytes_out, "ttft_ms": ttft_ms, "usage": usage_info}
        except TimeoutError:
            raise MonitorError(504, "Upstream timeout", "upstream_timeout")
        except BrokenPipeError:
            raise
        except OSError as exc:
            raise MonitorError(502, "Upstream connection failed: " + str(exc), "upstream_connection_failed")
        finally:
            conn.close()


def main():
    ensure_price_file()
    init_db()
    print("znyengine CPA usage monitor")
    print(f"listen: http://{HOST}:{PORT}")
    print(f"dashboard: http://{HOST}:{PORT}/")
    print(f"monitored base url: http://{HOST}:{PORT}/v1")
    print(f"upstream: {UPSTREAM_BASE_URL}")
    print(f"data: {USAGE_DB}")
    print(f"prices: {PRICE_FILE}")
    if UPSTREAM_API_KEY:
        print("upstream auth: configured by monitor")
    elif PRESERVE_CLIENT_AUTHORIZATION:
        print("upstream auth: preserve client Authorization")
    else:
        print("upstream auth: disabled")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
