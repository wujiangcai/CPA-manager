# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from html import escape as html_escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def env_port(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(1, min(65535, value))


HOST = os.environ.get("CPA_DASHBOARD_HOST", "127.0.0.1")
PORT = env_port("CPA_DASHBOARD_PORT", 18321)
USAGE_URL = os.environ.get("CPA_USAGE_MONITOR_URL", "http://127.0.0.1:18319/").rstrip("/") + "/"
POOL_URL = os.environ.get("CPA_POOL_MONITOR_URL", "http://127.0.0.1:18320/").rstrip("/") + "/"


def fetch_text(url: str, timeout: int = 3) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return "ERROR: " + str(exc)


def render_page() -> str:
    page = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CPA 检测系统</title>
  <style>
    :root { --bg:#f6f7f8; --panel:#fff; --ink:#202124; --muted:#667085; --line:#d9dee5; --blue:#1f5fbf; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:"Microsoft YaHei","Segoe UI",Arial,sans-serif; background:var(--bg); color:var(--ink); }
    header { position:sticky; top:0; z-index:10; background:rgba(246,247,248,.96); border-bottom:1px solid var(--line); backdrop-filter:blur(10px); }
    .bar { height:64px; padding:0 16px; display:flex; align-items:center; gap:12px; }
    h1 { font-size:19px; margin:0; white-space:nowrap; }
    .sub { color:var(--muted); font-size:12px; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; }
    .tabs { display:flex; gap:8px; align-items:center; }
    button, a.tool { border:1px solid #bfc7d2; background:#fff; color:var(--ink); border-radius:6px; padding:8px 11px; cursor:pointer; text-decoration:none; font:inherit; white-space:nowrap; }
    button.active { background:var(--blue); border-color:var(--blue); color:#fff; }
    .frame-wrap { height:calc(100vh - 64px); width:100%; }
    iframe { display:none; width:100%; height:100%; border:0; background:#fff; }
    iframe.active { display:block; }
    @media (max-width:720px) {
      .bar { height:auto; min-height:64px; flex-wrap:wrap; padding:10px; }
      h1, .sub { width:100%; flex-basis:100%; }
      .tabs { width:100%; display:grid; grid-template-columns:1fr 1fr; }
      a.tool { display:none; }
      .frame-wrap { height:calc(100vh - 118px); }
    }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <h1>CPA 检测系统</h1>
      <div class="sub">总消耗 + 账号池合并面板</div>
      <div class="tabs">
        <button id="usageBtn" class="active" onclick="showTab('usage')">总消耗</button>
        <button id="poolBtn" onclick="showTab('pool')">号池账号</button>
      </div>
      <a class="tool" href="/api/ping" target="_blank">状态</a>
    </div>
  </header>
  <main class="frame-wrap">
    <iframe id="usageFrame" class="active" src="__USAGE_URL__"></iframe>
    <iframe id="poolFrame" src="__POOL_URL__"></iframe>
  </main>
  <script>
    function showTab(name) {
      const usage = name === 'usage';
      document.getElementById('usageFrame').classList.toggle('active', usage);
      document.getElementById('poolFrame').classList.toggle('active', !usage);
      document.getElementById('usageBtn').classList.toggle('active', usage);
      document.getElementById('poolBtn').classList.toggle('active', !usage);
      location.hash = name;
    }
    function showFromHash() {
      if (location.hash === '#pool') showTab('pool');
      else showTab('usage');
    }
    window.addEventListener('hashchange', showFromHash);
    showFromHash();
  </script>
</body>
</html>"""
    return page.replace("__USAGE_URL__", html_escape(USAGE_URL, quote=True)).replace("__POOL_URL__", html_escape(POOL_URL, quote=True))


class Handler(BaseHTTPRequestHandler):
    server_version = "zny-cpa-detection-dashboard/1.0"

    def log_message(self, fmt, *args):
        return

    def send_bytes(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status: int = 200):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, raw, "application/json; charset=utf-8")

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self.send_bytes(200, render_page().encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/ping":
            self.send_json({
                "ok": True,
                "name": "zny CPA detection dashboard",
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "dashboard": f"http://{HOST}:{PORT}/",
                "usage_ping": fetch_text(urllib.parse.urljoin(USAGE_URL, "ping")),
                "pool_ping": fetch_text(urllib.parse.urljoin(POOL_URL, "api/ping")),
            })
            return
        self.send_json({"ok": False, "error": "not found"}, 404)


def main():
    print(f"zny CPA detection dashboard: http://{HOST}:{PORT}/", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
