from __future__ import annotations

import hashlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    path = PROJECT_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


usage = load_module("cpa_usage_monitor_regression", "RUN_ON_YOUR_PC/cpa_usage_monitor.py")
dashboard = load_module("cpa_detection_dashboard_regression", "cpa_detection_dashboard.py")


class UsageMonitorRegressionTests(unittest.TestCase):
    def test_authorization_account_identifier_is_hashed_not_token_tail(self) -> None:
        token = "sensitive-token-with-distinct-tail-12345678"
        headers = {"Authorization": "Bearer " + token}

        account = usage.account_from_headers(headers)

        expected = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        self.assertEqual(account, "self:" + expected)
        self.assertNotIn("12345678", account)

    def test_read_body_rejects_truncated_request(self) -> None:
        handler = type(
            "FakeHandler",
            (),
            {
                "headers": {"Content-Length": "10"},
                "rfile": io.BytesIO(b"short"),
            },
        )()

        with self.assertRaises(usage.MonitorError) as context:
            usage.read_body(handler)

        self.assertEqual(context.exception.status, 400)
        self.assertEqual(context.exception.error_type, "bad_request")

    def test_usage_config_boolean_parser_handles_false_string(self) -> None:
        self.assertFalse(usage.config_bool("false", True))
        self.assertTrue(usage.config_bool("on", False))
        self.assertFalse(usage.config_bool("invalid", False))
        self.assertEqual(usage.config_int("invalid", 15, 1, 300), 15)
        self.assertEqual(usage.config_int(999, 15, 1, 300), 300)


class DashboardRegressionTests(unittest.TestCase):
    def test_render_page_uses_configured_and_html_escaped_service_urls(self) -> None:
        with (
            mock.patch.object(dashboard, "USAGE_URL", "http://usage.example/?a=1&b=2"),
            mock.patch.object(dashboard, "POOL_URL", 'http://pool.example/\"unsafe'),
        ):
            page = dashboard.render_page()

        self.assertIn("http://usage.example/?a=1&amp;b=2", page)
        self.assertIn("http://pool.example/&quot;unsafe", page)
        self.assertNotIn('src="http://127.0.0.1:18319/"', page)


if __name__ == "__main__":
    unittest.main()
