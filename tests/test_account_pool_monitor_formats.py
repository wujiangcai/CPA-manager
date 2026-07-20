from __future__ import annotations

import base64
import importlib.util
import json
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "account_pool_monitor" / "account_pool_monitor.py"
SPEC = importlib.util.spec_from_file_location("account_pool_monitor_module", MODULE_PATH)
assert SPEC and SPEC.loader
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


def jwt(payload: dict[str, object]) -> str:
    def encode(value: dict[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode({'alg': 'none', 'typ': 'JWT'})}.{encode(payload)}."


def access_token(account_id: str, email: str, plan: str = "plus") -> str:
    return jwt(
        {
            "exp": int(time.time()) + 3600,
            "email": email,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_plan_type": plan,
            },
        }
    )


class ImportFormatTests(unittest.TestCase):
    def test_cpa_session_auth_without_refresh_token_is_scanned_as_usable(self) -> None:
        account_id = "acc-cpa-1"
        email = "cpa@example.com"
        cpa = {
            "type": "codex",
            "account_id": account_id,
            "email": email,
            "plan_type": "plus",
            "access_token": access_token(account_id, email),
            "refresh_token": "",
            "session_token": "session-value",
            "expired": "2099-01-01T00:00:00Z",
        }

        parsed = monitor.parse_import_accounts(json.dumps(cpa).encode("utf-8"))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(monitor.detect_import_account_format(parsed[0][0]), "cpa")
        normalized = monitor.normalize_import_account(parsed[0][0])

        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = Path(temp_dir) / "cpa.json"
            auth_path.write_text(json.dumps(normalized), encoding="utf-8")
            accounts, warnings = monitor.scan_auth_accounts({"auth_dir": temp_dir})
            quota_payload = {
                "plan_type": "plus",
                "rate_limit": {
                    "primary_window": {"limit_window_seconds": 18000, "used_percent": 15},
                    "secondary_window": {"limit_window_seconds": 604800, "used_percent": 25},
                },
            }
            with mock.patch.object(monitor, "request_json_direct", return_value=quota_payload):
                report = monitor.query_one_codex_quota_direct(
                    accounts[0],
                    {
                        "quota_query_retries": 1,
                        "quota_low_threshold_percent": 5,
                        "quota_query_timeout_seconds": 5,
                        "proxy_url": "",
                    },
                )

        self.assertEqual(warnings, [])
        self.assertEqual(accounts[0]["status"], "ok")
        self.assertFalse(accounts[0]["refresh_required"])
        self.assertEqual(accounts[0]["_account_id"], account_id)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["min_remaining_percent"], 75.0)

    def test_sub2api_export_is_converted_to_cpa_and_can_run_vitality_probe(self) -> None:
        account_id = "acc-sub2-1"
        email = "sub2@example.com"
        token = access_token(account_id, email, "pro")
        sub2_document = {
            "exported_at": "2026-07-20T00:00:00Z",
            "proxies": [],
            "accounts": [
                {
                    "name": "Sub2 Account",
                    "platform": "openai",
                    "type": "oauth",
                    "concurrency": 10,
                    "priority": 1,
                    "credentials": {
                        "access_token": token,
                        "chatgpt_account_id": account_id,
                        "chatgpt_user_id": "user-sub2-1",
                        "email": email,
                        "expires_at": "2099-01-01T00:00:00Z",
                        "expires_in": 3600,
                        "plan_type": "pro",
                    },
                    "extra": {
                        "email": email,
                        "source": "chatgpt_web_session",
                        "last_refresh": "2026-07-20T00:00:00Z",
                    },
                }
            ],
        }

        parsed = monitor.parse_import_accounts(json.dumps(sub2_document).encode("utf-8"))
        self.assertEqual(len(parsed), 1)
        raw_account, source_key = parsed[0]
        self.assertEqual(source_key, "accounts-1")
        self.assertEqual(monitor.detect_import_account_format(raw_account), "sub2api")

        normalized = monitor.normalize_import_account(raw_account)
        self.assertEqual(normalized["type"], "codex")
        self.assertEqual(normalized["access_token"], token)
        self.assertEqual(normalized["refresh_token"], "")
        self.assertEqual(normalized["account_id"], account_id)
        self.assertEqual(normalized["email"], email)
        self.assertEqual(normalized["plan_type"], "pro")
        self.assertEqual(normalized["source_format"], "sub2api")
        self.assertTrue(normalized["refresh_token_optional"])

        quota_payload = {
            "plan_type": "pro",
            "rate_limit": {
                "allowed": True,
                "limit_reached": False,
                "primary_window": {"limit_window_seconds": 18000, "used_percent": 10},
                "secondary_window": {"limit_window_seconds": 604800, "used_percent": 20},
            },
        }
        cfg = {
            "quota_query_retries": 1,
            "quota_low_threshold_percent": 5,
            "quota_query_timeout_seconds": 5,
            "proxy_url": "",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            auth_path = Path(temp_dir) / "sub2.json"
            auth_path.write_text(json.dumps(normalized), encoding="utf-8")
            accounts, warnings = monitor.scan_auth_accounts({"auth_dir": temp_dir})
            self.assertEqual(warnings, [])
            self.assertEqual(accounts[0]["status"], "ok")
            self.assertFalse(accounts[0]["refresh_required"])

            with mock.patch.object(monitor, "request_json_direct", return_value=quota_payload) as request:
                report = monitor.query_one_codex_quota_direct(accounts[0], cfg)

        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["plan"], "pro")
        self.assertEqual(report["min_remaining_percent"], 80.0)
        self.assertEqual(request.call_args.args[0:2], ("GET", monitor.WHAM_USAGE_URL))
        self.assertEqual(request.call_args.args[3]["Chatgpt-Account-Id"], account_id)
        self.assertEqual(request.call_args.args[3]["Authorization"], "Bearer " + token)

    def test_sub2api_export_runs_through_batch_import_and_alive_archive(self) -> None:
        account_id = "acc-sub2-batch"
        email = "batch@example.com"
        document = {
            "exported_at": "2026-07-20T00:00:00Z",
            "proxies": [],
            "accounts": [
                {
                    "name": "Batch Account",
                    "platform": "openai",
                    "type": "oauth",
                    "credentials": {
                        "access_token": access_token(account_id, email),
                        "chatgpt_account_id": account_id,
                        "email": email,
                        "expires_at": "2099-01-01T00:00:00Z",
                        "plan_type": "plus",
                    },
                }
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            auth_dir = root / "auth"
            data_dir = root / "monitor_data"
            import_dir = data_dir / "import_batches"
            cfg = {
                "auth_dir": str(auth_dir),
                "cpa_base_url": "http://127.0.0.1:8317",
                "management_key": "",
                "import_try_management_upload": False,
                "import_keep_alive_in_auth_dir": True,
                "import_move_dead_from_auth_dir": True,
                "import_upload_concurrency": 2,
                "quota_query_concurrency": 2,
                "quota_low_threshold_percent": 5,
            }

            def fake_quota(config: dict[str, object], target_files: set[str], **_: object) -> dict[str, object]:
                accounts, _warnings = monitor.scan_auth_accounts(config)
                reports = []
                for account in accounts:
                    if account["file"] not in target_files:
                        continue
                    reports.append(
                        {
                            "provider": "codex",
                            "file": account["file"],
                            "name": account["name"],
                            "email": account["email"],
                            "plan": account["plan"],
                            "status": "ok",
                            "error": "",
                            "windows": [
                                {
                                    "id": "code-5h",
                                    "remaining_percent": 90.0,
                                    "exhausted": False,
                                }
                            ],
                            "additional_windows": [],
                            "min_remaining_percent": 90.0,
                        }
                    )
                return {"created_at": monitor.isoformat_local(), "reports": reports}

            patched_paths = {
                "DATA_DIR": data_dir,
                "IMPORT_DIR": import_dir,
                "QUOTA_CACHE_PATH": data_dir / "quota_cache.json",
                "EVENT_LOG_PATH": data_dir / "events.jsonl",
                "LAST_IMPORT_PATH": data_dir / "last_import_result.json",
            }
            with (
                mock.patch.multiple(monitor, **patched_paths),
                mock.patch.object(monitor, "validate_proxy_before_quota", return_value={"enabled": False, "ok": True}),
                mock.patch.object(monitor, "query_quota_reports_direct", side_effect=fake_quota),
            ):
                result = monitor.import_large_json_batch(
                    cfg,
                    "sub2-export.json",
                    json.dumps(document).encode("utf-8"),
                    refresh_quota=True,
                )

            self.assertEqual(result["formats"], {"sub2api": 1})
            self.assertEqual(result["uploaded"], 1)
            self.assertEqual(result["alive"], 1)
            self.assertEqual(result["dead"], 0)
            self.assertTrue(Path(result["zip"]).exists())
            auth_files = list(auth_dir.glob("*.json"))
            self.assertEqual(len(auth_files), 1)
            imported = json.loads(auth_files[0].read_text(encoding="utf-8"))
            self.assertEqual(imported["type"], "codex")
            self.assertEqual(imported["account_id"], account_id)
            self.assertEqual(imported["source_format"], "sub2api")
            self.assertNotIn("credentials", imported)

    def test_sub2api_document_inside_ndjson_is_flattened(self) -> None:
        document = {
            "exported_at": "2026-07-20T00:00:00Z",
            "proxies": [],
            "accounts": [
                {
                    "name": "One",
                    "platform": "openai",
                    "type": "oauth",
                    "credentials": {"access_token": "token-one", "chatgpt_account_id": "acc-one"},
                },
                {
                    "name": "Two",
                    "platform": "openai",
                    "type": "oauth",
                    "credentials": {"access_token": "token-two", "chatgpt_account_id": "acc-two"},
                },
            ],
        }
        raw = (json.dumps(document) + "\n").encode("utf-8")

        parsed = monitor.parse_ndjson_bytes(raw)

        self.assertEqual(len(parsed), 2)
        self.assertEqual([item[1] for item in parsed], ["line-1-accounts-1", "line-1-accounts-2"])
        self.assertTrue(all(monitor.detect_import_account_format(item[0]) == "sub2api" for item in parsed))

    def test_standard_cpa_oauth_still_requires_refresh_token(self) -> None:
        account_id = "acc-oauth-1"
        cpa = {
            "type": "codex",
            "account_id": account_id,
            "access_token": access_token(account_id, "oauth@example.com"),
            "refresh_token": "",
            "plan_type": "plus",
        }
        normalized = monitor.normalize_import_account(cpa)

        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "oauth.json").write_text(json.dumps(normalized), encoding="utf-8")
            accounts, _ = monitor.scan_auth_accounts({"auth_dir": temp_dir})

        self.assertEqual(accounts[0]["status"], "missing_token")
        self.assertTrue(accounts[0]["refresh_required"])

    def test_non_codex_auth_is_not_retyped_as_cpa(self) -> None:
        raw = {
            "type": "claude",
            "email": "claude@example.com",
            "account_id": "claude-account",
            "access_token": "claude-access-token",
            "refresh_token": "claude-refresh-token",
        }

        self.assertEqual(monitor.detect_import_account_format(raw), "other_auth")
        normalized = monitor.normalize_import_account(raw)
        self.assertEqual(normalized["type"], "claude")

    def test_all_supported_token_key_styles_are_sanitized(self) -> None:
        sanitized = monitor.sanitize_for_output(
            {
                "accessToken": "one",
                "refresh_token": "two",
                "idToken": "three",
                "session_token": "four",
                "remote_pool_management_key": "five",
            }
        )
        self.assertEqual(set(sanitized.values()), {"[hidden]"})

    def test_selected_alive_account_is_uploaded_to_remote_pool_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data_dir = root / "monitor_data"
            import_dir = data_dir / "import_batches"
            batch_id = "20260720_testbatch"
            alive_dir = import_dir / batch_id / "alive"
            alive_dir.mkdir(parents=True)
            first = {
                "type": "codex",
                "account_id": "remote-one",
                "access_token": "access-one",
                "refresh_token": "refresh-one",
                "email": "one@example.com",
            }
            second = {
                "type": "codex",
                "account_id": "remote-two",
                "access_token": "access-two",
                "refresh_token": "refresh-two",
                "email": "two@example.com",
            }
            (alive_dir / "one.json").write_text(json.dumps(first), encoding="utf-8")
            (alive_dir / "two.json").write_text(json.dumps(second), encoding="utf-8")
            last_import_path = data_dir / "last_import_result.json"
            last_import_path.parent.mkdir(parents=True, exist_ok=True)
            last_import_path.write_text(
                json.dumps(
                    {
                        "batch_id": batch_id,
                        "items": [
                            {"file": "one.json", "email": "one@example.com", "alive": True},
                            {"file": "two.json", "email": "two@example.com", "alive": True},
                            {"file": "dead.json", "email": "dead@example.com", "alive": False},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            cfg = {
                "remote_pool_base_url": "https://remote.example.com",
                "remote_pool_management_key": "remote-key",
                "remote_pool_upload_concurrency": 4,
                "remote_pool_timeout_seconds": 10,
            }
            uploaded: list[tuple[str, dict[str, object]]] = []

            def fake_upload(_cfg: dict[str, object], name: str, account: dict[str, object]) -> dict[str, object]:
                uploaded.append((name, account))
                return {"status": 200, "bytes": 100}

            patched_paths = {
                "DATA_DIR": data_dir,
                "IMPORT_DIR": import_dir,
                "LAST_IMPORT_PATH": last_import_path,
                "EVENT_LOG_PATH": data_dir / "events.jsonl",
            }
            with (
                mock.patch.multiple(monitor, **patched_paths),
                mock.patch.object(monitor, "upload_one_remote_pool_account", side_effect=fake_upload),
            ):
                result = monitor.submit_alive_accounts_to_remote_pool(cfg, batch_id, ["two.json", "two.json"])

            self.assertTrue(result["ok"])
            self.assertEqual(result["requested"], 1)
            self.assertEqual(result["uploaded"], 1)
            self.assertEqual([item[0] for item in uploaded], ["two.json"])
            self.assertEqual(uploaded[0][1]["account_id"], "remote-two")
            persisted = json.loads(last_import_path.read_text(encoding="utf-8"))
            by_file = {item["file"]: item for item in persisted["items"]}
            self.assertNotIn("remote_uploaded", by_file["one.json"])
            self.assertTrue(by_file["two.json"]["remote_uploaded"])
            self.assertEqual(persisted["remote_upload"]["uploaded"], 1)

    def test_remote_pool_rejects_non_alive_or_path_traversal_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data_dir = root / "monitor_data"
            import_dir = data_dir / "import_batches"
            batch_id = "batch_safe"
            alive_dir = import_dir / batch_id / "alive"
            alive_dir.mkdir(parents=True)
            last_import_path = data_dir / "last_import_result.json"
            last_import_path.write_text(
                json.dumps({"batch_id": batch_id, "items": [{"file": "dead.json", "alive": False}]}),
                encoding="utf-8",
            )
            cfg = {
                "remote_pool_base_url": "https://remote.example.com",
                "remote_pool_management_key": "remote-key",
            }
            with mock.patch.multiple(
                monitor,
                DATA_DIR=data_dir,
                IMPORT_DIR=import_dir,
                LAST_IMPORT_PATH=last_import_path,
                EVENT_LOG_PATH=data_dir / "events.jsonl",
            ):
                with self.assertRaisesRegex(ValueError, "只能提交已通过验活"):
                    monitor.submit_alive_accounts_to_remote_pool(cfg, batch_id, ["dead.json"])
                with self.assertRaisesRegex(ValueError, "只能提交已通过验活"):
                    monitor.submit_alive_accounts_to_remote_pool(cfg, batch_id, ["../outside.json"])

    def test_remote_pool_http_upload_uses_management_api_and_bearer_key(self) -> None:
        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit: int) -> bytes:
                return b'{"ok":true}'

        cfg = {
            "remote_pool_base_url": "https://remote.example.com/base",
            "remote_pool_management_key": "remote-secret-key",
            "remote_pool_timeout_seconds": 19,
        }
        account = {"type": "codex", "access_token": "example-access", "account_id": "account-one"}
        with mock.patch.object(monitor.urllib.request, "urlopen", return_value=FakeResponse()) as urlopen:
            result = monitor.upload_one_remote_pool_account(cfg, "account one.json", account)

        request = urlopen.call_args.args[0]
        self.assertEqual(result["status"], 201)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 19)
        self.assertEqual(
            request.full_url,
            "https://remote.example.com/base/v0/management/auth-files?name=account%20one.json",
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer remote-secret-key")
        self.assertEqual(json.loads(request.data.decode("utf-8"))["account_id"], "account-one")

    def test_remote_pool_http_endpoint_accepts_selected_files(self) -> None:
        captured: dict[str, object] = {}

        def fake_submit(_cfg: dict[str, object], batch_id: str, files: list[str]) -> dict[str, object]:
            captured["batch_id"] = batch_id
            captured["files"] = files
            return {"ok": True, "batch_id": batch_id, "requested": len(files), "uploaded": len(files), "failed": 0}

        with (
            mock.patch.object(monitor, "load_config", return_value={}),
            mock.patch.object(monitor, "submit_alive_accounts_to_remote_pool", side_effect=fake_submit),
            mock.patch.object(monitor, "build_status_payload", return_value={"ok": True, "last_import": {}}),
        ):
            server = ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                body = json.dumps({"batch_id": "batch_http", "files": ["one.json", "two.json"]}).encode("utf-8")
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/remote-pool/upload",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

        self.assertEqual(captured, {"batch_id": "batch_http", "files": ["one.json", "two.json"]})
        self.assertEqual(payload["remote_upload"]["uploaded"], 2)

    def test_import_without_refresh_does_not_archive_accounts_as_dead_without_cache(self) -> None:
        account_id = "no-cache-account"
        cpa = {
            "type": "codex",
            "account_id": account_id,
            "email": "nocache@example.com",
            "access_token": access_token(account_id, "nocache@example.com"),
            "refresh_token": "refresh-value",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            auth_dir = root / "auth"
            data_dir = root / "monitor_data"
            import_dir = data_dir / "import_batches"
            cfg = {
                "auth_dir": str(auth_dir),
                "cpa_base_url": "http://127.0.0.1:8317",
                "management_key": "",
                "import_try_management_upload": False,
                "import_keep_alive_in_auth_dir": True,
                "import_move_dead_from_auth_dir": True,
                "import_upload_concurrency": 1,
                "quota_query_concurrency": 1,
                "quota_low_threshold_percent": 5,
                "quota_delete_cache_max_age_seconds": 600,
            }
            patched_paths = {
                "DATA_DIR": data_dir,
                "IMPORT_DIR": import_dir,
                "QUOTA_CACHE_PATH": data_dir / "quota_cache.json",
                "EVENT_LOG_PATH": data_dir / "events.jsonl",
                "LAST_IMPORT_PATH": data_dir / "last_import_result.json",
            }
            with mock.patch.multiple(monitor, **patched_paths):
                with self.assertRaisesRegex(RuntimeError, "缓存不能覆盖"):
                    monitor.import_large_json_batch(
                        cfg,
                        "no-cache.json",
                        json.dumps(cpa).encode("utf-8"),
                        refresh_quota=False,
                    )

            self.assertEqual(len(list(auth_dir.glob("*.json"))), 1)
            self.assertEqual(list(import_dir.glob("*/dead/*.json")), [])

    def test_cleanup_quarantine_moves_instead_of_deleting_invalid_auth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            auth_dir = root / "auth"
            quarantine_dir = root / "quarantine"
            data_dir = root / "monitor_data"
            auth_dir.mkdir()
            source = auth_dir / "invalid.json"
            source.write_text(json.dumps({"type": "codex", "email": "invalid@example.com"}), encoding="utf-8")
            cfg = {
                "auth_dir": str(auth_dir),
                "auto_cleanup_enabled": True,
                "auto_cleanup_interval_seconds": 3600,
                "cleanup_quarantine_dir": str(quarantine_dir),
                "cleanup_move_missing_tokens": True,
                "cleanup_move_read_errors": True,
                "cleanup_move_expired": True,
                "cleanup_move_access_expired": False,
                "cleanup_skip_disabled": True,
                "cleanup_delete_quota_low": False,
            }
            patched_paths = {
                "DATA_DIR": data_dir,
                "EVENT_LOG_PATH": data_dir / "events.jsonl",
                "CLEANUP_MANIFEST_PATH": data_dir / "cleanup_manifest.jsonl",
            }
            with mock.patch.multiple(monitor, **patched_paths):
                result = monitor.cleanup_auth_pool(cfg, force=True, quota_cache=None)

            self.assertEqual(result["deleted"], 0)
            self.assertEqual(result["moved"], 1)
            self.assertFalse(source.exists())
            self.assertEqual(len(list(quarantine_dir.glob("missing_token/*.json"))), 1)

    def test_config_parsers_handle_string_booleans_and_invalid_numbers(self) -> None:
        self.assertFalse(monitor.config_bool("false", True))
        self.assertTrue(monitor.config_bool("yes", False))
        self.assertEqual(monitor.config_int("bad", 16, 1, 64), 16)
        self.assertEqual(monitor.config_int(1000, 16, 1, 64), 64)
        self.assertEqual(monitor.config_float("bad", 5, 0, 100), 5.0)

    def test_empty_auth_dir_never_scans_current_directory(self) -> None:
        accounts, warnings = monitor.scan_auth_accounts({"auth_dir": ""})
        self.assertEqual(accounts, [])
        self.assertTrue(any("auth_dir" in warning for warning in warnings))

    def test_millisecond_expiration_timestamp_is_parsed(self) -> None:
        parsed = monitor.parse_datetime(4070908800000)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.year, 2099)

    def test_remote_pool_controls_are_present_in_page(self) -> None:
        page = monitor.render_index()
        self.assertIn("remotePoolPanel", page)
        self.assertIn("submitSelectedRemoteAccounts", page)
        self.assertIn("/api/remote-pool/upload", page)


if __name__ == "__main__":
    unittest.main()
