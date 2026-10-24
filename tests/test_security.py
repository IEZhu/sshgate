"""Offline security checks; all privileged/process boundaries are fakes."""
import concurrent.futures
import ast
import importlib.util
import io
import json
import os
from email.message import Message
from pathlib import Path
import subprocess
import tempfile
import time
import sys
import unittest
from unittest.mock import Mock, mock_open, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sshgate", ROOT / "app.py")
app = importlib.util.module_from_spec(SPEC)
# Public RFC 6238 test vector, never a deployed credential.
with patch("builtins.open", mock_open(read_data=json.dumps({
    "totp_secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
}))):
    SPEC.loader.exec_module(app)


def request(body=b"code=123456", ip="203.0.113.10", peer="127.0.0.1"):
    handler = object.__new__(app.Handler)
    handler.path = "/verify"
    handler.client_address = (peer, 1234)
    handler.headers = Message()
    handler.headers["X-Real-Client"] = ip
    handler.headers["Content-Length"] = str(len(body))
    handler.rfile = io.BytesIO(body)
    handler._send = Mock()
    return handler


class ApplicationSecurity(unittest.TestCase):
    def setUp(self):
        app._fails.clear()
        app._used_steps.clear()

    def test_runtime_imports_remain_standard_library_only(self):
        tree = ast.parse((ROOT / "app.py").read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module.split(".")[0])
        self.assertEqual(imports - sys.stdlib_module_names, set())

    def test_rfc6238_and_drift_boundary(self):
        self.assertEqual(app.totp(59, digits=8), "94287082")
        with patch.object(app.time, "time", return_value=3000):
            for offset in (-30, 0, 30):
                app._used_steps.clear()
                self.assertTrue(app.verify_totp(app.totp(3000 + offset)))
            self.assertFalse(app.verify_totp(app.totp(2940)))
            for invalid in ("", "12345", "１２３４５６", "123456;id"):
                self.assertFalse(app.verify_totp(invalid))

    def test_success_is_single_use_across_ips_and_threads(self):
        with patch.object(app.time, "time", return_value=3000):
            code = app.totp(3000)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                accepted = list(pool.map(app.verify_totp, [code] * 16))
            self.assertEqual(sum(accepted), 1)
        with patch.object(app.time, "time", return_value=3090):
            self.assertTrue(app.verify_totp(app.totp(3090)))
            self.assertLessEqual(len(app._used_steps), 3)

    def test_rate_limit_is_per_ip_and_expires(self):
        with patch.object(app.time, "time", return_value=1000):
            for _ in range(app.CFG["max_fails"]):
                app.record_fail("203.0.113.10")
            self.assertTrue(app.is_locked("203.0.113.10"))
            self.assertFalse(app.is_locked("203.0.113.11"))
        with patch.object(app.time, "time", return_value=1900):
            self.assertFalse(app.is_locked("203.0.113.10"))
        app.record_fail("203.0.113.10")
        app.clear_fails("203.0.113.10")
        self.assertNotIn("203.0.113.10", app._fails)

    def test_proxy_and_ip_boundary(self):
        for peer in ("127.0.0.1", "::1"):
            self.assertEqual(app.client_ip(request(peer=peer)), "203.0.113.10")
        for invalid in ("203.0.113.10;id", "-n", "1.2.3.999", "::1", "1.2.3.4,5.6.7.8"):
            self.assertIsNone(app.client_ip(request(ip=invalid)))
        self.assertIsNone(app.client_ip(request(peer="203.0.113.20")))
        handler = request()
        handler.headers["X-Real-Client"] = "203.0.113.11"
        self.assertIsNone(app.client_ip(handler))

    @patch.object(app, "log")
    @patch.object(app.subprocess, "run")
    def test_helper_argv_success_and_replay(self, run, _log):
        with patch.object(app.time, "time", return_value=3000):
            handler = request(body=("code=" + app.totp(3000)).encode())
            handler.do_POST()
            run.assert_called_once_with(["sudo", "-n", app.CFG["open_helper"], "203.0.113.10"],
                                        check=True, timeout=15, capture_output=True)
            self.assertEqual(handler._send.call_args.args[0], 200)
            request(body=("code=" + app.totp(3000)).encode(), ip="203.0.113.11").do_POST()
            self.assertEqual(run.call_count, 1)

    @patch.object(app, "log")
    @patch.object(app.subprocess, "run", side_effect=subprocess.TimeoutExpired("fake", 15))
    def test_helper_failure_is_generic_and_code_stays_consumed(self, run, _log):
        with patch.object(app.time, "time", return_value=3000):
            handler = request(body=("code=" + app.totp(3000)).encode())
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 500)
            self.assertNotIn("TimeoutExpired", handler._send.call_args.args[1])
            handler.do_POST()
            self.assertEqual(run.call_count, 1)

    @patch.object(app, "log")
    @patch.object(app.subprocess, "run")
    def test_bad_requests_never_call_helper(self, run, _log):
        for length in ("-1", "no", "4097", "１２"):
            handler = request()
            handler.headers.replace_header("Content-Length", length)
            handler.do_POST()
            self.assertIn(handler._send.call_args.args[0], (400, 413))
            self.assertTrue(handler.close_connection)
        for header in ("Content-Length", "Transfer-Encoding"):
            handler = request()
            handler.headers[header] = "chunked" if header == "Transfer-Encoding" else "4"
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 400)
        request(ip="203.0.113.10;id").do_POST()
        run.assert_not_called()

    @patch.object(app, "log")
    @patch.object(app.subprocess, "run")
    def test_failed_codes_lock_out_before_helper(self, run, _log):
        with patch.object(app, "verify_totp", return_value=False):
            for _ in range(app.CFG["max_fails"]):
                handler = request()
                handler.do_POST()
                self.assertEqual(handler._send.call_args.args[0], 401)
            handler = request()
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 429)
        run.assert_not_called()

    @patch.object(app, "log")
    @patch.object(app.subprocess, "run")
    def test_content_length_handles_long_decimal_headers(self, run, _log):
        for value in ("9" * 5000, "0" * 5000 + "4097"):
            handler = request()
            handler.headers.replace_header("Content-Length", value)
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 413)
            self.assertTrue(handler.close_connection)
        with patch.object(app, "verify_totp", return_value=False):
            handler = request()
            handler.headers.replace_header("Content-Length", "0" * 5000 + "11")
            handler.do_POST()
            self.assertEqual(handler._send.call_args.args[0], 401)
        run.assert_not_called()


class HelperLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls"
        self.env = dict(os.environ, SSHGATE_STATE_DIR=str(self.state),
                        CALLS=str(self.calls), UFW_STATUS="", UFW_EXIT="0", UFW_INSERT_EXIT="0", SS_EXIT="0", SS_OUTPUT="")
        self.fake("ufw", 'printf "%s\\n" "$*" >> "$CALLS"\nif [ "$1" = status ]; then printf "%s\\n" "$UFW_STATUS"; elif [ "$1" = insert ]; then echo "Rule inserted"; exit "$UFW_INSERT_EXIT"; fi\nexit "$UFW_EXIT"')
        self.fake("logger", 'exit 0')
        self.fake("ss", 'printf "%s" "$SS_OUTPUT"\nexit "$SS_EXIT"')
        self.fake("date", 'echo 100000')

    def fake(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body + "\n")
        path.chmod(0o755)

    def run_script(self, name, *args):
        # Substitute process boundaries in a temporary copy; real UFW/ss/logger are never called.
        text = (ROOT / "sbin" / name).read_text().replace("UFW=/usr/sbin/ufw", "UFW=" + str(self.bin / "ufw"))
        text = text.replace("export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH", "")
        self.env["PATH"] = str(self.bin) + ":/usr/bin:/bin"
        return subprocess.run(["/bin/bash", "-c", text, name, *args], env=self.env,
                              capture_output=True, text=True, timeout=5)

    def test_open_deduplicates_and_refreshes_timestamp(self):
        self.assertEqual(self.run_script("sshgate-open", "203.0.113.10").returncode, 0)
        self.assertEqual((self.state / "203.0.113.10").read_text().strip(), "100000")
        self.assertIn("insert 1 allow from 203.0.113.10 to any port 22 proto tcp comment sshgate", self.calls.read_text())
        self.calls.write_text("")
        self.env["UFW_STATUS"] = "22/tcp ALLOW 203.0.113.10"
        self.assertEqual(self.run_script("sshgate-open", "203.0.113.10").returncode, 0)
        self.assertEqual(self.calls.read_text(), "status\n")

    def test_open_rejects_injection_extra_args_invalid_port_and_ufw_failure(self):
        for args in (("203.0.113.10;id",), ("999.1.2.3",), ("-n",), ("1.2.3.4", "5.6.7.8")):
            self.assertEqual(self.run_script("sshgate-open", *args).returncode, 2)
        self.assertFalse(self.calls.exists())
        self.env["SSHGATE_PORT"] = "22;id"
        self.assertEqual(self.run_script("sshgate-open", "203.0.113.10").returncode, 2)
        self.env.pop("SSHGATE_PORT")
        self.env["UFW_EXIT"] = "1"
        self.assertNotEqual(self.run_script("sshgate-open", "203.0.113.10").returncode, 0)
        self.assertEqual(list(self.state.iterdir()), [])
        self.env.update(UFW_EXIT="0", UFW_INSERT_EXIT="1")
        self.assertNotEqual(self.run_script("sshgate-open", "203.0.113.10").returncode, 0)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_reap_preserves_young_active_unknown_and_failed_delete(self):
        opening = self.state / "203.0.113.10"
        for timestamp, options in (("99999", {}), ("1", {"SS_OUTPUT": "active session\n"}),
                                   ("1", {"SS_EXIT": "1"}), ("1", {"UFW_EXIT": "1"}), ("invalid", {})):
            self.env.update(SS_OUTPUT="", SS_EXIT="0", UFW_EXIT="0")
            self.env.update(options)
            opening.write_text(timestamp)
            self.assertEqual(self.run_script("sshgate-reap").returncode, 0)
            self.assertTrue(opening.exists())

    def test_reap_dryrun_then_expired_idle_delete(self):
        opening = self.state / "203.0.113.10"
        opening.write_text("1")
        self.env["SSHGATE_DRYRUN"] = "1"
        result = self.run_script("sshgate-reap")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("would-close", result.stdout)
        self.assertTrue(opening.exists())
        self.env["SSHGATE_DRYRUN"] = "0"
        result = self.run_script("sshgate-reap")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(opening.exists())
        self.assertIn("delete allow from 203.0.113.10 to any port 22 proto tcp", self.calls.read_text())

    def test_reap_decimal_leading_zeros_and_later_files(self):
        self.env["SSHGATE_MIN_AGE"] = "08"
        for ip, timestamp in (("203.0.113.10", "08"), ("203.0.113.11", "09"),
                              ("203.0.113.12", "99999")):
            (self.state / ip).write_text(timestamp)
        result = self.run_script("sshgate-reap")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "203.0.113.10").exists())
        self.assertFalse((self.state / "203.0.113.11").exists())
        self.assertTrue((self.state / "203.0.113.12").exists())
        self.assertIn("delete allow from 203.0.113.11", self.calls.read_text())


if __name__ == "__main__":
    unittest.main()
