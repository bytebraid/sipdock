"""Operator-facing configuration, native startup inputs, firewall and alerting."""
import contextlib
import io
import ipaddress
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import sipdock as app


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.data = yaml.safe_load(Path("tests/lab.yaml").read_text())
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(app, "RUN", self.root))
        self.enterContext(patch.object(app, "SCHEMA", self.root))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        (self.root / "standard-create.sql").write_text("")
        (self.root / "uac-create.sql").write_text(
            "CREATE TABLE uacreg(l_uuid,l_username,l_domain,r_username,r_domain,auth_username,"
            "auth_password,auth_proxy,expires);")

    def test_client_limits_and_backward_compatibility(self):
        for value in (None, 1, 7, 30):
            with self.subTest(value=value):
                if value is None:
                    self.data.pop("max_clients")
                else:
                    self.data["max_clients"] = value
                app.configure(self.data)
                settings = (self.root / "settings.cfg").read_text()
                self.assertIn(f"#!define MAX_CLIENTS {value or 16}\n", settings)
                self.assertNotIn(self.data["upstream"]["password"], settings)
                with contextlib.closing(sqlite3.connect(self.root / "line.sqlite")) as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM uacreg").fetchone()[0], 1)

    def test_unsupported_limits(self):
        for value in (True, 0, -1, 31, 2.5, "6", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "max_clients"):
                app.configure(dict(self.data, max_clients=value))

    def test_tls_and_debug_defines(self):
        self.data.pop("logging")
        self.data["upstream"].pop("auth_username")
        app.configure(self.data, tls=True)
        text = (self.root / "settings.cfg").read_text()
        self.assertIn('#!define AUTH_USER "1001"', text)
        self.assertIn("#!define PHONE_MTLS", text)
        self.assertIn("#!define REG_DEBUG 0", text)

    def test_reject_invalid_inputs(self):
        for key, value in (("logging", False), ("logging", {"debug": 1}), ("advertised_host", "bad host"),
                           ("upstream", None)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                app.configure(dict(self.data, **{key: value}))
        for key, value in (("password", "replace-with-provider-password"), ("username", ""),
                           ("trusted_sources", []), ("trusted_sources", [1]),
                           ("trusted_sources", ["0.0.0.0/0"]), ("expires", 0)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                app.configure(dict(self.data, upstream=dict(self.data["upstream"], **{key: value})))

    def test_certificate_paths(self):
        pem = self.root / "test.pem"
        pem.write_bytes(b"test")
        settings = dict.fromkeys(("certificate", "private_key", "client_ca"), str(pem))
        self.assertEqual(app.tls_material(settings), dict.fromkeys(settings, b"test"))
        with self.assertRaises(ValueError):
            app.tls_material(dict(settings, private_key="relative.key"))

    @patch("sipdock.ssl.SSLContext")
    def test_tls_config_requires_a_trusted_phone(self, context):
        material = {name: name.encode() for name in ("certificate", "private_key", "client_ca")}
        app.configure_tls(material)
        for name, contents in material.items():
            self.assertEqual((self.root / name).read_bytes(), contents)
        profile = (self.root / "tls.cfg").read_text()
        self.assertIn("require_certificate = yes", profile)
        self.assertIn("verify_certificate = yes", profile)
        context.return_value.load_verify_locations.assert_called_once_with(cafile=str(self.root / "client_ca"))

    def test_main_dispatches_health_and_monitor(self):
        config = self.root / "config.yaml"
        config.write_text(yaml.safe_dump(self.data))
        with patch.object(app, "CONFIG", config), patch("sipdock.os.dup2"), patch("sipdock.os.umask"):
            with patch.object(app.sys, "argv", ["sipdock", "monitor"]), patch("sipdock.monitor") as monitor:
                app.main()
                monitor.assert_called_once_with(self.data)
            for mode, host in (("healthcheck", "127.0.0.1"), ("monitor-healthcheck", "proxy")):
                with patch.object(app.sys, "argv", ["sipdock", mode]), patch("sipdock.probe", return_value=None) as probe:
                    with self.assertRaises(SystemExit) as result:
                        app.main()
                    self.assertIsNone(result.exception.code)
                    probe.assert_called_once_with(host)
            with patch.object(app.sys, "argv", ["sipdock", "serve"]):
                for value in ({"enable": "on"}, {"enabled": True}):
                    config.write_text(yaml.safe_dump(dict(self.data, tls=value)))
                    with self.assertRaises(ValueError):
                        app.main()
                for contents in ("[]", "broken: ["):
                    config.write_text(contents)
                    with self.assertRaises(ValueError):
                        app.main()


class FirewallTests(unittest.TestCase):
    def test_reject_bad_cidrs(self):
        for value in ("any", [1], ["::/0"], ["198.51.100.1/24"], ["::1/128"]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                app.cidrs({"client_ipv4": value}, "client_ipv4", 4)

    def test_port_and_family_isolation(self):
        ip = ipaddress.ip_network
        clients = [ip("192.0.2.0/25"), ip("192.0.2.128/25"), ip("2001:db8::/64")]
        for tls in (True, False):
            for version in (4, 6):
                rules = app.firewall_rules(version, clients, [ip("203.0.113.1")],
                                           [ip("198.51.100.1")], [], tls)
                self.assertIn(":INPUT DROP", rules)
                self.assertIn("-i lo -j ACCEPT", rules)
                self.assertIn("tcp --dport 5061" if tls else "udp --dport 5060", rules)
                self.assertNotIn("--dport 8081", rules)
                self.assertEqual("192.0.2.0/24" in rules, version == 4)
                self.assertEqual("203.0.113.1/32" in rules, version == 4)
                self.assertEqual("--dport 8080" in rules, version == 4)
                self.assertEqual("2001:db8::/64" in rules, version == 6)

    @patch("sipdock.subprocess.run")
    @patch("sipdock.os.getuid", create=True, return_value=0)
    def test_both_tables_required(self, uid, run):
        with contextlib.redirect_stdout(io.StringIO()):
            app.install_firewall({"upstream": {"trusted_sources": ["192.0.2.4"]}}, True)
        self.assertEqual([c.args[0][0] for c in run.call_args_list], ["iptables-restore", "ip6tables-restore"])
        self.assertTrue(all(c.kwargs["check"] for c in run.call_args_list))


class MonitorTests(unittest.TestCase):
    @patch("sipdock.http.client.HTTPConnection")
    def test_http_probe(self, factory):
        conn = factory.return_value
        for status, expected in ((200, None), (503, "HTTP 503")):
            conn.getresponse.return_value.status = status
            self.assertEqual(app.probe("127.0.0.1"), expected)
        conn.request.side_effect = ConnectionRefusedError()
        self.assertEqual(app.probe(), "ConnectionRefusedError")

    def test_mail_settings_and_delivery(self):
        data = yaml.safe_load(Path("tests/lab.yaml").read_text())["alerts"]
        for security, port in (("tls", 465), ("starttls", 587), ("plain", 25)):
            alerts = dict(data, security=security, username="sender", password="test")
            del alerts["smtp_port"]
            settings = app.mail_settings(alerts)
            self.assertEqual(settings[1], port)
            with patch("sipdock.smtplib.SMTP") as smtp, patch("sipdock.smtplib.SMTP_SSL") as smtps:
                app.notify(settings, "HTTP 503", "proxy.test")
                client = (smtps if security == "tls" else smtp).return_value
                self.assertEqual(client.starttls.called, security == "starttls")
                client.login.assert_called_once_with("sender", "test")
                self.assertEqual(client.send_message.call_args.args[0]["To"], data["to"])
        with self.assertRaises(ValueError):
            app.mail_settings(dict(data, security="unknown"))

    def test_alert_rearms_after_recovery(self):
        data = yaml.safe_load(Path("tests/lab.yaml").read_text())
        with patch("sipdock.probe", side_effect=["down", "down", "down", None, "down", "down"]), \
             patch("sipdock.time.sleep", side_effect=[None]*5 + [KeyboardInterrupt()]), \
             patch("sipdock.notify") as notify, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                app.monitor(data)
            self.assertEqual(notify.call_count, 2)
