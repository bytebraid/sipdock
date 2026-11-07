"""Timing, peer identity and transport contracts for single-line failover."""
import logging
import unittest
from unittest.mock import Mock, patch

import yaml

import sipdock as app


class MutexTests(unittest.TestCase):
    def test_duplicate_role_reports_both_lines(self):
        for config, key, first, second in (
            ("mutex:\n  enabled: true\nmutex:\n  enabled: false\n", "mutex", 1, 3),
            ("mutex:\n  enabled: true\n  enabled: false\n", "enabled", 2, 3),
        ):
            with self.subTest(key=key), patch.object(app, "CONFIG") as file, \
                 patch.object(app.sys, "argv", ["sipdock", "serve"]), \
                 patch("sipdock.os.dup2"), patch("sipdock.os.umask"), patch("sipdock.serve") as serve:
                file.read_text.return_value = config
                with self.assertRaisesRegex(ValueError, f"'{key}' on lines {first} and {second}"):
                    app.main()
                serve.assert_not_called()
        config = "base: &defaults {enabled: false}\nmutex: {<<: *defaults, enabled: true}"
        self.assertTrue(yaml.load(config, Loader=app.ConfigLoader)["mutex"]["enabled"])

    def test_settings(self):
        def endpoint(**opts):
            return app.mutex_endpoint({"mutex": opts}, "primary.test")

        self.assertIsNone(endpoint())
        for uri in (None, "$advertised_host/healthz"):
            opts = {"healthz": uri} if uri else {}
            url = endpoint(enabled=True, **opts)
            self.assertEqual(url.geturl(), "https://primary.test/healthz")
        for uri in ([], "", "ftp://host/healthz", "https://user@host", "host:99999/healthz",
                    "host/healthz#fragment", "host/healthz\n"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                endpoint(enabled=True, healthz=uri)
        with self.assertRaises(ValueError):
            endpoint(enabled="false")

    @patch("sipdock.http.client.HTTPConnection")
    @patch("sipdock.http.client.HTTPSConnection")
    def test_peer_transport(self, https, http):
        url = app.mutex_endpoint({"mutex": {"enabled": True, "healthz": "master:5062/check?line=1"}}, "local")
        tls = https.return_value
        tls.getresponse.return_value.status = 503
        self.assertEqual(app.poll_peer(url), ("down", None))
        http.assert_not_called()
        tls.request.side_effect = TimeoutError()
        reply = http.return_value.getresponse.return_value
        reply.status, reply.getheader.return_value = 200, "master"
        for body, state in ((b"registered\n", "registered"), (b"ready\n", "ready"), (b"ok", "healthy")):
            reply.read.return_value = body
            self.assertEqual(app.poll_peer(url), (state, "master"))
        http.assert_called_with("master", 5062, timeout=3)
        http.return_value.request.assert_called_with("GET", "/check?line=1", headers={"Cache-Control": "no-cache"})
        http.return_value.request.side_effect = ConnectionRefusedError()
        self.assertEqual(app.poll_peer(url), ("down", None))

    @patch("sipdock.http.client.HTTPConnection")
    @patch("sipdock.http.client.HTTPSConnection")
    def test_debug_records_both_uris_status_and_complete_body(self, https, http):
        endpoint = app.mutex_endpoint({"mutex": {"enabled": True, "healthz": "master:5062/check?line=1"}}, "local")
        https.return_value.request.side_effect = ConnectionRefusedError("refused")
        reply = http.return_value.getresponse.return_value
        body = b"registrar offline\n".ljust(4096, b".")
        tail = b"end\x1b[0m"
        reply.read.side_effect = [body, tail]
        reply.status = 503
        with self.assertLogs("sipdock", level="DEBUG") as logs:
            self.assertEqual(app.poll_peer(endpoint), ("down", None))
        messages = [record.getMessage() for record in logs.records]
        self.assertTrue(any("https://master:5062/check?line=1 status=unavailable" in m and "refused" in m
                            for m in messages))
        self.assertIn(f"Mutex GET http://master:5062/check?line=1 status=503 body={body!r}", messages)
        self.assertIn(f"Mutex GET http://master:5062/check?line=1 status=503 body continued={tail!r}", messages)

    @patch("sipdock.http.client.HTTPConnection")
    def test_registered_response_prevents_takeover_and_reports_next_poll(self, http):
        endpoint = app.mutex_endpoint({"mutex": {"enabled": True, "healthz": "http://master:5062/healthz"}}, "local")
        reply = http.return_value.getresponse.return_value
        reply.status = 200
        reply.read.return_value = b"registered\n"
        reply.getheader.return_value = "master-id"
        changes, stop = app.Queue(), Mock()
        stop.is_set.side_effect = [False, False, True]
        with self.assertLogs("sipdock", level="DEBUG") as logs, \
             patch("sipdock.time.monotonic", side_effect=[0, 1.25, 20, 20.5]):
            app.watch_master(endpoint, "standby-id", changes, stop)
        self.assertTrue(changes.empty(), "a healthy master must never trigger a registration request")
        self.assertEqual([c.args[0] for c in stop.wait.call_args_list], [18.75, 19.5])
        messages = "\n".join(record.getMessage() for record in logs.records)
        self.assertIn("Mutex polling loop started for http://master:5062/healthz", messages)
        self.assertEqual(messages.count("status=200 body=b'registered\\n'"), 2)
        self.assertIn("role=standby", messages)
        self.assertIn("Next mutex poll in 18.750s", messages)

        reply.read.side_effect = TimeoutError()
        with self.assertLogs("sipdock", level="ERROR"):
            self.assertEqual(app.poll_peer(endpoint), ("healthy", "master-id"))

    def test_log_colours_and_source(self):
        formatter = app.ThreadFormatter()

        def render(thread, level):
            record = logging.LogRecord("sipdock.Registration", level, "sipdock.py", 321, "message", (), None)
            record.threadName = thread
            return formatter.format(record)

        main = render("MainThread", logging.INFO)
        poll = render("mutex-poll", logging.DEBUG)
        self.assertNotEqual(main.split("m", 1)[0], poll.split("m", 1)[0])
        self.assertIn("DEBUG sipdock.Registration:321 [mutex-poll] message", poll)
        for thread in ("MainThread", "mutex-poll"):
            for level in (logging.ERROR, logging.CRITICAL):
                self.assertTrue(render(thread, level).startswith("\x1b[1;33m"))
                self.assertTrue(render(thread, level).endswith("\x1b[0m"))

    def test_ready_requires_six_full_uninterrupted_intervals(self):
        election = app.Election("local")
        for peer in ("a", "b"):
            for _ in range(6):
                election.observe("ready", peer)
                self.assertFalse(election.active)
                self.assertEqual(election.interval, 20)
        election.observe("registered", "b")
        for _ in range(6):
            election.observe("ready", "b")
            self.assertFalse(election.active)
        election.observe("ready", "b")
        self.assertTrue(election.active)
        self.assertEqual(election.interval, 10)

    def test_yield_self_and_failback(self):
        for healthy in ("ready", "registered"):
            election = app.Election("local")
            election.observe("down", None)
            for state in ("down", "registered", "ready"):
                election.observe(state, "local")
                self.assertTrue(election.active)
            election.observe("healthy", "unidentified")
            self.assertTrue(election.active)
            election.observe(healthy, "master")
            self.assertEqual(election.interval, 30)
            for _ in range(10):
                election.observe("registered", "master")
                self.assertFalse(election.active)
            election.observe("down", None)
            self.assertTrue(election.active)

    def test_registration_failure_and_refresh_schedule(self):
        for mutex, schedule in ((True, [30] * 6), (False, [2, 4, 8, 16, 30, 30])):
            line = app.Registration(None, "contact", mutex)
            info = {"flags": 0, "diff_expires": 0}
            with patch.object(line, "rpc", return_value=info) as rpc, self.assertLogs("sipdock.Registration", "ERROR"):
                for delay in schedule:
                    line.step()
                    rpc.assert_called_with("uac.reg_register", "l_uuid", "contact")
                    info["flags"] = 2
                    for _ in range(3):
                        self.assertLess(line.step(), 1)
                        rpc.assert_called_with("uac.reg_info", "l_uuid", "contact")
                    info["flags"] = 0
                    self.assertEqual(line.step(), delay)
                line.step()
                info.update(flags=4, diff_expires=120)
                self.assertEqual(line.step(), 110)
                line.step()
                info.update(flags=0, diff_expires=0)
                self.assertEqual(line.step(), schedule[0])
