"""Wire-level smoke test. Run in the isolated container described in the README."""

import hashlib
import http.client
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, closing
from email.parser import Parser
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Queue
from threading import Event, Thread
from uuid import uuid4
from pathlib import Path

import yaml

PROXY = ("127.0.0.1", 5060)
AOR = "sip:1001@provider.test"
DOMAIN = "sip:provider.test"
PASSWORD = "lab-only"
MAIL = Queue()


class Peer:
    transport = "UDP"
    def __init__(self, stack, host="127.0.0.1", port=0):
        self.sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.sock.bind((host, port))
        self.host, self.port = self.sock.getsockname()
        self.contact = f"sip:1001@{self.host}:{self.port}"
        self.agent = "Lab phone"

    def send(self, message):
        self.sock.sendto(message.encode(), PROXY)

    def receive(self, prefix, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                raw = self.sock.recv(65535).decode()
            except TimeoutError:
                break
            start, rest = raw.split("\r\n", 1)
            if start.startswith(prefix):
                return start, Parser().parsestr(rest)
        raise AssertionError(f"{self.contact} timed out awaiting {prefix}")

    def request(self, method, uri, *, origin=AOR, to=None, call=None, seq=1,
                headers=(), body="", branch=None):
        lines = [
            f"{method} {uri} SIP/2.0",
            f"Via: SIP/2.0/{self.transport} {self.host}:{self.port};branch=z9hG4bK{branch or uuid4().hex};rport",
            "Max-Forwards: 70", f"From: <{origin}>;tag=origin",
            f"To: {to or '<' + uri + '>'}", f"Call-ID: {call or uuid4().hex}",
            f"CSeq: {seq} {method}", *headers, f"Content-Length: {len(body)}",
        ]
        self.send("\r\n".join(lines) + "\r\n\r\n" + body)

    def reply(self, request, status, tag="ok", headers=()):
        _, req = request
        lines = [f"SIP/2.0 {status}"]
        for key in ("Via", "Record-Route", "From", "To", "Call-ID", "CSeq"):
            for value in req.get_all(key, []):
                if key == "To" and ";tag=" not in value:
                    value += ";tag=" + tag
                lines.append(f"{key}: {value}")
        self.send("\r\n".join([*lines, *headers, "Content-Length: 0", "", ""]))

    def register(self, expires=120, *, password=PASSWORD, auth_user="lab-auth", expected=200, wildcard=False):
        call = uuid4().hex
        contact = [f"Contact: <{self.contact}>;expires={expires}", f"User-Agent: {self.agent}"]
        if wildcard:
            contact = ["Contact: *", f"Expires: {expires}"]
        self.request("REGISTER", DOMAIN, call=call, to=f"<{AOR}>", headers=contact)
        challenge = self.receive("SIP/2.0 401")[1]["WWW-Authenticate"]
        auth = authorization(challenge, "REGISTER", DOMAIN, password, auth_user)
        self.request("REGISTER", DOMAIN, call=call, seq=2, to=f"<{AOR}>",
                     headers=[*contact, "Authorization: " + auth])
        return self.receive(f"SIP/2.0 {expected}")[1]


def fields(header):
    return dict(re.findall(r'(\w+)="?([^", ]+)', header))


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


def authorization(challenge, method, uri, password=PASSWORD, username="lab-auth"):
    ch = fields(challenge)
    ha1 = md5(f"{username}:{ch['realm']}:{password}")
    ha2 = md5(f"{method}:{uri}")
    digest = md5(f"{ha1}:{ch['nonce']}:00000001:phone:auth:{ha2}")
    return (f'Digest username="{username}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", '
            f'uri="{uri}", response="{digest}", qop=auth, nc=00000001, cnonce="phone"')


def health(expected, body=None):
    deadline = time.monotonic() + 20
    observed = None
    while time.monotonic() < deadline:
        try:
            with closing(http.client.HTTPConnection("127.0.0.1", 8080, timeout=2)) as conn:
                conn.request("GET", "/healthz")
                response = conn.getresponse()
                observed = (response.status, response.read(100))
                if response.status == expected and (body is None or observed[1].strip() == body):
                    return response.getheader("X-SipDock-Instance")
        except (OSError, http.client.HTTPException) as exc:
            observed = type(exc).__name__
        time.sleep(0.1)
    raise AssertionError(f"expected HTTP {expected}, last result {observed!r}")


def registrations(*phones, upstream="Registered"):
    with closing(http.client.HTTPConnection("127.0.0.1", 8081, timeout=3)) as conn:
        conn.request("GET", "/registrations")
        response = conn.getresponse()
        page = response.read().decode()
        assert response.status == 200 and response.getheader("Cache-Control") == "no-store"
    limit = yaml.safe_load(Path("/etc/sipdock/config.yaml").read_text()).get("max_clients", 16)
    assert f"Registered phones ({len(phones)} of {limit})" in page and f"<strong>{upstream}</strong>" in page, page
    assert ("No phones are currently registered" in page) == (not phones)
    assert "<script>" not in page and "lab-only" not in page
    for phone in phones:
        assert phone.contact.split("@")[1] in page, page
        assert f"{phone.host}:{phone.port}" in page, page
        assert phone.agent.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") in page
    return page


def upstream_register(provider, *, standby=False, release=False, timeout=20, lifetime=180):
    request = provider.receive("REGISTER", timeout)
    contact = request[1]["Contact"]
    if standby:
        assert re.fullmatch(r"<sip:sd-[0-9a-f]{24}@127\.0\.0\.1:5060>", contact), contact
    else:
        assert "sip:1001@127.0.0.1:5060" in contact
    assert (int(request[1]["Expires"]) == 0) == release
    provider.reply(request, "401 Unauthorized", headers=[
        'WWW-Authenticate: Digest realm="provider.test", nonce="labnonce", qop="auth"'])
    start, headers = request = provider.receive("REGISTER")
    assert headers["Contact"] == contact and (int(headers["Expires"]) == 0) == release
    actual = fields(headers["Authorization"])
    assert actual["username"] == "lab-auth" and actual["uri"] == start.split()[1]
    ha1 = md5("lab-auth:provider.test:" + PASSWORD)
    ha2 = md5("REGISTER:" + actual["uri"])
    assert actual["response"] == md5(f"{ha1}:labnonce:{actual['nc']}:{actual['cnonce']}:auth:{ha2}")
    provider.reply(request, "200 OK", headers=["Contact: " + contact, f"Expires: {0 if release else lifetime}"])
    health(200, b"ready" if release else b"registered")
    return contact


def inbound(provider, phones, destination="sip:1001@127.0.0.1:5060"):
    call = uuid4().hex
    caller = "sip:external@provider.test"
    provider.request("INVITE", destination,
                     origin=caller, to=f"<{AOR}>", call=call, headers=[
                         f"Contact: <{provider.contact}>", "Content-Type: application/sdp"],
                     body="v=0\r\ns=lab\r\n")
    # Every branch must arrive before any phone sends a provisional reply.
    branches = [phone.receive("INVITE") for phone in phones]
    # Wait until the losing branch's provisional response has reached the
    # provider before answering. UDP workers can process the replies in parallel.
    for phone, req in reversed(list(zip(phones, branches))):
        assert req[1]["Call-ID"] == call and req[1].get_payload() == "v=0\r\ns=lab\r\n"
        phone.reply(req, "180 Ringing", tag=str(phone.port))
        provider.receive("SIP/2.0 180")
    winner = phones[0]
    winner.reply(branches[0], "200 OK", tag=str(winner.port),
                 headers=[f"Contact: <{winner.contact}>"])
    answer = provider.receive("SIP/2.0 200")[1]
    for loser, branch in zip(phones[1:], branches[1:]):
        cancel = loser.receive("CANCEL")
        assert cancel[1]["Call-ID"] == call
        loser.reply(cancel, "200 OK", tag=str(loser.port))
        loser.reply(branch, "487 Request Terminated", tag=str(loser.port))
        loser.receive("ACK")
    uri = re.search(r"<([^>]+)>", answer["Contact"])[1]
    for method, seq in [("ACK", 1), ("BYE", 2)]:
        provider.request(method, uri, origin=caller, call=call, seq=seq,
                         to=answer["To"], headers=["Route: " + rr for rr in reversed(answer.get_all("Record-Route"))])
        request = winner.receive(method)
        assert request[1]["Call-ID"] == call
        if method == "BYE":
            winner.reply(request, "200 OK")
            provider.receive("SIP/2.0 200")


def outbound(phone, provider):
    uri = "sip:5551234@provider.test"
    call, branch = uuid4().hex, uuid4().hex
    contact = f"Contact: <{phone.contact}>"
    phone.request("INVITE", uri, call=call, branch=branch, headers=[contact])
    req = provider.receive("INVITE")
    assert req[0] == f"INVITE {uri} SIP/2.0" and req[1]["Call-ID"] == call
    challenge = 'Digest realm="provider.test", nonce="outbound", qop="auth"'
    provider.reply(req, "407 Proxy Authentication Required", headers=["Proxy-Authenticate: " + challenge])
    response = phone.receive("SIP/2.0 407")[1]
    phone.request("ACK", uri, call=call, branch=branch, to=response["To"])
    credentials = authorization(response["Proxy-Authenticate"], "INVITE", uri)
    phone.request("INVITE", uri, call=call, seq=2,
                  headers=[contact, "Proxy-Authorization: " + credentials])
    req = provider.receive("INVITE")
    assert req[1]["Proxy-Authorization"] == credentials and req[1]["CSeq"] == "2 INVITE"
    provider.reply(req, "200 OK", headers=[f"Contact: <{provider.contact}>"])
    answer = phone.receive("SIP/2.0 200")[1]
    for method, seq in [("ACK", 2), ("BYE", 3)]:
        phone.request(method, provider.contact, call=call, seq=seq, to=answer["To"],
                      headers=["Route: " + rr for rr in reversed(answer.get_all("Record-Route"))])
        request = provider.receive(method)
        assert request[1]["Call-ID"] == call
        if method == "BYE":
            provider.reply(request, "200 OK")
            phone.receive("SIP/2.0 200")


class MailSink(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 test SMTP\r\n")
        while line := self.rfile.readline():
            verb = line.split()[0].upper()
            if verb == b"DATA":
                self.wfile.write(b"354 continue\r\n")
                lines = []
                while (line := self.rfile.readline()) not in (b"", b".\r\n"):
                    lines.append(line)
                MAIL.put(b"".join(lines))
            if verb == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            self.wfile.write(b"250 ok\r\n")


def stop(process):
    if process.poll() is None:
        process.terminate()
        process.wait(10)


def capacity(stack, provider, limit):
    phones = [Peer(stack) for _ in range(limit)]
    extra = Peer(stack)
    for phone in phones:
        phone.register(expires=600)
    phones[0].register(expires=600)
    extra.register(expected=503)
    registrations(*phones)
    inbound(provider, phones)
    phones.pop().register(0)
    extra.register()
    registrations(*phones, extra)
    for phone in [*phones, extra]:
        phone.register(0)
    print(f"PASS all {limit} clients ring, overflow rejected, capacity reused", flush=True)


def check_lower_limits():
    # The release hook provides a new tmpfs here. Never overwrite an operator configuration.
    path = Path("/etc/sipdock/config.yaml")
    fixture = Path(__file__).with_name("lab.yaml").read_bytes()
    with path.open("xb") as config:
        config.write(fixture)
    for limit in (1, 5):
        path.write_text(yaml.safe_dump(dict(yaml.safe_load(fixture), max_clients=limit)))
        with ExitStack() as stack:
            provider = Peer(stack, "127.0.0.2", 15060)
            server = subprocess.Popen(["python3", "sipdock.py", "serve"])
            stack.callback(stop, server)
            health(503)
            if limit == 1:
                request = provider.receive("REGISTER")
                provider.reply(request, "403 Forbidden")
                before = time.monotonic()
                request = provider.receive("REGISTER")
                assert 2 <= time.monotonic() - before < 4
                provider.reply(request, "403 Forbidden")
                before = time.monotonic()
            upstream_register(provider)
            if limit == 1:
                assert 4 <= time.monotonic() - before < 7
                print("PASS preferred master retries rejected registrations with backoff")
            capacity(stack, provider, limit)
    path.write_bytes(fixture)


def check_failover():
    # This runs only with the release hook's isolated tmpfs and lab config.
    path = Path("/etc/sipdock/config.yaml")
    fixture = path.read_bytes()
    config = yaml.safe_load(fixture)

    class Master(BaseHTTPRequestHandler):
        status = 200
        polled = Event()
        timeout = 1

        def do_GET(self):
            self.send_response(self.status)
            self.send_header("X-SipDock-Instance", "master")
            self.end_headers()
            self.wfile.write(b"registered\n" if self.status == 200 else b"down\n")
            self.polled.set()

        def log_message(self, *args):
            pass

    with ExitStack() as stack:
        stack.callback(path.write_bytes, fixture)
        master = stack.enter_context(HTTPServer(("127.0.0.1", 0), Master))
        Thread(target=master.serve_forever, daemon=True).start()
        stack.callback(master.shutdown)
        # A bare URI probes HTTPS first. This HTTP-only master exercises fallback.
        config["mutex"] = dict(enabled=True, healthz=f"127.0.0.1:{master.server_port}/healthz")
        path.write_text(yaml.safe_dump(config))
        provider = Peer(stack, "127.0.0.2", 15060)
        server = subprocess.Popen(["python3", "sipdock.py", "serve"])
        stack.callback(stop, server)
        instance = health(200, b"ready")
        assert instance and instance != "master"
        assert Master.polled.wait(5), "standby did not check the master"
        provider.sock.settimeout(2)
        try:
            provider.sock.recv(8192)
            raise AssertionError("standby sent SIP traffic while the master was registered")
        except TimeoutError:
            pass
        Master.status = 503
        contact = upstream_register(provider, standby=True, timeout=25, lifetime=8)
        assert upstream_register(provider, standby=True, timeout=8) == contact
        phones = [Peer(stack), Peer(stack)]
        for phone in phones:
            phone.register()
        inbound(provider, phones, destination=contact.strip("<>"))
        Master.status = 200
        assert upstream_register(provider, standby=True, release=True, timeout=15) == contact
        assert health(200, b"ready") == instance
        Master.status = 503
        refused = provider.receive("REGISTER", 35)
        assert int(refused[1]["Expires"]) > 0
        started = time.monotonic()
        provider.reply(refused, "403 Forbidden")
        health(503)
        assert upstream_register(provider, standby=True, timeout=35) == contact
        elapsed = time.monotonic() - started
        assert 29 <= elapsed < 34, elapsed
        print("PASS standby, takeover, authenticated release, reacquisition and 30s provider retry")


def main():
    with ExitStack() as stack:
        provider = Peer(stack, "127.0.0.2", 15060)
        a, b, stranger = [Peer(stack) for _ in range(3)]
        # Two LAN phones behind one NAT. Only their observed UDP sockets
        # are reachable, including for the ACK and BYE after one answers.
        a.contact = "sip:1001@192.168.1.10:5060"
        b.contact = "sip:1001@192.168.1.11:5060"
        a.agent, b.agent = "Gigaset N300 IP", "tSIP & <script>"
        log = stack.enter_context(tempfile.TemporaryFile(mode="w+b"))
        def show_log():
            log.seek(0)
            print(log.read().decode(errors="replace"), end="")
        stack.callback(show_log)
        server = subprocess.Popen(["python3", "sipdock.py", "serve"], stdout=log, stderr=subprocess.STDOUT)
        stack.callback(stop, server)
        health(503)
        registrations(upstream="Unregistered")
        with closing(http.client.HTTPConnection("127.0.0.1", 8080, timeout=3)) as conn:
            conn.request("GET", "/registrations")
            assert conn.getresponse().status == 404
        upstream_register(provider)
        print("PASS authenticated upstream registration and HTTP 503/200")
        stranger.request("INVITE", AOR)
        stranger.receive("SIP/2.0 403")
        stranger.request("REGISTER", DOMAIN, to="<sip:wrong@provider.test>")
        stranger.receive("SIP/2.0 403")
        stranger.register(password="wrong-test-secret", expected=401)
        stranger.register(auth_user="mistyped-auth-user", expected=401)
        stranger.register(wildcard=True, expected=400)
        registrations()
        for phone in (a, b):
            phone.register()
            outbound(phone, provider)
        registrations(a, b)
        inbound(provider, [a, b])
        print("PASS two registrations, outbound digest, parallel ringing, CANCEL, ACK and BYE")
        b.register(0)
        registrations(a)
        inbound(provider, [a])
        a.register(0)
        registrations()
        cfg = yaml.safe_load(Path("/etc/sipdock/config.yaml").read_text())
        limit = cfg.get("max_clients", 16)
        capacity(stack, provider, limit)
        # The location store can retain expired records until its next sweep.
        # The status page must stop reporting them when the lease ends.
        response = stranger.register(1)
        granted = int(re.search(r"expires=(\d+)", response["Contact"])[1])
        assert 1 <= granted <= 60
        time.sleep(granted + 1)
        registrations()
        provider.request("INVITE", AOR)
        provider.receive("SIP/2.0 480")
        print("PASS unregistering one phone preserves the other, empty line returns 480")
        smtp = stack.enter_context(socketserver.TCPServer(("127.0.0.1", 1587), MailSink))
        Thread(target=smtp.serve_forever, daemon=True).start()
        stack.callback(smtp.shutdown)
        monitor = subprocess.Popen(["python3", "sipdock.py", "monitor"])
        stack.callback(stop, monitor)
        time.sleep(2)
        assert MAIL.empty()
        stop(server)
        log.seek(0)
        output = log.read().decode()
        assert all(secret not in output for secret in
                   (PASSWORD, "wrong-test-secret", md5(f"lab-auth:sipdock:{PASSWORD}"),
                    "Authorization: Digest", 'response="')), output
        if cfg.get("logging", {}).get("debug", False):
            for event in ("reason=unknown-line", "reason=initial-challenge", "reason=digest-mismatch",
                          "reason=auth-user-mismatch", "REGISTER accepted", "upstream REGISTER sent",
                          "upstream REGISTER reply", "source=127.0.0.1:", "Gigaset"):
                assert event in output, event
        else:
            assert "sipdock REGISTER" not in output and "sipdock receive" not in output
        print("PASS registration diagnostics, live contact list, expiry and private report port")
        message = MAIL.get(timeout=25)
        assert b"To: ops@example.test" in message and b"unhealthy" in message
        time.sleep(3)
        assert MAIL.empty()
        print("PASS proxy shutdown triggers one email to the configured recipient")


if __name__ == "__main__":
    if sys.argv[1:] == ["--capacity-matrix"]:
        check_lower_limits()
        check_failover()
    main()
