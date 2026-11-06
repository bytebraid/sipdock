"""Wire tests with the throwaway identities created by security.sh."""
import socket
import ssl
import subprocess
import time
from contextlib import ExitStack
from email.parser import Parser

from calls import AOR, DOMAIN, Peer, health, inbound, outbound, registrations, stop, upstream_register


def connect(stack, address, identity=None):
    context = ssl.create_default_context(cafile="/keys/pki/server/client-ca.pem")
    if identity:
        issuer = "untrusted" if identity == "rogue" else "pki"
        context.load_cert_chain(f"/keys/{issuer}/clients/{identity}/tsip.pem")
    raw = stack.enter_context(socket.create_connection((address, 5061), timeout=5))
    return stack.enter_context(context.wrap_socket(raw, server_hostname="proxy.test"))


class TLSPhone(Peer):
    transport = "TLS"

    def __init__(self, stack, address):
        self.sock = connect(stack, address, "phone")
        self.reader = stack.enter_context(self.sock.makefile("rb"))
        self.host = "[::1]" if ":" in address else address
        self.port = self.sock.getsockname()[1]
        self.contact = f"sip:1001@{self.host}:{self.port};transport=tls"
        self.agent = "Test TLS phone"

    def send(self, message):
        self.sock.sendall(message.encode())

    def receive(self, prefix, timeout=7):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.01, deadline - time.monotonic()))
            start = self.reader.readline().decode().strip()
            if not start:
                raise AssertionError(f"TLS connection closed waiting for {prefix}")
            lines = []
            while (line := self.reader.readline()) not in (b"\r\n", b""):
                lines.append(line)
            headers = b"".join(lines).decode()
            length = int(Parser().parsestr(headers)["Content-Length"])
            body = self.reader.read(length).decode()
            if start.startswith(prefix):
                return start, Parser().parsestr(headers + "\r\n" + body)
        raise AssertionError(f"timed out waiting for {prefix}")


def main():
    with ExitStack() as stack:
        provider = Peer(stack, "127.0.0.2", 15060)
        server = subprocess.Popen(["python3", "sipdock.py", "serve"])
        stack.callback(stop, server)
        health(503)
        upstream_register(provider)
        for identity in (None, "rogue"):
            try:
                channel = connect(stack, "127.0.0.1", identity)
                # TLS 1.3 can deliver a fatal client-cert alert on first read.
                channel.sendall(b"\r\n\r\n")
                if channel.recv(128):
                    raise AssertionError(f"untrusted identity accepted: {identity}")
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                pass
        udp_phone = Peer(stack)
        for peer in (udp_phone, provider):
            peer.request("REGISTER", DOMAIN, to=f"<{AOR}>")
            peer.receive("SIP/2.0 403")
        print("PASS untrusted or missing client certificates and plaintext REGISTER rejected", flush=True)
        phones = [TLSPhone(stack, "127.0.0.1"), TLSPhone(stack, "::1")]
        for phone in phones:
            phone.register(password="incorrect", expected=401)
            phone.register()
            outbound(phone, provider)
        inbound(provider, phones)
        for phone in phones:
            phone.register(0)
        registrations()
        print("PASS IPv4 and IPv6 mTLS registration, digest, outbound and forked incoming call", flush=True)


if __name__ == "__main__":
    main()
