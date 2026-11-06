"""Probe the running proxy from a distinct, dual-stack Docker namespace."""
import socket
import sys
from contextlib import ExitStack
from uuid import uuid4

from mtls import connect


def register(sock, transport):
    host, port = sock.getsockname()[:2]
    via = f"[{host}]" if ":" in host else host
    msg = (f"REGISTER sip:provider.test SIP/2.0\r\nVia: SIP/2.0/{transport} {via}:{port};branch=z9hG4bK{uuid4().hex};rport\r\n"
           "From: <sip:1001@provider.test>;tag=net\r\nTo: <sip:1001@provider.test>\r\n"
           f"Call-ID: {uuid4().hex}\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 10\r\nContent-Length: 0\r\n\r\n")
    sock.sendall(msg.encode())
    return sock.recv(4096).split(b"\r\n", 1)[0]


def check(host, role, mode):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for port in (5060, 5061, 8080, 8081):
        allowed = ((role == "phone" and port == (5061 if mode == "tls" else 5060))
                   or (role == "management" and port == 8080)
                   or (role == "provider" and port == 5060 and family == socket.AF_INET))
        try:
            with ExitStack() as stack:
                if port == 5061 and allowed:
                    sock = connect(stack, host, "phone")
                    result = register(sock, "TLS")
                else:
                    stype = socket.SOCK_DGRAM if port == 5060 else socket.SOCK_STREAM
                    sock = stack.enter_context(socket.socket(family, stype))
                    sock.settimeout(1.5)
                    sock.connect((host, port))
                    if port == 5060:
                        result = register(sock, "UDP")
                    else:
                        sock.sendall(b"GET /healthz HTTP/1.0\r\nHost: proxy\r\n\r\n")
                        result = sock.recv(1024)
        except TimeoutError:
            assert not allowed, (host, role, mode, port, "unexpected drop")
            continue
        assert allowed, (host, role, mode, port, "unexpected access", result)
        expected = b"503" if port == 8080 else b"403" if role == "provider" and mode == "tls" else b"401"
        assert expected in result, (host, role, mode, port, result)


for dest in ("192.0.2.2", "2001:db8:1328:5::2"):
    check(dest, sys.argv[1], sys.argv[2])
print("PASS IPv4/IPv6 ingress", *sys.argv[1:])
