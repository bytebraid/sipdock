#!/usr/bin/env python3
"""Issue certificates for SipDock's phone-facing mutual TLS listener."""

import argparse
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile


def openssl(*args):
    result = subprocess.run(["openssl", *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "OpenSSL failed")


def identity(name, server):
    if server:
        if "%" in name:
            raise ValueError("use an IP address without a zone identifier")
        try:
            return "IP:" + str(ipaddress.ip_address(name))
        except ValueError:
            label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            if len(name) <= 253 and all(re.fullmatch(label, s) for s in name.split(".")):
                return "DNS:" + name
        raise ValueError("use the DNS name or IP address phones connect to")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", name):
        raise ValueError("use 1-63 letters, digits, hyphens or underscores for the phone ID")


def issue(base, command, name):
    server, ca = base / "server", base / "ca"
    ca_key, ca_cert = ca / "ca.key", ca / "ca.pem"
    init = command == "init"
    if init:
        files = {"key": ca_key, "cert": ca_cert, "trust": server / "client-ca.pem"}
    else:
        san = identity(name, command == "server")
        if not ca_key.is_file() or not ca_cert.is_file():
            raise ValueError("CA missing; run 'init' first or restore your existing CA")
        if command == "server":
            files = {"key": server / "privkey.pem", "cert": server / "fullchain.pem"}
        else:
            phone = base / "clients" / name
            files = {"key": phone / "client.key", "cert": phone / "client.pem",
                     "bundle": phone / "tsip.pem"}
    for path in files.values():
        if os.path.lexists(path):
            raise ValueError(f"refusing to replace {path}")
    base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base, prefix=".issue-") as staging:
        tmp = Path(staging)
        key, cert = tmp / "key", tmp / "cert"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt",
                f"rsa_keygen_bits:{3072 if init else 2048}", "-out", key)
        if init:
            openssl("req", "-new", "-x509", "-sha256", "-days", "3650", "-key", key,
                    "-subj", "/CN=SipDock private CA", "-out", cert,
                    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            shutil.copyfile(cert, tmp / "trust")
        else:
            is_server = command == "server"
            # The server identity is its SAN. A constant CN also allows long DNS names.
            openssl("req", "-new", "-key", key, "-subj", "/CN=" + ("SipDock server" if is_server else name),
                    "-out", tmp / "req")
            extensions = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,keyEncipherment",
                          "extendedKeyUsage=" + ("serverAuth" if is_server else "clientAuth")]
            if is_server:
                extensions.append("subjectAltName=" + san)
            (tmp / "ext").write_text("\n".join(extensions) + "\n", encoding="ascii")
            openssl("x509", "-req", "-in", tmp / "req", "-CA", ca_cert, "-CAkey", ca_key,
                    "-set_serial", "0x01" + secrets.token_hex(15), "-sha256", "-days", "365",
                    "-extfile", tmp / "ext", "-out", cert)
            openssl("verify", "-CAfile", ca_cert, "-purpose", "sslserver" if is_server else "sslclient", cert)
            if not is_server:
                (tmp / "bundle").write_bytes(cert.read_bytes() + key.read_bytes())

        for filename, dest in files.items():
            dest.parent.mkdir(parents=True, exist_ok=True)
            with (tmp / filename).open("rb") as src, dest.open("xb") as out:
                shutil.copyfileobj(src, out)
    for dest in files.values():
        print(dest)


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False,
        epilog="Example: init, then server sip.example.net, then client deskphone. See certs/README.md.")
    parser.add_argument("-h", "-?", "--help", action="help", help="show this help and exit")
    parser.add_argument("--dir", type=Path, default=Path(__file__).resolve().parents[1] / "certs",
                        help="certificate directory (default: this project's certs/)")
    parser.add_argument("command", choices=["init", "server", "client"],
                        help="create the signing CA, issue a server certificate, or issue a phone identity")
    parser.add_argument("name", nargs="?", help="server DNS name/IP or unique phone ID; omit for init")
    args = parser.parse_args()
    if (args.command == "init") != (args.name is None):
        parser.error("init takes no name; server and client each require one")
    os.umask(0o077)
    try:
        issue(args.dir, args.command, args.name)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"certs: {exc}\n")


if __name__ == "__main__":
    main()
