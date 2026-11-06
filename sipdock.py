"""Configure Kamailio or run its independent HTTP/SMTP monitor."""

import hashlib
import http.client
import ipaddress
import json
import os
import re
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import time
from contextlib import closing
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path

import yaml

CONFIG = Path("/etc/sipdock/config.yaml")
RUN = Path("/run/sipdock")
SCHEMA = Path("/usr/share/kamailio/db_sqlite")
HEALTH_HOST = "proxy"
HOST = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
SIP_ID = r"[a-zA-Z0-9+*_.@-]{1,64}"


def section(data, key):
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a YAML mapping")
    return value


def string(data, key, pattern=None):
    value = data.get(key)
    if not isinstance(value, str) or not value or not value.isprintable():
        raise ValueError(f"{key} must be a nonempty quoted string")
    if pattern and not re.fullmatch(pattern, value):
        raise ValueError(f"invalid {key}")
    return value


def integer(data, key, default, minimum, maximum):
    value = data.get(key, default)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer between {minimum} and {maximum}")
    return value


def cidrs(mapping, key, version=None):
    values = mapping.get(key, [])
    if not isinstance(values, list):
        raise ValueError(f"{key} must be a list of CIDRs")
    networks = []
    for entry in values:
        if not isinstance(entry, str):
            raise ValueError(f"{key} requires IPv4 or IPv6 CIDR strings")
        network = ipaddress.ip_network(entry, strict=True)
        if network.prefixlen == 0 or (version and network.version != version):
            raise ValueError(f"invalid network {entry} in {key}")
        networks.append(network)
    return networks


def firewall_rules(version, client, provider, health, admin, tls):
    # Restore the filter table in this container's own network namespace.
    # Match reply-direction traffic for our own DNS, SMTP and upstream requests.
    rules = ["*filter", ":INPUT DROP [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [0:0]",
             "-A INPUT -i lo -j ACCEPT", "-A INPUT -m conntrack --ctstate INVALID -j DROP",
             "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT"]
    if version == 6:
        # IPv6 needs neighbor discovery on the bridge. These messages cannot
        # traverse a router with their required hop limit intact.
        for kind in ("neighbor-solicitation", "neighbor-advertisement"):
            rules.append(f"-A INPUT -p ipv6-icmp --icmpv6-type {kind} -m hl --hl-eq 255 -j ACCEPT")
    groups = [(client, "tcp" if tls else "udp", 5061 if tls else 5060),
              (provider, "udp", 5060), (health, "tcp", 8080), (admin, "tcp", 8081)]
    for networks, protocol, port in groups:
        family = [n for n in networks if n.version == version]
        for network in ipaddress.collapse_addresses(family):
            rules.append(f"-A INPUT -s {network} -p {protocol} --dport {port} -j ACCEPT")
    return "\n".join([*rules, "COMMIT", ""])


def install_firewall(data, tls):
    if os.getuid() != 0:
        raise ValueError("serve requires container root and NET_ADMIN to install both firewall policies")
    firewall = data.get("firewall", {})
    if not isinstance(firewall, dict):
        raise ValueError("firewall must be a mapping")
    clients = cidrs(firewall, "client_ipv4", 4) + cidrs(firewall, "client_ipv6", 6)
    provider = cidrs(section(data, "upstream"), "trusted_sources", 4)
    health = cidrs(firewall, "health_sources")
    admin = cidrs(firewall, "admin_sources")
    for version, command in [(4, "iptables-restore"), (6, "ip6tables-restore")]:
        rules = firewall_rules(version, clients, provider, health, admin, tls)
        subprocess.run([command, "--wait", "5"], input=rules, text=True, check=True)
    print(f"Inbound firewall active on IPv4 and IPv6. Phone transport: {'mTLS' if tls else 'UDP'}.", flush=True)


def tls_material(settings):
    result = {}
    for key in ("certificate", "private_key", "client_ca"):
        path = Path(string(settings, key))
        if not path.is_absolute() or not path.is_file():
            raise ValueError(f"tls.{key} must be an absolute path to a mounted PEM file")
        result[key] = path.read_bytes()
    return result


def configure_tls(material):
    # Only the container bootstrap needs access to a root-owned mounted key.
    # These copies are written after dropping privileges, under umask 077.
    for key, contents in material.items():
        (RUN / key).write_bytes(contents)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(RUN / "certificate", RUN / "private_key", password=lambda: "")
    context.load_verify_locations(cafile=str(RUN / "client_ca"))
    (RUN / "tls.cfg").write_text(
        "[server:default]\nmethod = TLSv1.2+\nverify_certificate = yes\nrequire_certificate = yes\n"
        f"certificate = {RUN}/certificate\nprivate_key = {RUN}/private_key\nca_list = {RUN}/client_ca\n"
    )


def configure(data, tls=False):
    max_clients = integer(data, "max_clients", 16, 1, 30)
    logging = data.get("logging", {})
    if not isinstance(logging, dict) or type(logging.get("debug", False)) is not bool:
        raise ValueError("logging.debug must be true or false")
    debug = logging.get("debug", False)
    advertised = string(data, "advertised_host", HOST)
    upstream = section(data, "upstream")
    domain = string(upstream, "domain", HOST)
    host = string(upstream, "host", HOST)
    port = integer(upstream, "port", 5060, 1, 65535)
    user = string(upstream, "username", r"[a-zA-Z0-9+*_.-]{1,64}")
    auth = string(upstream, "auth_username", SIP_ID) if "auth_username" in upstream else user
    password = string(upstream, "password")
    if password == "replace-with-provider-password":
        raise ValueError("set upstream.password to the provider password")
    expiry = integer(upstream, "expires", 300, 60, 86400)
    sources = upstream.get("trusted_sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("upstream.trusted_sources needs at least one provider IPv4 address or subnet")
    networks = []
    for source in sources:
        if not isinstance(source, str):
            raise ValueError("trusted_sources entries must be IPv4 addresses or CIDRs")
        network = ipaddress.IPv4Network(source)
        if network.prefixlen == 0:
            raise ValueError("trusted_sources must be limited to provider addresses")
        networks.append(str(network))

    target = f"sip:{host}:{port}"
    # Digest on REGISTER uses our realm. Phones answer provider call challenges
    # directly, so the original Request-URI, CSeq and authorization stay paired.
    digest = hashlib.md5(f"{auth}:sipdock:{password}".encode()).hexdigest()
    values = {
        "ADVERTISED_HOST": advertised,
        "ADVERTISED_SOCKET": f"{advertised}:5060",
        "LINE_USER": user,
        "LINE_AOR": f"sip:{user}@{domain}",
        "AUTH_USER": auth,
        "LOCAL_HA1": digest,
        "UPSTREAM_URI": target,
        "TRUSTED_SOURCES": ",".join(networks),
    }
    template = Path(__file__).with_name("registrations.html").read_text(encoding="utf-8")
    (RUN / "settings.cfg").write_text(
        "".join(f'#!define {name} "{value}"\n' for name, value in values.items())
        + f"#!define REG_DEBUG {int(debug)}\n"
        + f"#!define MAX_CLIENTS {max_clients}\n"
        + ("#!define PHONE_MTLS\n" if tls else "")
        + f"#!define REPORT_TEMPLATE {json.dumps(template)}\n"
    )
    # Use the schema packaged with this Kamailio build. Recreate the one-row
    # database on every start so credential rotations take effect on restart.
    db_path = RUN / "line.next"
    db_path.unlink(missing_ok=True)
    with closing(sqlite3.connect(db_path)) as db:
        for schema in ("standard-create.sql", "uac-create.sql"):
            db.executescript((SCHEMA / schema).read_text())
        db.execute(
            """INSERT INTO uacreg
               (l_uuid,l_username,l_domain,r_username,r_domain,auth_username,
                auth_password,auth_proxy,expires)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (user, user, domain, user, domain, auth, password, target, expiry),
        )
        db.commit()
    db_path.replace(RUN / "line.sqlite")
    print(f"SipDock accepts up to {max_clients} contacts. SIP diagnostics {'enabled' if debug else 'disabled'}.", flush=True)


def probe(host=HEALTH_HOST):
    with closing(http.client.HTTPConnection(host, 8080, timeout=3)) as connection:
        try:
            connection.request("GET", "/healthz")
            status = connection.getresponse().status
            return None if status == 200 else f"HTTP {status}"
        except (OSError, http.client.HTTPException) as exc:
            return type(exc).__name__


def mail_settings(alerts):
    mode = alerts.get("security", "starttls")
    if mode not in ("starttls", "tls", "plain"):
        raise ValueError("alerts.security must be starttls, tls or plain")
    host = string(alerts, "smtp_host", HOST)
    port = integer(alerts, "smtp_port", {"starttls": 587, "tls": 465, "plain": 25}[mode], 1, 65535)
    addresses = []
    for field in ("from", "to"):
        address = Address(addr_spec=string(alerts, field))
        if not address.domain:
            raise ValueError(f"alerts.{field} needs a full email address")
        addresses.append(address.addr_spec)
    user = alerts.get("username")
    password = string(alerts, "password") if user else None
    if user:
        string(alerts, "username")
    return host, port, mode, user, password, *addresses


def notify(settings, detail, smtp_identity):
    host, port, mode, user, password, sender, recipient = settings
    message = EmailMessage()
    message["From"], message["To"] = sender, recipient
    message["Subject"] = "SipDock SIP proxy is unhealthy"
    message.set_content(f"The proxy failed consecutive GET /healthz checks.\nLatest result: {detail}\n")
    context = ssl.create_default_context()
    if mode == "tls":
        client = smtplib.SMTP_SSL(host, port, local_hostname=smtp_identity, timeout=10, context=context)
    else:
        client = smtplib.SMTP(host, port, local_hostname=smtp_identity, timeout=10)
    with client:
        if mode == "starttls":
            client.starttls(context=context)
        if user:
            client.login(user, password)
        client.send_message(message)


def monitor(data):
    alerts = data.get("alerts", {})
    if not isinstance(alerts, dict) or type(alerts.get("enabled", False)) is not bool:
        raise ValueError("alerts.enabled must be true or false")
    interval = integer(alerts, "interval_seconds", 15, 1, 86400)
    threshold = integer(alerts, "failure_threshold", 3, 1, 1000)
    settings = mail_settings(alerts) if alerts.get("enabled") else None
    smtp_identity = string(data, "advertised_host", HOST)
    try:
        smtp_identity = f"[{ipaddress.IPv4Address(smtp_identity)}]"
    except ipaddress.AddressValueError:
        pass  # A DNS name is already valid in EHLO.
    print("Monitoring GET /healthz. Email alerts " + ("enabled." if settings else "disabled."))
    failures = 0
    sent = False
    while True:
        detail = probe()
        if detail is None:
            if failures:
                print("Proxy health recovered.")
            failures, sent = 0, False
        else:
            failures += 1
            if failures == threshold:
                print(f"Proxy unhealthy after {failures} checks ({detail}).")
            if settings and failures >= threshold and not sent:
                try:
                    notify(settings, detail, smtp_identity)
                    sent = True
                    print("Unhealthy notification sent.")
                except (OSError, smtplib.SMTPException) as exc:
                    print(f"Email delivery failed ({type(exc).__name__}). Will retry.")
        time.sleep(interval)


def main():
    # Kamailio -E and Python startup errors both go to Docker's stdout stream.
    os.dup2(1, 2)
    os.umask(0o077)
    if sys.argv[1:] in (["healthcheck"], ["monitor-healthcheck"]):
        detail = probe("127.0.0.1" if sys.argv[1] == "healthcheck" else HEALTH_HOST)
        sys.exit(detail)
    try:
        data = yaml.safe_load(CONFIG.read_text())
    except yaml.YAMLError:
        raise ValueError("invalid config.yaml syntax") from None
    if not isinstance(data, dict):
        raise ValueError("config.yaml must be a mapping")
    if sys.argv[1:] == ["monitor"]:
        monitor(data)
    elif sys.argv[1:] == ["serve"]:
        settings = data.get("tls", {})
        if not isinstance(settings, dict) or type(settings.get("enable", False)) is not bool:
            raise ValueError("tls.enable must be true or false")
        if settings.keys() - {"enable", "certificate", "private_key", "client_ca"}:
            raise ValueError("unknown TLS option; use enable, certificate, private_key and client_ca")
        tls = settings.get("enable", False)
        install_firewall(data, tls)
        material = tls_material(settings) if tls else None
        import pwd
        account = pwd.getpwnam("kamailio")
        os.chown(RUN, account.pw_uid, account.pw_gid, follow_symlinks=False)
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        if material:
            configure_tls(material)
        configure(data, tls)
        os.execlp("kamailio", "kamailio", "-DD", "-E", "-f", "/opt/sipdock/kamailio.cfg")
    else:
        raise ValueError("use serve or monitor")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as error:
        sys.exit(f"SipDock startup failed: {error}")
