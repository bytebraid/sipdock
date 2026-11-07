"""Run Kamailio and control upstream registration, or monitor HTTP health and SMTP alerts."""

import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from contextlib import closing
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from urllib.parse import urlsplit

import yaml

CONFIG = Path("/etc/sipdock/config.yaml")
RUN = Path("/run/sipdock")
SCHEMA = Path("/usr/share/kamailio/db_sqlite")
HEALTH_HOST = "proxy"
# Flags returned by Kamailio's uac.reg_info RPC.
UAC_REG_ONGOING = 1 << 1
UAC_REG_ONLINE = 1 << 2
HOST = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
SIP_ID = r"[a-zA-Z0-9+*_.@-]{1,64}"
LOG = logging.getLogger("sipdock")


class ThreadFormatter(logging.Formatter):
    converter = time.gmtime
    colours = (36, 35, 32, 34, 96, 95, 92, 94)

    def __init__(self):
        super().__init__("%(asctime)s %(levelname)s %(name)s:%(lineno)d [%(threadName)s] %(message)s",
                         datefmt="%Y-%m-%dT%H:%M:%SZ")
        self.thread_colours = {"MainThread": self.colours[0]}

    def format(self, record):
        if record.levelno >= logging.ERROR:
            colour = "1;33"
        else:
            colour = self.thread_colours.setdefault(
                record.threadName, self.colours[len(self.thread_colours) % len(self.colours)])
        return f"\x1b[{colour}m{super().format(record)}\x1b[0m"


def debug_enabled(data):
    settings = data.get("logging", {})
    if not isinstance(settings, dict) or type(settings.get("debug", False)) is not bool:
        raise ValueError("logging.debug must be true or false")
    return settings.get("debug", False)


class ConfigLoader(yaml.SafeLoader):
    def compose_mapping_node(self, anchor):
        node = super().compose_mapping_node(anchor)
        # Check explicit setting names before YAML merges are expanded. An
        # inherited default may still be overridden by an explicit setting.
        lines = {}
        for key, _ in node.value:
            if key.tag == "tag:yaml.org,2002:str":
                line = key.start_mark.line + 1
                if key.value in lines:
                    raise ValueError(f"duplicate config.yaml key {key.value!r} on lines {lines[key.value]} and {line}")
                lines[key.value] = line
        return node


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


def mutex_endpoint(data, advertised):
    mutex = data.get("mutex", {})
    if not isinstance(mutex, dict) or type(mutex.get("enabled", False)) is not bool:
        raise ValueError("mutex.enabled must be true or false")
    uri = mutex.get("healthz", f"{advertised}/healthz")
    if not isinstance(uri, str) or not uri.isascii() or re.search(r"[\x00-\x20\x7f\\#]", uri):
        raise ValueError("mutex.healthz must be an HTTP(S) health URI")
    uri = uri.replace("$advertised_host", advertised)
    url = urlsplit(uri if "://" in uri else "https://" + uri)
    if (url.scheme not in ("http", "https") or not url.hostname or url.username is not None
            or url.port == 0):
        raise ValueError("mutex.healthz must specify an HTTP(S) host without credentials")
    return url if mutex.get("enabled") else None


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
    LOG.info("Inbound firewall active on IPv4 and IPv6. Phone transport is %s.", "mTLS" if tls else "UDP")


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
    debug = debug_enabled(data)
    advertised = string(data, "advertised_host", HOST)
    endpoint = mutex_endpoint(data, advertised)
    instance = os.urandom(12).hex()
    upstream = section(data, "upstream")
    domain = string(upstream, "domain", HOST)
    host = string(upstream, "host", HOST)
    port = integer(upstream, "port", 5060, 1, 65535)
    user = string(upstream, "username", r"[a-zA-Z0-9+*_.-]{1,64}")
    contact = f"sd-{instance}" if endpoint else user
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
        "CONTACT_USER": contact,
        "INSTANCE_HEADER": f"X-SipDock-Instance: {instance}\\r\\n",
        "STANDBY_INIT": f"standby=i:{int(endpoint is not None)}",
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
            (contact, user, domain, user, domain, auth, password, target, expiry),
        )
        db.commit()
    db_path.replace(RUN / "line.sqlite")
    LOG.info("Accepting up to %d contacts. SIP diagnostics %s.", max_clients, "enabled" if debug else "disabled")
    if endpoint is None:
        LOG.info("Preferred master (mutex.enabled=false). Registering independently. Peer polling is disabled.")
    else:
        LOG.info("Standby (mutex.enabled=true). Waiting for master health at %s", endpoint.geturl())
    return endpoint, instance, contact


def probe(host=HEALTH_HOST):
    with closing(http.client.HTTPConnection(host, 8080, timeout=3)) as connection:
        try:
            connection.request("GET", "/healthz")
            status = connection.getresponse().status
            return None if status == 200 else f"HTTP {status}"
        except (OSError, http.client.HTTPException) as exc:
            return type(exc).__name__


def peer_response(response, uri):
    ok = response.status == 200
    debug = LOG.isEnabledFor(logging.DEBUG)
    if not ok and not debug:
        LOG.error("Mutex GET %s status=%d", uri, response.status)
        return "down", None

    peer = response.getheader("X-SipDock-Instance")
    try:
        body = response.read(4096 if debug else 65)
        if debug:
            level = logging.DEBUG if ok else logging.ERROR
            LOG.log(level, "Mutex GET %s status=%d body=%r", uri, response.status, body)
            # Preserve the entire diagnostic if a reverse proxy serves a large
            # error page, without allocating its full size in the SIP process.
            chunk = body
            while len(chunk) == 4096:
                chunk = response.read(4096)
                if chunk:
                    LOG.log(level, "Mutex GET %s status=%d body continued=%r", uri, response.status, chunk)
    except (OSError, http.client.HTTPException) as exc:
        LOG.error("Mutex GET %s status=%d body incomplete (%r) error=%r",
                  uri, response.status, getattr(exc, "partial", b""), exc)
        # A peer that returned 200 is up even if its state is unreadable.
        return ("healthy", peer) if ok else ("down", None)
    if not ok:
        return "down", None
    if len(body) <= 64 and body.strip() in (b"ready", b"registered"):
        return body.strip().decode("ascii"), peer
    return "healthy", peer


def poll_peer(url):
    path = url.path or "/"
    if url.query:
        path += "?" + url.query
    transports = [("http", http.client.HTTPConnection)]
    if url.scheme == "https":
        transports.insert(0, ("https", http.client.HTTPSConnection))
    for scheme, transport in transports:
        uri = url._replace(scheme=scheme, path=url.path or "/").geturl()
        LOG.debug("Mutex GET %s", uri)
        try:
            with closing(transport(url.hostname, url.port, timeout=3)) as connection:
                connection.request("GET", path, headers={"Cache-Control": "no-cache"})
                return peer_response(connection.getresponse(), uri)
        except (OSError, http.client.HTTPException) as exc:
            if scheme == "https":
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.error("Mutex GET %s status=unavailable body=unavailable error=%r. Trying HTTP.", uri, exc)
            else:
                LOG.error("Mutex GET %s status=unavailable body=unavailable error=%r", uri, exc)
    return "down", None


class Election:
    log = LOG.getChild("Election")

    def __init__(self, instance):
        self.instance = instance
        self.active = False
        self.interval = 20
        self.ready_polls = 0
        self.ready_peer = None

    def observe(self, state, peer):
        if state != "ready" or peer != self.ready_peer:
            self.ready_polls = 0
        self.ready_peer = peer
        if self.active:
            if state in ("ready", "registered") and peer != self.instance:
                self.active = False
                self.interval = 30
                self.ready_polls = int(state == "ready")
        elif state == "down":
            self.active = True
        elif state == "ready":
            # The first observation starts the clock. Six complete intervals
            # must pass, all reporting the same ready peer.
            self.ready_polls += 1
            self.active = self.ready_polls >= 7
        if self.active:
            self.ready_polls = 0
            self.interval = 10


class Registration:
    """Drive one Kamailio UAC record over a private Unix datagram socket."""
    log = LOG.getChild("Registration")

    def __init__(self, channel, contact, mutex):
        self.channel = channel
        self.contact = contact
        self.initial_delay = 30 if mutex else 2
        self.delay = self.initial_delay
        self.pending = False
        self.contact_in_use = False
        self.request_id = 0

    def rpc(self, method, *params):
        self.request_id += 1
        request = dict(jsonrpc="2.0", id=self.request_id, method=method, params=params)
        self.channel.send(json.dumps(request).encode())
        reply = json.loads(self.channel.recv(65536))
        if reply.get("id") != self.request_id or "result" not in reply:
            # Registration records contain credentials. Never log the response.
            code = reply.get("error", {}).get("code", "invalid response")
            raise ValueError(f"Kamailio RPC {method} failed ({code})")
        return reply["result"]

    def take_over(self):
        # reg_unregister sets the in-memory expiry to zero. Restore the
        # configured record before starting a new term.
        self.rpc("uac.reg_refresh", self.contact)
        self.rpc("pv.shvSet", "standby", "int", 0)
        self.pending = False
        self.delay = self.initial_delay
        self.log.info("Standby taking over upstream registration.")

    def unregister(self):
        self.log.info("Sending upstream unregister (Expires=0).")
        self.rpc("uac.reg_unregister", "l_uuid", self.contact)
        self.contact_in_use = False

    def yield_to_peer(self):
        self.unregister()
        self.rpc("pv.shvSet", "standby", "int", 1)
        self.log.info("Entered standby after releasing upstream registration.")

    def step(self):
        if not self.pending:
            self.contact_in_use = True
            self.log.debug("Requesting upstream registration or renewal.")
            self.rpc("uac.reg_register", "l_uuid", self.contact)
            self.pending = True
            return 0.25
        info = self.rpc("uac.reg_info", "l_uuid", self.contact)
        if info["flags"] & UAC_REG_ONGOING:
            return 0.25
        self.pending = False
        lifetime = info["diff_expires"]
        if info["flags"] & UAC_REG_ONLINE and lifetime > 0:
            self.delay = self.initial_delay
            return max(0.5, lifetime - min(10, lifetime / 5))
        delay = self.delay
        self.delay = min(30, 2 * delay)
        self.log.error("Upstream registration failed. Retrying in %ds.", delay)
        return delay


def watch_master(endpoint, instance, changes, stop):
    election = Election(instance)
    election.log.debug("Mutex polling loop started for %s (initial interval %ds).", endpoint.geturl(), election.interval)
    try:
        while not stop.is_set():
            started = time.monotonic()
            was_active = election.active
            state, peer = poll_peer(endpoint)
            election.observe(state, peer)
            if election.active != was_active:
                if election.active:
                    reason = "master health check failed" if state == "down" else "peer ready for six intervals"
                    election.log.info("Takeover requested because %s.", reason)
                else:
                    election.log.info("Yielding to peer %r reporting %s.", peer, state)
                changes.put(election.active)
            delay = max(0, started + election.interval - time.monotonic())
            election.log.debug("Peer state=%s instance=%r self=%s role=%s ready_polls=%d. Next mutex poll in %.3fs.",
                               state, peer, peer == instance, "active" if election.active else "standby",
                               election.ready_polls, delay)
            stop.wait(delay)
    except Exception as error:
        changes.put(error)


def control_registration(server, line, endpoint, instance):
    # Peer DNS and HTTPS timeouts must not postpone a SIP renewal or retry.
    changes = Queue()
    stop = Event()
    active = endpoint is None
    if endpoint:
        Thread(name="mutex-poll", target=watch_master, args=(endpoint, instance, changes, stop), daemon=True).start()
    next_register = 0
    try:
        while server.poll() is None:
            delay = max(0, next_register - time.monotonic()) if active else 1
            try:
                change = changes.get(timeout=min(1, delay))
            except Empty:
                if active and time.monotonic() >= next_register:
                    delay = line.step()
                    next_register = time.monotonic() + delay
                continue
            if isinstance(change, Exception):
                raise change
            active = change
            if active:
                line.take_over()
                next_register = 0
            else:
                line.yield_to_peer()
    finally:
        stop.set()


def serve(endpoint, instance, contact):
    def stop(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    reply_path = RUN / "controller.sock"
    reply_path.unlink(missing_ok=True)
    with closing(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)) as channel:
        channel.bind(str(reply_path))
        channel.settimeout(5)
        line = Registration(channel, contact, endpoint is not None)
        server = subprocess.Popen(["kamailio", "-DD", "-E", "-f", "/opt/sipdock/kamailio.cfg"])
        try:
            deadline = time.monotonic() + 30
            while server.poll() is None:
                try:
                    channel.connect(str(RUN / "kamailio.sock"))
                    # The RPC socket can open before the UAC worker loads SQLite.
                    if line.rpc("uac.reg_dump"):
                        break
                except (FileNotFoundError, ConnectionRefusedError):
                    pass
                if time.monotonic() >= deadline:
                    raise ValueError("Kamailio did not load the upstream registration")
                time.sleep(0.1)
            if server.poll() is None:
                control_registration(server, line, endpoint, instance)
            sys.exit(server.returncode)
        except (SystemExit, KeyboardInterrupt):
            if server.poll() is None and line.contact_in_use:
                line.unregister()
                # Give the registrar time to challenge and confirm the release.
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    if not line.rpc("uac.reg_info", "l_uuid", contact)["flags"] & UAC_REG_ONGOING:
                        break
                    time.sleep(0.1)
            raise
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait()
            reply_path.unlink(missing_ok=True)


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
    LOG.info("Monitoring GET /healthz. Email alerts %s.", "enabled" if settings else "disabled")
    failures = 0
    sent = False
    while True:
        detail = probe()
        if detail is None:
            if failures:
                LOG.info("Proxy health recovered.")
            failures, sent = 0, False
        else:
            failures += 1
            if failures == threshold:
                LOG.error("Proxy unhealthy after %d checks (%s).", failures, detail)
            if settings and failures >= threshold and not sent:
                try:
                    notify(settings, detail, smtp_identity)
                    sent = True
                    LOG.info("Unhealthy notification sent.")
                except (OSError, smtplib.SMTPException) as exc:
                    LOG.error("Email delivery failed (%s). Will retry.", type(exc).__name__)
        time.sleep(interval)


def main():
    # Kamailio -E and Python startup errors both go to Docker's stdout stream.
    os.dup2(1, 2)
    os.umask(0o077)
    if sys.argv[1:] in (["healthcheck"], ["monitor-healthcheck"]):
        detail = probe("127.0.0.1" if sys.argv[1] == "healthcheck" else HEALTH_HOST)
        if detail is not None:
            LOG.error("Health check failed (%s).", detail)
            sys.exit(1)
        sys.exit()
    try:
        data = yaml.load(CONFIG.read_text(), Loader=ConfigLoader)
    except yaml.YAMLError:
        raise ValueError("invalid config.yaml syntax") from None
    if not isinstance(data, dict):
        raise ValueError("config.yaml must be a mapping")
    LOG.setLevel(logging.DEBUG if debug_enabled(data) else logging.INFO)
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
        serve(*configure(data, tls))
    else:
        raise ValueError("use serve or monitor")


if __name__ == "__main__":
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ThreadFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    try:
        main()
    except (ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError) as error:
        LOG.error("SipDock failed: %s", error)
        sys.exit(1)
    except Exception:
        LOG.exception("SipDock failed unexpectedly.")
        sys.exit(1)
