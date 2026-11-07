<h1 align="center">📳 Installing SipDock 📳</h1>

<h5 align="center">Configure, Run, Debug, Repeat</h5>
# 🖥️ Docker Install and Configuration

> ### 🔥 **FIREWALL REMINDER** - You must add your allowed CIDRs in [`config.yml`](config.example.yaml)

⚠️ **iptables** running in the container will **DROP** all inbound connections not whitelisted in [`config.yaml`](config.example.yaml)

## 📋 Quest Items You Must Collect

- A Linux host reachable by the provider and phones. Default ports are **UDP 5060** for the provider and UDP phones; **TCP 5061** for phones using mutual TLS. **TCP 5062** for health probes and host-loopback. Local **TCP 8081** for the registration page.
- Docker Compose v2, a working IPv4/IPv6 bridge, and kernel support for IPv4 and IPv6 netfilter. Use the supplied bridge and container capabilities. **Do not use host networking:** SipDock installs firewall rules in its network namespace.
- One SIP account with any VoIP provider supporting **IPv4 UDP registration**. From your chosen VoIP provider, obtain registration server, domain, SIP credentials (user/auth user/password) and inbound signalling IPs. Credentials are required, trunks authenticated by IP alone cannot satisfy SipDock’s registration health check.
- ***[/tools/]("/tools") require Python 3 and OpenSSL 1.1.1+*** to issue certificates; ***Bash and Docker CLI*** access for the debug shell. Email alerts need a ***reachable SMTP relay.***


## 🐳 Installing Docker Engine on Linux

[Ubuntu](https://docs.docker.com/engine/install/ubuntu/) · [Debian](https://docs.docker.com/engine/install/debian/) · [Red Hat Enterprise Linux](https://docs.docker.com/engine/install/rhel/) · [Fedora](https://docs.docker.com/engine/install/fedora/) · [CentOS Stream](https://docs.docker.com/engine/install/centos/) · [Installation guides on GitHub](https://github.com/docker/docs/tree/main/content/manuals/engine/install)

## 🪟 Installing Docker Engine on Windows (unsupported)

<p align="center"><img src="docs/ymmv.gif" width="350px" /></p>

### **YMMV — Windows is unsupported** 

  - 🐧 Use a Linux VM (Recommended) 
  - 👩‍💻 WSL 2 


[Install WSL 2](https://learn.microsoft.com/en-us/windows/wsl/install) · [Install Docker Desktop on Windows](https://docs.docker.com/desktop/setup/install/windows-install/) · [Configure Docker’s WSL 2 backend](https://docs.docker.com/desktop/features/wsl/)


## 🛡️ Configure the firewall and VoIP line

On a **new** installation, copy the example and add the following line to the project's `.env`:

```sh
(umask 077; cp -n config.example.yaml config.yml)
```

```dotenv
SIPDOCK_CONFIG=./config.yml
```

If you already have an edited `config.yaml`, keep it and omit the override. Both services read the same file. Edit these entries:

| YAML setting | What to enter |
| --- | --- |
| `firewall.client_ipv4`, `client_ipv6` | Source addresses **as seen by SipDock**: e.g. the office NAT address as a `/32`, or one phone’s IPv6 address as a `/128`. Empty lists leave remote phones blocked. |
| `upstream.trusted_sources` | Your provider’s **inbound SIP IPv4** addresses, including failover. Replace the example address. These sources are trusted to originate calls; never add phone ISP ranges or an entire cloud network here. |
| `firewall.health_sources`, `admin_sources` | Keep the supplied monitor and host gateway entries. Add your load balancer’s probe CIDRs to **health** only. |
| `advertised_host`, `upstream` | Set SipDock’s reachable host, the provider’s domain, registrar host/port, line username, authentication ID and password. Quote numeric identifiers and passwords. |
| `max_clients`, `alerts` | Choose 1–30 phone registrations (default 16). To receive outage email, enable alerts and set the recipient, sender, SMTP host, security mode and credentials. |

Check that the Compose bridge subnets do not overlap your LAN or VPN. If they do, update the bridge, static addresses and corresponding firewall grants together. A load balancer in front of SIP must preserve the client source IP; use TCP passthrough for mutual TLS.

## 📍🇬🇧 UK provider signalling addresses

Checked **6 November 2026**. Use the row for your **exact product** and confirm it against your order before granting access. The table separates documented signalling addresses from destinations that still need inbound confirmation. RTP media uses a different path and does not belong in `upstream.trusted_sources`.

| Provider / product | Published SIP IPv4 CIDRs | What to use |
| --- | --- | --- |
| Gamma SIP Trunks | `88.215.48.0/20`, `151.2.128.0/19` (published UDP signalling ranges, overlapping entries combined) | Prefer the assigned signalling gateway(s) from your order as `/32`. Gamma’s documented public trunk uses static-IP authentication; check registration support on your reseller product. [Service definition §6.1](https://assets.applytosupply.digitalmarketplace.service.gov.uk/g-cloud-14/documents/700154/722211090400184-service-definition-document-2024-05-03-1553.pdf) |
| BT Business Cloud Voice SIP | `217.32.186.185/32`, `217.32.186.121/32` | BT identifies these as primary/secondary signalling hosts and describes outbound registration. Confirm inbound sources for your service before trusting them. Do not include the adjacent media addresses. [BT firewall guide](https://business.bt.com/content/dam/bt-business/pdfs/help-and-support/phone-systems/configure-lan-and-firewall-for-cloud-voice/bt-cloud-voice-sip-trunking-lan-firewall-guide.pdf) |
| Voipfone | `46.31.225.0/24` <br/> (No complete inbound CIDR list verified) | `sip.voipfone.net` is the registrar. Ask [Voipfone support](https://www.voipfone.co.uk/contact) for current inbound and failover IPs; a registrar DNS answer does not establish the full list. [Configuration guide](https://www.voipfone.co.uk/support/hardware/telephones/hardware) |
| Andrews & Arnold (A&A) VoIP | `81.187.30.110/31`, `81.187.30.112/29`, `90.155.3.0/24`, `90.155.103.0/24` | A&A lists all four for incoming UDP 5060. Its guide also lists IPv6; SipDock currently uses IPv4 on the provider leg. [A&A firewall table](https://support.aa.net.uk/VoIP_Firewall) |
| Yay.com | `34.105.209.181/32`, `34.147.142.100/32`, `34.89.77.216/32`, `35.246.58.184/32`, `34.147.181.186/32`, `35.234.151.7/32`, `35.197.230.12/32`, `34.105.130.238/32`, `34.89.66.152/32`, `34.13.58.148/32` | Listed **SIP source** IPs. The guide lists TCP/TLS signalling; confirm UDP registration on your product. For a trunk, use **Show IP Ranges** in its settings. [Firewall guide](https://www.yay.com/faq/voip-network/firewall/) · [Trunk settings](https://www.yay.com/faq/sip/creating-a-sip-trunk/) |

## 🔐 Choose the phone transport

With mutual TLS, the phone verifies the proxy, the proxy requires a trusted phone certificate, and signalling between them is encrypted. Phones still need the SIP password. Follow [certificate generation and installation](certs/README.md) before setting `tls.enable: true`. For an existing TLS deployment, move the server files into **`certs/server/` before upgrading**.

TLS mode requires a client certificate from **every** phone. tSIP supports this; the Gigaset N300 IP has no documented client-key support. If the N300 must register directly, use UDP on a trusted LAN or through a VPN. The provider leg stays on UDP; this setting does not encrypt the audio.

## 🚀 Start and check

```sh
docker compose build proxy
# Standard Linux Docker: let the monitor group read the config without making it public.
cfg=./config.yml                      # set this to the host config file you chose above
gid=$(docker run --rm --entrypoint python3 sipdock:local -c 'import pwd; print(pwd.getpwnam("kamailio").pw_gid)')
sudo chgrp "$gid" "$cfg" && sudo chmod 640 "$cfg"
docker compose up -d --no-build
docker compose ps
docker compose logs --tail=50 proxy monitor
```

From an allowed probe, request `http://HOST:5062/healthz`. HTTP 200 with body `registered` means the provider accepted the upstream registration. HTTP 200 with `ready` means the standby is intentionally idle. HTTP 503 means SipDock is trying to register. For two hosts, configure one preferred master and one standby using the [DNS failover settings](README.md#dns-failover-with-a-preferred-master).

On the Docker host, open [the registrations page](http://127.0.0.1:8081/registrations). Register two phones using the [phone settings](README.md#-register-phones-and-set-capacity), call the line, answer one and check that the other stops ringing. Check two-way audio separately; RTP travels directly between the phone and provider.

The [Compose file](compose.yaml) keeps **four 10 MiB Docker logs per service**, including the active file: **80 MiB total** (about 84 MB) for one proxy and one monitor. Stdout and `docker compose logs` still work. After upgrading an existing stack, run `docker compose up -d --force-recreate` to apply rotation; a restart alone retains the old [Docker logging settings](https://docs.docker.com/engine/logging/drivers/json-file/).

## 🧰 Break glass: debug shell

Start with `docker compose logs -f proxy`; set `logging.debug: true` and recreate the proxy for registration diagnostics. If you need a terminal, run `bash debug.sh`. It copies tools only into the selected container and opens an unprivileged shell. For example, `bash debug.sh --command 'id; ip addr; netstat -an'`. Recreating the proxy removes the tools and clears in-memory registrations; phones will need to re-register.

```text
Usage: bash debug.sh [--container NAME|ID] [--user USER] [--command CMD]

Copy static Bash and BusyBox into the running SipDock proxy, then open /bin/bash.
  --container NAME|ID   Target container (default: current Compose proxy)
  --user USER           Shell user (default: kamailio; use 0 for firewall inspection)
  --command CMD         Run one Bash command instead of opening a terminal
  -h, -?, --help        Show this help

The first run needs access to Docker Hub and Debian package mirrors.
Recreate the proxy to discard the tools: docker compose up -d --force-recreate proxy
```
