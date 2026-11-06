# 🔐 SipDock certificates

Use [the certificate tool](../tools/certs.py) on a trusted Linux machine with Python 3 and OpenSSL 1.1.1 or newer. It creates a private certificate authority (CA), a server identity for SipDock and a separate identity for each phone. The files are PEM encoded. Only `certs/server/` is mounted in the proxy, read-only.

## 🍌 Issue the certificates

Run these commands from the project directory. Use the **DNS name or IP address the phones connect to**, then choose a unique ID for each phone.

```sh
python3 tools/certs.py --help           # -h and '-?' also work
python3 tools/certs.py init             # once; keep this CA for subsequent phones
python3 tools/certs.py server sip.example.net
python3 tools/certs.py client reception
python3 tools/certs.py client deskphone
```

The CA lasts ten years; server and phone certificates last one year. The tool prints paths, never key contents, and refuses to overwrite existing files. To issue on a separate machine or in a staging directory, add `--dir PATH` to each command.

| Files on the issuing machine | Where they belong |
| --- | --- |
| `certs/server/fullchain.pem`, `privkey.pem` | SipDock’s server certificate and private key. With this CA there are no intermediate certificates. |
| `certs/server/client-ca.pem` | Public CA certificate. SipDock uses it to verify phones; phones can use it to verify the tool-issued server. |
| `certs/clients/deskphone/client.pem`, `client.key` | Certificate and private key for **that phone only**. |
| `certs/clients/deskphone/tsip.pem` | Same phone certificate and key in a single file for tSIP. |
| `certs/ca/ca.pem`, `ca.key` | Issuer certificate and **private signing key**. Keep a protected offline backup. The proxy never needs this directory. |

## 📲 Install and enable

1. If you issued certificates elsewhere, securely copy **only the contents of** `certs/server/` to the Docker host’s `certs/server/`. Keep private files readable only by their owner.
2. Deliver each phone’s files privately. In tSIP, place its combined PEM in the application's `certificates` directory, select it in the TLS settings and enable server verification. Trust the public CA that signed the **server**. Use its certificate hostname and TCP port 5061.
3. In the service YAML, set `tls.enable: true` and keep the example paths: `/etc/sipdock/certs/fullchain.pem`, `/etc/sipdock/certs/privkey.pem` and `/etc/sipdock/certs/client-ca.pem`. Keep the phone's CIDR allowed. Run `docker compose up -d --force-recreate proxy`; the phone must still authenticate with the line’s SIP credentials.

**Already using TLS with an older SipDock Compose file?** Before recreating the proxy, move or copy the existing server chain, server key and public client CA from `certs/` into `certs/server/`, keeping their filenames. In-container paths stay the same. Do not generate a new CA for existing phones.

## ♻️ Public certificates and renewal

For a **Let’s Encrypt** server certificate, skip the tool’s `server` command. Copy the contents of Certbot’s `fullchain.pem` and `privkey.pem` (follow its symlinks) into `certs/server/`. Use `init` and `client` for your private phone CA. Phones should trust the public server chain; SipDock should trust only your phone CA. Have your Certbot renewal hook refresh both server files and run `docker compose restart proxy`.

To renew a tool-issued identity, keep the CA, back up and move aside the old identity files, then re-run the same `server` or `client` command. Restart the proxy for a new server identity or reinstall the new phone identity on its device. Reissuing a phone certificate does **not** invalidate the old one before expiry.
