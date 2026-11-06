#!/bin/sh
# Run on a Linux Docker host with OpenSSL and the locally built image.
set -eu
cd "$(dirname "$0")/.."
umask 077
lab=$(mktemp -d)
trap 'rm -rf "$lab"' EXIT
python3 tools/certs.py --dir "$lab/pki" init
python3 tools/certs.py --dir "$lab/pki" server proxy.test
python3 tools/certs.py --dir "$lab/pki" client phone
python3 tools/certs.py --dir "$lab/untrusted" init
python3 tools/certs.py --dir "$lab/untrusted" client rogue
cat tests/lab.yaml >"$lab/config.yaml"
cat >>"$lab/config.yaml" <<'EOF'
tls:
  enable: true
  certificate: /keys/pki/server/fullchain.pem
  private_key: /keys/pki/server/privkey.pem
  client_ca: /keys/pki/server/client-ca.pem
EOF
docker run --rm --network none --cap-add NET_ADMIN --sysctl net.ipv6.bindv6only=1 \
  --sysctl net.ipv6.conf.lo.disable_ipv6=0 -v "$PWD/tests:/tests:ro" -v "$lab:/keys:ro" \
  -v "$lab/config.yaml:/etc/sipdock/config.yaml:ro" --entrypoint python3 sipdock:local /tests/mtls.py

# No published host ports. Reserved documentation ranges are used only on
# this disposable bridge. Exercise the real filters from other namespaces.
net=$(docker network create --internal --ipv6 --subnet 192.0.2.0/28 \
  --subnet 2001:db8:1328:5::/64 "sipdock-test-$$")
cleanup() {
  if [ -s "$lab/cid" ]; then docker rm -f "$(cat "$lab/cid")" >/dev/null; fi
  docker network rm "$net" >/dev/null
  rm -rf "$lab"
}
trap cleanup EXIT
sed -i 's@127.0.0.2/32@192.0.2.6/32@' "$lab/config.yaml"
cat >>"$lab/config.yaml" <<'EOF'
firewall:
  client_ipv4: [192.0.2.3/32]
  client_ipv6: ["2001:db8:1328:5::3/128"]
  health_sources: [192.0.2.4/32, "2001:db8:1328:5::4/128"]
EOF
for mode in tls udp; do
  if [ "$mode" = udp ]; then sed -i 's/^  enable: true/  enable: false/' "$lab/config.yaml"; fi
  docker run -d --cidfile "$lab/cid" --network "$net" --ip 192.0.2.2 --ip6 2001:db8:1328:5::2 \
    --cap-add NET_ADMIN --sysctl net.ipv6.bindv6only=1 -v "$lab:/keys:ro" \
    -v "$lab/config.yaml:/etc/sipdock/config.yaml:ro" sipdock:local >/dev/null
  proxy=$(cat "$lab/cid")
  for i in $(seq 30); do
    if docker exec "$proxy" python3 -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8081/registrations', timeout=2).close()"; then break; fi
    sleep 1
  done
  i=3
  jobs=""
  for role in phone management denied provider; do
    docker run --rm --network "$net" --ip "192.0.2.$i" --ip6 "2001:db8:1328:5::$i" \
      -v "$lab:/keys:ro" -v "$PWD/tests:/tests:ro" --entrypoint python3 sipdock:local /tests/ingress.py "$role" "$mode" &
    jobs="$jobs $!"
    i=$((i+1))
  done
  failed=0
  for job in $jobs; do wait "$job" || failed=1; done
  if [ "$failed" != 0 ]; then docker logs "$proxy"; exit 1; fi
  docker rm -f "$proxy" >/dev/null
  rm "$lab/cid"
done
