#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: bash debug.sh [--container NAME|ID] [--user USER] [--command CMD]

Copy static Bash and BusyBox into the running SipDock proxy, then open /bin/bash.
  --container NAME|ID   Target container (default: current Compose proxy)
  --user USER           Shell user (default: kamailio; use 0 for firewall inspection)
  --command CMD         Run one Bash command instead of opening a terminal
  -h, -?, --help        Show this help

The first run needs access to Docker Hub and Debian package mirrors.
Recreate the proxy to discard the tools: docker compose up -d --force-recreate proxy
HELP
}
die() { printf 'debug.sh: %s\n' "$*" >&2; exit 1; }
container='' user=kamailio command='' oneshot=false
while (( $# )); do
  case "$1" in
    -h|'-?'|--help) usage; exit 0 ;;
    --container|--user|--command)
      [[ $# -ge 2 && -n $2 ]] || die "missing value for $1"
      case "$1" in
        --container) container=$2 ;; --user) user=$2 ;; --command) command=$2; oneshot=true ;;
      esac
      shift 2 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

if [[ -z $container ]]; then container=$(docker compose ps -q proxy); fi
[[ -n $container && $container != *$'\n'* && $container != -* ]] || die 'select one running proxy with --container'
target=$(docker container inspect -f '{{.Id}} {{.State.Running}} {{index .Config.Labels "org.opencontainers.image.title"}} {{.Image}}' "$container")
read -r cid running title image <<< "$target"
[[ $running == true && $title == SipDock ]] || die 'target must be a running SipDock container'

kit=/opt/sipdock-debug/bin
if ! docker exec --user kamailio "$cid" /bin/bash -c '[[ -x /opt/sipdock-debug/bin/busybox ]]' >/dev/null 2>&1; then
  platform=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$image")
  if [[ $platform == linux/arm ]]; then
    variant=$(docker image inspect -f '{{.Variant}}' "$image")
    [[ $variant =~ ^v[0-9]+$ ]] || die 'cannot determine the target ARM variant'
    platform+=/$variant
  fi
  archive=$(mktemp)
  trap 'rm -f -- "$archive"' EXIT
  echo "Preparing debug tools for $platform..." >&2
  docker run --rm --log-driver none --platform "$platform" debian:trixie-slim sh -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >&2
    apt-get install -y --no-install-recommends bash-static busybox-static >&2
    kit=/kit/opt/sipdock-debug/bin
    mkdir -p /kit/bin "$kit"
    cp "$(command -v bash-static)" /kit/bin/bash
    cp "$(command -v busybox)" "$kit/busybox"
    "$kit/busybox" --list | while read -r name; do
      [ "$name" = busybox ] || ln -s busybox "$kit/$name"
    done
    tar -C /kit -cf - bin opt/sipdock-debug
  ' > "$archive"
  docker cp - "$cid:/" < "$archive"
  rm -f -- "$archive"
  trap - EXIT
fi

args=(-i)
if ! $oneshot && [[ -t 0 && -t 1 ]]; then args+=(-t); fi
shell_args=(--noprofile --norc)
if $oneshot; then shell_args+=(-c "$command"); fi
exec docker exec "${args[@]}" --user "$user" -e "PATH=/usr/sbin:/usr/bin:$kit:/bin" \
  -e HISTFILE=/dev/null "$cid" /bin/bash "${shell_args[@]}"
