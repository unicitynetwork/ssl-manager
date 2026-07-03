#!/usr/bin/env bash
# Convenience runner for the tunnel-client image. Builds (if needed) and launches a
# container that tunnels a local service to the shared haproxy.
#
# Usage:
#   ./run-tunnel.sh --domain myservice.example.com --target localhost:8080 \
#     --host 213.199.61.236 --key ~/.ssh/tunnel_ed25519 \
#     --fingerprint SHA256:xxxx [--mode https|http] [--ssh-port 2022] [--api-key KEY] \
#     [--name tunnel-myservice] [--net host] [--dry-run]
#
# --target is HOST:PORT reachable FROM this container (use --net to share a network with
# the service, or --net host + localhost). --mode https (default) = your service serves
# TLS, haproxy SNI-passthrough on :443; --mode http = plain HTTP fronted on :80.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${TUNNEL_CLIENT_IMAGE:-tunnel-client:latest}"
MODE=https SSH_PORT=2022 NET="" NAME="" FP="" API_KEY="" DRY=false
DOMAIN="" TARGET="" HOST="" KEY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --fingerprint) FP="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --net) NET="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --dry-run) DRY=true; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$DOMAIN" ] || { echo "--domain required" >&2; exit 2; }
[ -n "$TARGET" ] || { echo "--target HOST:PORT required" >&2; exit 2; }
[ -n "$HOST" ]   || { echo "--host (public haproxy host) required" >&2; exit 2; }
[ -n "$KEY" ]    || { echo "--key (tunnel SSH private key) required" >&2; exit 2; }
[ -f "$KEY" ]    || { echo "key not found: $KEY" >&2; exit 2; }
TARGET_HOST="${TARGET%%:*}"; TARGET_PORT="${TARGET##*:}"
[ "$TARGET_HOST" != "$TARGET_PORT" ] || { echo "--target must be HOST:PORT" >&2; exit 2; }
KEY="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"
[ -n "$NAME" ] || NAME="tunnel-$(printf '%s' "$DOMAIN" | tr -c 'a-z0-9' '-' | sed 's/-\+/-/g;s/^-//;s/-$//')"

# Build image if absent
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE ..."
  docker build -q -t "$IMAGE" "$SCRIPT_DIR" >/dev/null
fi

CMD=(docker run -d --name "$NAME" --restart unless-stopped)
[ -n "$NET" ] && CMD+=(--network "$NET")
CMD+=(-v "${KEY}:/tunnel/id:ro"
  -e "PUBLIC_HOST=${HOST}" -e "TUNNEL_SSH_PORT=${SSH_PORT}"
  -e "DOMAIN=${DOMAIN}" -e "TARGET_HOST=${TARGET_HOST}" -e "TARGET_PORT=${TARGET_PORT}"
  -e "MODE=${MODE}")
[ -n "$FP" ]      && CMD+=(-e "TUNNEL_HOST_KEY_FINGERPRINT=${FP}")
[ -n "$API_KEY" ] && CMD+=(-e "TUNNEL_API_KEY=${API_KEY}")
CMD+=("$IMAGE")

if [ "$DRY" = true ]; then
  printf '%s ' "${CMD[@]}" | sed 's/TUNNEL_API_KEY=[^ ]*/TUNNEL_API_KEY=***/'; echo
  exit 0
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
"${CMD[@]}"
echo "started ${NAME} — logs: docker logs -f ${NAME}"
