#!/bin/bash
#
# Example: Fulcrum-Alpha run script using ssl-manager/run-lib.sh
#
# Usage:
#   ./run-fulcrum.sh --domain electrum.example.com --ssl-email admin@example.com
#   ./run-fulcrum.sh --no-ssl
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── App identity ──────────────────────────────────────────────────────────────
CONTAINER_NAME="${CONTAINER_NAME:-fulcrum-alpha}"
IMAGE_NAME="${FULCRUM_IMAGE:-fulcrum-alpha:latest}"
APP_TITLE="Fulcrum-Alpha SPV Server"

# ── App networking ────────────────────────────────────────────────────────────
APP_NET="${APP_NET:-alpha-net}"
DATA_VOLUME="${DATA_VOLUME:-fulcrum-data}"
HEALTH_PORT=50001
SSL_CHECK_PORT=50002
SSL_HTTPS_PORT="${SSL_HTTPS_PORT:-50002}"
APP_HTTP_PORT="${APP_HTTP_PORT:-0}"

# ── App defaults ──────────────────────────────────────────────────────────────
RPC_HOST="${RPC_HOST:-alpha-node}"
RPC_PORT="${RPC_PORT:-8589}"
RPC_USER="${RPC_USER:-user}"
RPC_PASS="${RPC_PASS:-password}"
PORT_TCP="${PORT_TCP:-50001}"
PORT_SSL="${PORT_SSL:-50002}"
PORT_WS="${PORT_WS:-50003}"
PORT_WSS="${PORT_WSS:-50004}"

# ── Source the library ────────────────────────────────────────────────────────
source "${SCRIPT_DIR}/../run-lib.sh"

# ── App hooks ─────────────────────────────────────────────────────────────────

app_parse_args() {
    case "$1" in
        --rpc-container)  require_arg "$1" "${2:-}"; RPC_HOST="$2";  return 2 ;;
        --rpc-localhost)  RPC_HOST="host.docker.internal"; return 1 ;;
        --rpc-host)       require_arg "$1" "${2:-}"; RPC_HOST="$2";  return 2 ;;
        --rpc-port)       require_arg "$1" "${2:-}"; RPC_PORT="$2";  return 2 ;;
        --rpc-user)       require_arg "$1" "${2:-}"; RPC_USER="$2";  return 2 ;;
        --rpc-pass)       require_arg "$1" "${2:-}"; RPC_PASS="$2";  return 2 ;;
        --port-tcp)       require_arg "$1" "${2:-}"; PORT_TCP="$2";  return 2 ;;
        --port-ssl)       require_arg "$1" "${2:-}"; PORT_SSL="$2";  return 2 ;;
        --port-ws)        require_arg "$1" "${2:-}"; PORT_WS="$2";   return 2 ;;
        --port-wss)       require_arg "$1" "${2:-}"; PORT_WSS="$2";  return 2 ;;
        *)                return 0 ;;
    esac
}

app_env_args() {
    echo "-e RPC_HOST=$RPC_HOST"
    echo "-e RPC_PORT=$RPC_PORT"
    echo "-e RPC_USER=$RPC_USER"
    echo "-e RPC_PASS=$RPC_PASS"
}

app_port_args() {
    echo "-p ${PORT_TCP}:50001"
    echo "-p ${PORT_SSL}:50002"
    echo "-p ${PORT_WS}:50003"
    echo "-p ${PORT_WSS}:50004"
}

app_docker_args() {
    if [ "$USE_HAPROXY" = true ] && [ -n "$HAPROXY_HOST" ] && [ -z "$EXTRA_PORTS" ]; then
        EXTRA_PORTS='[{"listen":50001,"target":50001,"mode":"tcp"},{"listen":50003,"target":50003,"mode":"http"},{"listen":50004,"target":50004,"mode":"tcp"}]'
        echo "-e EXTRA_PORTS=$EXTRA_PORTS"
    fi
}

app_needs_host_gateway() { [ "$RPC_HOST" = "host.docker.internal" ]; }

app_print_config() { echo "  RPC:        $RPC_HOST:$RPC_PORT"; }

app_help() {
    cat <<'APPHELP'
Alpha Node RPC:
  --rpc-container <name>   Alpha container (default: alpha-node)
  --rpc-localhost           Alpha on host machine
  --rpc-host <host>        Custom RPC host
  --rpc-port <port>        RPC port (default: 8589)
  --rpc-user/--rpc-pass    RPC credentials (default: user/password)

Ports (direct mode only):
  --port-tcp/ssl/ws/wss    Electrum ports (default: 50001-50004)
APPHELP
}

app_health_check() {
    local container="$1"
    local ver; ver=$(echo '{"id":1,"method":"server.version","params":["healthcheck","1.4"]}' | \
        docker exec -i "$container" nc -w3 localhost 50001 2>/dev/null | head -1)
    local sv; sv=$(echo "$ver" | jq -r '.result[0]' 2>/dev/null)
    [ -n "$sv" ] && [ "$sv" != "null" ] && echo "pass:Server version: $sv" || echo "fail:server.version not responding"

    local tip; tip=$(echo '{"id":2,"method":"blockchain.headers.subscribe","params":[]}' | \
        docker exec -i "$container" nc -w3 localhost 50001 2>/dev/null | head -1)
    local h; h=$(echo "$tip" | jq -r '.result.height' 2>/dev/null)
    [ -n "$h" ] && [ "$h" != "null" ] && [ "$h" -gt 0 ] 2>/dev/null && echo "pass:Block height: $h (synced)" || echo "warn:Could not query block height"

    if [ -n "$SSL_DOMAIN" ]; then
        local sv2; sv2=$(echo '{"id":3,"method":"server.version","params":["healthcheck","1.4"]}' | \
            docker exec -i "$container" openssl s_client -connect localhost:50002 -quiet 2>/dev/null | head -1)
        local sn; sn=$(echo "$sv2" | jq -r '.result[0]' 2>/dev/null)
        [ -n "$sn" ] && [ "$sn" != "null" ] && echo "pass:SSL Electrum: $sn" || echo "fail:SSL Electrum not responding"
    fi
}

app_summary() {
    echo ""
    echo "Endpoints:"
    if [ "$USE_HAPROXY" = true ] && [ -n "$HAPROXY_HOST" ] && [ -n "$SSL_DOMAIN" ]; then
        echo "  SSL:  $SSL_DOMAIN:443 (via HAProxy)"
        echo "  WS:   $SSL_DOMAIN:50003 (via HAProxy)"
        echo "  WSS:  $SSL_DOMAIN:50004 (via HAProxy)"
    else
        echo "  TCP:  localhost:$PORT_TCP"
        echo "  WS:   localhost:$PORT_WS"
    fi
    echo "  Admin: docker exec \"$CONTAINER_NAME\" FulcrumAdmin -p 8000 getinfo"
}

ssl_manager_run "$@"
