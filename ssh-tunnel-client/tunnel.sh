#!/bin/sh
# tunnel-client — expose a service running on a firewalled host through the shared
# haproxy, with no public IP on the service's host. Pairs with the staging-tunnel sshd
# endpoint (see ../ssh-tunnel-endpoint). Generic: tunnel ANY http/https service.
#
# It opens:
#   ssh -R 0.0.0.0:<rport>:<TARGET_HOST>:<TARGET_PORT>   (public :80/:443 -> here -> service)
#       -L 127.0.0.1:8404:<haproxy-api>                  (to call the Registration API)
# then registers <DOMAIN> -> <endpoint>:<rport> with haproxy, and DELETEs it on shutdown.
# Supervises + reconnects. No app logic reaches the server (the endpoint is a plain sshd).
#
# MODE=https (default): haproxy SNI/TCP-passthrough on :443 → your service terminates TLS
#                       (serves a valid cert for DOMAIN). Registers https_port.
# MODE=http           : haproxy mode-http on :80 → your service serves plain HTTP.
#                       Registers http_port. (:443 is NOT served in this mode — haproxy
#                       terminates no TLS, so a cert-less service can only be fronted on :80.)
set -eu

log()  { echo "[tunnel-client] $*"; }
warn() { echo "[tunnel-client] WARN: $*" >&2; }
die()  { echo "[tunnel-client] ERROR: $*" >&2; exit 1; }

# ── config (env) ─────────────────────────────────────────────────────────────
PUBLIC_HOST="${PUBLIC_HOST:?PUBLIC_HOST (public haproxy host, e.g. 213.199.61.236) is required}"
DOMAIN="${DOMAIN:?DOMAIN (public hostname to expose, e.g. myservice.example.com) is required}"
TARGET_HOST="${TARGET_HOST:?TARGET_HOST (the local service host/name) is required}"
TARGET_PORT="${TARGET_PORT:?TARGET_PORT (the local service port) is required}"
MODE="${MODE:-https}"                              # https (SNI passthrough :443) | http (:80)
SSH_PORT="${TUNNEL_SSH_PORT:-2022}"
SSH_USER="${TUNNEL_SSH_USER:-tunnel}"
KEY_SRC="${TUNNEL_SSH_KEY:-/tunnel/id}"
HOST_FP="${TUNNEL_HOST_KEY_FINGERPRINT:-}"         # optional SHA256:... pin (recommended)
ENDPOINT_ALIAS="${TUNNEL_ENDPOINT_ALIAS:-staging-tunnel}"  # haproxy-net name of the sshd endpoint
API_HOST="${HAPROXY_API_HOST:-haproxy}"            # resolved SERVER-side (must match endpoint PermitOpen)
API_PORT="${HAPROXY_API_PORT:-8404}"
PORT_BASE="${TUNNEL_PORT_BASE:-21000}"
PORT_SPAN="${TUNNEL_PORT_SPAN:-100}"
LOCAL_API_PORT="${TUNNEL_LOCAL_API_PORT:-8404}"    # -L bind inside this container
API_KEY="${TUNNEL_API_KEY:-}"                      # Bearer token if the endpoint API requires it
HEALTHCHECK="${HEALTHCHECK:-true}"                 # gate "tunnel LIVE" on the service answering
HEALTHCHECK_PATH="${HEALTHCHECK_PATH:-/}"

case "$MODE" in
  https|http) ;;
  *) die "MODE must be 'https' or 'http' (got '$MODE')" ;;
esac

# The key is mounted read-only, so `chmod` on it is a no-op and ssh refuses a
# group/world-readable key. Copy it into a private writable location and lock perms.
[ -f "$KEY_SRC" ] || die "SSH key not found at $KEY_SRC (mount TUNNEL_SSH_KEY read-only)"
SSH_KEY="/tmp/tunnel_id"
cp "$KEY_SRC" "$SSH_KEY"
chmod 600 "$SSH_KEY"

# ── known_hosts: pin the endpoint's host key if a fingerprint was supplied ─────
KNOWN_HOSTS="/tmp/known_hosts"
: > "$KNOWN_HOSTS"
if [ -n "$HOST_FP" ]; then
  if ! ssh-keyscan -p "$SSH_PORT" -T 10 "$PUBLIC_HOST" > "$KNOWN_HOSTS" 2>/dev/null || [ ! -s "$KNOWN_HOSTS" ]; then
    die "ssh-keyscan of $PUBLIC_HOST:$SSH_PORT failed (endpoint unreachable?)"
  fi
  if ssh-keygen -lf "$KNOWN_HOSTS" 2>/dev/null | grep -qF "$HOST_FP"; then
    log "endpoint host key verified against pin $HOST_FP"
    STRICT="yes"
  else
    die "endpoint host key fingerprint mismatch — expected $HOST_FP (possible MITM)"
  fi
else
  warn "TUNNEL_HOST_KEY_FINGERPRINT not set — trusting endpoint on first use (accept-new)"
  STRICT="accept-new"
fi

SSH_OPTS="-i $SSH_KEY -p $SSH_PORT \
  -o UserKnownHostsFile=$KNOWN_HOSTS \
  -o StrictHostKeyChecking=$STRICT \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes -o ConnectTimeout=20 \
  -o IdentitiesOnly=yes -o BatchMode=yes"

# ── deterministic starting port from the domain (idempotent per service) ──────
HASH="$(printf '%s' "$DOMAIN" | cksum | cut -d' ' -f1)"
START_OFF="$(( HASH % PORT_SPAN ))"

api() {  # api METHOD PATH [DATA] — via the -L forwarded Registration API. Prints HTTP status.
  _m="$1"; _p="$2"; _d="${3:-}"
  set -- -sS -o /dev/null -w '%{http_code}' -m 10 -X "$_m"
  [ -n "$API_KEY" ] && set -- "$@" -H "Authorization: Bearer ${API_KEY}"
  [ -n "$_d" ] && set -- "$@" -H 'Content-Type: application/json' -d "$_d"
  curl "$@" "http://127.0.0.1:${LOCAL_API_PORT}${_p}"
}

register() {  # register RPORT -> 0 on success
  _rp="$1"
  if [ "$MODE" = http ]; then
    _body="{\"domain\":\"${DOMAIN}\",\"container\":\"${ENDPOINT_ALIAS}\",\"http_port\":${_rp},\"https_port\":null}"
  else
    _body="{\"domain\":\"${DOMAIN}\",\"container\":\"${ENDPOINT_ALIAS}\",\"http_port\":null,\"https_port\":${_rp}}"
  fi
  _code="$(api POST /v1/backends "$_body" || true)"
  # A 409 means the domain is already registered (e.g. a stale entry from a hard-killed
  # prior instance). If WE own it (same endpoint), the ownership-scoped DELETE succeeds and
  # the retry registers; if a different container owns it, the DELETE 403s and we fail (as
  # we should — don't hijack another backend's domain).
  if [ "$_code" = 409 ]; then
    warn "register 409 for ${DOMAIN} (already registered) — deleting our stale entry and retrying"
    deregister
    _code="$(api POST /v1/backends "$_body" || true)"
  fi
  case "$_code" in
    200|201) log "registered ${DOMAIN} -> ${ENDPOINT_ALIAS}:${_rp} (${MODE}, haproxy $_code)"; return 0 ;;
    *) warn "register returned $_code for ${DOMAIN}"; return 1 ;;
  esac
}

# Deregister robustly: reuse the live -L when the supervised ssh is up (retrying transient
# errors, no second tunnel to self-collide on the port); open a one-shot -L only when ssh
# is down — so a registered DOMAIN never leaks a stale backend.
deregister() {
  if [ -n "${SSH_PID:-}" ] && kill -0 "$SSH_PID" 2>/dev/null; then
    _t=0
    while [ "$_t" -lt 3 ]; do
      _c="$(api DELETE "/v1/backends/${DOMAIN}" || true)"
      case "$_c" in 200|204|404) log "deregistered ${DOMAIN} (haproxy $_c)"; return 0 ;; esac
      _t=$(( _t + 1 )); sleep 1
    done
    warn "deregister via live tunnel failed for ${DOMAIN} (last $_c)"
    return 0
  fi
  # shellcheck disable=SC2086
  ssh $SSH_OPTS -L "127.0.0.1:${LOCAL_API_PORT}:${API_HOST}:${API_PORT}" -N "${SSH_USER}@${PUBLIC_HOST}" &
  _dp=$!
  sleep 3
  if kill -0 "$_dp" 2>/dev/null; then
    _c="$(api DELETE "/v1/backends/${DOMAIN}" || true)"
    log "deregistered ${DOMAIN} via one-shot tunnel (haproxy $_c)"
    kill "$_dp" 2>/dev/null || true
  else
    warn "could not reach endpoint to deregister ${DOMAIN} (stale registration may linger)"
  fi
}

# 0 if the local service is actually answering, so we don't advertise a dead backend
# (which would 502 through the tunnel). Skippable via HEALTHCHECK=false for non-HTTP TCP.
service_reachable() {
  [ "$HEALTHCHECK" = true ] || return 0
  if [ "$MODE" = http ]; then
    curl -s  -o /dev/null --max-time 4 "http://${TARGET_HOST}:${TARGET_PORT}${HEALTHCHECK_PATH}"
  else
    curl -sk -o /dev/null --max-time 4 "https://${TARGET_HOST}:${TARGET_PORT}${HEALTHCHECK_PATH}"
  fi
}

# Try one connection: cycle candidate ports on a BIND clash, but bail out (rc 2) on an
# auth/connectivity failure instead of churning through all ports. rc 0 = established
# (RPORT + SSH_PID set); 1 = no free port; 2 = ssh connect error.
ERRLOG="/tmp/ssh_err"
attempt_connect() {
  _i=0
  while [ "$_i" -lt "$PORT_SPAN" ]; do
    _off=$(( (START_OFF + _i) % PORT_SPAN ))
    _cand=$(( PORT_BASE + _off ))
    log "attempting reverse tunnel on remote port ${_cand}"
    : > "$ERRLOG"
    # shellcheck disable=SC2086
    ssh $SSH_OPTS \
      -R "0.0.0.0:${_cand}:${TARGET_HOST}:${TARGET_PORT}" \
      -L "127.0.0.1:${LOCAL_API_PORT}:${API_HOST}:${API_PORT}" \
      -N "${SSH_USER}@${PUBLIC_HOST}" 2>"$ERRLOG" &
    SSH_PID=$!
    sleep 5
    if kill -0 "$SSH_PID" 2>/dev/null; then
      RPORT="$_cand"
      return 0
    fi
    wait "$SSH_PID" 2>/dev/null || true
    if grep -qiE 'forwarding (request )?failed|remote port forwarding failed|cannot listen to port|bind: Address already in use' "$ERRLOG"; then
      warn "remote port ${_cand} unavailable (bind clash) — trying next"
      _i=$(( _i + 1 ))
      continue
    fi
    warn "ssh connect failed (not a port clash): $(tr '\n' ' ' < "$ERRLOG" | sed 's/  */ /g' | cut -c1-200)"
    return 2
  done
  return 1
}

RPORT=""
SSH_PID=""
EVER_REGISTERED=0   # latch: once we ever register, cleanup must always deregister
cleanup() {
  trap - TERM INT EXIT
  log "shutting down — deregistering + closing tunnel"
  [ "$EVER_REGISTERED" = 1 ] && deregister || true
  [ -n "${SSH_PID:-}" ] && kill "$SSH_PID" 2>/dev/null || true
  exit 0
}
trap cleanup TERM INT EXIT

log "domain=${DOMAIN} mode=${MODE} target=${TARGET_HOST}:${TARGET_PORT} endpoint=${SSH_USER}@${PUBLIC_HOST}:${SSH_PORT}"
log "port search: ${PORT_BASE}+[${START_OFF}..${START_OFF}+${PORT_SPAN}) mod ${PORT_SPAN}"

# ── supervise loop: (re)connect, pick a free remote port, register, wait ──────
while true; do
  RPORT=""
  SSH_PID=""
  if attempt_connect; then
    :
  else
    rc=$?
    [ "$rc" = 2 ] && warn "connection error — backing off 15s" \
                  || warn "no free remote port in [${PORT_BASE}..$((PORT_BASE+PORT_SPAN-1))] — retrying in 15s"
    sleep 15
    continue
  fi

  # Don't advertise a backend that isn't actually answering (would 502 through the tunnel).
  if ! service_reachable; then
    warn "target ${TARGET_HOST}:${TARGET_PORT} (${MODE}) not answering — not registering; retrying in 10s"
    # If a prior round registered this domain, drop that entry now (its tunnel is gone) so
    # haproxy doesn't keep fronting a dead port while the service is down.
    [ "$EVER_REGISTERED" = 1 ] && deregister || true
    kill "$SSH_PID" 2>/dev/null || true
    wait "$SSH_PID" 2>/dev/null || true
    sleep 10
    continue
  fi

  # register (retry a few times). `registered_now` is re-evaluated every iteration so a
  # failed re-registration on reconnect is caught; EVER_REGISTERED only drives cleanup.
  registered_now=0
  n=0
  while [ "$n" -lt 5 ]; do
    if register "$RPORT"; then registered_now=1; EVER_REGISTERED=1; break; fi
    n=$(( n + 1 ))
    sleep 3
  done

  if [ "$registered_now" != 1 ]; then
    warn "registration failed after retries — NOT live; tearing down and retrying"
    # Drop any stale entry from a prior successful round so haproxy stops fronting it.
    [ "$EVER_REGISTERED" = 1 ] && deregister || true
    kill "$SSH_PID" 2>/dev/null || true
    wait "$SSH_PID" 2>/dev/null || true
    sleep 10
    continue
  fi

  _scheme="https"; [ "$MODE" = http ] && _scheme="http"
  log "tunnel LIVE — ${_scheme}://${DOMAIN}  (remote port ${RPORT})"
  wait "$SSH_PID" 2>/dev/null || true
  warn "ssh tunnel dropped — reconnecting"
  sleep 3
done
