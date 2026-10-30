#!/bin/bash
# =============================================================================
# PROXY protocol v2 end-to-end test: haproxy (registration API) + ssl-manager.
#
# Topology (all throwaway, prefix $PREFIX, explicit subnets):
#   ${PREFIX}-hanet  10.251.71.0/24  haproxy-net analogue (haproxy + backends)
#   ${PREFIX}-ext    10.251.72.0/24  "internet": clients reach haproxy only
#   ${PREFIX}-app    10.251.73.0/24  a backend's private app network (untrusted)
#
#   ${PREFIX}-haproxy   $HAPROXY_IMAGE (hanet + ext); alias new/new2/old.pp2.test
#   ${PREFIX}-new       backend FROM $SSL_MANAGER_IMAGE, defaults (PROXY v2 on)
#   ${PREFIX}-new2      same, strict trust (haproxy) + shim re-emits PROXY v2 to app
#   ${PREFIX}-old       backend FROM $SSL_MANAGER_OLD_IMAGE (pre-PROXY client)
#   ${PREFIX}-client[2] curl clients on ext with fixed IPs .50/.51
#   ${PREFIX}-evil      on app net (untrusted) / ${PREFIX}-evilha on hanet
#
# Usage: HAPROXY_IMAGE=haproxy-pp2test SSL_MANAGER_IMAGE=ssl-manager-pp2test \
#        SSL_MANAGER_OLD_IMAGE=ssl-manager-pp2test-old ./run-e2e.sh
# Exit 0 only if every check passed. Always cleans up its own resources.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-pp2test}"
HAPROXY_IMAGE="${HAPROXY_IMAGE:-haproxy-pp2test}"
SSL_MANAGER_IMAGE="${SSL_MANAGER_IMAGE:-ssl-manager-pp2test}"
SSL_MANAGER_OLD_IMAGE="${SSL_MANAGER_OLD_IMAGE:-}"
EXPECT_PP="${EXPECT_PP:-true}"   # false = baseline run against a pre-PROXY haproxy
KEEP="${KEEP:-0}"

HANET="${PREFIX}-hanet"; EXT="${PREFIX}-ext"; APPNET="${PREFIX}-app"
HAP="${PREFIX}-haproxy"; NEW="${PREFIX}-new"; NEW2="${PREFIX}-new2"; NEW3="${PREFIX}-new3"; OLD="${PREFIX}-old"
CLIENT="${PREFIX}-client"; CLIENT2="${PREFIX}-client2"; EVIL="${PREFIX}-evil"; EVILHA="${PREFIX}-evilha"
TOOL_IMG="${PREFIX}-backend-new"   # has curl/openssl/python3/nc
CLIENT_IP=10.251.72.50; CLIENT2_IP=10.251.72.51; HAP_EXT_IP=10.251.72.10; HAP_HA_IP=10.251.71.10

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
check(){ local name="$1" got="$2" want="$3"; if [ "$got" = "$want" ]; then ok "$name"; else bad "$name" "want=[$want] got=[$got]"; fi; }

cleanup() {
    [ "$KEEP" = "1" ] && { echo "KEEP=1: leaving resources"; return; }
    for c in "$HAP" "$NEW" "$NEW2" "$NEW3" "$OLD" "$CLIENT" "$CLIENT2" "$EVIL" "$EVILHA"; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    for n in "$HANET" "$EXT" "$APPNET"; do docker network rm "$n" >/dev/null 2>&1 || true; done
    docker rmi "${PREFIX}-backend-new" "${PREFIX}-backend-old" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "== build test backends"
docker build -q --build-arg BASE="$SSL_MANAGER_IMAGE" -t "${PREFIX}-backend-new" "$HERE" >/dev/null || exit 1
if [ -n "$SSL_MANAGER_OLD_IMAGE" ]; then
    docker build -q --build-arg BASE="$SSL_MANAGER_OLD_IMAGE" -t "${PREFIX}-backend-old" "$HERE" >/dev/null || exit 1
fi

echo "== networks"
docker network create --subnet 10.251.71.0/24 "$HANET" >/dev/null || exit 1
docker network create --subnet 10.251.72.0/24 "$EXT" >/dev/null || exit 1
docker network create --subnet 10.251.73.0/24 "$APPNET" >/dev/null || exit 1

echo "== haproxy ($HAPROXY_IMAGE)"
docker create --name "$HAP" --network "$HANET" --ip "$HAP_HA_IP" \
    --network-alias new.pp2.test --network-alias new2.pp2.test --network-alias new3.pp2.test --network-alias old.pp2.test \
    "$HAPROXY_IMAGE" >/dev/null || exit 1
docker network connect --ip "$HAP_EXT_IP" "$EXT" "$HAP"
docker start "$HAP" >/dev/null
for _ in $(seq 1 30); do docker exec "$HAP" curl -sf http://127.0.0.1:8404/v1/health >/dev/null 2>&1 && break; sleep 1; done

start_backend() {  # name image domain [extra docker args...]
    local name="$1" image="$2" domain="$3"; shift 3
    docker create --name "$name" --hostname "$name" --network "$HANET" \
        -e SSL_DOMAIN="$domain" -e SSL_TEST_MODE=true -e HAPROXY_HOST="$HAP" \
        -e APP_HTTP_PORT=8080 -e SSL_HTTPS_PORT=443 -e SSL_PROXY_LOG_CONNECTIONS=true \
        "$@" "$image" >/dev/null || return 1
    docker network connect "$APPNET" "$name"
    docker start "$name" >/dev/null
}
start_backend "$NEW" "${PREFIX}-backend-new" new.pp2.test
start_backend "$NEW2" "${PREFIX}-backend-new" new2.pp2.test \
    -e SSL_PROXY_TRUSTED_CIDRS=haproxy \
    -e SSL_PROXY_HTTPS_UPSTREAM=auto:8446 -e SSL_PROXY_HTTPS_UPSTREAM_PROTOCOL=v2
# misconfigured: shim port collides with APP_HTTP_PORT -> must degrade to "none", not die
start_backend "$NEW3" "${PREFIX}-backend-new" new3.pp2.test -e SSL_PROXY_HTTPS_PORT=8080
[ -n "$SSL_MANAGER_OLD_IMAGE" ] && start_backend "$OLD" "${PREFIX}-backend-old" old.pp2.test

for c in "$CLIENT:$CLIENT_IP" "$CLIENT2:$CLIENT2_IP"; do
    docker run -d --name "${c%%:*}" --network "$EXT" --ip "${c##*:}" --entrypoint sleep "$TOOL_IMG" 3600 >/dev/null
done
docker run -d --name "$EVIL" --network "$APPNET" --entrypoint sleep "$TOOL_IMG" 3600 >/dev/null
docker run -d --name "$EVILHA" --network "$HANET" --entrypoint sleep "$TOOL_IMG" 3600 >/dev/null

echo "== wait for backends (ssl-setup -> app)"
for b in "$NEW" "$NEW2" "$NEW3" ${SSL_MANAGER_OLD_IMAGE:+"$OLD"}; do
    for _ in $(seq 1 90); do
        docker logs "$b" 2>&1 | grep -q "app starting" && break
        if [ "$(docker inspect -f '{{.State.Running}}' "$b")" != "true" ]; then break; fi
        sleep 1
    done
    if docker logs "$b" 2>&1 | grep -q "app starting"; then ok "$b: ssl-setup completed (incl. nonce check via haproxy)"; else bad "$b: ssl-setup did not complete" "$(docker logs "$b" 2>&1 | tail -5 | tr '\n' '|')"; fi
done
sleep 4  # last registration's debounced reload

j() { python3 -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); print(d.get(sys.argv[1]))' "$1" 2>/dev/null; }
http_via()  { docker exec "$1" curl -s --max-time 5 --resolve "$2:80:$HAP_EXT_IP" "${@:3}" "http://$2/"; }
https_via() { docker exec "$1" curl -sk --max-time 5 --resolve "$2:443:$HAP_EXT_IP" "https://$2/"; }
ip_of()     { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"; }
NEW_HA_IP=$(ip_of "$NEW" "$HANET")

echo "== registration state"
reg=$(docker exec "$HAP" curl -s http://127.0.0.1:8404/v1/backends/new.pp2.test)
if [ "$EXPECT_PP" = "true" ]; then
    check "registration new.pp2.test proxy_protocol" "$(echo "$reg" | j proxy_protocol)" "v2"
    check "registration new.pp2.test https_proxy_port" "$(echo "$reg" | j https_proxy_port)" "8445"
fi
docker exec "$HAP" sed -n '/pp2.test/p' /etc/haproxy/domains.map | sed 's/^/     map: /'

echo "== (a) real client IP on HTTP :80"
out=$(http_via "$CLIENT" new.pp2.test -H "X-Forwarded-For: 6.6.6.6" -H "X-Real-IP: 6.6.6.6")
echo "     $out"
if [ "$EXPECT_PP" = "true" ]; then
    check "HTTP: app X-Real-IP is the real client" "$(echo "$out" | j x_real_ip)" "$CLIENT_IP"
    check "HTTP: app X-Forwarded-For overwritten (spoofed 6.6.6.6 dropped)" "$(echo "$out" | j xff)" "$CLIENT_IP"
    out2=$(http_via "$CLIENT2" new.pp2.test)
    check "HTTP: second client sees its own IP (no mixing)" "$(echo "$out2" | j x_real_ip)" "$CLIENT2_IP"
else
    check "BASELINE HTTP: app sees haproxy, not the client" "$(echo "$out" | j xff)" "6.6.6.6, $HAP_HA_IP"
fi

echo "== (a) real client IP on TLS-SNI passthrough :443"
out=$(https_via "$CLIENT" new.pp2.test); echo "     default shim: $out"
check "TLS: served by the app's own TLS listener" "$(echo "$out" | j listener)" "tls"
if [ "$EXPECT_PP" = "true" ]; then
    check "TLS default: app peer is its own container IP (not loopback)" "$(echo "$out" | j peer)" "$NEW_HA_IP"
    if docker logs "$NEW" 2>&1 | grep -q "client ${CLIENT_IP}:[0-9]* (via $HAP_HA_IP PROXYv2)"; then ok "TLS default: shim logged the real client IP"; else bad "TLS default: shim log lacks real client IP" "$(docker logs "$NEW" 2>&1 | grep ssl-pp-proxy | tail -3 | tr '\n' '|')"; fi
    out=$(https_via "$CLIENT" new2.pp2.test); echo "     shim->app PROXY v2: $out"
    check "TLS upstream-v2: app on PROXY listener got the real client IP" "$(echo "$out" | j pp_src)" "$CLIENT_IP"
    out=$(https_via "$CLIENT2" new2.pp2.test)
    check "TLS upstream-v2: second client IP" "$(echo "$out" | j pp_src)" "$CLIENT2_IP"
else
    check "BASELINE TLS: app peer is haproxy" "$(echo "$out" | j peer)" "$HAP_HA_IP"
fi

if [ "$EXPECT_PP" = "true" ]; then
    echo "== misconfiguration degrades to no-PROXY (never an outage)"
    check "colliding SSL_PROXY_HTTPS_PORT -> registered proxy_protocol none" \
        "$(docker exec "$HAP" curl -s http://127.0.0.1:8404/v1/backends/new3.pp2.test | j proxy_protocol)" "none"
    out=$(http_via "$CLIENT" new3.pp2.test)
    check "misconfigured backend still serves HTTP (legacy XFF)" "$(echo "$out" | j xff)" "$HAP_HA_IP"
    check "misconfigured backend still serves TLS" "$(https_via "$CLIENT" new3.pp2.test | j listener)" "tls"
fi

if [ -n "$SSL_MANAGER_OLD_IMAGE" ]; then
    echo "== (b) OLD ssl-manager client (no flag) unchanged"
    reg=$(docker exec "$HAP" curl -s http://127.0.0.1:8404/v1/backends/old.pp2.test)
    pp_old=$(echo "$reg" | j proxy_protocol); [ "$EXPECT_PP" = "true" ] && check "old client registered without PROXY" "$pp_old" "none"
    out=$(http_via "$CLIENT" old.pp2.test); echo "     $out"
    check "old HTTP works, legacy XFF (haproxy hop)" "$(echo "$out" | j xff)" "$HAP_HA_IP"
    out=$(https_via "$CLIENT" old.pp2.test)
    check "old TLS works, app peer is haproxy (as before)" "$(echo "$out" | j peer)" "$HAP_HA_IP"
fi

if [ "$EXPECT_PP" = "true" ]; then
    echo "== (c) forged PROXY headers"
    forge='import sys,socket;sys.path.insert(0,"/usr/local/lib/ssl-manager");import proxyproto as pp
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5)
s.sendall(pp.build_v2("6.6.6.6",1234,"10.0.0.1",80)+sys.argv[3].encode().decode("unicode_escape").encode("latin1"))
s.settimeout(5);out=b""
try:
    while True:
        d=s.recv(4096)
        if not d: break
        out+=d
except Exception: pass
print(repr(out[:300]))'
    r=$(docker exec "$EVIL" python3 -c "$forge" "$(ip_of "$NEW" "$APPNET")" 80 'GET / HTTP/1.0\r\nHost: new.pp2.test\r\n\r\n')
    check "untrusted peer (app net) forged header to :80 -> connection closed" "$r" "b''"
    r=$(docker exec "$EVIL" python3 -c "$forge" "$(ip_of "$NEW" "$APPNET")" 8445 'x')
    check "untrusted peer (app net) forged header to TLS shim -> closed" "$r" "b''"
    r=$(docker exec "$EVILHA" python3 -c "$forge" "$(ip_of "$NEW2" "$HANET")" 80 'GET / HTTP/1.0\r\nHost: new2.pp2.test\r\n\r\n')
    check "strict trust (haproxy only): forged header from haproxy-net peer -> closed" "$r" "b''"
    if docker logs "$NEW" 2>&1 | grep -q "UNTRUSTED peer"; then ok "rejections are logged"; else bad "rejections not logged"; fi
    # Documented residual risk of the DEFAULT trust (auto = whole haproxy-net subnet):
    # any container on haproxy-net can assert a client IP. Shown, not asserted.
    r=$(docker exec "$EVILHA" python3 -c "$forge" "$NEW_HA_IP" 80 'GET / HTTP/1.0\r\nHost: new.pp2.test\r\n\r\n')
    case "$r" in *6.6.6.6*) echo "     INFO (documented risk): default trust=auto accepts a header from another haproxy-net container: $(echo "$r" | grep -o '"x_real_ip": "[^"]*"')";;
                 *) echo "     INFO: haproxy-net peer header not adopted: $(echo "$r" | cut -c1-60)";; esac
    # A client sending a header THROUGH haproxy: haproxy's real header comes first,
    # the forged one is just payload -> never adopted.
    r=$(docker exec "$CLIENT" python3 -c "$forge" "$HAP_EXT_IP" 80 'GET / HTTP/1.0\r\nHost: new.pp2.test\r\n\r\n')
    case "$r" in *6.6.6.6*) bad "client-forged header through haproxy was adopted" "$r";; *) ok "client-forged header through haproxy not adopted ($(echo "$r" | cut -c1-40))";; esac

    echo "== (d) direct connections without a header still work"
    out=$(docker exec "$EVIL" curl -s --max-time 5 "http://$(ip_of "$NEW" "$APPNET")/")
    check "direct HTTP from app net: proxied, XFF = direct peer" "$(echo "$out" | j xff)" "$(ip_of "$EVIL" "$APPNET")"
    check "direct /_ssl/health" "$(docker exec "$EVIL" curl -s -o /dev/null -w '%{http_code}' "http://$(ip_of "$NEW" "$APPNET")/_ssl/health")" "200"
    out=$(docker exec "$EVILHA" curl -sk --max-time 5 "https://$NEW:443/")
    check "direct TLS to app :443 (hairpin-style, no header)" "$(echo "$out" | j listener)" "tls"
    out=$(docker exec "$EVILHA" curl -sk --max-time 5 "https://$NEW:8445/")
    check "direct TLS to shim :8445 without header" "$(echo "$out" | j listener)" "tls"
    out=$(docker exec "$NEW" curl -s --max-time 5 "http://localhost/")
    check "in-container localhost HTTP" "$(echo "$out" | j x_real_ip)" "127.0.0.1"

    echo "== (e) haproxy health checks + persistence"
    stat=$(docker exec "$HAP" sh -c 'echo "show stat" | socat stdio /var/run/haproxy.sock' | cut -d, -f1,2,18 | grep pp2test-new)
    echo "$stat" | sed 's/^/     /'
    for be in "${NEW}-http-pp" "${NEW}-https-8445-pp" "${NEW2}-http-pp" "${NEW2}-https-8445-pp"; do
        case "$stat" in *"$be,$NEW"*UP*|*"$be,$NEW2"*UP*) ok "health UP: $be";; *) bad "health not UP: $be";; esac
    done
    docker restart "$HAP" >/dev/null
    for _ in $(seq 1 30); do docker exec "$HAP" curl -sf http://127.0.0.1:8404/v1/health >/dev/null 2>&1 && break; sleep 1; done
    sleep 3
    check "after haproxy restart: registration still v2" "$(docker exec "$HAP" curl -s http://127.0.0.1:8404/v1/backends/new.pp2.test | j proxy_protocol)" "v2"
    out=""; for _ in $(seq 1 10); do out=$(http_via "$CLIENT" new.pp2.test); [ "$(echo "$out" | j x_real_ip)" = "$CLIENT_IP" ] && break; sleep 1; done
    check "after haproxy restart: real client IP on :80" "$(echo "$out" | j x_real_ip)" "$CLIENT_IP"
    out=$(https_via "$CLIENT" new2.pp2.test)
    check "after haproxy restart: real client IP on :443" "$(echo "$out" | j pp_src)" "$CLIENT_IP"
fi

echo ""
echo "== RESULT: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
