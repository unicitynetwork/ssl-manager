#!/bin/sh
# staging-tunnel entrypoint: install host keys + developer authorized_keys, run sshd.
set -eu

mkdir -p /etc/ssh/keys
# Host keys — for a STABLE, reproducible fingerprint that survives volume loss, prefer an
# operator-provided key: the staging-tunnel dir is mounted read-only at /auth-src, so a
# gitignored hostkeys/ appears at /auth-src/hostkeys/. When present it is authoritative
# (re-installed every start). Otherwise fall back to generating into the persistent volume
# (stable across restarts, but a fresh fingerprint if the volume is ever recreated).
if [ -f /auth-src/hostkeys/ssh_host_ed25519_key ]; then
  echo "[staging-tunnel] using operator-provided host key(s) from hostkeys/ (stable)"
  for k in ssh_host_ed25519_key ssh_host_rsa_key; do
    [ -f "/auth-src/hostkeys/$k" ]     && install -m 600 "/auth-src/hostkeys/$k"     "/etc/ssh/keys/$k"
    [ -f "/auth-src/hostkeys/$k.pub" ] && install -m 644 "/auth-src/hostkeys/$k.pub" "/etc/ssh/keys/$k.pub"
  done
else
  if [ ! -f /etc/ssh/keys/ssh_host_ed25519_key ]; then
    echo "[staging-tunnel] generating host keys (no hostkeys/ mounted — not portable across volume loss)"
    ssh-keygen -t ed25519 -f /etc/ssh/keys/ssh_host_ed25519_key -N '' >/dev/null
  fi
  [ -f /etc/ssh/keys/ssh_host_rsa_key ] || ssh-keygen -t rsa -b 3072 -f /etc/ssh/keys/ssh_host_rsa_key -N '' >/dev/null
fi

# Install developer keys. The staging-tunnel dir is mounted read-only at /auth-src
# (mounting the dir, not the file, avoids Docker auto-creating an empty-dir shadow when
# authorized_keys is absent — see docker-compose.yml).
if [ -f /auth-src/authorized_keys ]; then
  install -o tunnel -g tunnel -m 600 /auth-src/authorized_keys /home/tunnel/.ssh/authorized_keys
  # Count only real key lines (non-comment, non-blank) — an all-comments file (e.g. the
  # example copied without adding a key) must report 0, not the comment-line count.
  _keys="$(grep -cE '^[[:space:]]*[^#[:space:]]' /home/tunnel/.ssh/authorized_keys 2>/dev/null || true)"
  [ -n "$_keys" ] || _keys=0
  echo "[staging-tunnel] installed ${_keys} authorized key(s)"
  [ "${_keys}" -eq 0 ] && echo "[staging-tunnel] WARN: authorized_keys has no usable keys — every tunnel will be refused" >&2
else
  echo "[staging-tunnel] WARN: no authorized_keys found (create staging-tunnel/authorized_keys from the example) — no one can tunnel" >&2
fi

echo "[staging-tunnel] endpoint host key fingerprint (pin this as TUNNEL_HOST_KEY_FINGERPRINT):"
ssh-keygen -lf /etc/ssh/keys/ssh_host_ed25519_key.pub | sed 's/^/[staging-tunnel]   /'

exec /usr/sbin/sshd -D -e
