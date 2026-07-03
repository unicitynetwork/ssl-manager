#!/bin/sh
# staging-tunnel entrypoint: persist host keys, install developer authorized_keys, run sshd.
set -eu

mkdir -p /etc/ssh/keys
# Generate persistent host keys on first run (kept in the mounted /etc/ssh/keys volume).
if [ ! -f /etc/ssh/keys/ssh_host_ed25519_key ]; then
  echo "[staging-tunnel] generating host keys"
  ssh-keygen -t ed25519 -f /etc/ssh/keys/ssh_host_ed25519_key -N '' >/dev/null
fi
[ -f /etc/ssh/keys/ssh_host_rsa_key ] || ssh-keygen -t rsa -b 3072 -f /etc/ssh/keys/ssh_host_rsa_key -N '' >/dev/null

# Install developer keys. The staging-tunnel dir is mounted read-only at /auth-src
# (mounting the dir, not the file, avoids Docker auto-creating an empty-dir shadow when
# authorized_keys is absent — see docker-compose.yml).
if [ -f /auth-src/authorized_keys ]; then
  install -o tunnel -g tunnel -m 600 /auth-src/authorized_keys /home/tunnel/.ssh/authorized_keys
  # Count only real key lines (non-comment, non-blank) — an all-comments file (e.g. the
  # example copied without adding a key) must report 0, not the comment-line count.
  _keys="$(grep -cE '^[[:space:]]*[^#[:space:]]' /home/tunnel/.ssh/authorized_keys 2>/dev/null || echo 0)"
  echo "[staging-tunnel] installed ${_keys} authorized key(s)"
  [ "${_keys}" -eq 0 ] && echo "[staging-tunnel] WARN: authorized_keys has no usable keys — every tunnel will be refused" >&2
else
  echo "[staging-tunnel] WARN: no authorized_keys found (create staging-tunnel/authorized_keys from the example) — no one can tunnel" >&2
fi

echo "[staging-tunnel] endpoint host key fingerprint (pin this as TUNNEL_HOST_KEY_FINGERPRINT):"
ssh-keygen -lf /etc/ssh/keys/ssh_host_ed25519_key.pub | sed 's/^/[staging-tunnel]   /'

exec /usr/sbin/sshd -D -e
