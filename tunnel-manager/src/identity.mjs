/**
 * Identity management — Sphere SDK / Nostr keypair and WireGuard keypair.
 *
 * Loads or generates persistent identity files stored in TUNNEL_IDENTITY_DIR.
 */

import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import * as crypto from 'node:crypto';

const LOG_PREFIX = '[tunnel-manager:identity]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }

/**
 * Load or generate the Nostr identity (secp256k1 keypair).
 * Returns { npub, nsec, pubkeyHex, privkeyHex }.
 */
export function loadOrCreateNostrIdentity(identityDir) {
  mkdirSync(identityDir, { recursive: true, mode: 0o700 });
  const identityFile = join(identityDir, 'sphere-identity.json');

  if (existsSync(identityFile)) {
    try {
      const data = JSON.parse(readFileSync(identityFile, 'utf-8'));
      log(`Loaded existing Nostr identity: ${data.npub}`);
      return data;
    } catch (err) {
      warn(`Failed to load identity file: ${err.message}, regenerating`);
    }
  }

  // Generate a new secp256k1 keypair
  // We use a simple 32-byte random private key (valid for secp256k1)
  const privkeyBytes = crypto.randomBytes(32);
  const privkeyHex = privkeyBytes.toString('hex');

  // Store as a placeholder - the actual npub/nsec encoding will be done
  // when nostr-tools is available. For now, store raw hex.
  const identity = {
    privkeyHex,
    pubkeyHex: '', // Will be computed on first use with nostr-tools
    npub: '',
    nsec: '',
    createdAt: new Date().toISOString(),
  };

  writeFileSync(identityFile, JSON.stringify(identity, null, 2), { mode: 0o600 });
  chmodSync(identityFile, 0o600);
  log('Generated new Nostr identity');

  return identity;
}

/**
 * Load or generate the WireGuard keypair.
 * Returns { privateKey, publicKey } (base64 strings).
 */
export function loadOrCreateWireguardKeys(identityDir) {
  mkdirSync(identityDir, { recursive: true, mode: 0o700 });
  const privateKeyFile = join(identityDir, 'wg-private.key');
  const publicKeyFile = join(identityDir, 'wg-public.key');

  if (existsSync(privateKeyFile) && existsSync(publicKeyFile)) {
    const privateKey = readFileSync(privateKeyFile, 'utf-8').trim();
    const publicKey = readFileSync(publicKeyFile, 'utf-8').trim();
    if (privateKey && publicKey) {
      log('Loaded existing WireGuard keypair');
      return { privateKey, publicKey };
    }
  }

  try {
    const privateKey = execSync('wg genkey', { encoding: 'utf-8' }).trim();
    const publicKey = execSync(`echo "${privateKey}" | wg pubkey`, {
      encoding: 'utf-8',
      shell: '/bin/bash',
    }).trim();

    writeFileSync(privateKeyFile, privateKey + '\n', { mode: 0o600 });
    chmodSync(privateKeyFile, 0o600);
    writeFileSync(publicKeyFile, publicKey + '\n', { mode: 0o600 });
    chmodSync(publicKeyFile, 0o600);
    log('Generated new WireGuard keypair');

    return { privateKey, publicKey };
  } catch (err) {
    throw new Error(`Failed to generate WireGuard keys: ${err.message}`);
  }
}
