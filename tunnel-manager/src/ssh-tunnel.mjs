/**
 * SSH reverse tunnel management (lite mode).
 *
 * Uses autossh to establish SSH -R port forwarding from the remote
 * HAProxy host to the local container. This is the fallback for
 * environments where WireGuard is not available or CAP_NET_ADMIN
 * cannot be granted.
 */

import { spawn, execSync, execFileSync } from 'node:child_process';
import { writeFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const LOG_PREFIX = '[tunnel-manager:ssh]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

/**
 * Input validation functions.
 */
function validateHostname(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) {
    throw new Error('Invalid hostname');
  }
  // Allow IP addresses and valid hostnames
  if (!/^[a-zA-Z0-9._-]+$/.test(host)) {
    throw new Error('Hostname contains invalid characters');
  }
}

function validatePort(port) {
  const p = parseInt(port, 10);
  if (isNaN(p) || p < 1 || p > 65535) throw new Error('Invalid port number');
  return p;
}

/**
 * Check if autossh is available.
 */
export function checkSshAvailability() {
  try {
    execFileSync('which', ['autossh'], { stdio: 'pipe', timeout: 30000 });
    return { available: true, method: 'autossh' };
  } catch {}

  try {
    execFileSync('which', ['ssh'], { stdio: 'pipe', timeout: 30000 });
    return { available: true, method: 'ssh' };
  } catch {}

  return { available: false, method: 'none' };
}

/**
 * Verify the SSH host key fingerprint.
 * Returns true if the fingerprint matches.
 */
export function verifyHostKey(host, port, expectedFingerprint) {
  validateHostname(host);
  const validPort = validatePort(port);

  try {
    // Use execFileSync for ssh-keyscan to avoid shell injection,
    // then pipe output to ssh-keygen via stdin
    const keyscanOutput = execFileSync(
      'ssh-keyscan', ['-p', String(validPort), '-T', '10', host],
      { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] }
    );

    const fingerprintOutput = execSync('ssh-keygen -lf -', {
      input: keyscanOutput,
      encoding: 'utf-8',
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    for (const line of fingerprintOutput.split('\n')) {
      if (line.includes(expectedFingerprint)) {
        return true;
      }
    }

    warn(`Host key fingerprint mismatch for ${host}:${validPort}`);
    return false;
  } catch (e) {
    err(`Failed to verify host key: ${e.message}`);
    return false;
  }
}

/**
 * Establish SSH reverse tunnel using autossh.
 *
 * @param {Object} auth - SSH auth from TUNNEL_OFFER
 * @param {Object} opts - Additional options
 * @returns {Object} { process, pid }
 */
export function establishSshTunnel(auth, opts = {}) {
  const { ssh_host, ssh_port, ssh_user, ssh_host_key_fingerprint, forwarded_ports } = auth;

  // Validate inputs from tunnel offer (attacker-controlled)
  validateHostname(ssh_host);
  const validPort = validatePort(ssh_port);
  validateHostname(ssh_user); // SSH usernames have similar character constraints

  // Verify host key
  if (ssh_host_key_fingerprint) {
    if (!verifyHostKey(ssh_host, validPort, ssh_host_key_fingerprint)) {
      throw new Error('SSH host key fingerprint verification failed');
    }
    log('SSH host key fingerprint verified');
  }

  // Build port forwarding arguments
  const portArgs = [];
  for (const fp of forwarded_ports) {
    const localPort = validatePort(fp.local_port);
    portArgs.push('-R', `${fp.remote_bind}:localhost:${localPort}`);
    log(`Port forward: ${fp.remote_bind} -> localhost:${localPort} (${fp.description})`);
  }

  // SSH options for stability
  const sshOpts = [
    '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ExitOnForwardFailure=yes',
    '-o', 'ConnectTimeout=30',
    '-N', // No remote command
  ];

  // Choose autossh or ssh
  const useAutossh = checkSshAvailability().method === 'autossh';
  const cmd = useAutossh ? 'autossh' : 'ssh';
  const args = [];

  if (useAutossh) {
    // autossh monitoring disabled (we use ServerAliveInterval instead)
    args.push('-M', '0');
  }

  args.push(
    ...sshOpts,
    '-p', String(validPort),
    ...portArgs,
    `${ssh_user}@${ssh_host}`,
  );

  log(`Starting ${cmd} tunnel to ${ssh_user}@${ssh_host}:${validPort}`);
  const proc = spawn(cmd, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });

  proc.stdout.on('data', (data) => {
    log(`[ssh] ${data.toString().trim()}`);
  });

  proc.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) warn(`[ssh] ${msg}`);
  });

  proc.on('exit', (code) => {
    log(`SSH tunnel process exited with code ${code}`);
  });

  return {
    process: proc,
    pid: proc.pid,
  };
}

/**
 * Kill the SSH tunnel process.
 */
export function killSshTunnel(proc) {
  if (proc && proc.process && !proc.process.killed) {
    try {
      proc.process.kill('SIGTERM');
      // Give it a moment then force kill
      setTimeout(() => {
        if (!proc.process.killed) {
          proc.process.kill('SIGKILL');
        }
      }, 5000);
    } catch {}
  }
}

/**
 * Check if SSH tunnel ports are forwarded and accessible.
 */
export function verifySshTunnel(forwardedPorts) {
  let allOk = true;
  for (const fp of forwardedPorts) {
    const localPort = validatePort(fp.local_port);
    try {
      execFileSync('nc', ['-z', 'localhost', String(localPort)], {
        stdio: 'pipe',
        timeout: 5000,
      });
    } catch {
      warn(`Port ${localPort} (${fp.description}) not reachable`);
      allOk = false;
    }
  }
  return allOk;
}
