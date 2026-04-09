/**
 * SSH reverse tunnel management (lite mode).
 *
 * Uses autossh to establish SSH -R port forwarding from the remote
 * HAProxy host to the local container. This is the fallback for
 * environments where WireGuard is not available or CAP_NET_ADMIN
 * cannot be granted.
 */

import { spawn, execSync } from 'node:child_process';
import { writeFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const LOG_PREFIX = '[tunnel-manager:ssh]';

function log(msg) { console.log(`${LOG_PREFIX} ${msg}`); }
function warn(msg) { console.error(`${LOG_PREFIX} WARNING: ${msg}`); }
function err(msg) { console.error(`${LOG_PREFIX} ERROR: ${msg}`); }

/**
 * Check if autossh is available.
 */
export function checkSshAvailability() {
  try {
    execSync('which autossh', { stdio: 'pipe' });
    return { available: true, method: 'autossh' };
  } catch {}

  try {
    execSync('which ssh', { stdio: 'pipe' });
    return { available: true, method: 'ssh' };
  } catch {}

  return { available: false, method: 'none' };
}

/**
 * Verify the SSH host key fingerprint.
 * Returns true if the fingerprint matches.
 */
export function verifyHostKey(host, port, expectedFingerprint) {
  try {
    const output = execSync(
      `ssh-keyscan -p ${port} -T 10 ${host} 2>/dev/null | ssh-keygen -lf - 2>/dev/null`,
      { encoding: 'utf-8', shell: '/bin/bash' }
    );

    for (const line of output.split('\n')) {
      if (line.includes(expectedFingerprint)) {
        return true;
      }
    }

    warn(`Host key fingerprint mismatch for ${host}:${port}`);
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

  // Verify host key
  if (ssh_host_key_fingerprint) {
    if (!verifyHostKey(ssh_host, ssh_port, ssh_host_key_fingerprint)) {
      throw new Error('SSH host key fingerprint verification failed');
    }
    log('SSH host key fingerprint verified');
  }

  // Build port forwarding arguments
  const portArgs = [];
  for (const fp of forwarded_ports) {
    portArgs.push('-R', `${fp.remote_bind}:localhost:${fp.local_port}`);
    log(`Port forward: ${fp.remote_bind} -> localhost:${fp.local_port} (${fp.description})`);
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
    '-p', String(ssh_port),
    ...portArgs,
    `${ssh_user}@${ssh_host}`,
  );

  log(`Starting ${cmd} tunnel to ${ssh_user}@${ssh_host}:${ssh_port}`);
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
    try {
      execSync(`nc -z localhost ${fp.local_port} 2>/dev/null`, {
        stdio: 'pipe',
        timeout: 5000,
      });
    } catch {
      warn(`Port ${fp.local_port} (${fp.description}) not reachable`);
      allOk = false;
    }
  }
  return allOk;
}
