'use strict';

const crypto = require('crypto');
const { execFileSync } = require('child_process');

/**
 * Handles E2EE decryption of server credentials and manages
 * Windows Credential Manager via cmdkey.exe.
 */
class RdpCredentialHandler {
  constructor(log) {
    this.log = log;
    this._clientKeyPair = null;
  }

  /**
   * Generate an ephemeral ECDH key pair for E2EE credential exchange.
   * @returns {{ publicKey: string, privateKey: string }}
   */
  generateKeyPair() {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    this._clientKeyPair = {
      publicKey: ecdh.getPublicKey('base64'),
      privateKey: ecdh,
    };
    return { publicKey: this._clientKeyPair.publicKey };
  }

  /**
   * Decrypt credentials received from server (encrypted with our public key).
   * Server encrypts with AES-256-GCM using the ECDH shared secret.
   * @param {object} encrypted - { data, iv, authTag, serverPublicKey }
   * @returns {{ username: string, password: string, domain?: string }}
   */
  decryptCredentials(encrypted) {
    if (!this._clientKeyPair) {
      throw new Error('No client key pair generated. Call generateKeyPair() first.');
    }

    // Derive shared secret from server's public key + our private key
    const serverPubKeyBuffer = Buffer.from(encrypted.serverPublicKey, 'base64');
    const sharedSecret = this._clientKeyPair.privateKey.computeSecret(serverPubKeyBuffer);

    // Derive AES key from shared secret
    const aesKey = crypto.createHash('sha256').update(sharedSecret).digest();

    // Decrypt AES-256-GCM
    const iv = Buffer.from(encrypted.iv, 'base64');
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted.data, 'base64')),
      decipher.final(),
    ]);

    const credentials = JSON.parse(decrypted.toString('utf-8'));
    this.log.info('Credentials decrypted successfully (E2EE)');

    // Clear key pair after use
    this._clientKeyPair = null;

    return credentials;
  }

  /**
   * Store credentials in Windows Credential Manager via cmdkey.exe.
   * @param {string} host - RDP target host
   * @param {string} username - Username (with domain prefix if applicable)
   * @param {string} password - Password
   * @param {string} [domain] - Optional domain (will be prepended to username)
   */
  storeCredentials(host, username, password, domain) {
    const target = `TERMSRV/${host}`;
    const user = domain ? `${domain}\\${username}` : username;

    try {
      // Delete existing credential first (ignore errors)
      try {
        execFileSync('cmdkey.exe', ['/delete', target], {
          timeout: 5000,
          windowsHide: true,
        });
      } catch {}

      // Store new credential
      execFileSync('cmdkey.exe', [
        '/generic', target,
        '/user', user,
        '/pass', password,
      ], {
        timeout: 5000,
        windowsHide: true,
      });

      this.log.info(`Credentials stored for ${target} (user: ${user})`);
    } catch (err) {
      this.log.error(`Failed to store credentials for ${target}:`, err.message);
      throw new Error(`cmdkey failed: ${err.message}`);
    }
  }

  /**
   * Clear credentials for a specific host from Windows Credential Manager.
   * @param {string} host - RDP target host
   */
  clearCredentials(host) {
    const target = `TERMSRV/${host}`;

    try {
      execFileSync('cmdkey.exe', ['/delete', target], {
        timeout: 5000,
        windowsHide: true,
      });
      this.log.info(`Credentials cleared for ${target}`);
    } catch (err) {
      // cmdkey returns error if credential doesn't exist -- that's OK
      this.log.debug(`cmdkey /delete for ${target}:`, err.message);
    }
  }

  /**
   * Clear ALL GateControl-related credentials from Windows Credential Manager.
   * Used during crash cleanup and app exit.
   */
  clearAllGateControlCredentials() {
    try {
      const output = execFileSync('cmdkey.exe', ['/list'], {
        encoding: 'utf-8',
        timeout: 10000,
        windowsHide: true,
      });

      // Find all TERMSRV/* entries
      const lines = output.split('\n');
      let clearedCount = 0;

      for (const line of lines) {
        const match = line.match(/Target:\s*(TERMSRV\/.+)/i);
        if (match) {
          const target = match[1].trim();
          try {
            execFileSync('cmdkey.exe', ['/delete', target], {
              timeout: 5000,
              windowsHide: true,
            });
            clearedCount++;
          } catch {}
        }
      }

      if (clearedCount > 0) {
        this.log.info(`Cleared ${clearedCount} TERMSRV credentials from Credential Manager`);
      }
    } catch (err) {
      this.log.warn('Failed to enumerate/clear credentials:', err.message);
    }
  }
}

module.exports = RdpCredentialHandler;
