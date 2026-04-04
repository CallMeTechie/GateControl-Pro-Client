'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const RdpCredentialHandler = require('../src/services/rdp/rdp-credential');

/**
 * Simulates the server-side ecdhEncrypt() to test the client credential handler.
 * Must match the server implementation in gatecontrol/src/utils/crypto.js exactly.
 */
function serverEcdhEncrypt(plaintext, clientPublicKeyBase64) {
  const clientPubBuf = Buffer.from(clientPublicKeyBase64, 'base64');
  const serverEcdh = crypto.createECDH('prime256v1');
  serverEcdh.generateKeys();

  const sharedSecret = serverEcdh.computeSecret(clientPubBuf);
  const salt = Buffer.concat([clientPubBuf, serverEcdh.getPublicKey()]);
  const aesKey = crypto.hkdfSync('sha256', sharedSecret, salt, 'gatecontrol-rdp-e2ee-v1', 32);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(aesKey), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    data: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    serverPublicKey: serverEcdh.getPublicKey('base64'),
  };
}

// Minimal logger stub
const log = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };

describe('RdpCredentialHandler E2EE', () => {
  it('generates a valid ECDH P-256 public key', () => {
    const handler = new RdpCredentialHandler(log);
    const { publicKey } = handler.generateKeyPair();
    const buf = Buffer.from(publicKey, 'base64');
    assert.equal(buf.length, 65);
    assert.equal(buf[0], 0x04);
  });

  it('decrypts server-encrypted credentials (full round-trip)', () => {
    const handler = new RdpCredentialHandler(log);
    const { publicKey } = handler.generateKeyPair();

    const credentialsJson = JSON.stringify({
      username: 'admin',
      password: 'S3cret!',
      domain: 'CORP',
    });

    const encrypted = serverEcdhEncrypt(credentialsJson, publicKey);
    const creds = handler.decryptCredentials(encrypted);

    assert.equal(creds.username, 'admin');
    assert.equal(creds.password, 'S3cret!');
    assert.equal(creds.domain, 'CORP');
  });

  it('clears keypair after decryption', () => {
    const handler = new RdpCredentialHandler(log);
    const { publicKey } = handler.generateKeyPair();

    const encrypted = serverEcdhEncrypt('{"username":"a","password":"b","domain":null}', publicKey);
    handler.decryptCredentials(encrypted);

    // Second call must fail — keypair was cleared
    assert.throws(
      () => handler.decryptCredentials(encrypted),
      /No client key pair generated/
    );
  });

  it('fails with wrong client keypair', () => {
    const handler1 = new RdpCredentialHandler(log);
    const { publicKey: pubKey1 } = handler1.generateKeyPair();

    const handler2 = new RdpCredentialHandler(log);
    handler2.generateKeyPair();

    // Encrypt for handler1, try to decrypt with handler2
    const encrypted = serverEcdhEncrypt('{"username":"x","password":"y","domain":null}', pubKey1);
    assert.throws(() => handler2.decryptCredentials(encrypted));
  });

  it('fails with tampered ciphertext', () => {
    const handler = new RdpCredentialHandler(log);
    const { publicKey } = handler.generateKeyPair();

    const encrypted = serverEcdhEncrypt('{"username":"a","password":"b","domain":null}', publicKey);
    encrypted.data = Buffer.from('tampered').toString('base64');

    assert.throws(() => handler.decryptCredentials(encrypted));
  });

  it('handles unicode credentials', () => {
    const handler = new RdpCredentialHandler(log);
    const { publicKey } = handler.generateKeyPair();

    const credentialsJson = JSON.stringify({
      username: 'Ädmin',
      password: 'Pässwörd€',
      domain: null,
    });

    const encrypted = serverEcdhEncrypt(credentialsJson, publicKey);
    const creds = handler.decryptCredentials(encrypted);

    assert.equal(creds.username, 'Ädmin');
    assert.equal(creds.password, 'Pässwörd€');
    assert.equal(creds.domain, null);
  });

  it('each generateKeyPair() produces unique keys', () => {
    const handler = new RdpCredentialHandler(log);
    const { publicKey: k1 } = handler.generateKeyPair();
    const { publicKey: k2 } = handler.generateKeyPair();
    assert.notEqual(k1, k2);
  });
});
