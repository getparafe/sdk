/**
 * Unit tests for Ed25519 key generation and challenge signing.
 */

import * as nodeCrypto from 'node:crypto';
import { generateKeyPair, signChallenge, loadPrivateKey } from '../src/crypto.js';

describe('generateKeyPair', () => {
  it('returns base64-encoded publicKey and privateKey strings', () => {
    const { publicKey, privateKey } = generateKeyPair();
    expect(typeof publicKey).toBe('string');
    expect(typeof privateKey).toBe('string');
    expect(publicKey.length).toBeGreaterThan(0);
    expect(privateKey.length).toBeGreaterThan(0);
  });

  it('generates valid Ed25519 SPKI DER public key', () => {
    const { publicKey } = generateKeyPair();
    const buf = Buffer.from(publicKey, 'base64');
    const key = nodeCrypto.createPublicKey({ key: buf, format: 'der', type: 'spki' });
    expect(key.asymmetricKeyType).toBe('ed25519');
  });

  it('generates valid Ed25519 PKCS8 DER private key', () => {
    const { privateKey } = generateKeyPair();
    const buf = Buffer.from(privateKey, 'base64');
    const key = nodeCrypto.createPrivateKey({ key: buf, format: 'der', type: 'pkcs8' });
    expect(key.asymmetricKeyType).toBe('ed25519');
  });

  it('generates unique key pairs each call', () => {
    const pair1 = generateKeyPair();
    const pair2 = generateKeyPair();
    expect(pair1.publicKey).not.toBe(pair2.publicKey);
    expect(pair1.privateKey).not.toBe(pair2.privateKey);
  });
});

describe('loadPrivateKey', () => {
  it('reconstructs a KeyObject from a base64 PKCS8 DER buffer', () => {
    const { privateKey } = generateKeyPair();
    const keyObj = loadPrivateKey(privateKey);
    expect(keyObj.asymmetricKeyType).toBe('ed25519');
    expect(keyObj.type).toBe('private');
  });
});

describe('signChallenge', () => {
  it('returns a non-empty base64 string', () => {
    const { privateKey } = generateKeyPair();
    // Generate a realistic 32-byte (64-char hex) challenge nonce
    const challengeNonce = nodeCrypto.randomBytes(32).toString('hex');
    const sig = signChallenge(challengeNonce, privateKey);
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
    // Ed25519 signatures are always 64 bytes = 88 chars in base64
    const sigBuf = Buffer.from(sig, 'base64');
    expect(sigBuf.length).toBe(64);
  });

  it('produces a signature verifiable with the matching public key', () => {
    const { publicKey, privateKey } = generateKeyPair();
    const challengeNonce = nodeCrypto.randomBytes(32).toString('hex');
    const sig = signChallenge(challengeNonce, privateKey);

    // Verify using node:crypto directly (same as broker's verifyChallengeResponse)
    const pubKeyObj = nodeCrypto.createPublicKey({
      key: Buffer.from(publicKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const data = Buffer.from(challengeNonce, 'hex');
    const sigBuf = Buffer.from(sig, 'base64');
    const valid = nodeCrypto.verify(null, data, pubKeyObj, sigBuf);
    expect(valid).toBe(true);
  });

  it('produces different signatures for different challenges', () => {
    const { privateKey } = generateKeyPair();
    const nonce1 = nodeCrypto.randomBytes(32).toString('hex');
    const nonce2 = nodeCrypto.randomBytes(32).toString('hex');
    const sig1 = signChallenge(nonce1, privateKey);
    const sig2 = signChallenge(nonce2, privateKey);
    expect(sig1).not.toBe(sig2);
  });

  it('signature fails verification with a different public key', () => {
    const pair1 = generateKeyPair();
    const pair2 = generateKeyPair();
    const nonce = nodeCrypto.randomBytes(32).toString('hex');
    const sig = signChallenge(nonce, pair1.privateKey);

    const pubKeyObj = nodeCrypto.createPublicKey({
      key: Buffer.from(pair2.publicKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const data = Buffer.from(nonce, 'hex');
    const sigBuf = Buffer.from(sig, 'base64');
    const valid = nodeCrypto.verify(null, data, pubKeyObj, sigBuf);
    expect(valid).toBe(false);
  });
});
