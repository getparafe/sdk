/**
 * Ed25519 key generation and challenge signing for @parafe-trust/sdk
 * Uses Node.js native crypto module.
 */

import * as nodeCrypto from 'node:crypto';

export interface KeyPair {
  /** Base64-encoded SPKI DER public key */
  publicKey: string;
  /** Base64-encoded PKCS8 DER private key */
  privateKey: string;
}

/**
 * Generate a fresh Ed25519 key pair.
 * Returns base64-encoded DER buffers (SPKI for public, PKCS8 for private).
 */
export function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ed25519');

  const publicKeyBase64 = publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64');

  const privateKeyBase64 = privateKey
    .export({ type: 'pkcs8', format: 'der' })
    .toString('base64');

  return { publicKey: publicKeyBase64, privateKey: privateKeyBase64 };
}

/**
 * Reconstruct a private KeyObject from a base64-encoded PKCS8 DER buffer.
 */
export function loadPrivateKey(privateKeyBase64: string): nodeCrypto.KeyObject {
  return nodeCrypto.createPrivateKey({
    key: Buffer.from(privateKeyBase64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

/**
 * Sign a challenge nonce for handshake completion.
 *
 * The broker sends challenge_for_target as a 64-char hex string.
 * We decode it to raw bytes and sign with the agent's Ed25519 private key.
 * Returns the signature as a base64 string — what the broker expects as challenge_response.
 */
export function signChallenge(challengeNonce: string, privateKeyBase64: string): string {
  const privateKey = loadPrivateKey(privateKeyBase64);
  const data = Buffer.from(challengeNonce, 'hex');
  const signature = nodeCrypto.sign(null, data, privateKey);
  return signature.toString('base64');
}
