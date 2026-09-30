/**
 * Agent keys, challenge signing and proofs of possession for @getparafe/sdk.
 * Uses Node.js native crypto (and jose for the proof JWTs).
 *
 * Agents may use Ed25519 (default) or P-256 / ES256 (the key type AP2 uses).
 */

import * as nodeCrypto from 'node:crypto';
import * as jose from 'jose';

export type KeyAlgorithm = 'Ed25519' | 'P-256';

export interface KeyPair {
  /** Base64-encoded SPKI DER public key */
  publicKey: string;
  /** Base64-encoded PKCS8 DER private key */
  privateKey: string;
}

/**
 * Generate a fresh agent key pair: Ed25519 (default) or P-256.
 * Returns base64-encoded DER buffers (SPKI for public, PKCS8 for private).
 */
export function generateKeyPair(algorithm: KeyAlgorithm = 'Ed25519'): KeyPair {
  const { privateKey, publicKey } = algorithm === 'P-256'
    ? nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    : nodeCrypto.generateKeyPairSync('ed25519');

  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
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

/** The JWS algorithm for an agent key: 'EdDSA' (Ed25519) or 'ES256' (P-256). */
export function keyAlg(key: nodeCrypto.KeyObject): 'EdDSA' | 'ES256' {
  if (key.asymmetricKeyType === 'ed25519') return 'EdDSA';
  if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') return 'ES256';
  throw new Error(`Unsupported agent key type: ${key.asymmetricKeyType}`);
}

/**
 * Sign a challenge nonce for handshake completion.
 *
 * The broker sends challenge_for_target as a 64-char hex string. We sign its raw
 * bytes with the agent's key (Ed25519, or P-256 ECDSA/SHA-256 as raw r||s) and
 * return base64, which is what the broker expects as challenge_response.
 */
export function signChallenge(challengeNonce: string, privateKeyBase64: string): string {
  const privateKey = loadPrivateKey(privateKeyBase64);
  const data = Buffer.from(challengeNonce, 'hex');
  const signature = keyAlg(privateKey) === 'ES256'
    ? nodeCrypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    : nodeCrypto.sign(null, data, privateKey);
  return signature.toString('base64');
}

/**
 * A proof of possession: a short JWT signed with the agent's key
 * (typ `parafe-pop+jwt`), with a fresh `iat` and a random single-use `jti`.
 *
 * - Request proofs (the `Parafe-PoP` header): claims `htm`, `htu` and what the
 *   request authorizes (`session_id`; or `target_agent_id` + `requested_scope`).
 * - Presentation proofs (sent beside a consent token): `ath`, `aud`, `mid`.
 */
export async function signProof(privateKeyBase64: string, claims: Record<string, unknown>): Promise<string> {
  const privateKey = loadPrivateKey(privateKeyBase64);
  return new jose.SignJWT({ jti: nodeCrypto.randomUUID(), ...claims })
    .setProtectedHeader({ alg: keyAlg(privateKey), typ: 'parafe-pop+jwt' })
    .setIssuedAt()
    .sign(privateKey);
}

/** base64url(SHA-256(value)): how Parafé artifacts reference each other. */
export function sha256b64u(value: string): string {
  return nodeCrypto.createHash('sha256').update(value).digest('base64url');
}

/**
 * The presentation proof an initiator sends with its consent token, so the
 * target can check the token is being presented by the key it's bound to
 * (`cnf.jkt`). `audience` is the target agent's DID (the token's `aud`).
 */
export async function createPresentationProof(
  privateKeyBase64: string,
  consentToken: string,
  audience: string,
  messageId?: string
): Promise<string> {
  return signProof(privateKeyBase64, {
    ath: sha256b64u(consentToken),
    aud: audience,
    ...(messageId ? { mid: messageId } : {}),
  });
}

/** RFC 7638 thumbprint of a public key given as base64 SPKI DER. */
export function publicKeyThumbprint(publicKeyBase64: string): string {
  const key = nodeCrypto.createPublicKey({ key: Buffer.from(publicKeyBase64, 'base64'), format: 'der', type: 'spki' });
  const jwk = key.export({ format: 'jwk' }) as { kty: string; crv: string; x: string; y?: string };
  const members = jwk.kty === 'EC'
    ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return sha256b64u(JSON.stringify(members));
}
