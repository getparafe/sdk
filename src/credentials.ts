/**
 * AES-256-GCM credential file encryption/decryption for @parafe-trust/sdk
 *
 * File format (outer JSON):
 *   { version: 1, algorithm: 'aes-256-gcm', salt: '<base64 16-byte>',
 *     iv: '<base64 12-byte>', tag: '<base64 16-byte>', ciphertext: '<base64>' }
 *
 * Decrypted payload:
 *   { agentId, agentName, credential, publicKey, privateKey, issuedAt, expiresAt }
 *
 * Key derivation: scrypt(passphrase, salt, 32) with N=16384, r=8, p=1
 */

import * as nodeCrypto from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import type { StoredCredentials, EncryptedCredentialFile } from './types.js';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;

function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    nodeCrypto.scrypt(
      passphrase,
      salt,
      KEY_LEN,
      { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
      (err, key) => {
        if (err) reject(err);
        else resolve(key as Buffer);
      }
    );
  });
}

/**
 * Encrypt StoredCredentials to an AES-256-GCM file.
 */
export async function encryptCredentials(
  filePath: string,
  credentials: StoredCredentials,
  passphrase: string
): Promise<void> {
  const salt = nodeCrypto.randomBytes(16);
  const iv = nodeCrypto.randomBytes(12);
  const key = await deriveKey(passphrase, salt);

  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = JSON.stringify(credentials);
  const ciphertextBuf = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const fileData: EncryptedCredentialFile = {
    version: 1,
    algorithm: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertextBuf.toString('base64'),
  };

  await writeFile(filePath, JSON.stringify(fileData, null, 2), 'utf8');
}

/**
 * Decrypt an AES-256-GCM credential file back to StoredCredentials.
 */
export async function decryptCredentials(
  filePath: string,
  passphrase: string
): Promise<StoredCredentials> {
  const raw = await readFile(filePath, 'utf8');
  let fileData: EncryptedCredentialFile;

  try {
    fileData = JSON.parse(raw) as EncryptedCredentialFile;
  } catch {
    throw new Error('Credential file is not valid JSON');
  }

  if (fileData.version !== 1 || fileData.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported credential file version or algorithm');
  }

  const salt = Buffer.from(fileData.salt, 'base64');
  const iv = Buffer.from(fileData.iv, 'base64');
  const tag = Buffer.from(fileData.tag, 'base64');
  const ciphertext = Buffer.from(fileData.ciphertext, 'base64');

  const key = await deriveKey(passphrase, salt);

  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  let plaintext: string;
  try {
    plaintext = decipher.update(ciphertext).toString('utf8') + decipher.final('utf8');
  } catch {
    throw new Error('Failed to decrypt credentials — wrong passphrase or corrupted file');
  }

  try {
    return JSON.parse(plaintext) as StoredCredentials;
  } catch {
    throw new Error('Decrypted credential payload is not valid JSON');
  }
}
