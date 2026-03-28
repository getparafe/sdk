/**
 * Unit tests for AES-256-GCM credential file encryption/decryption.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { encryptCredentials, decryptCredentials } from '../src/credentials.js';
import type { StoredCredentials } from '../src/types.js';

const TEST_CREDS: StoredCredentials = {
  agentId: 'prf_agent_test01',
  agentName: 'test-agent',
  credential: 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJwcmZfYWdlbnRfdGVzdDAxIn0.fakeSignature',
  publicKey: 'MCowBQYDK2VwAyEAfakePublicKey==',
  privateKey: 'MC4CAQAwBQYDK2VwBCIEIfakePrivateKey==',
  issuedAt: '2026-03-28T00:00:00.000Z',
  expiresAt: '2026-04-27T00:00:00.000Z',
};

function tempFile(): string {
  return join(tmpdir(), `parafe-test-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
}

describe('encryptCredentials / decryptCredentials', () => {
  it('round-trips credentials correctly', async () => {
    const filePath = tempFile();
    try {
      await encryptCredentials(filePath, TEST_CREDS, 'test-passphrase-123');
      const result = await decryptCredentials(filePath, 'test-passphrase-123');

      expect(result.agentId).toBe(TEST_CREDS.agentId);
      expect(result.agentName).toBe(TEST_CREDS.agentName);
      expect(result.credential).toBe(TEST_CREDS.credential);
      expect(result.publicKey).toBe(TEST_CREDS.publicKey);
      expect(result.privateKey).toBe(TEST_CREDS.privateKey);
      expect(result.issuedAt).toBe(TEST_CREDS.issuedAt);
      expect(result.expiresAt).toBe(TEST_CREDS.expiresAt);
    } finally {
      await rm(filePath, { force: true });
    }
  });

  it('produces different ciphertexts for the same input (random IV)', async () => {
    const filePath1 = tempFile();
    const filePath2 = tempFile();
    try {
      await encryptCredentials(filePath1, TEST_CREDS, 'same-passphrase');
      await encryptCredentials(filePath2, TEST_CREDS, 'same-passphrase');

      const { readFile } = await import('node:fs/promises');
      const data1 = JSON.parse(await readFile(filePath1, 'utf8'));
      const data2 = JSON.parse(await readFile(filePath2, 'utf8'));

      // IV and ciphertext should differ each time
      expect(data1.iv).not.toBe(data2.iv);
      expect(data1.ciphertext).not.toBe(data2.ciphertext);
    } finally {
      await rm(filePath1, { force: true });
      await rm(filePath2, { force: true });
    }
  });

  it('throws on wrong passphrase', async () => {
    const filePath = tempFile();
    try {
      await encryptCredentials(filePath, TEST_CREDS, 'correct-passphrase');
      await expect(decryptCredentials(filePath, 'wrong-passphrase')).rejects.toThrow();
    } finally {
      await rm(filePath, { force: true });
    }
  });

  it('throws when file does not exist', async () => {
    await expect(
      decryptCredentials('/nonexistent/path/file.enc', 'any')
    ).rejects.toThrow();
  });

  it('throws on corrupted file content', async () => {
    const filePath = tempFile();
    const { writeFile } = await import('node:fs/promises');
    try {
      await writeFile(filePath, 'not valid json', 'utf8');
      await expect(decryptCredentials(filePath, 'any')).rejects.toThrow('not valid JSON');
    } finally {
      await rm(filePath, { force: true });
    }
  });

  it('writes file with correct version and algorithm metadata', async () => {
    const filePath = tempFile();
    try {
      await encryptCredentials(filePath, TEST_CREDS, 'passphrase');
      const { readFile } = await import('node:fs/promises');
      const data = JSON.parse(await readFile(filePath, 'utf8'));
      expect(data.version).toBe(1);
      expect(data.algorithm).toBe('aes-256-gcm');
      expect(typeof data.salt).toBe('string');
      expect(typeof data.iv).toBe('string');
      expect(typeof data.tag).toBe('string');
      expect(typeof data.ciphertext).toBe('string');
    } finally {
      await rm(filePath, { force: true });
    }
  });
});
