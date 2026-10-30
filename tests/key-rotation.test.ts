/**
 * Unit tests: rotateKey() (broker SPEC-006) proves the new key, authenticates
 * as the agent or its manager, and replaces the loaded key and credential file;
 * receipts are signed with the credential's kid. No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient, ValidationError } from '../src/index.js';
import { encryptCredentials, decryptCredentials } from '../src/credentials.js';
import type { StoredCredentials } from '../src/types.js';

const DID = 'did:web:broker.test:agents:prf_agent_shop01';
const agentKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const unsigned = (claims: Record<string, unknown>) =>
  `${Buffer.from('{"alg":"ES256"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;
const CREDS: StoredCredentials = {
  agentId: 'prf_agent_shop01',
  agentName: 'shop',
  credential: unsigned({ sub: 'prf_agent_shop01' }),
  credentialSdJwt: `${unsigned({ sub: DID })}~`,
  publicKey: agentKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  privateKey: agentKeys.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  issuedAt: '2026-09-28T00:00:00.000Z',
  expiresAt: '2099-01-01T00:00:00.000Z',
};
const ROTATED = {
  agent_id: 'prf_agent_shop01',
  kid: `${DID}#keys-2`,
  key_version: 2,
  retired_kid: `${DID}#keys-1`,
  retired_at: '2026-10-30T00:00:00.000Z',
  credential: unsigned({ sub: 'prf_agent_shop01', kid: `${DID}#keys-2` }),
  credential_sd_jwt: `${unsigned({ sub: DID, kid: `${DID}#keys-2` })}~`,
  issued_at: '2026-10-30T00:00:00.000Z',
  expires_at: '2026-11-29T00:00:00.000Z',
  sessions_ended: 1,
};

const files: string[] = [];
async function loadedClient(opts: { apiKey?: string } = {}): Promise<{ client: ParafeClient; file: string }> {
  const file = join(tmpdir(), `parafe-rotate-test-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  files.push(file);
  await encryptCredentials(file, CREDS, 'pass');
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0, ...opts });
  await client.loadCredentials(file, 'pass');
  return { client, file };
}

let calls: { url: string; headers: Record<string, string>; body: Record<string, unknown> }[] = [];
let respond: () => { status: number; body: unknown } = () => ({ status: 200, body: ROTATED });
const realFetch = globalThis.fetch;
beforeEach(() => {
  calls = [];
  respond = () => ({ status: 200, body: ROTATED });
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : {} });
    const { status, body } = respond();
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  await Promise.all(files.map((f) => rm(f, { force: true })));
});

describe('rotateKey()', () => {
  it('the agent rotates itself: credential, proof from the old key, proof from the new key', async () => {
    const { client, file } = await loadedClient();
    const r = await client.rotateKey();
    const url = 'https://broker.test/agents/prf_agent_shop01/rotate-key';
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(url);
    expect(calls[0]!.headers.Authorization).toBe(`Bearer ${CREDS.credential}`);

    const oldProof = await jose.jwtVerify(calls[0]!.headers['Parafe-PoP']!, createPublicKey({ key: Buffer.from(CREDS.publicKey, 'base64'), format: 'der', type: 'spki' }));
    expect(oldProof.payload).toMatchObject({ htm: 'POST', htu: url, agent_id: 'prf_agent_shop01' });

    const body = calls[0]!.body as { new_public_key: string; new_key_proof: string };
    expect(body.new_public_key).toBe(r.publicKey);
    expect(body.new_public_key).not.toBe(CREDS.publicKey);
    const newProof = await jose.jwtVerify(body.new_key_proof, createPublicKey({ key: Buffer.from(body.new_public_key, 'base64'), format: 'der', type: 'spki' }));
    expect(newProof.payload).toMatchObject({ htm: 'POST', htu: url, agent_id: 'prf_agent_shop01' });

    expect(r).toMatchObject({ kid: `${DID}#keys-2`, keyVersion: 2, retiredKid: `${DID}#keys-1`, sessionsEnded: 1, saved: true });
    const onDisk = await decryptCredentials(file, 'pass');
    expect(onDisk.privateKey).toBe(r.privateKey);
    expect(onDisk.credential).toBe(ROTATED.credential);
  });

  it('signs receipts with the new kid afterwards (and #keys-1 before)', async () => {
    const { client } = await loadedClient();
    const before = await client.signActionReceipt({ sessionId: 's', consentToken: 't', action: 'a' });
    expect(jose.decodeProtectedHeader(before).kid).toBe(`${DID}#keys-1`);
    await client.rotateKey();
    const after = await client.signActionReceipt({ sessionId: 's', consentToken: 't', action: 'a' });
    expect(jose.decodeProtectedHeader(after).kid).toBe(`${DID}#keys-2`);
    const keys = client.exportKeys();
    await jose.compactVerify(after, createPublicKey({ key: Buffer.from(keys.publicKey, 'base64'), format: 'der', type: 'spki' }));
  });

  it('with an API key, its manager rotates it (no credential, no old-key proof)', async () => {
    const { client } = await loadedClient({ apiKey: 'prf_key_live_x' });
    await client.rotateKey('prf_agent_shop01');
    expect(calls[0]!.headers.Authorization).toBe('Bearer prf_key_live_x');
    expect(calls[0]!.headers['Parafe-PoP']).toBeUndefined();
  });

  it("rotating another agent returns the new key and leaves the loaded one alone", async () => {
    const { client, file } = await loadedClient({ apiKey: 'prf_key_live_x' });
    respond = () => ({ status: 200, body: { ...ROTATED, agent_id: 'prf_agent_other' } });
    const r = await client.rotateKey('prf_agent_other');
    expect(r.saved).toBeUndefined();
    expect(r.privateKey).toBeTruthy();
    expect(client.exportKeys().privateKey).toBe(CREDS.privateKey);
    expect((await decryptCredentials(file, 'pass')).privateKey).toBe(CREDS.privateKey);
  });

  it('without an API key, refuses to rotate another agent', async () => {
    const { client } = await loadedClient();
    await expect(client.rotateKey('prf_agent_other')).rejects.toBeInstanceOf(ValidationError);
    expect(calls).toHaveLength(0);
  });

  it("keeps the old key when the broker refuses", async () => {
    const { client } = await loadedClient();
    respond = () => ({ status: 403, body: { error: 'org_must_rotate', message: 'An organization runs this agent' } });
    await expect(client.rotateKey()).rejects.toMatchObject({ code: 'org_must_rotate' });
    expect(client.exportKeys().privateKey).toBe(CREDS.privateKey);
  });
});
