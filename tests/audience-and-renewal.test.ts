/**
 * Unit tests: a consent token is checked against the agent it was issued for
 * (S-69), a renewed credential is written back to the file it was loaded from,
 * and validation refusals keep the broker's details. No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient, AuthError, ValidationError } from '../src/index.js';
import { encryptCredentials, decryptCredentials } from '../src/credentials.js';
import { mapBrokerError } from '../src/errors.js';
import type { StoredCredentials } from '../src/types.js';

const agentKeys = generateKeyPairSync('ed25519');
const CREDS: StoredCredentials = {
  agentId: 'prf_agent_shop01',
  agentName: 'shop',
  credential: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcmZfYWdlbnRfc2hvcDAxIn0.sig',
  publicKey: agentKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  privateKey: agentKeys.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  issuedAt: '2026-09-28T00:00:00.000Z',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

const broker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const JWKS = { keys: [{ ...(broker.publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'es-1', alg: 'ES256' }] } as never;

function consentToken(target: string, initiator = 'prf_agent_alex01'): Promise<string> {
  return new jose.SignJWT({ token_type: 'consent', scope: 's', session_id: 'sess_1', sub: initiator, target_agent_id: target })
    .setProtectedHeader({ alg: 'ES256', kid: 'es-1' })
    .setIssuedAt().setExpirationTime('5m').setIssuer('parafe-trust-broker')
    .sign(broker.privateKey);
}

const files: string[] = [];
async function loadedClient(creds: StoredCredentials = CREDS): Promise<{ client: ParafeClient; file: string }> {
  const file = join(tmpdir(), `parafe-renew-test-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  files.push(file);
  await encryptCredentials(file, creds, 'pass');
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
  await client.loadCredentials(file, 'pass');
  return { client, file };
}

let bodies: Record<string, unknown>[] = [];
let respond: () => { status: number; body: unknown } = () => ({ status: 200, body: {} });
const realFetch = globalThis.fetch;
beforeEach(() => {
  bodies = [];
  globalThis.fetch = jest.fn(async (_url: unknown, init?: RequestInit) => {
    bodies.push(init?.body ? JSON.parse(String(init.body)) : {});
    const { status, body } = respond();
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(async () => {
  globalThis.fetch = realFetch;
  await Promise.all(files.map((f) => rm(f, { force: true })));
});

describe('consent token audience (S-69)', () => {
  it('verifyConsentLocally accepts a token for the loaded agent and reports its target', async () => {
    const { client } = await loadedClient();
    const r = await client.verifyConsentLocally(await consentToken(CREDS.agentId), JWKS);
    expect(r.valid).toBe(true);
    expect(r.targetAgentId).toBe(CREDS.agentId);
  });

  it('verifyConsentLocally refuses a token issued for another agent', async () => {
    const { client } = await loadedClient();
    const err = await client.verifyConsentLocally(await consentToken('prf_agent_other99'), JWKS).catch((e) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect(err.code).toBe('wrong_audience');
  });

  it("doesn't check when the loaded agent is the token's initiator, or with agentId: null", async () => {
    const { client } = await loadedClient();
    const own = await consentToken('prf_agent_other99', CREDS.agentId);
    expect((await client.verifyConsentLocally(own, JWKS)).valid).toBe(true);
    expect((await client.verifyConsentLocally(await consentToken('prf_agent_other99'), JWKS, { agentId: null })).valid).toBe(true);
  });

  it('an explicit agentId is checked even with nothing loaded', async () => {
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
    const token = await consentToken('prf_agent_other99');
    expect((await client.verifyConsentLocally(token, JWKS)).valid).toBe(true);
    await expect(client.verifyConsentLocally(token, JWKS, { agentId: CREDS.agentId })).rejects.toMatchObject({ code: 'wrong_audience' });
  });

  it('verifyConsent sends the loaded agent as agent_id, and the refusal keeps its code', async () => {
    const { client } = await loadedClient();
    const token = await consentToken(CREDS.agentId);
    respond = () => ({ status: 200, body: { valid: true, action: 'a', permitted: true, session_id: 'sess_1' } });
    await client.verifyConsent({ consentToken: token, action: 'a', sessionId: 'sess_1' });
    expect(bodies[0].agent_id).toBe(CREDS.agentId);

    await client.verifyConsent({ consentToken: token, action: 'a', sessionId: 'sess_1', agentId: null });
    expect(bodies[1]).not.toHaveProperty('agent_id');

    respond = () => ({ status: 401, body: { valid: false, error: 'wrong_audience', reason: 'This consent token was issued for x' } });
    await expect(client.verifyConsent({ consentToken: token, action: 'a', sessionId: 'sess_1' })).rejects.toMatchObject({ code: 'wrong_audience' });
  });
});

describe('renewCredential() keeps the credential file current', () => {
  it('writes the renewed credential back to the file it was loaded from', async () => {
    const { client, file } = await loadedClient();
    respond = () => ({ status: 200, body: { agent_id: CREDS.agentId, renewed: true, reason: 'near_expiry', credential: 'new.credential.jwt', issued_at: 'now', expires_at: '2099-02-01T00:00:00.000Z' } });
    const r = await client.renewCredential(CREDS.agentId);
    expect(r.saved).toBe(true);
    const onDisk = await decryptCredentials(file, 'pass');
    expect(onDisk.credential).toBe('new.credential.jwt');
    expect(onDisk.expiresAt).toBe('2099-02-01T00:00:00.000Z');
    expect(onDisk.privateKey).toBe(CREDS.privateKey);
  });

  it('reports a file it could not write, and keeps the new credential loaded', async () => {
    const { client } = await loadedClient();
    // Point the remembered file somewhere unwritable.
    (client as unknown as { credentialFile: { path: string; passphrase: string } }).credentialFile = { path: '/nonexistent-dir/creds.enc', passphrase: 'pass' };
    respond = () => ({ status: 200, body: { agent_id: CREDS.agentId, renewed: true, credential: 'new.credential.jwt' } });
    const r = await client.renewCredential(CREDS.agentId);
    expect(r.saved).toBe(false);
    expect(r.saveError).toBeTruthy();
    expect(client.exportKeys().credential).toBe('new.credential.jwt');
  });

  it("doesn't touch the file when nothing was renewed", async () => {
    const { client, file } = await loadedClient();
    respond = () => ({ status: 200, body: { agent_id: CREDS.agentId, renewed: false } });
    const r = await client.renewCredential(CREDS.agentId);
    expect(r).not.toHaveProperty('saved');
    expect((await decryptCredentials(file, 'pass')).credential).toBe(CREDS.credential);
  });
});

describe('validation refusals', () => {
  it('keep the broker details and say them when there is no message', () => {
    const err = mapBrokerError(400, { error: 'validation_error', details: ['agent_name is required', 'public_key is required'] });
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).details).toEqual(['agent_name is required', 'public_key is required']);
    expect(err.message).toBe('agent_name is required; public_key is required');
  });

  it('keep unknown scope policy fields', () => {
    const err = mapBrokerError(400, { error: 'unknown_policy_fields', message: 'Unknown fields', unknown_fields: ['min_tier'] }) as ValidationError;
    expect(err.unknownFields).toEqual(['min_tier']);
    expect(err.message).toBe('Unknown fields');
  });
});
