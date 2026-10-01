/**
 * Unit tests: operator and principal (broker SPEC-002). register() sends
 * principal_name and acts_for; claim status, handshake results, receipts and
 * local consent verification carry the parties. No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient, ForbiddenError } from '../src/index.js';
import { mapBrokerError } from '../src/errors.js';
import { encryptCredentials } from '../src/credentials.js';
import type { StoredCredentials } from '../src/types.js';

const agentKeys = generateKeyPairSync('ed25519');
const CREDS: StoredCredentials = {
  agentId: 'prf_agent_alex01',
  agentName: 'alex-assistant',
  credential: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcmZfYWdlbnRfYWxleDAxIn0.sig',
  publicKey: agentKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  privateKey: agentKeys.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  issuedAt: '2026-09-28T00:00:00.000Z',
  expiresAt: '2099-01-01T00:00:00.000Z',
};
const CLAIM = { claim_url: 'https://platform.parafe.ai/claim?code=7KQ2-M9XD-4H', code: '7KQ2-M9XD-4H', expires_at: '2026-09-30T12:30:00.000Z' };

let calls: { url: string; method: string; headers: Record<string, string>; body?: string }[] = [];
let respond: (url: string) => { status: number; body: unknown } = () => ({ status: 200, body: {} });
const realFetch = globalThis.fetch;

beforeEach(() => {
  calls = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body as string | undefined });
    const { status, body } = respond(String(url));
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

async function clientWithCredentials(apiKey?: string): Promise<ParafeClient> {
  const file = join(tmpdir(), `parafe-claim-test-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey, retries: 0 });
  try {
    await encryptCredentials(file, CREDS, 'pass');
    await client.loadCredentials(file, 'pass');
  } finally {
    await rm(file, { force: true });
  }
  return client;
}

async function proofClaims(headers: Record<string, string>) {
  const { payload } = await jose.jwtVerify(headers['Parafe-PoP'], createPublicKey(agentKeys.privateKey), { typ: 'parafe-pop+jwt' });
  return payload;
}

describe('operator and principal (SPEC-002)', () => {
  it('register() sends principal_name and acts_for, and maps the parties', async () => {
    respond = () => ({ status: 201, body: {
      agent_id: 'prf_agent_u1', agent_name: 'assistant-u1', identity_assurance: 'registered', verification_tier: 'unverified',
      principal_name: 'Platform user', principal_type: 'external', principal_id: null, principal_ref: 'user-8f3a',
      operator_type: 'org', operator_id: 'prf_org_p', credential: 'x.y.z', issued_at: 'now', expires_at: 'later',
    } });
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey: 'prf_key_live_org', retries: 0 });
    const r = await client.register({ name: 'assistant-u1', type: 'personal', principalName: 'Platform user', actsFor: { ref: 'user-8f3a' } });
    const body = JSON.parse(calls[0].body as string);
    expect(body).toMatchObject({ principal_name: 'Platform user', acts_for: { ref: 'user-8f3a' } });
    expect(body).not.toHaveProperty('owner');
    expect(r).toMatchObject({ operatorType: 'org', operatorId: 'prf_org_p', principalType: 'external', principalId: null, principalRef: 'user-8f3a' });
  });

  it('register() without actsFor sends no acts_for', async () => {
    respond = () => ({ status: 201, body: { agent_id: 'prf_agent_x', agent_name: 'x', identity_assurance: 'self_registered', verification_tier: 'unverified', credential: 'x.y.z', issued_at: 'now', expires_at: 'later' } });
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
    const r = await client.register({ name: 'x-agent', type: 'personal', principalName: 'Alex' });
    expect(JSON.parse(calls[0].body as string)).not.toHaveProperty('acts_for');
    expect(r).toMatchObject({ operatorType: null, operatorId: null, principalType: null, principalId: null, principalRef: null });
  });

  it('getClaimStatus() maps principal and operator fields', async () => {
    respond = () => ({ status: 200, body: {
      claimed: false, operator_type: 'org', operator_id: 'prf_org_p', principal_type: 'external', principal_ref: 'user-8f3a',
      identity_assurance: 'registered', verification_tier: 'unverified', principal_tier: null, credential_current: true, registered_at: '2026-10-01T00:00:00.000Z',
    } });
    const client = await clientWithCredentials();
    expect(await client.getClaimStatus()).toEqual({
      claimed: false, operatorType: 'org', operatorId: 'prf_org_p', principalType: 'external', principalRef: 'user-8f3a',
      identityAssurance: 'registered', verificationTier: 'unverified', principalTier: null, credentialCurrent: true, registeredAt: '2026-10-01T00:00:00.000Z',
    });
  });

  it('getClaimStatus() returns principalEmail only when shared', async () => {
    respond = () => ({ status: 200, body: {
      claimed: true, operator_type: null, operator_id: null, principal_type: 'personal', principal_ref: null, identity_assurance: 'claimed',
      verification_tier: 'email_verified', principal_tier: 'email_verified', credential_current: true, registered_at: 'r',
      principal_email: 'alex@example.com', principal_email_verified: true,
    } });
    const client = await clientWithCredentials();
    const s = await client.getClaimStatus();
    expect(s.principalEmail).toBe('alex@example.com');
    expect(s.principalEmailVerified).toBe(true);
    expect(s).not.toHaveProperty('ownerEmail');
  });
});
