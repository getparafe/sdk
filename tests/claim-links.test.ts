/**
 * Unit tests: claim links (Phase 1.5). A keyless agent gets a claim link at
 * registration, can ask for a new one, reads its claim status, and learns about
 * the link from a handshake refused for identity or tier. No network: fetch is stubbed.
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
const LINK = { url: CLAIM.claim_url, code: CLAIM.code, expiresAt: CLAIM.expires_at };

let calls: { url: string; method: string; headers: Record<string, string>; body?: Record<string, unknown> }[] = [];
let respond: (url: string) => { status: number; body: unknown } = () => ({ status: 200, body: {} });
const realFetch = globalThis.fetch;

beforeEach(() => {
  calls = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>, body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined });
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

describe('claim links (Phase 1.5)', () => {
  it('a keyless register() returns claimLink', async () => {
    respond = () => ({ status: 201, body: {
      agent_id: 'prf_agent_new', agent_name: 'alex-assistant', identity_assurance: 'self_registered', verification_tier: 'unverified',
      credential: 'x.y.z', issued_at: 'now', expires_at: 'later', claim: CLAIM,
    } });
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
    const result = await client.register({ name: 'alex-assistant', type: 'personal', principalName: 'Alex' });
    expect(result.claimLink).toEqual(LINK);
    expect(calls[0].headers.Authorization).toBeUndefined();
  });

  it('register() proves it holds the key it registers (broker SPEC-003 part 4)', async () => {
    respond = () => ({ status: 201, body: {
      agent_id: 'prf_agent_new', agent_name: 'prf_agent_new', identity_assurance: 'self_registered', verification_tier: 'unverified',
      credential: 'x.y.z', issued_at: 'now', expires_at: 'later', claim: CLAIM,
    } });
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey: 'prf_key_live_test', retries: 0 });
    await client.register({ type: 'personal', name: 'proof-agent' });
    const pub = createPublicKey({ key: Buffer.from(calls[0].body!.public_key as string, 'base64'), format: 'der', type: 'spki' });
    const { payload } = await jose.jwtVerify(calls[0].headers['Parafe-PoP'], pub, { typ: 'parafe-pop+jwt' });
    expect(payload).toMatchObject({ htm: 'POST', htu: 'https://broker.test/agents/register' });
    expect(typeof payload.jti).toBe('string');
    expect(calls[0].headers.Authorization).toBe('Bearer prf_key_live_test');
  });

  it('a keyless register() needs no name or principal (broker SPEC-002 decision 10)', async () => {
    respond = () => ({ status: 201, body: {
      agent_id: 'prf_agent_new', agent_name: 'prf_agent_new', principal_name: null, identity_assurance: 'self_registered', verification_tier: 'unverified',
      credential: 'x.y.z', issued_at: 'now', expires_at: 'later', claim: CLAIM,
    } });
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
    const result = await client.register({ type: 'personal' });
    expect(calls[0].body).not.toHaveProperty('agent_name');
    expect(calls[0].body).not.toHaveProperty('principal_name');
    // The link's code is the one to show the person (no second code).
    expect(result.claimLink).toEqual(LINK);
    expect(result.claimLink).not.toHaveProperty('pairingCode');
    expect(client.credentialStatus()).toMatchObject({ loaded: true, agentName: 'prf_agent_new' });
  });

  it('createClaimLink() authenticates as the agent (credential + proof), even with an API key set', async () => {
    respond = () => ({ status: 201, body: CLAIM });
    const client = await clientWithCredentials('prf_key_live_user_abc');
    const link = await client.createClaimLink();
    expect(link).toEqual(LINK);
    expect(calls[0].url).toBe('https://broker.test/agents/prf_agent_alex01/claim-link');
    expect(calls[0].method).toBe('POST');
    expect(calls[0].headers.Authorization).toBe(`Bearer ${CREDS.credential}`);
    const claims = await proofClaims(calls[0].headers);
    expect(claims).toMatchObject({ htm: 'POST', htu: calls[0].url, agent_id: CREDS.agentId });
  });

  it('getClaimStatus() maps the status and signs a GET proof', async () => {
    respond = () => ({ status: 200, body: {
      claimed: true, identity_assurance: 'claimed', verification_tier: 'unverified', principal_tier: 'email_verified', credential_current: false,
      registered_at: '2026-09-30T12:00:00.000Z', operator_type: null, operator_id: null, principal_type: 'personal', principal_ref: null,
    } });
    const client = await clientWithCredentials();
    const status = await client.getClaimStatus();
    expect(status).toEqual({
      claimed: true, identityAssurance: 'claimed', verificationTier: 'unverified', principalTier: 'email_verified', credentialCurrent: false,
      operatorType: null, operatorId: null, principalType: 'personal', principalRef: null,
      registeredAt: '2026-09-30T12:00:00.000Z',
    });
    expect(calls[0].url).toBe('https://broker.test/agents/prf_agent_alex01/claim-status');
    expect(calls[0].method).toBe('GET');
    const claims = await proofClaims(calls[0].headers);
    expect(claims).toMatchObject({ htm: 'GET', agent_id: CREDS.agentId });
  });

  const STATUS = (claimed: boolean) => ({
    claimed, identity_assurance: claimed ? 'claimed' : 'self_registered', verification_tier: 'unverified', principal_tier: claimed ? 'unverified' : null,
    credential_current: !claimed, registered_at: '2026-09-30T12:00:00.000Z', operator_type: null, operator_id: null, principal_type: claimed ? 'personal' : null, principal_ref: null,
  });

  it('getClaimStatus({ waitSeconds }) asks the broker to wait, with the proof bound to the URL without the query', async () => {
    respond = () => ({ status: 200, body: STATUS(false) });
    const client = await clientWithCredentials();
    await client.getClaimStatus({ waitSeconds: 25 });
    expect(calls[0].url).toBe('https://broker.test/agents/prf_agent_alex01/claim-status?wait=25');
    const claims = await proofClaims(calls[0].headers);
    expect(claims).toMatchObject({ htm: 'GET', htu: 'https://broker.test/agents/prf_agent_alex01/claim-status', agent_id: CREDS.agentId });
  });

  it('waitForClaim() asks again, with a new proof each time, until the person approves', async () => {
    let n = 0;
    respond = () => ({ status: 200, body: STATUS(++n >= 3) });
    const client = await clientWithCredentials();
    const status = await client.waitForClaim({ waitSeconds: 5 });
    expect(status.claimed).toBe(true);
    expect(calls).toHaveLength(3);
    for (const c of calls) expect(c.url).toBe('https://broker.test/agents/prf_agent_alex01/claim-status?wait=5');
    const jtis = await Promise.all(calls.map(async (c) => (await proofClaims(c.headers)).jti));
    expect(new Set(jtis).size).toBe(3);
  });

  it('waitForClaim() gives up after timeoutMs and returns the last status', async () => {
    respond = () => ({ status: 200, body: STATUS(false) });
    const client = await clientWithCredentials();
    const status = await client.waitForClaim({ waitSeconds: 1, timeoutMs: 1 });
    expect(status.claimed).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it('waitForClaim() refuses a wait over 60 seconds, or of 0 (it would ask without pausing)', async () => {
    const client = await clientWithCredentials();
    await expect(client.waitForClaim({ waitSeconds: 61 })).rejects.toThrow(/0 to 60/);
    await expect(client.waitForClaim({ waitSeconds: 0 })).rejects.toThrow(/at least 1/);
    expect(calls).toHaveLength(0);
  });

  it('waitForClaim() rides out a deploy (502) and asks again with a new proof', async () => {
    let n = 0;
    respond = () => (++n === 1 ? { status: 502, body: { error: 'bad_gateway' } } : { status: 200, body: STATUS(true) });
    const client = await clientWithCredentials();
    const status = await client.waitForClaim({ waitSeconds: 5 });
    expect(status.claimed).toBe(true);
    expect(calls).toHaveLength(2);
    const [a, b] = await Promise.all(calls.map(async (c) => (await proofClaims(c.headers)).jti));
    expect(a).not.toBe(b);
  });

  it('waitForClaim() stops on a refusal (the agent was revoked)', async () => {
    respond = () => ({ status: 409, body: { error: 'agent_inactive', message: 'Agent is revoked' } });
    const client = await clientWithCredentials();
    await expect(client.waitForClaim({ waitSeconds: 5 })).rejects.toThrow(/revoked/);
    expect(calls).toHaveLength(1);
  });

  it('a handshake refused for tier carries .claim and .hint', async () => {
    respond = () => ({ status: 403, body: {
      error: 'tier_insufficient', message: "Scope 'place-order' requires verification_tier 'email_verified'",
      claim: CLAIM, hint: 'Ask the person you act for to open this link to verify you.',
    } });
    const client = await clientWithCredentials();
    const err = await client.handshake({ targetAgentId: 'prf_agent_shop', scope: 'place-order', permissions: ['create_order'] }).catch((e) => e);
    expect(err).toBeInstanceOf(ForbiddenError);
    expect(err.code).toBe('tier_insufficient');
    expect(err.claim).toEqual(LINK);
    expect(err.hint).toBe('Ask the person you act for to open this link to verify you.');
  });

  it('renewal picks up the name in the new credential (a keyless agent renamed to its agent ID)', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const renewed = await new jose.SignJWT({ sub: CREDS.agentId, name: CREDS.agentId }).setProtectedHeader({ alg: 'EdDSA' }).sign(privateKey);
    respond = () => ({ status: 200, body: { agent_id: CREDS.agentId, renewed: true, reason: 'identity_changed', credential: renewed, issued_at: 'now', expires_at: '2099-02-01T00:00:00.000Z' } });
    const client = await clientWithCredentials();
    expect(client.credentialStatus()).toMatchObject({ agentName: 'alex-assistant' });
    await client.renewCredential(CREDS.agentId);
    expect(client.credentialStatus()).toMatchObject({ agentName: CREDS.agentId });
  });

  it('other 403s have no claim', () => {
    const err = mapBrokerError(403, { error: 'scope_not_found', message: 'nope' }) as ForbiddenError;
    expect(err).toBeInstanceOf(ForbiddenError);
    expect(err.claim).toBeUndefined();
    expect(err.hint).toBeUndefined();
  });
});

describe('reputation floors (B18)', () => {
  it('a 403 from a reputation floor carries the signal, what is required and what the agent has', () => {
    const err = mapBrokerError(403, { error: 'tenure_insufficient', message: 'too new', signal: 'tenure_days', required: 30, actual: 2 }) as ForbiddenError;
    expect(err.code).toBe('tenure_insufficient');
    expect(err.reputation).toEqual({ signal: 'tenure_days', required: 30, actual: 2 });
    expect((mapBrokerError(403, { error: 'tier_insufficient', message: 'm' }) as ForbiddenError).reputation).toBeUndefined();
  });
});
